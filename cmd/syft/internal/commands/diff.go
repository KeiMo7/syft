package commands

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/cmd/syft/internal/ui"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/syft/diff"
)

const diffExample = `  {{.appName}} {{.command}} old.syft.json new.syft.json                       diff two SBOM files, table report to stdout
  {{.appName}} {{.command}} old.syft.json new.syft.json --diff-format json   machine-readable diff report for pipeline gating
  {{.appName}} {{.command}} old.syft.json new.syft.json --high-risk           only newly added components and downgrades
  {{.appName}} {{.command}} old.syft.json new.syft.json --scope ./subsystem   limit the diff to one subsystem directory
  {{.appName}} {{.command}} old.syft.json new.syft.json --diff-format jsonl --fail-on high-risk
  cat new.syft.json | {{.appName}} {{.command}} old.syft.json -              read the new SBOM from STDIN
  {{.appName}} {{.command}} old.syft.json new.syft.json --diff-format jsonl --fail-on high-risk   stream one JSON object per line and fail on high-risk changes
`

// DiffOptions is the CLI configuration for the diff command.
type DiffOptions struct {
	options.Config      `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
	Diff                options.Diff `yaml:"diff" json:"diff" mapstructure:"diff"`
}

// Diff constructs the `syft diff` sub-command.
func Diff(app clio.Application) *cobra.Command {
	id := app.ID()

	opts := &DiffOptions{
		UpdateCheck: options.DefaultUpdateCheck(),
		Diff:        options.DefaultDiff(),
	}

	return app.SetupCommand(&cobra.Command{
		Use:     "diff [OLD-SBOM] [NEW-SBOM]",
		Short:   "Compare two SBOMs and report component-level changes",
		Long:    "Compare two SBOM snapshots and report added, removed and version-changed components with deterministic identity rules, dependency-layer grouping and machine-readable output for unattended pipeline gating.",
		Example: internal.Tprintf(diffExample, map[string]any{"appName": id.Name, "command": "diff"}),
		Args:    validateDiffArgs,
		PreRunE: applicationUpdateCheck(id, &opts.UpdateCheck),
		RunE: func(cmd *cobra.Command, args []string) error {
			restoreStdout := ui.CaptureStdoutToTraceLog()
			defer restoreStdout()

			return RunDiff(cmd.Context(), opts, args[0], args[1], os.Stdin)
		},
	}, opts)
}

func validateDiffArgs(_ *cobra.Command, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("exactly two SBOM inputs are required (use \"-\" for STDIN for at most one of them)")
	}

	if args[0] == "-" && args[1] == "-" {
		return fmt.Errorf("only one of the two SBOM inputs can be read from STDIN")
	}

	return nil
}

// RunDiff executes the full diff pipeline: load both inputs, refuse schema mismatches,
// compute the in-memory diff and emit the selected report format.
func RunDiff(_ context.Context, opts *DiffOptions, oldPath, newPath string, stdin io.Reader) error {
	oldInput, err := loadDiffInput(oldPath, stdin)
	if err != nil {
		return err
	}

	newInput, err := loadDiffInput(newPath, stdin)
	if err != nil {
		return err
	}

	if err := diff.CheckSchemaCompatibility(oldInput.Input, newInput.Input); err != nil {
		return err
	}

	computeOpts := diff.Options{
		HighRiskOnly: opts.Diff.HighRiskOnly,
		PathPrefixes: opts.Diff.Scope,
	}

	changes, err := diff.Compute(oldInput.SBOM, newInput.SBOM, computeOpts)
	if err != nil {
		return err
	}

	pageChanges, page := diff.Paginate(changes, diff.Pagination{Page: opts.Diff.Page, PageSize: opts.Diff.PageSize})

	report := diff.NewReport(oldInput.Input, newInput.Input, pageChanges, computeOpts)
	report.Page = page
	report.PageSize = opts.Diff.PageSize

	if err := writeDiffReport(opts.Diff.Format, report); err != nil {
		return err
	}

	return gateError(opts.Diff.FailOn, report)
}

func loadDiffInput(path string, stdin io.Reader) (*diff.LoadedInput, error) {
	var reader io.Reader
	if path == "-" {
		reader = stdin
	}

	loaded, err := diff.LoadSBOM(path, reader)
	if err != nil {
		return nil, err
	}

	return loaded, nil
}

func writeDiffReport(formatName string, report diff.Report) error {
	var output bytes.Buffer

	switch diff.OutputFormat(strings.ToLower(strings.TrimSpace(formatName))) {
	case diff.JSONOutput:
		if err := diff.WriteJSON(&output, report); err != nil {
			return err
		}
	case diff.JSONLOutput:
		if err := diff.WriteJSONL(&output, report); err != nil {
			return err
		}
	case diff.TableOutput, "":
		if err := diff.WriteTable(&output, report); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported diff report format %q (supported: table, json, jsonl)", formatName)
	}

	bus.Report(output.String())
	return nil
}

// gateError turns a non-empty gating selection into a non-zero exit signal without
// suppressing the already-written report.
func gateError(failOn []string, report diff.Report) error {
	if len(failOn) == 0 {
		return nil
	}

	matched := make(map[string]struct{})
	for _, rule := range failOn {
		rule = strings.ToLower(strings.TrimSpace(rule))
		if applies(rule, report) {
			matched[rule] = struct{}{}
		}
	}

	if len(matched) == 0 {
		return nil
	}

	rules := make([]string, 0, len(matched))
	for rule := range matched {
		rules = append(rules, rule)
	}

	return &GateError{Rules: rules}
}

func applies(rule string, report diff.Report) bool {
	switch rule {
	case "added":
		return report.Counts.Added > 0
	case "removed":
		return report.Counts.Removed > 0
	case "version-changed":
		return report.Counts.VersionChanged > 0
	case "version-unknown":
		return report.Counts.VersionUnknown > 0
	case "downgrade":
		for _, group := range report.Counts.ByDirection {
			if group.Key == string(diff.Downgrade) && group.Count > 0 {
				return true
			}
		}
	case "high-risk":
		return report.Counts.HighRisk > 0
	}
	return false
}

// GateError indicates that a diff triggered one of the pipeline gating rules.
type GateError struct {
	Rules []string
}

func (e *GateError) Error() string {
	return fmt.Sprintf("diff gating failed, triggered rules: %s", strings.Join(e.Rules, ", "))
}
