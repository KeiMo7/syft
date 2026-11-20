package commands

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/go-homedir"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/cmd/syft/internal/ui"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/syft/diff"
	"github.com/anchore/syft/syft/format/cpes"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/purls"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
)

const diffExample = `  {{.appName}} {{.command}} old.syft.json new.syft.json                       diff two SBOMs, report goes to stdout
  {{.appName}} {{.command}} old.syft.json new.syft.json -o diff-json          same, as machine-readable JSON
  {{.appName}} {{.command}} old.syft.json new.syft.json -o diff-json=diff.json   write the JSON report to "diff.json"
`

type DiffOptions struct {
	options.Config      `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
	Diff                options.Diff `yaml:"diff" json:"diff" mapstructure:"diff"`
}

func Diff(app clio.Application) *cobra.Command {
	id := app.ID()

	opts := &DiffOptions{
		UpdateCheck: options.DefaultUpdateCheck(),
		Diff:        options.DefaultDiff(),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "diff <OLD-SBOM> <NEW-SBOM>",
		Short: "Diff two SBOM documents",
		Long: "[Experimental] Compare the package sets of two SBOM documents (typically two scans of the same artifact) " +
			"and report what was added, what disappeared, what changed version, and what is unchanged. " +
			"The report is deterministic: comparing the same two documents always produces byte-for-byte identical output.",
		Example: internal.Tprintf(diffExample, map[string]any{
			"appName": id.Name,
			"command": "diff",
		}),
		Args:    validateDiffArgs,
		PreRunE: applicationUpdateCheck(id, &opts.UpdateCheck),
		RunE: func(cmd *cobra.Command, args []string) error {
			restoreStdout := ui.CaptureStdoutToTraceLog()
			defer restoreStdout()

			return RunDiff(cmd.Context(), opts, args[0], args[1])
		},
	}, opts)
}

func validateDiffArgs(cmd *cobra.Command, args []string) error {
	if len(args) != 2 {
		if err := cmd.Help(); err != nil {
			return fmt.Errorf("unable to display help: %w", err)
		}
		return fmt.Errorf("an old (baseline) SBOM and a new SBOM argument are required")
	}
	if args[0] == "-" && args[1] == "-" {
		return fmt.Errorf("only one of the two SBOMs can be read from STDIN")
	}
	return nil
}

func RunDiff(ctx context.Context, opts *DiffOptions, oldInput, newInput string) error {
	// resolve and validate the output before reading anything, so a bad -o value fails the
	// command without any work (or partial output) happening first
	reportFormat, reportPath, err := parseDiffOutput(opts.Diff.Output)
	if err != nil {
		return err
	}

	// a temp dir is only needed when STDIN is a pipe and has to be spilled to disk; mirrors RunConvert
	td := tmpdir.FromContext(ctx)
	if td == nil {
		_, td = tmpdir.Root(ctx, "syft-diff")
		defer func() {
			_ = td.Cleanup()
		}()
	}

	oldDoc, err := readDiffDocument("baseline", oldInput, td)
	if err != nil {
		return err
	}

	newDoc, err := readDiffDocument("new", newInput, td)
	if err != nil {
		return err
	}

	d := diff.Compare(oldDoc, newDoc)

	var content []byte
	switch reportFormat {
	case "diff-json":
		content, err = diff.RenderJSON(d)
	case "diff-text":
		content = diff.RenderText(d)
	}
	if err != nil {
		return err
	}

	if reportPath == "" {
		bus.Report(string(content))
		return nil
	}

	return writeFileAtomic(reportPath, content)
}

// parseDiffOutput splits a "<format>[=<path>]" output value and validates the format.
func parseDiffOutput(output string) (reportFormat string, reportPath string, err error) {
	reportFormat, reportPath, _ = strings.Cut(strings.TrimSpace(output), "=")
	switch reportFormat {
	case "diff-text", "diff-json":
		return reportFormat, reportPath, nil
	case "":
		return "diff-text", reportPath, nil
	default:
		return "", "", fmt.Errorf("unsupported diff output format %q (supported: diff-text, diff-json)", reportFormat)
	}
}

// readDiffDocument opens one SBOM input and extracts its comparable view, mapping each
// failure mode to a distinguishable error: a missing file, an unrecognized format, a corrupt
// document, and an incompatible tool version each get their own message.
func readDiffDocument(label string, input string, td *tmpdir.TempDir) (*diff.Document, error) {
	reader, _, err := openConvertInput(input, td)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s SBOM not found: %s", label, input)
		}
		return nil, fmt.Errorf("unable to open %s SBOM: %w", label, err)
	}
	defer func() {
		_ = reader.Close()
	}()

	doc, err := diff.ReadDocument(reader)
	if err != nil {
		switch {
		case errors.Is(err, diff.ErrFormatNotIdentified):
			return nil, fmt.Errorf("%s SBOM format not recognized: %s (supported formats: %s)", label, input, supportedDecoderIDs())
		case errors.Is(err, diff.ErrIncompatibleSchema):
			return nil, fmt.Errorf("%s SBOM is incompatible with this syft: %v", label, err)
		case errors.Is(err, diff.ErrCorruptDocument):
			return nil, fmt.Errorf("%s SBOM could not be decoded (file may be corrupt): %s: %v", label, input, err)
		default:
			return nil, fmt.Errorf("unable to read %s SBOM: %s: %w", label, input, err)
		}
	}
	return doc, nil
}

func supportedDecoderIDs() string {
	ids := []string{
		string(syftjson.ID),
		string(cyclonedxjson.ID),
		string(cyclonedxxml.ID),
		string(spdxjson.ID),
		string(spdxtagvalue.ID),
		string(purls.ID),
		string(cpes.ID),
	}
	return strings.Join(ids, ", ")
}

// writeFileAtomic writes the report to a temp file in the destination directory and renames
// it into place, so a failure partway through never leaves a half-written report behind.
func writeFileAtomic(path string, content []byte) error {
	expandedPath, err := homedir.Expand(path)
	if err != nil {
		expandedPath = path
	}

	if err := os.MkdirAll(filepath.Dir(expandedPath), 0755); err != nil {
		return fmt.Errorf("unable to create report directory: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(expandedPath), ".syft-diff-*.tmp")
	if err != nil {
		return fmt.Errorf("unable to create report file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("unable to write report file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("unable to write report file: %w", err)
	}
	if err := os.Rename(tmpName, expandedPath); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("unable to finalize report file: %w", err)
	}
	return nil
}
