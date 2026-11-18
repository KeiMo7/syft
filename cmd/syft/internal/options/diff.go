package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/diff"
)

var _ clio.FlagAdder = (*Diff)(nil)

// Diff holds the options specific to the `syft diff` command.
type Diff struct {
	// HighRiskOnly restricts the report to newly introduced components and downgrades.
	HighRiskOnly bool `yaml:"high-risk-only" json:"high-risk-only" mapstructure:"high-risk-only"`

	// Scope limits the comparison to components located under the given path prefixes.
	Scope []string `yaml:"scope" json:"scope" mapstructure:"scope"`

	// Page is the 1-based page of changes to report when PageSize is set.
	Page int `yaml:"page" json:"page" mapstructure:"page"`

	// PageSize bounds the number of changes emitted in one report; zero means no
	// pagination. With the jsonl output the report is always streamed.
	PageSize int `yaml:"page-size" json:"page-size" mapstructure:"page-size"`

	// Format selects the report format (json, jsonl, table).
	Format string `yaml:"format" json:"format" mapstructure:"format"`

	// FailOn lists change types that make the command exit non-zero for pipeline gating
	// (added, removed, version-changed, version-unknown, downgrade, high-risk).
	FailOn []string `yaml:"fail-on" json:"fail-on" mapstructure:"fail-on"`
}

// DefaultDiff returns the default diff options.
func DefaultDiff() Diff {
	return Diff{
		Format:   string(diff.TableOutput),
		Page:     1,
		PageSize: 0,
	}
}

func (d *Diff) AddFlags(flags clio.FlagSet) {
	flags.BoolVarP(&d.HighRiskOnly, "high-risk", "",
		"only report high-risk changes (newly introduced components and version downgrades)")
	flags.StringArrayVarP(&d.Scope, "scope", "",
		"limit the diff to components under the given path prefix (repeatable)")
	flags.IntVarP(&d.Page, "page", "",
		"1-based page of changes to emit (used together with --page-size)")
	flags.IntVarP(&d.PageSize, "page-size", "",
		"maximum number of changes to emit in one report; 0 emits everything (use the jsonl output format to stream large reports)")
	flags.StringVarP(&d.Format, "diff-format", "",
		"report output format: table, json, jsonl (jsonl streams one change per line)")
	flags.StringArrayVarP(&d.FailOn, "fail-on", "",
		"exit non-zero when any of the given change types is present (repeatable): added, removed, version-changed, version-unknown, downgrade, high-risk")
}
