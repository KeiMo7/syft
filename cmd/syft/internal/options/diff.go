package options

import (
	"github.com/anchore/clio"
)

var _ interface {
	clio.FlagAdder
	clio.FieldDescriber
} = (*Diff)(nil)

// Diff holds the options specific to the diff command.
type Diff struct {
	Output string `yaml:"output" json:"output" mapstructure:"output"`
}

func DefaultDiff() Diff {
	return Diff{
		Output: "diff-text",
	}
}

func (o *Diff) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Output, "output", "o",
		"diff report output format (<format>=<file> to output to a file), formats=[diff-text, diff-json]")
}

func (o *Diff) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.Output, `the output format of the diff report (options: diff-text, diff-json)
to write the report to a file instead of STDOUT, use '<format>=<file>':
  output: "diff-json=<diff-output-file>"
`)
}
