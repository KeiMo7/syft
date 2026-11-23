package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/cataloging"
)

type identityMergeConfig struct {
	Enabled           bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	ConflictThreshold int  `yaml:"conflict-threshold" json:"conflict-threshold" mapstructure:"conflict-threshold"`
	FailOnConflict    bool `yaml:"fail-on-conflict" json:"fail-on-conflict" mapstructure:"fail-on-conflict"`
}

var _ clio.FieldDescriber = (*identityMergeConfig)(nil)

func defaultIdentityMergeConfig() identityMergeConfig {
	def := cataloging.DefaultIdentityMergeConfig()
	return identityMergeConfig{
		Enabled:           def.Enabled,
		ConflictThreshold: def.ConflictThreshold,
		FailOnConflict:    def.FailOnConflict,
	}
}

func (o *identityMergeConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.Enabled, "fold package records that describe the same component (normalizing name spelling and equivalent versions) into one entry, retaining every location, license, checksum and external identifier")
	descriptions.Add(&o.ConflictThreshold, "the number of merge conflicts above which the summary carries a prominent warning (0 disables the warning)")
	descriptions.Add(&o.FailOnConflict, "fail the scan when the conflict count exceeds conflict-threshold instead of emitting a warned result")
}

func (o identityMergeConfig) ToConfig() cataloging.IdentityMergeConfig {
	return cataloging.DefaultIdentityMergeConfig().
		WithEnabled(o.Enabled).
		WithConflictThreshold(o.ConflictThreshold).
		WithFailOnConflict(o.FailOnConflict)
}
