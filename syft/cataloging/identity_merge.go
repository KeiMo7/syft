package cataloging

import (
	"github.com/anchore/syft/syft/pkg/identity"
)

// IdentityMergeConfig controls the post-cataloging pass that folds package records which describe
// the same component.
type IdentityMergeConfig struct {
	// Enabled turns the identity merge pass on. It is off by default: the pass rewrites the
	// package collection and the relationships between packages, which existing consumers may not
	// expect from a scan.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// ConflictThreshold is the number of conflicts above which the report warns prominently. The
	// merged result is still produced. Zero disables the warning.
	ConflictThreshold int `yaml:"conflict-threshold" json:"conflict-threshold" mapstructure:"conflict-threshold"`

	// FailOnConflict makes a run whose conflict count exceeds ConflictThreshold fail instead of
	// emitting a warned result.
	FailOnConflict bool `yaml:"fail-on-conflict" json:"fail-on-conflict" mapstructure:"fail-on-conflict"`
}

// DefaultIdentityMergeConfig returns the default identity merge configuration (disabled).
func DefaultIdentityMergeConfig() IdentityMergeConfig {
	return IdentityMergeConfig{
		Enabled:           false,
		ConflictThreshold: identity.DefaultConflictThreshold,
	}
}

// WithEnabled returns a copy of the configuration with the enabled flag set.
func (c IdentityMergeConfig) WithEnabled(enabled bool) IdentityMergeConfig {
	c.Enabled = enabled
	return c
}

// WithConflictThreshold returns a copy of the configuration with the given threshold.
func (c IdentityMergeConfig) WithConflictThreshold(threshold int) IdentityMergeConfig {
	c.ConflictThreshold = threshold
	return c
}

// WithFailOnConflict returns a copy of the configuration with the fail-on-conflict flag set.
func (c IdentityMergeConfig) WithFailOnConflict(fail bool) IdentityMergeConfig {
	c.FailOnConflict = fail
	return c
}

// Options converts the configuration into engine options.
func (c IdentityMergeConfig) Options() identity.Options {
	return identity.DefaultOptions().WithConflictThreshold(c.ConflictThreshold)
}
