package incremental

import (
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// Config is the opt-in configuration for incremental cataloging.
type Config struct {
	// Enabled turns incremental cataloging on. The zero value is disabled.
	Enabled bool

	// Baseline is an already decoded reference SBOM.
	Baseline *sbom.SBOM

	// BaselinePath is loaded when Baseline is nil.
	BaselinePath string

	// CheckpointPath receives atomic partial SBOMs while a scan is running. A
	// partial checkpoint is never accepted as a complete reference manifest.
	CheckpointPath string

	// ForceFull bypasses change detection.
	ForceFull bool

	// SourceOverride can override the source compatibility decision.
	SourceOverride SourceOverride

	// AllowDifferentSource skips the source-family check. Callers should use
	// this only when they know the reference SBOM describes the same logical
	// subject through a different registry identity.
	AllowDifferentSource bool
}

// Options converts the persistent configuration into change detection options.
func (c Config) Options() Options {
	override := c.SourceOverride
	if override == nil && c.AllowDifferentSource {
		override = func(_, _ source.Description) (bool, bool) {
			return true, true
		}
	}
	return Options{
		ForceFull:      c.ForceFull,
		SourceOverride: override,
	}
}
