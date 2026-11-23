package options

import (
	"testing"

	"github.com/anchore/clio"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/cataloging"
)

func TestIdentityMergeConfigDefaults(t *testing.T) {
	cfg := defaultIdentityMergeConfig()
	assert.False(t, cfg.Enabled, "identity merging must be off by default")
	assert.Equal(t, cataloging.DefaultIdentityMergeConfig().ConflictThreshold, cfg.ConflictThreshold)
	assert.False(t, cfg.FailOnConflict)
}

func TestIdentityMergeConfigRoundTrip(t *testing.T) {
	cfg := identityMergeConfig{
		Enabled:           true,
		ConflictThreshold: 7,
		FailOnConflict:    true,
	}

	got := cfg.ToConfig()
	assert.True(t, got.Enabled)
	assert.Equal(t, 7, got.ConflictThreshold)
	assert.True(t, got.FailOnConflict)
	assert.Equal(t, 7, got.Options().ConflictThreshold)
}

func TestCatalog_ToSBOMConfigThreadsIdentityMerge(t *testing.T) {
	cfg := DefaultCatalog()
	cfg.IdentityMerge = identityMergeConfig{Enabled: true, ConflictThreshold: 3}

	sbomCfg := cfg.ToSBOMConfig(clio.Identification{Name: "syft", Version: "test"})
	assert.True(t, sbomCfg.IdentityMerge.Enabled)
	assert.Equal(t, 3, sbomCfg.IdentityMerge.ConflictThreshold)
}
