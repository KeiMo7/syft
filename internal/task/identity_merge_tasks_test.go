package task

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func mergeTestPackage(name, version string, ty pkg.Type, foundBy, path string) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Type:      ty,
		FoundBy:   foundBy,
		Locations: file.NewLocationSet(file.NewLocation(path)),
	}
	p.SetID()
	return p
}

func runIdentityMergeTask(t *testing.T, cfg cataloging.IdentityMergeConfig, packages ...pkg.Package) (*sbom.SBOM, error) {
	t.Helper()

	tsk := NewIdentityMergeTask(cfg)
	require.NotNil(t, tsk)

	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(packages...)}}
	builder := sbomsync.NewBuilder(s)

	err := tsk.Execute(context.Background(), nil, builder)
	return s, err
}

func TestNewIdentityMergeTask_DisabledReturnsNil(t *testing.T) {
	assert.Nil(t, NewIdentityMergeTask(cataloging.DefaultIdentityMergeConfig()))
}

func TestIdentityMergeTask_FoldsDuplicates(t *testing.T) {
	a := mergeTestPackage("django", "4.2.0", pkg.PythonPkg, "c1", "/a")
	b := mergeTestPackage("Django", "v4.2", pkg.PythonPkg, "c2", "/b")

	s, err := runIdentityMergeTask(t, cataloging.DefaultIdentityMergeConfig().WithEnabled(true), a, b)
	require.NoError(t, err)

	assert.Equal(t, 1, s.Artifacts.Packages.PackageCount())
	require.NotNil(t, s.IdentityMergeReport)
	assert.Equal(t, 2, s.IdentityMergeReport.InputCount)
	assert.Equal(t, 1, s.IdentityMergeReport.OutputCount)
	assert.True(t, s.IdentityMergeReport.Reconciliation.Balanced)
}

func TestIdentityMergeTask_FailOnConflict(t *testing.T) {
	// three revision conflicts exceed a threshold of one
	packages := []pkg.Package{
		mergeTestPackage("libc6", "2.31-13", pkg.DebPkg, "c1", "/a"),
		mergeTestPackage("libc6", "2.31", pkg.DebPkg, "c2", "/b"),
		mergeTestPackage("bash", "5.1-2", pkg.DebPkg, "c1", "/c"),
		mergeTestPackage("bash", "5.1", pkg.DebPkg, "c2", "/d"),
	}

	cfg := cataloging.DefaultIdentityMergeConfig().
		WithEnabled(true).
		WithConflictThreshold(1).
		WithFailOnConflict(true)

	s, err := runIdentityMergeTask(t, cfg, packages...)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identity merge found")

	// even on failure the merged result is present: the failure is about review, not data loss
	require.NotNil(t, s.IdentityMergeReport)
	assert.Equal(t, 2, s.IdentityMergeReport.OutputCount)
	assert.True(t, s.IdentityMergeReport.ThresholdExceeded)
}

func TestIdentityMergeTask_WarnOnlyBelowFail(t *testing.T) {
	packages := []pkg.Package{
		mergeTestPackage("libc6", "2.31-13", pkg.DebPkg, "c1", "/a"),
		mergeTestPackage("libc6", "2.31", pkg.DebPkg, "c2", "/b"),
	}

	cfg := cataloging.DefaultIdentityMergeConfig().
		WithEnabled(true).
		WithConflictThreshold(0). // disable the warning
		WithFailOnConflict(true)

	s, err := runIdentityMergeTask(t, cfg, packages...)
	require.NoError(t, err)
	require.NotNil(t, s.IdentityMergeReport)
	assert.Empty(t, s.IdentityMergeReport.Warning)
}

func TestIdentityMergeConfigOptions(t *testing.T) {
	cfg := cataloging.DefaultIdentityMergeConfig().WithConflictThreshold(42)
	opts := cfg.Options()
	assert.Equal(t, 42, opts.ConflictThreshold)
}
