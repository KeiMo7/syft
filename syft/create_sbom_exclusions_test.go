package syft

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cataloging/exclusions"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func TestFinalizeExclusionsWritesDescriptorAndAuditFile(t *testing.T) {
	auditFile := filepath.Join(t.TempDir(), "exclusions.json")
	cfg := DefaultCreateSBOMConfig().WithExclusionConfig(exclusions.Config{
		Rules: []exclusions.RuleConfig{
			{Path: "**/vendor/**"},
			{Ecosystem: "npm"},
		},
		AuditFile: auditFile,
	})
	recorder := exclusions.NewPathRecorder()
	recorder.Record(1, "**/vendor/**", "app/vendor/lib")
	cfg.WithExclusionPathRecorder(recorder)
	matcher, err := cfg.exclusionMatcherForRun()
	require.NoError(t, err)

	npmPkg := exclusionTestPackage("left-pad", pkg.NpmPkg, "/app/node_modules/left-pad/index.js", "layer-1")
	goPkg := exclusionTestPackage("example", pkg.GoModulePkg, "/app/main.go", "layer-1")
	s := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(npmPkg, goPkg),
		},
		Descriptor: sbom.Descriptor{
			Name:          "syft",
			Version:       "test",
			Configuration: configurationAuditTrail{},
		},
	}
	cfg.skippedCatalogers = []exclusions.CatalogerSkip{{
		Cataloger: "javascript-package-cataloger",
		RuleIndex: 2,
		Ecosystem: "npm",
	}}

	require.NoError(t, finalizeExclusions(s, cfg, matcher, true))
	assert.Equal(t, 1, s.Artifacts.Packages.PackageCount())
	assert.Nil(t, s.Artifacts.Packages.Package(npmPkg.ID()))

	trail, ok := s.Descriptor.Configuration.(configurationAuditTrail)
	require.True(t, ok)
	require.NotNil(t, trail.Exclusions)
	assert.True(t, trail.Exclusions.Interrupted)
	assert.Equal(t, 2, trail.Exclusions.EvaluatedPackageCount)
	assert.Equal(t, 1, trail.Exclusions.ExcludedPackageCount)
	assert.Equal(t, 1, trail.Exclusions.ExcludedPathCount)
	assert.Len(t, trail.Exclusions.Matches, 1)
	require.Len(t, trail.Exclusions.SkippedCatalogers, 1)

	contents, err := os.ReadFile(auditFile)
	require.NoError(t, err)
	var persisted exclusions.Audit
	require.NoError(t, json.Unmarshal(contents, &persisted))
	assert.True(t, persisted.Interrupted)
	assert.Equal(t, 1, persisted.ExcludedPackageCount)
	assert.Equal(t, 1, persisted.ExcludedPathCount)

	trailJSON, err := json.Marshal(trail)
	require.NoError(t, err)
	assert.Contains(t, string(trailJSON), `"exclusions"`)
	assert.Contains(t, string(trailJSON), `"excluded-package-count":1`)
}

func TestConfigurationAuditTrailOmitsExclusionsByDefault(t *testing.T) {
	contents, err := json.Marshal(configurationAuditTrail{})
	require.NoError(t, err)
	assert.NotContains(t, string(contents), `"exclusions"`)
}

func exclusionTestPackage(name string, packageType pkg.Type, path, layer string) pkg.Package {
	p := pkg.Package{
		Name: name,
		Type: packageType,
		Locations: file.NewLocationSet(file.NewLocationFromCoordinates(file.Coordinates{
			RealPath:     path,
			FileSystemID: layer,
		})),
	}
	p.SetID()
	return p
}
