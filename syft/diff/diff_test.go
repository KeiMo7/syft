package diff

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func testPackage(name, version, purl string, pkgType pkg.Type, paths ...string) pkg.Package {
	locations := make([]file.Location, 0, len(paths))
	for _, path := range paths {
		locations = append(locations, file.NewLocation(path))
	}

	p := pkg.Package{
		Name:      name,
		Version:   version,
		PURL:      purl,
		Type:      pkgType,
		Locations: file.NewLocationSet(locations...),
	}
	p.SetID()
	return p
}

func testSBOM(packages ...pkg.Package) sbom.SBOM {
	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(packages...),
		},
	}
}

func withRelationships(input sbom.SBOM, relationships ...artifact.Relationship) sbom.SBOM {
	input.Relationships = relationships
	return input
}

func changeIndex(changes []Change) map[string]Change {
	index := make(map[string]Change, len(changes))
	for _, change := range changes {
		index[change.IdentityKey] = change
	}
	return index
}

func TestComputeAddedRemovedUpgradedDowngraded(t *testing.T) {
	oldSBOM := testSBOM(
		testPackage("kept", "1.0.0", "pkg:npm/kept@1.0.0", pkg.NpmPkg, "/app/package.json"),
		testPackage("removed-lib", "2.0.0", "pkg:npm/removed-lib@2.0.0", pkg.NpmPkg),
		testPackage("upgraded-lib", "1.2.3", "pkg:npm/upgraded-lib@1.2.3", pkg.NpmPkg),
		testPackage("downgraded-lib", "3.0.0", "pkg:npm/downgraded-lib@3.0.0", pkg.NpmPkg),
		testPackage("revised-lib", "1.4.2", "pkg:npm/revised-lib@1.4.2", pkg.NpmPkg),
	)

	newSBOM := testSBOM(
		testPackage("kept", "1.0.0", "pkg:npm/kept@1.0.0", pkg.NpmPkg, "/app/package.json"),
		testPackage("added-lib", "1.0.0", "pkg:npm/added-lib@1.0.0", pkg.NpmPkg),
		testPackage("upgraded-lib", "2.0.0", "pkg:npm/upgraded-lib@2.0.0", pkg.NpmPkg),
		testPackage("downgraded-lib", "2.9.0", "pkg:npm/downgraded-lib@2.9.0", pkg.NpmPkg),
		testPackage("revised-lib", "1.4.3", "pkg:npm/revised-lib@1.4.3", pkg.NpmPkg),
	)

	changes, err := Compute(oldSBOM, newSBOM, Options{})
	require.NoError(t, err)

	index := changeIndex(changes)

	added, ok := index["purl:pkg:npm/added-lib"]
	require.True(t, ok)
	assert.Equal(t, Added, added.Type)
	assert.True(t, added.IsHighRisk())

	removed, ok := index["purl:pkg:npm/removed-lib"]
	require.True(t, ok)
	assert.Equal(t, Removed, removed.Type)
	assert.False(t, removed.IsHighRisk())

	upgraded, ok := index["purl:pkg:npm/upgraded-lib"]
	require.True(t, ok)
	assert.Equal(t, VersionChanged, upgraded.Type)
	assert.Equal(t, Upgrade, upgraded.Direction)
	assert.Equal(t, "1.2.3", upgraded.OldVersion)
	assert.Equal(t, "2.0.0", upgraded.NewVersion)
	assert.False(t, upgraded.IsHighRisk())

	downgraded, ok := index["purl:pkg:npm/downgraded-lib"]
	require.True(t, ok)
	assert.Equal(t, VersionChanged, downgraded.Type)
	assert.Equal(t, Downgrade, downgraded.Direction)
	assert.True(t, downgraded.IsHighRisk())

	revised, ok := index["purl:pkg:npm/revised-lib"]
	require.True(t, ok)
	assert.Equal(t, VersionChanged, revised.Type)
	assert.Equal(t, RevisionOnly, revised.Direction)

	_, present := index["purl:pkg:npm/kept"]
	assert.False(t, present, "unchanged components must not be reported")
}

func TestIdentityIsVersionIndependentAndQualifierAware(t *testing.T) {
	oldPkg := testPackage("lib", "1.0.0", "pkg:deb/debian/lib@1.0.0?arch=amd64", pkg.DebPkg)
	newPkg := testPackage("lib", "1.1.0", "pkg:deb/debian/lib@1.1.0?arch=amd64", pkg.DebPkg)
	otherArch := testPackage("lib", "1.1.0", "pkg:deb/debian/lib@1.1.0?arch=arm64", pkg.DebPkg)

	oldIdentity := componentIdentity(oldPkg)
	newIdentity := componentIdentity(newPkg)
	armIdentity := componentIdentity(otherArch)

	assert.Equal(t, PURLIdentity, oldIdentity.rule)
	assert.Equal(t, oldIdentity.key, newIdentity.key, "version must not participate in identity")
	assert.NotEqual(t, newIdentity.key, armIdentity.key, "distribution qualifiers must participate in identity")
	assert.NotContains(t, oldIdentity.key, "1.0.0")
}

func TestDegradedIdentityWhenPURLMissing(t *testing.T) {
	oldSBOM := testSBOM(testPackage("plain", "1.0.0", "", pkg.PythonPkg))
	newSBOM := testSBOM(testPackage("plain", "2.0.0", "", pkg.PythonPkg))

	changes, err := Compute(oldSBOM, newSBOM, Options{})
	require.NoError(t, err)
	require.Len(t, changes, 1)

	assert.Equal(t, NameTypeIdentity, changes[0].IdentityRule)
	assert.True(t, changes[0].Unreliable)
	assert.Equal(t, VersionChanged, changes[0].Type)
	assert.Equal(t, Upgrade, changes[0].Direction)
}

func TestMissingVersionIsSeparateCategory(t *testing.T) {
	oldSBOM := testSBOM(testPackage("mystery", "1.0.0", "pkg:generic/mystery@1.0.0", pkg.UnknownPkg))
	newSBOM := testSBOM(testPackage("mystery", "", "pkg:generic/mystery", pkg.UnknownPkg))

	changes, err := Compute(oldSBOM, newSBOM, Options{})
	require.NoError(t, err)
	require.Len(t, changes, 1)

	assert.Equal(t, VersionUnknown, changes[0].Type)
	assert.NotEqual(t, VersionChanged, changes[0].Type)
}

func TestUncomparableVersionsAreFlagged(t *testing.T) {
	oldSBOM := testSBOM(testPackage("dated", "20240101", "pkg:generic/dated@20240101", pkg.UnknownPkg))
	newSBOM := testSBOM(testPackage("dated", "20240202", "pkg:generic/dated@20240202", pkg.UnknownPkg))

	changes, err := Compute(oldSBOM, newSBOM, Options{})
	require.NoError(t, err)
	require.Len(t, changes, 1)

	assert.Equal(t, VersionChanged, changes[0].Type)
	assert.Equal(t, NoDirection, changes[0].Direction)
	assert.True(t, changes[0].Unreliable)
}

func TestHighRiskOnlyFilter(t *testing.T) {
	oldSBOM := testSBOM(
		testPackage("downgraded-lib", "3.0.0", "pkg:npm/downgraded-lib@3.0.0", pkg.NpmPkg),
		testPackage("removed-lib", "1.0.0", "pkg:npm/removed-lib@1.0.0", pkg.NpmPkg),
	)
	newSBOM := testSBOM(
		testPackage("downgraded-lib", "2.0.0", "pkg:npm/downgraded-lib@2.0.0", pkg.NpmPkg),
		testPackage("added-lib", "1.0.0", "pkg:npm/added-lib@1.0.0", pkg.NpmPkg),
	)

	changes, err := Compute(oldSBOM, newSBOM, Options{HighRiskOnly: true})
	require.NoError(t, err)

	assert.Len(t, changes, 2)
	for _, change := range changes {
		assert.True(t, change.IsHighRisk())
	}
}

func TestPathScopeFiltersBothSides(t *testing.T) {
	oldSBOM := testSBOM(
		testPackage("in-scope", "1.0.0", "pkg:npm/in-scope@1.0.0", pkg.NpmPkg, "/work/subsystem/a/package.json"),
		testPackage("out-of-scope", "1.0.0", "pkg:npm/out-of-scope@1.0.0", pkg.NpmPkg, "/work/other/package.json"),
	)
	newSBOM := testSBOM(
		testPackage("in-scope", "2.0.0", "pkg:npm/in-scope@2.0.0", pkg.NpmPkg, "/work/subsystem/b/package.json"),
		testPackage("out-of-scope", "1.0.0", "pkg:npm/out-of-scope@1.0.0", pkg.NpmPkg, "/work/other/package.json"),
	)

	changes, err := Compute(oldSBOM, newSBOM, Options{PathPrefixes: []string{"/work/subsystem"}})
	require.NoError(t, err)
	require.Len(t, changes, 1)

	assert.Equal(t, "in-scope", changes[0].Name)
}

func TestPathScopeAcceptsHostAbsolutePrefix(t *testing.T) {
	oldSBOM := testSBOM(
		testPackage("in-scope", "1.0.0", "pkg:npm/in-scope@1.0.0", pkg.NpmPkg, "/subsystem/package.json"),
	)
	newSBOM := testSBOM(
		testPackage("in-scope", "2.0.0", "pkg:npm/in-scope@2.0.0", pkg.NpmPkg, "/subsystem/package.json"),
	)

	changes, err := Compute(oldSBOM, newSBOM, Options{PathPrefixes: []string{"/work/repo/subsystem"}})
	require.NoError(t, err)
	require.Len(t, changes, 1)

	assert.Equal(t, "in-scope", changes[0].Name)
}

func TestDirectAndTransitiveLayerGrouping(t *testing.T) {
	root := testPackage("root", "1.0.0", "pkg:npm/root@1.0.0", pkg.NpmPkg)
	child := testPackage("child", "1.0.0", "pkg:npm/child@1.0.0", pkg.NpmPkg)

	oldSBOM := withRelationships(
		testSBOM(root, child),
		artifact.Relationship{From: root, To: child, Type: artifact.DependencyOfRelationship},
	)

	upgradedChild := testPackage("child", "2.0.0", "pkg:npm/child@2.0.0", pkg.NpmPkg)
	newSBOM := withRelationships(
		testSBOM(root, upgradedChild),
		artifact.Relationship{From: root, To: upgradedChild, Type: artifact.DependencyOfRelationship},
	)

	changes, err := Compute(oldSBOM, newSBOM, Options{})
	require.NoError(t, err)
	require.Len(t, changes, 1)

	assert.Equal(t, TransitiveDependency, changes[0].NewLayer)
	assert.Equal(t, TransitiveDependency, changes[0].OldLayer)

	report := NewReport(InputDescription{}, InputDescription{}, changes, Options{})
	require.Contains(t, report.Counts.ByLayer, GroupCount{Key: string(TransitiveDependency), Count: 1})
}

func TestEmptySBOMsProduceStructuredResult(t *testing.T) {
	emptyOld := sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	emptyNew := sbom.SBOM{} // nil collection, as produced by a scan with zero components

	changes, err := Compute(emptyOld, emptyNew, Options{})
	require.NoError(t, err)
	assert.Empty(t, changes)

	report := NewReport(InputDescription{}, InputDescription{}, changes, Options{})
	assert.Equal(t, 0, report.Counts.Added)
	assert.NotNil(t, report.Changes)
}

func TestNilCollectionStillReportsAddedComponents(t *testing.T) {
	emptyOld := sbom.SBOM{}
	newSBOM := testSBOM(testPackage("new-lib", "1.0.0", "pkg:npm/new-lib@1.0.0", pkg.NpmPkg))

	changes, err := Compute(emptyOld, newSBOM, Options{})
	require.NoError(t, err)
	require.Len(t, changes, 1)
	assert.Equal(t, Added, changes[0].Type)
}

func TestLayerMoveIsReported(t *testing.T) {
	root := testPackage("root", "1.0.0", "pkg:npm/root@1.0.0", pkg.NpmPkg)
	lib := testPackage("lib", "1.0.0", "pkg:npm/lib@1.0.0", pkg.NpmPkg)
	other := testPackage("other", "1.0.0", "pkg:npm/other@1.0.0", pkg.NpmPkg)

	// lib starts as a direct dependency; other stays transitive on both sides
	oldSBOM := withRelationships(
		testSBOM(root, lib, other),
		artifact.Relationship{From: root, To: other, Type: artifact.DependencyOfRelationship},
	)

	// lib becomes transitive when root starts depending on it
	newSBOM := withRelationships(
		testSBOM(root, lib, other),
		artifact.Relationship{From: root, To: lib, Type: artifact.DependencyOfRelationship},
		artifact.Relationship{From: root, To: other, Type: artifact.DependencyOfRelationship},
	)

	changes, err := Compute(oldSBOM, newSBOM, Options{})
	require.NoError(t, err)
	require.Len(t, changes, 1)

	assert.Equal(t, DirectDependency, changes[0].OldLayer)
	assert.Equal(t, TransitiveDependency, changes[0].NewLayer)
	assert.True(t, changes[0].LayerChanged)
	assert.Equal(t, NoDirection, changes[0].Direction)
}

func TestReportGroupsByComponentType(t *testing.T) {
	oldSBOM := testSBOM(
		testPackage("py-lib", "1.0.0", "pkg:pypi/py-lib@1.0.0", pkg.PythonPkg),
		testPackage("npm-lib", "1.0.0", "pkg:npm/npm-lib@1.0.0", pkg.NpmPkg),
	)
	newSBOM := testSBOM(
		testPackage("py-lib", "2.0.0", "pkg:pypi/py-lib@2.0.0", pkg.PythonPkg),
		testPackage("npm-lib", "2.0.0", "pkg:npm/npm-lib@2.0.0", pkg.NpmPkg),
	)

	changes, err := Compute(oldSBOM, newSBOM, Options{})
	require.NoError(t, err)

	report := NewReport(InputDescription{}, InputDescription{}, changes, Options{})
	assert.ElementsMatch(t,
		[]GroupCount{
			{Key: string(pkg.NpmPkg), Count: 1},
			{Key: string(pkg.PythonPkg), Count: 1},
		},
		report.Counts.ByType,
	)
	assert.Equal(t, 2, report.Counts.VersionChanged)
}
