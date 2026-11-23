package identitymerge

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/identity"
	"github.com/anchore/syft/syft/sbom"
)

func testPackage(name, version string, ty pkg.Type, foundBy, path string, purl string) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Type:      ty,
		FoundBy:   foundBy,
		PURL:      purl,
		Language:  pkg.LanguageFromPURL(purl),
		Locations: file.NewLocationSet(file.NewLocation(path)),
	}
	p.SetID()
	return p
}

func testSBOM(packages ...pkg.Package) *sbom.SBOM {
	return &sbom.SBOM{
		Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(packages...)},
	}
}

func TestMergeSBOM_FoldsPackages(t *testing.T) {
	a := testPackage("Django", "4.2.0", pkg.PythonPkg, "python-package-cataloger", "/a", "pkg:pypi/django@4.2.0")
	b := testPackage("django", "v4.2", pkg.PythonPkg, "python-installed-package-cataloger", "/b", "pkg:pypi/django@4.2")
	c := testPackage("django", "4.2.0", pkg.PythonPkg, "binary-classifier-cataloger", "/c", "pkg:pypi/django@4.2.0")

	s := testSBOM(a, b, c)
	result := MergeSBOM(s, identity.DefaultOptions())

	assert.Equal(t, 1, s.Artifacts.Packages.PackageCount())
	assert.Equal(t, 3, result.Report.InputCount)
	assert.Equal(t, 1, result.Report.OutputCount)
	assert.Equal(t, 2, result.Report.MergePairCount)
	assert.True(t, result.Report.Reconciliation.Balanced)

	merged := s.Artifacts.Packages.Sorted()
	require.Len(t, merged, 1)
	require.NotNil(t, merged[0].MergeInfo)
	assert.Equal(t, identity.StateMerged, merged[0].MergeInfo.State)
	assert.ElementsMatch(t, []string{string(a.ID()), string(b.ID()), string(c.ID())}, merged[0].MergeInfo.Members)

	// every location survives
	assert.Len(t, merged[0].Locations.ToSlice(), 3)

	// every source survives
	assert.ElementsMatch(t,
		[]string{"python-package-cataloger", "python-installed-package-cataloger", "binary-classifier-cataloger"},
		merged[0].MergeInfo.Sources,
	)

	// report is retained on the SBOM
	require.NotNil(t, s.IdentityMergeReport)
	assert.Equal(t, 1, s.IdentityMergeReport.OutputCount)
}

func TestMergeSBOM_RemapsRelationships(t *testing.T) {
	app := testPackage("myapp", "1.0.0", pkg.PythonPkg, "python-package-cataloger", "/app", "")
	a := testPackage("requests", "2.22.0", pkg.PythonPkg, "python-package-cataloger", "/a", "pkg:pypi/requests@2.22.0")
	b := testPackage("requests", "2.22.0", pkg.PythonPkg, "python-installed-package-cataloger", "/b", "pkg:pypi/requests@2.22.0")

	s := testSBOM(app, a, b)
	s.Relationships = []artifact.Relationship{
		// the app depends on both duplicate records; after merging there must be exactly one edge
		{From: app, To: a, Type: artifact.DependencyOfRelationship},
		{From: app, To: b, Type: artifact.DependencyOfRelationship},
		// a self-edge that only exists because two duplicate records each had a location
		{From: a, To: b, Type: artifact.ContainsRelationship},
	}

	MergeSBOM(s, identity.DefaultOptions())

	assert.Equal(t, 2, s.Artifacts.Packages.PackageCount())

	require.Len(t, s.Relationships, 1, "duplicate and self edges must collapse to one")
	rel := s.Relationships[0]
	assert.Equal(t, artifact.DependencyOfRelationship, rel.Type)
	assert.Equal(t, app.ID(), rel.From.ID())
	assert.NotEqual(t, a.ID(), rel.To.ID())
	assert.NotEqual(t, b.ID(), rel.To.ID())
}

func TestMergeSBOM_SerializesAdditivelyAndRoundTrips(t *testing.T) {
	a := testPackage("Django", "4.2.0", pkg.PythonPkg, "python-package-cataloger", "/a", "pkg:pypi/django@4.2.0")
	b := testPackage("django", "v4.2", pkg.PythonPkg, "python-installed-package-cataloger", "/b", "pkg:pypi/django@4.2")

	s := testSBOM(a, b)
	MergeSBOM(s, identity.DefaultOptions())

	var buffer bytes.Buffer
	require.NoError(t, syftjson.NewFormatEncoder().Encode(&buffer, *s))
	encoded := buffer.Bytes()

	// the additive fields are present
	assert.Contains(t, string(encoded), `"mergeInfo"`)
	assert.Contains(t, string(encoded), `"identityMerge"`)

	// decode and re-encode: the merge report and merge info must survive the cycle
	decoded, formatID, _, err := syftjson.NewFormatDecoder().Decode(bytes.NewReader(encoded))
	require.NoError(t, err)
	assert.Equal(t, syftjson.ID, formatID)

	require.NotNil(t, decoded.IdentityMergeReport)
	assert.Equal(t, s.IdentityMergeReport.OutputCount, decoded.IdentityMergeReport.OutputCount)

	packages := decoded.Artifacts.Packages.Sorted()
	require.Len(t, packages, 1)
	require.NotNil(t, packages[0].MergeInfo)
	assert.Equal(t, identity.StateMerged, packages[0].MergeInfo.State)

	// a second encode/decode/encode cycle must be byte-stable; the first decode normalizes a few
	// coordinates (it backfills fullPath), which is pre-existing decoder behavior, not merge loss
	var second bytes.Buffer
	require.NoError(t, syftjson.NewFormatEncoder().Encode(&second, *decoded))

	decodedAgain, _, _, err := syftjson.NewFormatDecoder().Decode(bytes.NewReader(second.Bytes()))
	require.NoError(t, err)
	var third bytes.Buffer
	require.NoError(t, syftjson.NewFormatEncoder().Encode(&third, *decodedAgain))

	assert.JSONEq(t, second.String(), third.String())
	require.NotNil(t, decodedAgain.IdentityMergeReport)
	assert.Equal(t, s.IdentityMergeReport.OutputCount, decodedAgain.IdentityMergeReport.OutputCount)
}

func TestMergeSBOM_OmitsMergeFieldsWhenUnused(t *testing.T) {
	// a document that never ran identity merging must not grow the new fields
	s := testSBOM(testPackage("alpha", "1.0.0", pkg.PythonPkg, "python-package-cataloger", "/a", ""))

	var buffer bytes.Buffer
	require.NoError(t, syftjson.NewFormatEncoder().Encode(&buffer, *s))

	assert.NotContains(t, buffer.String(), `"mergeInfo"`)
	assert.NotContains(t, buffer.String(), `"identityMerge"`)
}

func TestMergeSBOM_DeterministicAcrossInputOrder(t *testing.T) {
	packages := []pkg.Package{
		testPackage("Django", "4.2.0", pkg.PythonPkg, "python-package-cataloger", "/a", "pkg:pypi/django@4.2.0"),
		testPackage("django", "v4.2", pkg.PythonPkg, "python-installed-package-cataloger", "/b", "pkg:pypi/django@4.2"),
		testPackage("libc6", "2.31-13", pkg.DebPkg, "dpkg-db-cataloger", "/c", ""),
		testPackage("libc6", "2.31", pkg.DebPkg, "binary-classifier-cataloger", "/d", ""),
	}

	encode := func(order []pkg.Package) string {
		s := testSBOM(order...)
		MergeSBOM(s, identity.DefaultOptions())
		var buffer bytes.Buffer
		require.NoError(t, syftjson.NewFormatEncoder().Encode(&buffer, *s))
		return buffer.String()
	}

	baseline := encode(packages)

	rotations := make([][]pkg.Package, 0, len(packages))
	for i := range packages {
		rotations = append(rotations, append(append([]pkg.Package{}, packages[i:]...), packages[:i]...))
	}
	reversed := make([]pkg.Package, len(packages))
	for i, p := range packages {
		reversed[len(packages)-1-i] = p
	}
	rotations = append(rotations, reversed)

	for _, order := range rotations {
		assert.JSONEq(t, baseline, encode(order), "merged output must not depend on input order")
	}

	// the same input twice produces identical bytes
	assert.Equal(t, baseline, encode(packages))
}

func TestMergeSBOM_RetainsMetadataPayloads(t *testing.T) {
	// two records of one component, each with a different metadata payload
	a := testPackage("pygments", "2.6.1", pkg.PythonPkg, "python-package-cataloger", "/a", "pkg:pypi/pygments@2.6.1")
	a.Metadata = pkg.PythonPackage{Name: "pygments", Version: "2.6.1", Author: "from-package-json"}
	a.SetID()
	b := testPackage("Pygments", "2.6.1", pkg.PythonPkg, "python-installed-package-cataloger", "/b", "pkg:pypi/pygments@2.6.1")
	b.Metadata = pkg.PythonPackage{Name: "Pygments", Version: "2.6.1", Author: "from-dist-info"}
	b.SetID()

	s := testSBOM(a, b)
	MergeSBOM(s, identity.DefaultOptions())

	merged := s.Artifacts.Packages.Sorted()
	require.Len(t, merged, 1)
	require.NotNil(t, merged[0].MergeInfo)

	// both metadata payloads are retained
	require.Len(t, merged[0].MergeInfo.MetadataPayloads, 2)
	authors := map[string]bool{}
	for _, payload := range merged[0].MergeInfo.MetadataPayloads {
		var decoded pkg.PythonPackage
		require.NoError(t, json.Unmarshal(payload.Payload, &decoded))
		authors[decoded.Author] = true
	}
	assert.True(t, authors["from-package-json"])
	assert.True(t, authors["from-dist-info"])
}

func TestMergeSBOM_NilSBOM(t *testing.T) {
	result := MergeSBOM(nil, identity.DefaultOptions())
	assert.Equal(t, 0, result.Report.InputCount)
	assert.Equal(t, 0, result.Report.OutputCount)
	assert.True(t, result.Report.Reconciliation.Balanced)
}

func TestMergeSBOM_RelationshipTargetsSurvivingPackage(t *testing.T) {
	app := testPackage("myapp", "1.0.0", pkg.PythonPkg, "c1", "/app", "")
	a := testPackage("requests", "2.22.0", pkg.PythonPkg, "c1", "/a", "pkg:pypi/requests@2.22.0")
	b := testPackage("requests", "2.22.0", pkg.PythonPkg, "c2", "/b", "pkg:pypi/requests@2.22.0")

	s := testSBOM(app, a, b)
	s.Relationships = []artifact.Relationship{{From: app, To: a, Type: artifact.DependencyOfRelationship}}

	MergeSBOM(s, identity.DefaultOptions())

	require.Len(t, s.Relationships, 1)
	childID := s.Relationships[0].To.ID()
	assert.NotNil(t, s.Artifacts.Packages.Package(childID), "relationship must target a surviving package id")
}

func TestMergeSBOM_ReMergeAfterDecodeIsIdempotent(t *testing.T) {
	// merging, encoding, decoding and merging again must not change anything: the first pass already
	// produced one entry per identity, so the second pass has nothing to fold.
	a := testPackage("Django", "4.2.0", pkg.PythonPkg, "python-package-cataloger", "/a", "pkg:pypi/django@4.2.0")
	b := testPackage("django", "v4.2", pkg.PythonPkg, "python-installed-package-cataloger", "/b", "pkg:pypi/django@4.2")
	lib := testPackage("libc6", "2.31-13", pkg.DebPkg, "dpkg-db-cataloger", "/c", "")

	s := testSBOM(a, b, lib)
	first := MergeSBOM(s, identity.DefaultOptions())

	var buffer bytes.Buffer
	require.NoError(t, syftjson.NewFormatEncoder().Encode(&buffer, *s))

	decoded, _, _, err := syftjson.NewFormatDecoder().Decode(bytes.NewReader(buffer.Bytes()))
	require.NoError(t, err)

	second := MergeSBOM(decoded, identity.DefaultOptions())
	assert.Equal(t, first.Report.OutputCount, second.Report.OutputCount)
	assert.Equal(t, 0, second.Report.MergePairCount, "re-merging already-merged output must fold nothing")
	assert.True(t, second.Report.Reconciliation.Balanced)
	assert.Equal(t, len(first.Components), len(second.Components))
}
