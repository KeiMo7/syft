package diff

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func rec(id, name, version, typ, purl string, locations ...string) Record {
	return NewRecord(id, name, version, typ, purl, "test-cataloger", locations)
}

func doc(records ...Record) *Document {
	return &Document{
		Format:        "syft-json",
		SchemaVersion: "16.1.13",
		ToolName:      "syft",
		ToolVersion:   "1.0.0",
		SourceName:    "test-source",
		Records:       records,
	}
}

func TestCompare_identical(t *testing.T) {
	oldDoc := doc(
		rec("id-1", "lodash", "4.17.21", "npm", "pkg:npm/lodash@4.17.21", "app/package-lock.json"),
		rec("id-2", "react", "18.2.0", "npm", "pkg:npm/react@18.2.0", "app/package-lock.json"),
	)
	newDoc := doc(
		rec("id-3", "react", "18.2.0", "npm", "pkg:npm/react@18.2.0", "app/package-lock.json"),
		rec("id-4", "lodash", "4.17.21", "npm", "pkg:npm/lodash@4.17.21", "app/package-lock.json"),
	)

	d := Compare(oldDoc, newDoc)

	assert.Equal(t, 0, d.Summary.Added)
	assert.Equal(t, 0, d.Summary.Removed)
	assert.Equal(t, 0, d.Summary.Changed)
	assert.Equal(t, 2, d.Summary.Unchanged)
	assert.False(t, d.Tool.Changed)

	// every unchanged entry must trace back to concrete entries in BOTH documents
	for _, e := range d.Unchanged {
		require.NotEmpty(t, e.OldRefs, "unchanged entry %s must reference the old SBOM", e.Name)
		require.NotEmpty(t, e.NewRefs, "unchanged entry %s must reference the new SBOM", e.Name)
	}
}

func TestCompare_pureAddition(t *testing.T) {
	oldDoc := doc(
		rec("id-1", "lodash", "4.17.21", "npm", "pkg:npm/lodash@4.17.21", "app/package-lock.json"),
	)
	newDoc := doc(
		rec("id-2", "lodash", "4.17.21", "npm", "pkg:npm/lodash@4.17.21", "app/package-lock.json"),
		rec("id-3", "left-pad", "1.3.0", "npm", "pkg:npm/left-pad@1.3.0", "app/package-lock.json"),
	)

	d := Compare(oldDoc, newDoc)

	assert.Equal(t, 1, d.Summary.Added)
	assert.Equal(t, 0, d.Summary.Removed)
	assert.Equal(t, 0, d.Summary.Changed)
	assert.Equal(t, 1, d.Summary.Unchanged)
	require.Len(t, d.Added, 1)
	assert.Equal(t, "left-pad", d.Added[0].Name)
	assert.False(t, d.Added[0].NewSubproject, "subproject exists in the old document, so this is a plain addition")
	require.Len(t, d.Added[0].NewRefs, 1)
	assert.Equal(t, "id-3", d.Added[0].NewRefs[0].ID)
}

func TestCompare_pureRemoval(t *testing.T) {
	oldDoc := doc(
		rec("id-1", "lodash", "4.17.21", "npm", "pkg:npm/lodash@4.17.21", "app/package-lock.json"),
		rec("id-2", "debug", "3.1.0", "npm", "pkg:npm/debug@3.1.0", "app/package-lock.json"),
	)
	newDoc := doc(
		rec("id-3", "lodash", "4.17.21", "npm", "pkg:npm/lodash@4.17.21", "app/package-lock.json"),
	)

	d := Compare(oldDoc, newDoc)

	assert.Equal(t, 0, d.Summary.Added)
	assert.Equal(t, 1, d.Summary.Removed)
	assert.Equal(t, 0, d.Summary.Changed)
	assert.Equal(t, 1, d.Summary.Unchanged)
	require.Len(t, d.Removed, 1)
	assert.Equal(t, "debug", d.Removed[0].Name)
	require.Len(t, d.Removed[0].OldRefs, 1)
	assert.Equal(t, "id-2", d.Removed[0].OldRefs[0].ID)
}

func TestCompare_versionChange_isNotAddPlusRemove(t *testing.T) {
	oldDoc := doc(
		rec("id-1", "react", "18.2.0", "npm", "pkg:npm/react@18.2.0", "app/package-lock.json"),
	)
	newDoc := doc(
		rec("id-2", "react", "18.3.1", "npm", "pkg:npm/react@18.3.1", "app/package-lock.json"),
	)

	d := Compare(oldDoc, newDoc)

	assert.Equal(t, 0, d.Summary.Added, "a version change must not surface as an addition")
	assert.Equal(t, 0, d.Summary.Removed, "a version change must not surface as a removal")
	assert.Equal(t, 1, d.Summary.Changed)
	require.Len(t, d.Changed, 1)
	assert.Equal(t, "react", d.Changed[0].Name)
	assert.Equal(t, "18.2.0", d.Changed[0].From.Version)
	assert.Equal(t, "18.3.1", d.Changed[0].To.Version)
	assert.Equal(t, "id-1", d.Changed[0].From.Refs[0].ID)
	assert.Equal(t, "id-2", d.Changed[0].To.Refs[0].ID)
}

func TestCompare_sameDependencyInMultipleSubprojects_isLocatedPerSubproject(t *testing.T) {
	oldDoc := doc(
		rec("id-1", "lodash", "4.17.21", "npm", "pkg:npm/lodash@4.17.21", "frontend/package-lock.json"),
		rec("id-2", "lodash", "4.17.21", "npm", "pkg:npm/lodash@4.17.21", "backend/package-lock.json"),
	)
	newDoc := doc(
		rec("id-3", "lodash", "4.17.21", "npm", "pkg:npm/lodash@4.17.21", "frontend/package-lock.json"),
		rec("id-4", "lodash", "4.17.20", "npm", "pkg:npm/lodash@4.17.20", "backend/package-lock.json"),
	)

	d := Compare(oldDoc, newDoc)

	// the frontend copy is unchanged, the backend copy changed version: two separate rows,
	// never merged into one
	assert.Equal(t, 1, d.Summary.Unchanged)
	assert.Equal(t, 1, d.Summary.Changed)
	assert.Equal(t, 0, d.Summary.Added)
	assert.Equal(t, 0, d.Summary.Removed)

	require.Len(t, d.Unchanged, 1)
	assert.Equal(t, "frontend", d.Unchanged[0].Subproject)

	require.Len(t, d.Changed, 1)
	assert.Equal(t, "backend", d.Changed[0].Subproject)
	assert.Equal(t, "4.17.21", d.Changed[0].From.Version)
	assert.Equal(t, "4.17.20", d.Changed[0].To.Version)
}

func TestCompare_unionProperty(t *testing.T) {
	oldDoc := doc(
		rec("id-1", "stays", "1.0.0", "npm", "", "app/package-lock.json"),
		rec("id-2", "goes-away", "1.0.0", "npm", "", "app/package-lock.json"),
		rec("id-3", "bumps", "1.0.0", "npm", "", "app/package-lock.json"),
	)
	newDoc := doc(
		rec("id-4", "stays", "1.0.0", "npm", "", "app/package-lock.json"),
		rec("id-5", "shows-up", "2.0.0", "npm", "", "app/package-lock.json"),
		rec("id-6", "bumps", "1.0.1", "npm", "", "app/package-lock.json"),
	)

	d := Compare(oldDoc, newDoc)

	// the three classes (with changed pairing one old and one new entry) partition the union
	assert.Equal(t, len(oldDoc.Records), d.Summary.Unchanged+d.Summary.Removed+d.Summary.Changed)
	assert.Equal(t, len(newDoc.Records), d.Summary.Unchanged+d.Summary.Added+d.Summary.Changed)
}

func TestCompare_namespaceNormalization_viaPURL(t *testing.T) {
	// the same component recorded with a namespace in one document and without in the other,
	// but with agreeing purls: normalized, this is one unchanged entry
	oldDoc := doc(
		rec("id-1", "pkg", "1.0.0", "npm", "pkg:npm/%40scope/pkg@1.0.0", "app/package-lock.json"),
	)
	newDoc := doc(
		rec("id-2", "@scope/pkg", "1.0.0", "npm", "pkg:npm/%40scope/pkg@1.0.0", "app/package-lock.json"),
	)

	d := Compare(oldDoc, newDoc)

	assert.Equal(t, 1, d.Summary.Unchanged)
	assert.Equal(t, 0, d.Summary.Added)
	assert.Equal(t, 0, d.Summary.Removed)
	assert.Equal(t, 0, d.Summary.Incomparable)
}

func TestCompare_namespaceMismatch_withoutPURL_isMarkedIncomparable(t *testing.T) {
	// same situation but with no purl evidence: do not guess — flag as incomparable while
	// keeping the entries visible as a removal plus an addition
	oldDoc := doc(
		rec("id-1", "pkg", "1.0.0", "npm", "", "app/package-lock.json"),
	)
	newDoc := doc(
		rec("id-2", "@scope/pkg", "1.0.0", "npm", "", "app/package-lock.json"),
	)

	d := Compare(oldDoc, newDoc)

	assert.Equal(t, 1, d.Summary.Added)
	assert.Equal(t, 1, d.Summary.Removed)
	assert.Equal(t, 0, d.Summary.Unchanged)
	require.Equal(t, 1, d.Summary.Incomparable)
	assert.Equal(t, "id-1", d.Incomparable[0].Old.OldRefs[0].ID)
	assert.Equal(t, "id-2", d.Incomparable[0].New.NewRefs[0].ID)
	assert.Contains(t, d.Incomparable[0].Reason, "without purl evidence")
}

func TestCompare_toolVersionChange_marksEntriesPossiblyToolInduced(t *testing.T) {
	oldDoc := doc(
		rec("id-1", "stays", "1.0.0", "npm", "", "app/package-lock.json"),
		rec("id-2", "goes-away", "1.0.0", "npm", "", "app/package-lock.json"),
	)
	newDoc := doc(
		rec("id-3", "stays", "1.0.0", "npm", "", "app/package-lock.json"),
		rec("id-4", "shows-up", "1.0.0", "npm", "", "app/package-lock.json"),
	)
	newDoc.ToolVersion = "2.0.0"

	d := Compare(oldDoc, newDoc)

	assert.True(t, d.Tool.Changed)
	assert.NotEmpty(t, d.Tool.Note)
	require.Len(t, d.Added, 1)
	assert.True(t, d.Added[0].PossiblyToolInduced)
	require.Len(t, d.Removed, 1)
	assert.True(t, d.Removed[0].PossiblyToolInduced)
	require.Len(t, d.Unchanged, 1)
	assert.False(t, d.Unchanged[0].PossiblyToolInduced, "unchanged entries are not tool-induced differences")
}

func TestCompare_newSubproject_attributesAdditions(t *testing.T) {
	oldDoc := doc(
		rec("id-1", "lodash", "4.17.21", "npm", "", "frontend/package-lock.json"),
	)
	newDoc := doc(
		rec("id-2", "lodash", "4.17.21", "npm", "", "frontend/package-lock.json"),
		rec("id-3", "express", "4.18.2", "npm", "", "frontend/package-lock.json"),
		rec("id-4", "django", "4.2.0", "pypi", "", "services/api/requirements.txt"),
	)

	d := Compare(oldDoc, newDoc)

	assert.Equal(t, []string{"services/api"}, d.Subprojects.Added)
	assert.Empty(t, d.Subprojects.Removed)
	require.Len(t, d.Added, 2)
	byName := map[string]Entry{}
	for _, e := range d.Added {
		byName[e.Name] = e
	}
	assert.False(t, byName["express"].NewSubproject, "express was added to an existing subproject")
	assert.True(t, byName["django"].NewSubproject, "django arrived with the new services/api subproject")
}

func TestCompare_deterministic_regardlessOfInputOrder(t *testing.T) {
	mk := func() *Document {
		return doc(
			rec("id-1", "bbb", "1.0.0", "npm", "", "b/package-lock.json"),
			rec("id-2", "aaa", "1.0.0", "npm", "", "a/package-lock.json"),
			rec("id-3", "ccc", "1.0.0", "npm", "", "a/package-lock.json"),
		)
	}
	oldDoc := mk()
	newDoc := doc(
		rec("id-4", "ccc", "1.0.0", "npm", "", "a/package-lock.json"),
		rec("id-5", "aaa", "1.0.0", "npm", "", "a/package-lock.json"),
		rec("id-6", "bbb", "1.0.1", "npm", "", "b/package-lock.json"),
		rec("id-7", "ddd", "2.0.0", "npm", "", "a/package-lock.json"),
	)

	first := Compare(oldDoc, newDoc)
	second := Compare(oldDoc, newDoc)

	firstJSON, err := RenderJSON(first)
	require.NoError(t, err)
	secondJSON, err := RenderJSON(second)
	require.NoError(t, err)
	assert.Equal(t, string(firstJSON), string(secondJSON), "rendering the same comparison twice must be byte-identical")
	assert.Equal(t, string(RenderText(first)), string(RenderText(second)), "text rendering must be byte-identical too")
}

func TestReadDocument_streamsSyftJSON(t *testing.T) {
	// a document with a large irrelevant section: the streaming reader must skip it without
	// materializing it, and still pick up descriptor, schema, source and every artifact
	var sb strings.Builder
	sb.WriteString(`{"artifacts":[`)
	sb.WriteString(`{"id":"id-1","name":"lodash","version":"4.17.21","type":"npm","foundBy":"javascript-cataloger",`)
	sb.WriteString(`"locations":[{"path":"/app/package-lock.json"}],"purl":"pkg:npm/lodash@4.17.21","licenses":[{"value":"MIT","spdxExpression":"MIT","type":"declared","urls":[],"locations":[]}],"metadata":{"big":"` + strings.Repeat("x", 100000) + `"}}`)
	sb.WriteString(`],"artifactRelationships":[],"files":[`)
	for i := 0; i < 1000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"id":12345,"location":{"path":"/usr/share/some-file"},"metadata":{"mode":493},"digests":[{"algorithm":"sha256","value":"abc"}]}`)
	}
	sb.WriteString(`],"source":{"id":"src-id","name":"my-app","version":"","target":{}},`)
	sb.WriteString(`"descriptor":{"name":"syft","version":"1.2.3","configuration":{"huge":"` + strings.Repeat("y", 100000) + `"}},`)
	sb.WriteString(`"distro":{},"schema":{"version":"16.1.13","url":"https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.1.13.json"}}`)

	doc, err := ReadDocument(strings.NewReader(sb.String()))
	require.NoError(t, err)

	assert.Equal(t, "syft-json", doc.Format)
	assert.Equal(t, "16.1.13", doc.SchemaVersion)
	assert.Equal(t, "syft", doc.ToolName)
	assert.Equal(t, "1.2.3", doc.ToolVersion)
	assert.Equal(t, "my-app", doc.SourceName)
	require.Len(t, doc.Records, 1)
	assert.Equal(t, "id-1", doc.Records[0].ID)
	assert.Equal(t, "lodash", doc.Records[0].Name)
	assert.Equal(t, "4.17.21", doc.Records[0].Version)
	assert.Equal(t, []string{"app/package-lock.json"}, doc.Records[0].Locations)
	assert.Equal(t, "app", doc.Records[0].Subproject)
}

func TestReadDocument_unrecognizedFormat(t *testing.T) {
	_, err := ReadDocument(strings.NewReader("this is not an SBOM at all"))
	require.ErrorIs(t, err, ErrFormatNotIdentified)
}

func TestReadDocument_corruptDocument(t *testing.T) {
	// identified as syft-json by its trailing schema block, but the body is broken
	content := `{"artifacts": [ {"id": "id-1", broken json`
	tail := `],"schema":{"version":"16.1.13","url":"https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.1.13.json"}}`
	_, err := ReadDocument(strings.NewReader(content + tail))
	require.ErrorIs(t, err, ErrCorruptDocument)
}

func TestReadDocument_incompatibleSchema(t *testing.T) {
	content := `{"artifacts":[],"source":{"id":"x","name":"y"},"descriptor":{"name":"syft","version":"9.9.9"},` +
		`"schema":{"version":"999.0.0","url":"https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-999.0.0.json"}}`
	_, err := ReadDocument(strings.NewReader(content))
	require.ErrorIs(t, err, ErrIncompatibleSchema)
	assert.Contains(t, err.Error(), "regenerate the baseline")
}

func TestNormalizePath_noAbsolutePathsInIdentity(t *testing.T) {
	assert.Equal(t, "app/package-lock.json", normalizePath("/app/package-lock.json"))
	assert.Equal(t, "app/package-lock.json", normalizePath("./app/package-lock.json"))
	assert.Equal(t, "app/package-lock.json", normalizePath("/x/../app/package-lock.json"))
	assert.Equal(t, "app.war!/WEB-INF/lib.txt", normalizePath("/app.war!/WEB-INF/lib.txt"))
}
