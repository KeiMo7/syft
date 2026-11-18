package diff

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const syftJSONTemplate = `{
  "artifacts": [%s],
  "artifactRelationships": [],
  "files": [],
  "source": {"type": %q, "name": %q, "version": %q},
  "distro": {},
  "descriptor": {"name": "syft", "version": "1.0.0"},
  "schema": {"version": %q, "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-%s.json"}
}`

const artifactJSON = `{
    "id": %q,
    "name": %q,
    "version": %q,
    "type": "npm",
    "foundBy": "javascript-package-cataloger",
    "locations": [{"path": "/app/package.json"}],
    "licenses": [],
    "language": "javascript",
    "cpes": [],
    "purl": %q,
    "metadataType": "",
    "metadata": null
  }`

func writeTempSBOM(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func syftDocument(t *testing.T, schemaVersion, sourceType, sourceName, version string, artifacts ...string) string {
	t.Helper()
	return fmt.Sprintf(syftJSONTemplate, strings.Join(artifacts, ","), sourceType, sourceName, version, schemaVersion, schemaVersion)
}

func sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

func TestLoadSBOMPreservesProvenance(t *testing.T) {
	artifact := sprintf(artifactJSON, "id-1", "left-pad", "1.0.0", "pkg:npm/left-pad@1.0.0")
	document := syftDocument(t, "16.1.13", "directory", "/work/repo", "", artifact)
	path := writeTempSBOM(t, "old.json", document)

	loaded, err := LoadSBOM(path, nil)
	require.NoError(t, err)

	assert.Equal(t, "16.1.13", loaded.Input.SchemaVersion)
	assert.Equal(t, "syft-json", loaded.Input.FormatID)
	assert.Equal(t, "directory", loaded.Input.SourceType)
	assert.Equal(t, "/work/repo", loaded.Input.SourceName)
	assert.Equal(t, 1, loaded.Input.ComponentCount)
	require.NotNil(t, loaded.Input.GeneratedAt, "falls back to file modification time")
}

func TestSchemaMismatchErrorReportsBothVersions(t *testing.T) {
	oldDoc := syftDocument(t, "16.1.13", "directory", "old", "", "")
	newDoc := syftDocument(t, "15.0.0", "directory", "new", "", "")

	oldPath := writeTempSBOM(t, "old.json", oldDoc)
	newPath := writeTempSBOM(t, "new.json", newDoc)

	oldLoaded, err := LoadSBOM(oldPath, nil)
	require.NoError(t, err)
	newLoaded, err := LoadSBOM(newPath, nil)
	require.NoError(t, err)

	err = CheckSchemaCompatibility(oldLoaded.Input, newLoaded.Input)
	var mismatch *SchemaMismatchError
	require.ErrorAs(t, err, &mismatch)
	assert.Contains(t, err.Error(), "old=syft-json/16.1.13")
	assert.Contains(t, err.Error(), "new=syft-json/15.0.0")
}

func TestParseFailureCarriesLineAndColumn(t *testing.T) {
	invalid := `{
  "artifacts": [
    {"id": "broken"
  ],
  "schema": {"version": "16.1.13", "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.1.13.json"}
}`
	path := writeTempSBOM(t, "broken.json", invalid)

	_, err := LoadSBOM(path, nil)
	require.Error(t, err)

	var loadErr *LoadError
	require.ErrorAs(t, err, &loadErr)
	assert.Equal(t, "parse", loadErr.Stage)
	assert.Greater(t, loadErr.Line, 0)
	assert.Greater(t, loadErr.Column, 0)
	assert.Contains(t, loadErr.Error(), "line 4")
}

func TestSourceMismatchIsFlaggedInReport(t *testing.T) {
	oldArtifact := sprintf(artifactJSON, "id-1", "shared", "1.0.0", "pkg:npm/shared@1.0.0")
	newArtifact := sprintf(artifactJSON, "id-1", "shared", "1.0.0", "pkg:npm/shared@1.0.0")

	oldPath := writeTempSBOM(t, "old.json", syftDocument(t, "16.1.13", "image", "registry/example:latest", "latest", oldArtifact))
	newPath := writeTempSBOM(t, "new.json", syftDocument(t, "16.1.13", "directory", "/work/repo", "", newArtifact))

	oldLoaded, err := LoadSBOM(oldPath, nil)
	require.NoError(t, err)
	newLoaded, err := LoadSBOM(newPath, nil)
	require.NoError(t, err)

	changes, err := Compute(oldLoaded.SBOM, newLoaded.SBOM, Options{})
	require.NoError(t, err)
	assert.Empty(t, changes)

	report := NewReport(oldLoaded.Input, newLoaded.Input, changes, Options{})
	assert.True(t, report.SourceMismatch)
}

func TestLoadFromReader(t *testing.T) {
	document := syftDocument(t, "16.1.13", "directory", "repo", "", "")

	loaded, err := LoadSBOM("-", bytes.NewBufferString(document))
	require.NoError(t, err)
	assert.Equal(t, "-", loaded.Input.Path)
	assert.Equal(t, 0, loaded.Input.ComponentCount)
}

func TestZeroComponentDocumentDecodesWithoutError(t *testing.T) {
	path := writeTempSBOM(t, "empty.json", syftDocument(t, "16.1.13", "directory", "empty", "", ""))

	loaded, err := LoadSBOM(path, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, loaded.Input.ComponentCount)

	changes, err := Compute(loaded.SBOM, loaded.SBOM, Options{})
	require.NoError(t, err)
	assert.Empty(t, changes)

	var loadErr *LoadError
	assert.False(t, errors.As(nil, &loadErr))
}
