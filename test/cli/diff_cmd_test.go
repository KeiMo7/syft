package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/diff"
)

const diffSBOMTemplate = `{
  "artifacts": [%s],
  "artifactRelationships": [],
  "files": [],
  "source": {"type": "directory", "name": %q, "version": ""},
  "distro": {},
  "descriptor": {"name": "syft", "version": "1.0.0"},
  "schema": {"version": "16.1.13", "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.1.13.json"}
}`

const diffArtifactTemplate = `{
    "id": %q,
    "name": %q,
    "version": %q,
    "type": "python",
    "foundBy": "python-package-cataloger",
    "locations": [{"path": %q}],
    "licenses": [],
    "language": "python",
    "cpes": [],
    "purl": %q,
    "metadataType": "",
    "metadata": null
  }`

func writeDiffSBOM(t *testing.T, dir, name, sourceName string, artifacts ...string) string {
	t.Helper()
	document := fmt.Sprintf(diffSBOMTemplate, joinComma(artifacts), sourceName)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(document), 0o600))
	return path
}

func diffArtifact(id, name, version, path, purl string) string {
	return fmt.Sprintf(diffArtifactTemplate, id, name, version, path, purl)
}

func joinComma(values []string) string {
	var result string
	for index, value := range values {
		if index > 0 {
			result += ","
		}
		result += value
	}
	return result
}

func TestDiffCommandReportsAddedRemovedAndVersionChanges(t *testing.T) {
	dir := t.TempDir()

	oldPath := writeDiffSBOM(t, dir, "old.json", "/repo",
		diffArtifact("1", "kept", "1.0.0", "/requirements.txt", "pkg:pypi/kept@1.0.0"),
		diffArtifact("2", "removed-lib", "1.0.0", "/requirements.txt", "pkg:pypi/removed-lib@1.0.0"),
		diffArtifact("3", "requests", "2.31.0", "/requirements.txt", "pkg:pypi/requests@2.31.0"),
	)
	newPath := writeDiffSBOM(t, dir, "new.json", "/repo",
		diffArtifact("1", "kept", "1.0.0", "/requirements.txt", "pkg:pypi/kept@1.0.0"),
		diffArtifact("4", "added-lib", "1.0.0", "/requirements.txt", "pkg:pypi/added-lib@1.0.0"),
		diffArtifact("3", "requests", "2.32.3", "/requirements.txt", "pkg:pypi/requests@2.32.3"),
	)

	cmd, stdout, stderr := runSyft(t, nil, "diff", oldPath, newPath, "--diff-format", "json")
	defer logOutputOnFailure(t, cmd, stdout, stderr)
	assertSuccessfulReturnCode(t, stdout, stderr, cmd.ProcessState.ExitCode())

	var report diff.Report
	require.NoError(t, json.Unmarshal([]byte(stdout), &report))

	assert.Equal(t, 1, report.Counts.Added)
	assert.Equal(t, 1, report.Counts.Removed)
	assert.Equal(t, 1, report.Counts.VersionChanged)
	assert.False(t, report.SourceMismatch)

	byName := make(map[string]diff.Change)
	for _, change := range report.Changes {
		byName[change.Name] = change
	}

	assert.Equal(t, diff.Added, byName["added-lib"].Type)
	assert.Equal(t, diff.Removed, byName["removed-lib"].Type)
	assert.Equal(t, diff.Upgrade, byName["requests"].Direction)
	assert.Equal(t, "2.31.0", byName["requests"].OldVersion)
	assert.Equal(t, "2.32.3", byName["requests"].NewVersion)

	_, keptPresent := byName["kept"]
	assert.False(t, keptPresent)
}

func TestDiffCommandFailsOnHighRiskGate(t *testing.T) {
	dir := t.TempDir()

	oldPath := writeDiffSBOM(t, dir, "old.json", "/repo",
		diffArtifact("1", "requests", "2.0.0", "/requirements.txt", "pkg:pypi/requests@2.0.0"),
	)
	newPath := writeDiffSBOM(t, dir, "new.json", "/repo",
		diffArtifact("1", "requests", "1.0.0", "/requirements.txt", "pkg:pypi/requests@1.0.0"),
		diffArtifact("2", "added-lib", "1.0.0", "/requirements.txt", "pkg:pypi/added-lib@1.0.0"),
	)

	cmd := getSyftCommand(t, "diff", oldPath, newPath,
		"--diff-format", "json", "--high-risk", "--fail-on", "high-risk")
	stdout, stderr := runCommandObj(t, cmd, nil, true)
	defer logOutputOnFailure(t, cmd, stdout, stderr)

	assert.NotEqual(t, 0, cmd.ProcessState.ExitCode())
	assert.Contains(t, stderr, "diff gating failed")

	var report diff.Report
	require.NoError(t, json.Unmarshal([]byte(stdout), &report))
	assert.Equal(t, 2, report.Counts.HighRisk)
}

func TestDiffCommandRejectsSchemaMismatch(t *testing.T) {
	dir := t.TempDir()

	oldPath := writeDiffSBOM(t, dir, "old.json", "/repo")
	newPath := writeDiffSBOM(t, dir, "new.json", "/repo")

	rewriteSchema := func(path, version string) {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		var raw map[string]any
		require.NoError(t, json.Unmarshal(data, &raw))
		schema := raw["schema"].(map[string]any)
		schema["version"] = version
		schema["url"] = "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-" + version + ".json"
		encoded, err := json.Marshal(raw)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, encoded, 0o600))
	}

	rewriteSchema(oldPath, "15.0.0")

	cmd := getSyftCommand(t, "diff", oldPath, newPath)
	stdout, stderr := runCommandObj(t, cmd, nil, true)
	defer logOutputOnFailure(t, cmd, stdout, stderr)

	assert.NotEqual(t, 0, cmd.ProcessState.ExitCode())
	assert.Contains(t, stderr, "refusing to diff SBOMs with different schema versions")
	assert.Contains(t, stderr, "15.0.0")
	assert.Contains(t, stderr, "16.1.13")
}

func TestDiffCommandScopesByPathPrefix(t *testing.T) {
	dir := t.TempDir()

	oldPath := writeDiffSBOM(t, dir, "old.json", "/repo",
		diffArtifact("1", "scoped", "1.0.0", "/subsystem/requirements.txt", "pkg:pypi/scoped@1.0.0"),
		diffArtifact("2", "other", "1.0.0", "/requirements.txt", "pkg:pypi/other@1.0.0"),
	)
	newPath := writeDiffSBOM(t, dir, "new.json", "/repo",
		diffArtifact("1", "scoped", "2.0.0", "/subsystem/requirements.txt", "pkg:pypi/scoped@2.0.0"),
		diffArtifact("2", "other", "1.0.0", "/requirements.txt", "pkg:pypi/other@1.0.0"),
	)

	cmd, stdout, stderr := runSyft(t, nil, "diff", oldPath, newPath,
		"--scope", "/subsystem", "--diff-format", "json")
	defer logOutputOnFailure(t, cmd, stdout, stderr)
	assertSuccessfulReturnCode(t, stdout, stderr, cmd.ProcessState.ExitCode())

	var report diff.Report
	require.NoError(t, json.Unmarshal([]byte(stdout), &report))
	require.Len(t, report.Changes, 1)
	assert.Equal(t, "scoped", report.Changes[0].Name)
}
