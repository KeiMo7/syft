package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIdentityMergeCLI exercises the identity-merge configuration end to end: the same fixture
// produces duplicate package records without merging and one folded entry with it, and the report
// is present with balanced reconciliation.
func TestIdentityMergeCLI(t *testing.T) {
	root := t.TempDir()
	distInfo := filepath.Join(root, "site-packages", "requests-2.22.0.dist-info")
	require.NoError(t, os.MkdirAll(distInfo, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(distInfo, "METADATA"), []byte(strings.Join([]string{
		"Metadata-Version: 2.1",
		"Name: requests",
		"Version: 2.22.0",
		"Author: Kenneth Reitz",
		"License: Apache-2.0",
		"",
	}, "\n")), 0o600))

	vendor := filepath.Join(root, "vendor")
	require.NoError(t, os.MkdirAll(vendor, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(vendor, "requirements.txt"),
		[]byte("requests==2.22.0\n"), 0o600))

	scan := func(t *testing.T, withMerge bool) (int, *json.RawMessage) {
		t.Helper()
		out := filepath.Join(t.TempDir(), "sbom.json")
		args := []string{"scan", "dir:" + root, "-o", "syft-json=" + out, "-q"}
		if withMerge {
			cfg := filepath.Join(t.TempDir(), "syft.yaml")
			require.NoError(t, os.WriteFile(cfg, []byte("identity-merge:\n  enabled: true\n  conflict-threshold: 100\n"), 0o600))
			args = append(args, "-c", cfg)
		}

		cmd, stdout, stderr := runSyft(t, nil, args...)
		logOutputOnFailure(t, cmd, stdout, stderr)
		assertSuccessfulReturnCode(t, stdout, stderr, cmd.ProcessState.ExitCode())

		data, err := os.ReadFile(out)
		require.NoError(t, err)

		var doc struct {
			Artifacts     []struct{ Name string } `json:"artifacts"`
			IdentityMerge *json.RawMessage        `json:"identityMerge"`
		}
		require.NoError(t, json.Unmarshal(data, &doc))
		return len(doc.Artifacts), doc.IdentityMerge
	}

	before, beforeReport := scan(t, false)
	after, afterReport := scan(t, true)

	require.Nil(t, beforeReport, "the report must be absent when merging is off")
	require.NotNil(t, afterReport, "the report must be present when merging is on")

	assert.Greater(t, before, after, "merging must reduce the package count for a duplicate fixture")
	assert.Equal(t, 2, before)
	assert.Equal(t, 1, after)

	var report struct {
		InputCount     int  `json:"inputCount"`
		OutputCount    int  `json:"outputCount"`
		MergePairCount int  `json:"mergePairCount"`
		Balanced       bool `json:"balanced"`
		Reconciliation struct {
			Balanced bool `json:"balanced"`
		} `json:"reconciliation"`
	}
	require.NoError(t, json.Unmarshal(*afterReport, &report))
	assert.Equal(t, before, report.InputCount)
	assert.Equal(t, after, report.OutputCount)
	assert.Equal(t, before-report.MergePairCount, report.OutputCount)
	assert.True(t, report.Reconciliation.Balanced)
}
