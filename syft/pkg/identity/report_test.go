package identity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGenerateScenarioReport is the acceptance artifact generator. It runs the twelve scenario
// shapes through the merge engine and writes the real input, merged output and report into
// reports/identity-merge/output so a reviewer can diff them against the assertions in
// merge_test.go. It is skipped unless SYFT_UPDATE_IDENTITY_ARTIFACTS is set, so ordinary test runs
// do not touch the working tree.
func TestGenerateScenarioReport(t *testing.T) {
	if os.Getenv("SYFT_UPDATE_IDENTITY_ARTIFACTS") == "" {
		t.Skip("set SYFT_UPDATE_IDENTITY_ARTIFACTS=1 to regenerate reports/identity-merge/output")
	}

	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	require.NoError(t, err)
	outDir := filepath.Join(root, "reports", "identity-merge", "output")
	require.NoError(t, os.MkdirAll(outDir, 0o755))

	type output struct {
		Name       string            `json:"name"`
		Input      []Record          `json:"input"`
		Report     MergeReport       `json:"report"`
		Components []MergedComponent `json:"components"`
	}

	all := make([]output, 0, len(Scenarios()))
	for _, sc := range Scenarios() {
		result := Merge(sc.Records, DefaultOptions().WithConflictThreshold(1000))
		all = append(all, output{
			Name:       sc.Name,
			Input:      sc.Records,
			Report:     result.Report,
			Components: result.Components,
		})
	}

	data, err := json.MarshalIndent(all, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(outDir, "scenarios.json"), append(data, '\n'), 0o644))
}
