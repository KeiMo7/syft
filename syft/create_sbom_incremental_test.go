package syft

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/anchore/syft/syft/cataloging/incremental"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

func TestCreateSBOMWithIncrementalReusesUnchangedDirectory(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "app", "go.mod"), "module example.com/demo\n\ngo 1.24\n\nrequire github.com/foo/bar v1.2.3\n")

	firstSource := newDirectorySource(t, root)
	firstConfig := DefaultCreateSBOMConfig().WithIncrementalConfig(incremental.Config{Enabled: true})
	first, err := CreateSBOMWithIncremental(context.Background(), firstSource, firstConfig)
	require.NoError(t, err)
	require.NotEmpty(t, first.SBOM.Artifacts.Packages.PackageCount())
	assert.Contains(t, first.BaselineStatus, "no reference SBOM")

	baselinePath := filepath.Join(t.TempDir(), "baseline.syft.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(baselinePath), 0o755))
	require.NoError(t, incremental.WriteAtomic(baselinePath, first.SBOM))

	secondSource := newDirectorySource(t, root)
	secondConfig := DefaultCreateSBOMConfig().WithIncrementalConfig(incremental.Config{
		Enabled:      true,
		BaselinePath: baselinePath,
	})
	second, err := CreateSBOMWithIncremental(context.Background(), secondSource, secondConfig)
	require.NoError(t, err)

	assert.Equal(t, incremental.ModeIncremental, second.Stats.Mode)
	assert.False(t, second.Stats.FallbackRequired)
	assert.Equal(t, 0, second.Stats.ChangedPaths, "changed paths: %v", second.Plan.ChangedPaths)
	assert.Equal(t, len(second.SBOM.Artifacts.Packages.Sorted()), second.Stats.ReusedPackages)
	assert.Equal(t, 1.0, second.Stats.ReuseRatio)

	fullSource := newDirectorySource(t, root)
	full, err := CreateSBOM(context.Background(), fullSource, DefaultCreateSBOMConfig())
	require.NoError(t, err)
	assert.Equal(t, packageIDsForTest(full), packageIDsForTest(second.SBOM))
}

func TestCreateSBOMWithIncrementalReparsesChangedManifest(t *testing.T) {
	root := t.TempDir()
	manifestPath := filepath.Join(root, "app", "go.mod")
	writeTestFile(t, manifestPath, "module example.com/demo\n\ngo 1.24\n\nrequire github.com/foo/bar v1.2.3\n")

	firstSource := newDirectorySource(t, root)
	firstConfig := DefaultCreateSBOMConfig().WithIncrementalConfig(incremental.Config{Enabled: true})
	first, err := CreateSBOMWithIncremental(context.Background(), firstSource, firstConfig)
	require.NoError(t, err)
	require.NotEmpty(t, first.SBOM.Artifacts.Packages.PackageCount())

	baselinePath := filepath.Join(t.TempDir(), "baseline.syft.json")
	require.NoError(t, incremental.WriteAtomic(baselinePath, first.SBOM))
	writeTestFile(t, manifestPath, "module example.com/demo\n\ngo 1.24\n\nrequire github.com/foo/bar v1.2.4\n")

	secondSource := newDirectorySource(t, root)
	secondConfig := DefaultCreateSBOMConfig().WithIncrementalConfig(incremental.Config{
		Enabled:      true,
		BaselinePath: baselinePath,
	})
	second, err := CreateSBOMWithIncremental(context.Background(), secondSource, secondConfig)
	require.NoError(t, err)
	assert.Equal(t, incremental.ModeIncremental, second.Stats.Mode)
	assert.False(t, second.Stats.FallbackRequired)
	require.Len(t, second.Plan.ChangedPaths, 1)
	assert.Contains(t, second.Plan.ChangedPaths[0], "go.mod")
	assert.GreaterOrEqual(t, second.Stats.ParsedPackages, 1)

	fullSource := newDirectorySource(t, root)
	full, err := CreateSBOM(context.Background(), fullSource, DefaultCreateSBOMConfig())
	require.NoError(t, err)
	assert.Equal(t, packageIDsForTest(full), packageIDsForTest(second.SBOM))
}

func TestCreateSBOMWithIncrementalResumesPartialCheckpoint(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "app", "go.mod"), "module example.com/demo\n\ngo 1.24\n\nrequire github.com/foo/bar v1.2.3\n")

	firstSource := newDirectorySource(t, root)
	first, err := CreateSBOMWithIncremental(
		context.Background(),
		firstSource,
		DefaultCreateSBOMConfig().WithIncrementalConfig(incremental.Config{Enabled: true}),
	)
	require.NoError(t, err)

	checkpointPath := filepath.Join(t.TempDir(), "checkpoint.syft.json")
	require.NoError(t, incremental.WriteCheckpointAtomic(checkpointPath, first.SBOM, false, nil))
	_, err = incremental.LoadBaseline(checkpointPath)
	assert.ErrorIs(t, err, incremental.ErrBaselineIncomplete)

	secondSource := newDirectorySource(t, root)
	second, err := CreateSBOMWithIncremental(
		context.Background(),
		secondSource,
		DefaultCreateSBOMConfig().WithIncrementalConfig(incremental.Config{
			Enabled:        true,
			CheckpointPath: checkpointPath,
		}),
	)
	require.NoError(t, err)
	assert.Contains(t, second.BaselineStatus, "resuming from partial checkpoint")
	assert.Equal(t, incremental.ModeIncremental, second.Stats.Mode)

	complete, err := incremental.LoadBaseline(checkpointPath)
	require.NoError(t, err)
	assert.True(t, complete.Complete)
	assert.Equal(t, packageIDsForTest(second.SBOM), packageIDsForTest(complete.SBOM))
}

func newDirectorySource(t *testing.T, path string) *closingSource {
	t.Helper()
	src, err := directorysource.NewFromPath(path)
	require.NoError(t, err)
	return &closingSource{Source: src}
}

type closingSource struct {
	source.Source
}

func (s *closingSource) Close() error {
	return s.Source.Close()
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func packageIDsForTest(document *sbom.SBOM) []string {
	var ids []string
	for p := range document.Artifacts.Packages.Enumerate() {
		ids = append(ids, string(p.ID()))
	}
	sort.Strings(ids)
	return ids
}
