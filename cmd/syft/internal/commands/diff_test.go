package commands

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/diff"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func diffTestPackage(id, name, version, purl string, locations ...string) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Type:      pkg.NpmPkg,
		FoundBy:   "javascript-cataloger",
		PURL:      purl,
		Locations: file.NewLocationSet(),
	}
	for _, l := range locations {
		p.Locations.Add(file.NewLocation(l))
	}
	p.OverrideID(artifact.ID(id))
	return p
}

func diffTestSBOM(toolVersion string, pkgs ...pkg.Package) sbom.SBOM {
	catalog := pkg.NewCollection()
	for _, p := range pkgs {
		catalog.Add(p)
	}
	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: catalog,
		},
		Source: source.Description{
			ID:   "some-id",
			Name: "some-app",
			Metadata: source.DirectoryMetadata{
				Path: "/some/path",
			},
		},
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: toolVersion,
		},
	}
}

func writeDiffTestSBOM(t *testing.T, s sbom.SBOM) string {
	t.Helper()
	enc, err := syftjson.NewFormatEncoderWithConfig(syftjson.DefaultEncoderConfig())
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "sbom.syft.json")
	f, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, enc.Encode(f, s))
	require.NoError(t, f.Close())
	return path
}

func defaultDiffOptions(output string) *DiffOptions {
	return &DiffOptions{
		UpdateCheck: options.DefaultUpdateCheck(),
		Diff:        options.Diff{Output: output},
	}
}

func runDiffToFile(t *testing.T, oldPath, newPath, outPath string) error {
	t.Helper()
	opts := defaultDiffOptions("diff-json=" + outPath)
	return RunDiff(context.Background(), opts, oldPath, newPath)
}

func readDiffReport(t *testing.T, path string) diff.Diff {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	var d diff.Diff
	require.NoError(t, json.Unmarshal(content, &d))
	return d
}

func TestRunDiff_identicalDocuments(t *testing.T) {
	oldPath := writeDiffTestSBOM(t, diffTestSBOM("1.0.0",
		diffTestPackage("id-1", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "/app/package-lock.json"),
	))
	newPath := writeDiffTestSBOM(t, diffTestSBOM("1.0.0",
		diffTestPackage("id-2", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "/app/package-lock.json"),
	))
	out := filepath.Join(t.TempDir(), "diff.json")

	require.NoError(t, runDiffToFile(t, oldPath, newPath, out))

	d := readDiffReport(t, out)
	assert.Equal(t, 1, d.Summary.Unchanged)
	assert.Equal(t, 0, d.Summary.Added)
	assert.Equal(t, 0, d.Summary.Removed)
	assert.Equal(t, 0, d.Summary.Changed)
}

func TestRunDiff_addRemoveChange(t *testing.T) {
	oldPath := writeDiffTestSBOM(t, diffTestSBOM("1.0.0",
		diffTestPackage("id-1", "stays", "1.0.0", "pkg:npm/stays@1.0.0", "/app/package-lock.json"),
		diffTestPackage("id-2", "goes-away", "1.0.0", "pkg:npm/goes-away@1.0.0", "/app/package-lock.json"),
		diffTestPackage("id-3", "bumps", "1.0.0", "pkg:npm/bumps@1.0.0", "/app/package-lock.json"),
	))
	newPath := writeDiffTestSBOM(t, diffTestSBOM("1.0.0",
		diffTestPackage("id-4", "stays", "1.0.0", "pkg:npm/stays@1.0.0", "/app/package-lock.json"),
		diffTestPackage("id-5", "shows-up", "2.0.0", "pkg:npm/shows-up@2.0.0", "/app/package-lock.json"),
		diffTestPackage("id-6", "bumps", "1.0.1", "pkg:npm/bumps@1.0.1", "/app/package-lock.json"),
	))
	out := filepath.Join(t.TempDir(), "diff.json")

	require.NoError(t, runDiffToFile(t, oldPath, newPath, out))

	d := readDiffReport(t, out)
	assert.Equal(t, 1, d.Summary.Added)
	assert.Equal(t, 1, d.Summary.Removed)
	assert.Equal(t, 1, d.Summary.Changed)
	assert.Equal(t, 1, d.Summary.Unchanged)

	require.Len(t, d.Changed, 1)
	assert.Equal(t, "bumps", d.Changed[0].Name)
	assert.Equal(t, "1.0.0", d.Changed[0].From.Version)
	assert.Equal(t, "1.0.1", d.Changed[0].To.Version)
	require.NotEmpty(t, d.Changed[0].From.Refs)
	assert.Equal(t, "id-3", d.Changed[0].From.Refs[0].ID, "the change must trace back to the old SBOM entry")
	assert.Equal(t, "id-6", d.Changed[0].To.Refs[0].ID)
}

func TestRunDiff_byteIdenticalAcrossRuns(t *testing.T) {
	oldPath := writeDiffTestSBOM(t, diffTestSBOM("1.0.0",
		diffTestPackage("id-1", "bbb", "1.0.0", "pkg:npm/bbb@1.0.0", "/b/package-lock.json"),
		diffTestPackage("id-2", "aaa", "1.0.0", "pkg:npm/aaa@1.0.0", "/a/package-lock.json"),
		diffTestPackage("id-3", "ccc", "1.0.0", "pkg:npm/ccc@1.0.0", "/a/package-lock.json"),
	))
	newPath := writeDiffTestSBOM(t, diffTestSBOM("1.0.0",
		diffTestPackage("id-4", "ccc", "1.0.0", "pkg:npm/ccc@1.0.0", "/a/package-lock.json"),
		diffTestPackage("id-5", "aaa", "1.0.0", "pkg:npm/aaa@1.0.0", "/a/package-lock.json"),
		diffTestPackage("id-6", "bbb", "1.0.1", "pkg:npm/bbb@1.0.1", "/b/package-lock.json"),
		diffTestPackage("id-7", "ddd", "2.0.0", "pkg:npm/ddd@2.0.0", "/a/package-lock.json"),
	))

	dir := t.TempDir()
	out1 := filepath.Join(dir, "diff-1.json")
	out2 := filepath.Join(dir, "diff-2.json")

	require.NoError(t, runDiffToFile(t, oldPath, newPath, out1))
	require.NoError(t, runDiffToFile(t, oldPath, newPath, out2))

	content1, err := os.ReadFile(out1)
	require.NoError(t, err)
	content2, err := os.ReadFile(out2)
	require.NoError(t, err)
	assert.Equal(t, string(content1), string(content2),
		"comparing the same pair of SBOMs twice must produce byte-for-byte identical reports")
}

func TestRunDiff_sameDependencyLocatedPerSubproject(t *testing.T) {
	oldPath := writeDiffTestSBOM(t, diffTestSBOM("1.0.0",
		diffTestPackage("id-1", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "/frontend/package-lock.json"),
		diffTestPackage("id-2", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "/backend/package-lock.json"),
	))
	newPath := writeDiffTestSBOM(t, diffTestSBOM("1.0.0",
		diffTestPackage("id-3", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "/frontend/package-lock.json"),
		diffTestPackage("id-4", "lodash", "4.17.20", "pkg:npm/lodash@4.17.20", "/backend/package-lock.json"),
	))
	out := filepath.Join(t.TempDir(), "diff.json")

	require.NoError(t, runDiffToFile(t, oldPath, newPath, out))

	d := readDiffReport(t, out)
	require.Len(t, d.Unchanged, 1, "the frontend copy is its own row")
	assert.Equal(t, "frontend", d.Unchanged[0].Subproject)
	require.Len(t, d.Changed, 1, "the backend copy is a separate row, not merged with the frontend one")
	assert.Equal(t, "backend", d.Changed[0].Subproject)
	assert.Equal(t, "4.17.21", d.Changed[0].From.Version)
	assert.Equal(t, "4.17.20", d.Changed[0].To.Version)
}

func TestRunDiff_newSubprojectAttribution(t *testing.T) {
	oldPath := writeDiffTestSBOM(t, diffTestSBOM("1.0.0",
		diffTestPackage("id-1", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "/frontend/package-lock.json"),
	))
	newPath := writeDiffTestSBOM(t, diffTestSBOM("1.0.0",
		diffTestPackage("id-2", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "/frontend/package-lock.json"),
		diffTestPackage("id-3", "express", "4.18.2", "pkg:npm/express@4.18.2", "/frontend/package-lock.json"),
		diffTestPackage("id-4", "django", "4.2.0", "pkg:pypi/django@4.2.0", "/services/api/requirements.txt"),
	))
	out := filepath.Join(t.TempDir(), "diff.json")

	require.NoError(t, runDiffToFile(t, oldPath, newPath, out))

	d := readDiffReport(t, out)
	assert.Equal(t, []string{"services/api"}, d.Subprojects.Added)
	require.Len(t, d.Added, 2)
	byName := map[string]diff.Entry{}
	for _, e := range d.Added {
		byName[e.Name] = e
	}
	assert.False(t, byName["express"].NewSubproject)
	assert.True(t, byName["django"].NewSubproject)
}

func TestRunDiff_toolVersionChangeIsVisible(t *testing.T) {
	oldPath := writeDiffTestSBOM(t, diffTestSBOM("1.0.0",
		diffTestPackage("id-1", "goes-away", "1.0.0", "pkg:npm/goes-away@1.0.0", "/app/package-lock.json"),
	))
	newPath := writeDiffTestSBOM(t, diffTestSBOM("2.0.0",
		diffTestPackage("id-2", "shows-up", "1.0.0", "pkg:npm/shows-up@1.0.0", "/app/package-lock.json"),
	))
	out := filepath.Join(t.TempDir(), "diff.json")

	require.NoError(t, runDiffToFile(t, oldPath, newPath, out))

	d := readDiffReport(t, out)
	assert.True(t, d.Tool.Changed)
	assert.NotEmpty(t, d.Tool.Note)
	require.Len(t, d.Added, 1)
	assert.True(t, d.Added[0].PossiblyToolInduced, "with the tool version changed, additions may come from the tool")
	require.Len(t, d.Removed, 1)
	assert.True(t, d.Removed[0].PossiblyToolInduced)
}

func TestRunDiff_errorTaxonomy(t *testing.T) {
	validPath := writeDiffTestSBOM(t, diffTestSBOM("1.0.0",
		diffTestPackage("id-1", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "/app/package-lock.json"),
	))

	t.Run("missing baseline", func(t *testing.T) {
		err := runDiffToFile(t, filepath.Join(t.TempDir(), "does-not-exist.json"), validPath, filepath.Join(t.TempDir(), "out.json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "baseline SBOM not found")
	})

	t.Run("missing new", func(t *testing.T) {
		err := runDiffToFile(t, validPath, filepath.Join(t.TempDir(), "does-not-exist.json"), filepath.Join(t.TempDir(), "out.json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "new SBOM not found")
	})

	t.Run("unrecognized format", func(t *testing.T) {
		bogus := filepath.Join(t.TempDir(), "bogus.txt")
		require.NoError(t, os.WriteFile(bogus, []byte("definitely not an SBOM"), 0644))
		err := runDiffToFile(t, bogus, validPath, filepath.Join(t.TempDir(), "out.json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "format not recognized")
	})

	t.Run("corrupt document", func(t *testing.T) {
		corrupt := filepath.Join(t.TempDir(), "corrupt.json")
		content := `{"artifacts": [ {"id": "id-1", broken` +
			`],"schema":{"version":"16.0.0","url":"https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.0.json"}}`
		require.NoError(t, os.WriteFile(corrupt, []byte(content), 0644))
		err := runDiffToFile(t, corrupt, validPath, filepath.Join(t.TempDir(), "out.json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "may be corrupt")
	})

	t.Run("incompatible schema version", func(t *testing.T) {
		incompatible := filepath.Join(t.TempDir(), "future.json")
		content := `{"artifacts":[],"source":{"id":"x","name":"y"},"descriptor":{"name":"syft","version":"9.9.9"},` +
			`"schema":{"version":"999.0.0","url":"https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-999.0.0.json"}}`
		require.NoError(t, os.WriteFile(incompatible, []byte(content), 0644))
		err := runDiffToFile(t, incompatible, validPath, filepath.Join(t.TempDir(), "out.json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "incompatible")
		assert.Contains(t, err.Error(), "regenerate the baseline")
	})
}

func TestRunDiff_noPartialOutputOnFailure(t *testing.T) {
	oldPath := writeDiffTestSBOM(t, diffTestSBOM("1.0.0",
		diffTestPackage("id-1", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "/app/package-lock.json"),
	))
	dir := t.TempDir()
	out := filepath.Join(dir, "diff.json")

	// the new SBOM is garbage: the command must fail and leave no report behind at all
	bogus := filepath.Join(dir, "bogus.txt")
	require.NoError(t, os.WriteFile(bogus, []byte("not an SBOM"), 0644))

	err := runDiffToFile(t, oldPath, bogus, out)
	require.Error(t, err)

	_, statErr := os.Stat(out)
	assert.True(t, os.IsNotExist(statErr), "no report file may be left behind on failure")

	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), ".syft-diff-", "no temp file may be left behind on failure")
	}
}

func TestWriteFileAtomic(t *testing.T) {
	t.Run("writes content and leaves no temp files", func(t *testing.T) {
		dir := t.TempDir()
		out := filepath.Join(dir, "sub", "report.txt")
		require.NoError(t, writeFileAtomic(out, []byte("hello")))
		content, err := os.ReadFile(out)
		require.NoError(t, err)
		assert.Equal(t, "hello", string(content))

		entries, err := os.ReadDir(filepath.Dir(out))
		require.NoError(t, err)
		require.Len(t, entries, 1, "only the final report may remain")
	})

	t.Run("failure leaves no partial file", func(t *testing.T) {
		dir := t.TempDir()
		blocker := filepath.Join(dir, "blocker")
		require.NoError(t, os.WriteFile(blocker, []byte("i am a file"), 0644))

		// the destination's parent path is a regular file: writing must fail cleanly
		err := writeFileAtomic(filepath.Join(blocker, "report.txt"), []byte("hello"))
		require.Error(t, err)

		entries, readErr := os.ReadDir(dir)
		require.NoError(t, readErr)
		require.Len(t, entries, 1, "no partial or temp output may be left behind")
	})
}

func TestParseDiffOutput(t *testing.T) {
	format, path, err := parseDiffOutput("diff-json=out.json")
	require.NoError(t, err)
	assert.Equal(t, "diff-json", format)
	assert.Equal(t, "out.json", path)

	format, path, err = parseDiffOutput("diff-text")
	require.NoError(t, err)
	assert.Equal(t, "diff-text", format)
	assert.Empty(t, path)

	_, _, err = parseDiffOutput("spdx-json")
	require.Error(t, err, "SBOM formats are not diff report formats")
}
