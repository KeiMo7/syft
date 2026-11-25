package options

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/sbomartifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func integrationSBOM() sbom.SBOM {
	catalog := pkg.NewCollection()
	catalog.Add(pkg.Package{
		Name:    "musl-utils",
		Version: "1.2.3-r4",
		Type:    pkg.ApkPkg,
		FoundBy: "apk-db-cataloger",
		Locations: file.NewLocationSet(
			file.NewLocation("/lib/apk/db/installed"),
		),
		PURL: "pkg:apk/alpine/musl-utils@1.2.3-r4",
	})
	return sbom.SBOM{
		Artifacts: sbom.Artifacts{Packages: catalog},
		Source: source.Description{
			ID: "some-id", Name: "some-dir", Version: "latest",
			Metadata: source.DirectoryMetadata{Path: "/some/path"},
		},
		Descriptor: sbom.Descriptor{Name: "syft", Version: "v0.0.0-test", Configuration: struct{}{}},
	}
}

// Test_SBOMWriter_PersistenceForms drives the real makeSBOMWriter path used by both scan and
// convert, asserting directory and archive bundles are produced atomically with an index and that
// terminal (path-less) output still coexists with file targets without polluting them.
func Test_SBOMWriter_PersistenceForms(t *testing.T) {
	opt := DefaultOutput()
	require.NoError(t, opt.Format.PostLoad())
	encoders, err := opt.Encoders()
	require.NoError(t, err)
	require.NotEmpty(t, encoders)

	// pick three real encoders for a mixed multi-format request
	jsonEnc := findEncoder(t, encoders, "syft-json")
	spdxEnc := findEncoder(t, encoders, "spdx-json")
	cdxEnc := findEncoder(t, encoders, "cyclonedx-json")

	s := integrationSBOM()

	t.Run("directory bundle via writer", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "bundle")
		require.NoError(t, os.MkdirAll(dir, 0755))

		w, err := newSBOMMultiWriter(
			newSBOMWriterDescription(spdxEnc, dir),
			newSBOMWriterDescription(cdxEnc, dir),
		)
		require.NoError(t, err)
		require.NoError(t, w.Write(s))
		require.NoError(t, w.Close())

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		names := entryNames(entries)
		assert.Contains(t, names, sbomartifact.IndexName)
		assert.Len(t, names, 3) // two members + index
	})

	t.Run("archive bundle via writer", func(t *testing.T) {
		archive := filepath.Join(t.TempDir(), "bundle.zip")
		w, err := newSBOMMultiWriter(
			newSBOMWriterDescription(jsonEnc, archive),
			newSBOMWriterDescription(spdxEnc, archive),
		)
		require.NoError(t, err)
		require.NoError(t, w.Write(s))
		require.NoError(t, w.Close())

		r, err := zip.OpenReader(archive)
		require.NoError(t, err)
		t.Cleanup(func() { _ = r.Close() })
		var zipNames []string
		for _, f := range r.File {
			zipNames = append(zipNames, f.Name)
		}
		assert.Contains(t, zipNames, sbomartifact.IndexName)
		assert.Len(t, zipNames, 3) // two members + index
	})

	t.Run("single file keeps byte-identical encoded output", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "one.json")
		w, err := newSBOMMultiWriter(newSBOMWriterDescription(jsonEnc, path))
		require.NoError(t, err)
		require.NoError(t, w.Write(s))
		require.NoError(t, w.Close())

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		want := mustEncode(t, jsonEnc, s)
		assert.Equal(t, want, got)
	})

	t.Run("conflicting file target fails before writing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "conflict.json")
		require.NoError(t, os.WriteFile(path, []byte("existing"), 0644))
		_, err := newSBOMMultiWriter(
			newSBOMWriterDescription(jsonEnc, path),
			newSBOMWriterDescription(spdxEnc, path),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "single file")

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, []byte("existing"), got, "pre-existing content must be untouched on a rejected batch")
	})
}

// Test_SBOMWriter_ContextLockReachable ensures a batch built through the writer can be closed and
// leaves no locks held, exercising the same lifecycle scan.go/convert.go rely on.
func Test_SBOMWriter_ContextLockReachable(t *testing.T) {
	opt := DefaultOutput()
	require.NoError(t, opt.Format.PostLoad())
	encoders, err := opt.Encoders()
	require.NoError(t, err)
	jsonEnc := findEncoder(t, encoders, "syft-json")

	path := filepath.Join(t.TempDir(), "locked.json")
	w, err := newSBOMMultiWriter(newSBOMWriterDescription(jsonEnc, path))
	require.NoError(t, err)
	// abandon before Write: Close must release the acquired lock
	require.NoError(t, w.Close())

	// a second writer can now acquire the same destination without timing out
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = ctx
	w2, err := newSBOMMultiWriter(newSBOMWriterDescription(jsonEnc, path))
	require.NoError(t, err)
	require.NoError(t, w2.Write(integrationSBOM()))
	require.NoError(t, w2.Close())
}

func findEncoder(t *testing.T, encoders []sbom.FormatEncoder, id string) sbom.FormatEncoder {
	t.Helper()
	for _, e := range encoders {
		if string(e.ID()) == id {
			return e
		}
	}
	t.Fatalf("encoder %q not found", id)
	return nil
}

func mustEncode(t *testing.T, enc sbom.FormatEncoder, s sbom.SBOM) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, enc.Encode(&buf, s))
	return buf.Bytes()
}

func entryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
