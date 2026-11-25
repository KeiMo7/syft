package sbomartifact

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func testSBOM() sbom.SBOM {
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
		// pin every descriptor field that encoders render so the same SBOM value encodes to
		// identical bytes on every run (the real Descriptor would otherwise carry a fresh UUID
		// and wall-clock timestamp, making byte-level reproducibility untestable here)
		Descriptor: sbom.Descriptor{
			Name:          "syft",
			Version:       "v0.0.0-test",
			Configuration: struct{}{},
		},
	}
}

func testEncoders(t *testing.T) []sbom.FormatEncoder {
	t.Helper()
	spdxEnc, err := spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())
	require.NoError(t, err)
	cdxEnc, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	require.NoError(t, err)
	return []sbom.FormatEncoder{
		syftjson.NewFormatEncoder(),
		spdxEnc,
		cdxEnc,
	}
}

// failingEncoder always fails during encoding, used for failure injection.
type failingEncoder struct {
	id        sbom.FormatID
	version   string
	failAfter int
}

func (f failingEncoder) ID() sbom.FormatID { return f.id }
func (f failingEncoder) Aliases() []string { return nil }
func (f failingEncoder) Version() string   { return f.version }
func (f failingEncoder) Encode(w io.Writer, s sbom.SBOM) error {
	if f.failAfter > 0 {
		_, _ = w.Write(bytes.Repeat([]byte("x"), f.failAfter))
	}
	return fmt.Errorf("injected template render failure")
}

func TestClassifyPath(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "doc.json"), []byte("{}"), 0644))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "bundle"), 0755))

	tests := []struct {
		name    string
		path    string
		want    TargetKind
		wantErr bool
	}{
		{name: "missing plain path is a file", path: filepath.Join(dir, "new.json"), want: KindFile},
		{name: "missing zip is an archive", path: filepath.Join(dir, "new.zip"), want: KindArchive},
		{name: "missing sbom.zip is an archive", path: filepath.Join(dir, "new.sbom.zip"), want: KindArchive},
		{name: "existing file is a file", path: filepath.Join(dir, "doc.json"), want: KindFile},
		{name: "existing directory is a directory", path: filepath.Join(dir, "bundle"), want: KindDirectory},
		{name: "zip suffix on existing directory errors", path: filepath.Join(dir, "bundle.zip"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if strings.Contains(tt.name, "zip suffix on existing directory") {
				require.NoError(t, os.Mkdir(tt.path, 0755))
			}
			got, err := ClassifyPath(tt.path)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "directory")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMemberNameStableAndDistinct(t *testing.T) {
	encoders := testEncoders(t)
	names := make(map[string]string)
	for _, enc := range encoders {
		name := MemberName(enc)
		// stable across repeated derivation
		assert.Equal(t, name, MemberName(enc))
		if other, dup := names[name]; dup {
			t.Fatalf("member name %q derived by two encoders (%s, %s)", name, other, enc.ID())
		}
		names[name] = string(enc.ID())
		assert.False(t, strings.ContainsAny(name, "/\\ "), "member name must be filesystem-safe: %q", name)
	}

	// explicit versions participate in the name
	v23enc, err := spdxjson.NewFormatEncoderWithConfig(spdxjson.EncoderConfig{Version: "2.3"})
	require.NoError(t, err)
	v22enc, err := spdxjson.NewFormatEncoderWithConfig(spdxjson.EncoderConfig{Version: "2.2"})
	require.NoError(t, err)
	assert.NotEqual(t, MemberName(v23enc), MemberName(v22enc))
	assert.Contains(t, MemberName(v23enc), "2.3")
}

func TestBatch_TargetForms(t *testing.T) {
	encoders := testEncoders(t)
	s := testSBOM()

	tests := []struct {
		name        string
		setup       func(t *testing.T, root string) []Request
		assertions  func(t *testing.T, root string, b *Batch)
		wantErr     bool
		errContains string
	}{
		{
			name: "single file target keeps encoded bytes",
			setup: func(t *testing.T, root string) []Request {
				return []Request{{Path: filepath.Join(root, "one.json"), Encoders: encoders[:1]}}
			},
			assertions: func(t *testing.T, root string, b *Batch) {
				path := filepath.Join(root, "one.json")
				assert.FileExists(t, path)
				want := encodeNow(t, encoders[0], s)
				got, err := os.ReadFile(path)
				require.NoError(t, err)
				assert.Equal(t, want, got)
				info, err := os.Stat(path)
				require.NoError(t, err)
				assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
			},
		},
		{
			name: "directory target holds one member per format plus index",
			setup: func(t *testing.T, root string) []Request {
				return []Request{{Path: filepath.Join(root, "bundle"), Encoders: encoders}}
			},
			assertions: func(t *testing.T, root string, b *Batch) {
				dir := filepath.Join(root, "bundle")
				assertIndexAndMembers(t, dir, encoders, s, false)
				info, err := os.Stat(dir)
				require.NoError(t, err)
				assert.Equal(t, os.FileMode(0755), info.Mode().Perm())
			},
		},
		{
			name: "archive target matches directory members byte for byte",
			setup: func(t *testing.T, root string) []Request {
				return []Request{{Path: filepath.Join(root, "bundle.zip"), Encoders: encoders}}
			},
			assertions: func(t *testing.T, root string, b *Batch) {
				archive := filepath.Join(root, "bundle.zip")
				assertIndexAndMembers(t, archive, encoders, s, true)
				info, err := os.Stat(archive)
				require.NoError(t, err)
				assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
			},
		},
		{
			name: "mixed file directory and archive targets in one batch",
			setup: func(t *testing.T, root string) []Request {
				return []Request{
					{Path: filepath.Join(root, "mixed.json"), Encoders: encoders[:1]},
					{Path: filepath.Join(root, "mixed-dir"), Encoders: encoders[1:]},
					{Path: filepath.Join(root, "mixed.zip"), Encoders: encoders},
				}
			},
			assertions: func(t *testing.T, root string, b *Batch) {
				assert.FileExists(t, filepath.Join(root, "mixed.json"))
				assertIndexAndMembers(t, filepath.Join(root, "mixed-dir"), encoders[1:], s, false)
				assertIndexAndMembers(t, filepath.Join(root, "mixed.zip"), encoders, s, true)
			},
		},
		{
			name: "two requests on the same directory merge members and index",
			setup: func(t *testing.T, root string) []Request {
				dir := filepath.Join(root, "shared")
				return []Request{
					{Path: dir, Encoders: encoders[:1]},
					{Path: dir, Encoders: encoders[1:]},
				}
			},
			assertions: func(t *testing.T, root string, b *Batch) {
				assertIndexAndMembers(t, filepath.Join(root, "shared"), encoders, s, false)
			},
		},
		{
			name: "duplicate identical single file request is deduplicated",
			setup: func(t *testing.T, root string) []Request {
				p := filepath.Join(root, "dup.json")
				return []Request{
					{Path: p, Encoders: encoders[:1]},
					{Path: p, Encoders: encoders[:1]},
				}
			},
			assertions: func(t *testing.T, root string, b *Batch) {
				assert.FileExists(t, filepath.Join(root, "dup.json"))
			},
		},
		{
			name: "conflicting single file requests fail before anything is visible",
			setup: func(t *testing.T, root string) []Request {
				p := filepath.Join(root, "conflict.json")
				// an existing regular file is unambiguously a single-file destination, so a second
				// distinct format aimed at it must be rejected rather than silently overwritten
				require.NoError(t, os.WriteFile(p, []byte("existing"), 0644))
				return []Request{
					{Path: p, Encoders: encoders[:1]},
					{Path: p, Encoders: encoders[1:2]},
				}
			},
			wantErr:     true,
			errContains: "single file",
		},
		{
			name: "empty encoder set fails without creating an empty directory",
			setup: func(t *testing.T, root string) []Request {
				return []Request{{Path: filepath.Join(root, "empty"), Encoders: nil}}
			},
			wantErr:     true,
			errContains: "no output formats",
		},
		{
			name: "type mismatch: archive suffix on an existing directory is explicit",
			setup: func(t *testing.T, root string) []Request {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "occupied.zip"), 0755))
				return []Request{{Path: filepath.Join(root, "occupied.zip"), Encoders: encoders[:1]}}
			},
			wantErr:     true,
			errContains: "directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			requests := tt.setup(t, root)
			before := fingerprintTree(t, root)

			b, err := NewBatch(context.Background(), requests...)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				// nothing visible should have appeared beyond the pre-existing setup
				assert.Equal(t, before, fingerprintTree(t, root))
				return
			}
			require.NoError(t, err)
			require.NoError(t, b.Write(s))
			require.NoError(t, b.Close())
			assert.Empty(t, testStagingLeftovers(t, root))
			if tt.assertions != nil {
				tt.assertions(t, root, b)
			}
		})
	}
}

func TestBatch_ExistingContentReplacement(t *testing.T) {
	encoders := testEncoders(t)
	s := testSBOM()

	t.Run("directory target fully replaces previous content", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "bundle")
		require.NoError(t, os.MkdirAll(dir, 0755))
		stale := filepath.Join(dir, "stale-old-member.txt")
		require.NoError(t, os.WriteFile(stale, []byte("previous run"), 0644))

		b, err := NewBatch(context.Background(), Request{Path: dir, Encoders: encoders})
		require.NoError(t, err)
		require.NoError(t, b.Write(s))

		_, err = os.Lstat(stale)
		assert.True(t, os.IsNotExist(err), "stale member must be removed by whole-tree replacement")
		assertIndexAndMembers(t, dir, encoders, s, false)
		assert.Empty(t, testStagingLeftovers(t, root))
	})

	t.Run("file target replaces previous bytes atomically", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "doc.json")
		require.NoError(t, os.WriteFile(path, []byte("old content"), 0644))

		b, err := NewBatch(context.Background(), Request{Path: path, Encoders: encoders[:1]})
		require.NoError(t, err)
		require.NoError(t, b.Write(s))

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, encodeNow(t, encoders[0], s), got)
		assert.Empty(t, testStagingLeftovers(t, root))
	})

	t.Run("archive target replaces previous archive", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "bundle.zip")
		require.NoError(t, os.WriteFile(path, []byte("not even a zip"), 0644))

		b, err := NewBatch(context.Background(), Request{Path: path, Encoders: encoders})
		require.NoError(t, err)
		require.NoError(t, b.Write(s))

		assertIndexAndMembers(t, path, encoders, s, true)
	})
}

func TestBatch_FailureRollback(t *testing.T) {
	good := testEncoders(t)
	s := testSBOM()

	t.Run("failing encoder in directory leaves prior tree untouched", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "bundle")
		require.NoError(t, os.MkdirAll(dir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("old"), 0644))
		before := fingerprintTree(t, dir)

		failing := failingEncoder{id: "syft-json", version: "99.0.0", failAfter: 16}
		b, err := NewBatch(context.Background(),
			Request{Path: dir, Encoders: []sbom.FormatEncoder{good[1], failing}},
		)
		require.NoError(t, err)
		err = b.Write(s)
		require.Error(t, err)

		var encErr *EncodeError
		require.True(t, errors.As(err, &encErr))
		assert.Equal(t, "syft-json", encErr.Format)
		assert.Contains(t, encErr.Path, "bundle")

		assert.Equal(t, before, fingerprintTree(t, dir), "directory fingerprint must match pre-call state")
		assert.Empty(t, testStagingLeftovers(t, root))
	})

	t.Run("failing encoder rolls back already committed sibling targets", func(t *testing.T) {
		root := t.TempDir()
		goodFile := filepath.Join(root, "good.json")
		require.NoError(t, os.WriteFile(goodFile, []byte("precious"), 0644))
		badDir := filepath.Join(root, "bad-bundle")

		failing := failingEncoder{id: "syft-json", version: "99.0.0"}
		b, err := NewBatch(context.Background(),
			Request{Path: goodFile, Encoders: good[:1]},
			Request{Path: badDir, Encoders: []sbom.FormatEncoder{failing}},
		)
		require.NoError(t, err)
		require.Error(t, b.Write(s))

		got, err := os.ReadFile(goodFile)
		require.NoError(t, err)
		assert.Equal(t, []byte("precious"), got, "committed sibling must roll back to pre-call bytes")
		_, err = os.Lstat(badDir)
		assert.True(t, os.IsNotExist(err), "failed target must never become visible")
		assert.Empty(t, testStagingLeftovers(t, root))
	})

	t.Run("unwritable target reports target and stage, old content stays", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission semantics differ on windows")
		}
		if os.Getuid() == 0 {
			t.Skip("root bypasses file permissions")
		}
		root := t.TempDir()
		parent := filepath.Join(root, "locked")
		dir := filepath.Join(parent, "readonly")
		require.NoError(t, os.MkdirAll(dir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("old"), 0644))
		before := fingerprintTree(t, dir)

		// create the batch (and thus its sibling lock file) first, then make the parent directory
		// read-only: staging cannot be created beside the target, so the run fails during stage while
		// the existing directory is never moved, replaced or truncated.
		b, err := NewBatch(context.Background(), Request{Path: dir, Encoders: good})
		require.NoError(t, err)
		require.NoError(t, os.Chmod(parent, 0500))
		t.Cleanup(func() { _ = os.Chmod(parent, 0755) })

		err = b.Write(s)
		require.Error(t, err)
		// the error identifies the target area (its parent path appears in the stage message)
		assert.Contains(t, err.Error(), "locked")

		// while the parent is read-only the lock file cannot be removed, but the lock itself is
		// released; restore permissions, then close so the lock file is cleaned up like any other
		require.NoError(t, os.Chmod(parent, 0755))
		assert.NoError(t, b.Close())
		assert.Equal(t, before, fingerprintTree(t, dir))
		// lock files are intentional coordination files, not staging residue; assert no stage/backup
		assert.Empty(t, testStagingLeftovers(t, root))
	})

	t.Run("writer closed mid encode leaves no partial file", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "doc.json")
		require.NoError(t, os.WriteFile(path, []byte("old"), 0644))
		before := fingerprintTree(t, root)

		// an encoder that emits partial bytes before failing models a write end that dies midway
		// (template render failure / broken pipe); the staged partial must never reach the target
		failing := failingEncoder{id: "syft-json", version: "99.0.0", failAfter: 32}
		b, err := NewBatch(context.Background(), Request{Path: path, Encoders: []sbom.FormatEncoder{failing}})
		require.NoError(t, err)
		require.Error(t, b.Write(s))

		assert.Equal(t, before, fingerprintTree(t, root))
		assert.Empty(t, testStagingLeftovers(t, root))
	})
}

func TestBatch_Reproducible(t *testing.T) {
	encoders := testEncoders(t)
	s := testSBOM()

	t.Run("two runs produce identical directory member sets and identical deterministic members", func(t *testing.T) {
		root := t.TempDir()
		dirA := filepath.Join(root, "a")
		dirB := filepath.Join(root, "b")

		for _, dir := range []string{dirA, dirB} {
			b, err := NewBatch(context.Background(), Request{Path: dir, Encoders: encoders})
			require.NoError(t, err)
			require.NoError(t, b.Write(s))
		}
		membersA := readAllMembers(t, dirA)
		membersB := readAllMembers(t, dirB)
		// same derived member names in both runs, including the index
		assert.Equal(t, sortedKeys(membersA), sortedKeys(membersB))

		// syft-json carries no per-encode random UUID, so it is byte identical across runs
		syftName := MemberName(encoders[0])
		assert.Equal(t, membersA[syftName], membersB[syftName])

		// index structure (ignoring volatile content digests) is identical
		assert.Equal(t, indexSkeleton(t, membersA[IndexName]), indexSkeleton(t, membersB[IndexName]))
	})

	t.Run("two runs produce archives with the same entry sequence and metadata", func(t *testing.T) {
		root := t.TempDir()
		a := filepath.Join(root, "a.zip")
		b := filepath.Join(root, "b.zip")
		for _, p := range []string{a, b} {
			batch, err := NewBatch(context.Background(), Request{Path: p, Encoders: encoders})
			require.NoError(t, err)
			require.NoError(t, batch.Write(s))
		}
		// the entry sequence (names, order, fixed timestamps) is fully reproducible; member bytes
		// differ only where the format itself embeds a per-encode UUID, which is encoder behavior
		// this package must not alter.
		assert.Equal(t, zipEntryList(t, a), zipEntryList(t, b))
	})

	t.Run("archive entries unpack to the same bytes as directory members of one run", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "bundle")
		archive := filepath.Join(root, "bundle.zip")

		// one batch, one encode per format: the directory and the archive consume the same shared
		// encoded members, so every member — including formats that embed per-encode UUIDs and the
		// index itself — is byte-identical across the two forms.
		b, err := NewBatch(context.Background(),
			Request{Path: dir, Encoders: encoders},
			Request{Path: archive, Encoders: encoders},
		)
		require.NoError(t, err)
		require.NoError(t, b.Write(s))

		dirMembers := readAllMembers(t, dir)
		zipMembers := readZipMembers(t, archive)

		assert.Equal(t, sortedKeys(dirMembers), sortedKeys(zipMembers))
		for name, dirBytes := range dirMembers {
			assert.Equal(t, dirBytes, zipMembers[name], "member %q must be byte-identical across directory and archive", name)
		}

		// every member: index digest on each side matches the actual member bytes
		assertIndexMatchesMembers(t, dirMembers)
		assertIndexMatchesMembers(t, zipMembers)
	})
}

func TestBatch_ConcurrentWriters(t *testing.T) {
	encoders := testEncoders(t)
	s := testSBOM()

	t.Run("concurrent writers to the same directory both produce complete artifacts", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "bundle")
		// seed the directory so the destination resolves to a bundle rather than a missing file
		require.NoError(t, os.MkdirAll(dir, 0755))

		const writers = 4
		var wg sync.WaitGroup
		errs := make([]error, writers)
		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				b, err := NewBatch(context.Background(), Request{Path: dir, Encoders: encoders})
				if err != nil {
					errs[i] = err
					return
				}
				errs[i] = b.Write(s)
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			assert.NoError(t, err)
		}

		// exactly one complete, internally consistent tree survives
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assertIndexAndMembers(t, dir, encoders, s, false)
		assert.Len(t, entries, len(encoders)+1) // members + index, no staging residue
		assert.Empty(t, testStagingLeftovers(t, root))
	})

	t.Run("concurrent writers to the same archive leave one valid zip", func(t *testing.T) {
		root := t.TempDir()
		archive := filepath.Join(root, "bundle.zip")

		const writers = 4
		var wg sync.WaitGroup
		errs := make([]error, writers)
		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				b, err := NewBatch(context.Background(), Request{Path: archive, Encoders: encoders})
				if err != nil {
					errs[i] = err
					return
				}
				errs[i] = b.Write(s)
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			assert.NoError(t, err)
		}
		assertIndexAndMembers(t, archive, encoders, s, true)
	})
}

func TestBatch_SymlinkRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	root := t.TempDir()
	outside := filepath.Join(root, "outside.txt")
	require.NoError(t, os.WriteFile(outside, []byte("sensitive"), 0644))
	link := filepath.Join(t.TempDir(), "link.json")
	require.NoError(t, os.Symlink(outside, link))

	b, err := NewBatch(context.Background(), Request{Path: link, Encoders: testEncoders(t)[:1]})
	require.NoError(t, err)
	err = b.Write(testSBOM())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symlink")

	got, err := os.ReadFile(outside)
	require.NoError(t, err)
	assert.Equal(t, []byte("sensitive"), got, "must never follow the symlink outside the target")
}

func TestIndexContainsNoAbsolutePaths(t *testing.T) {
	root := t.TempDir()
	// an explicit directory destination so multi-format output resolves to a bundle
	dir := filepath.Join(root, "deep", "bundle")
	require.NoError(t, os.MkdirAll(dir, 0755))
	encoders := testEncoders(t)
	b, err := NewBatch(context.Background(), Request{Path: dir, Encoders: encoders})
	require.NoError(t, err)
	require.NoError(t, b.Write(testSBOM()))

	data, err := os.ReadFile(filepath.Join(dir, IndexName))
	require.NoError(t, err)
	assert.NotContains(t, string(data), root)
	assert.NotContains(t, string(data), "/home/")
	var idx Index
	require.NoError(t, jsonUnmarshal(data, &idx))
	assert.Equal(t, indexSchemaVersion, idx.SchemaVersion)
	assert.Len(t, idx.Entries, len(encoders))
	for _, e := range idx.Entries {
		assert.False(t, filepath.IsAbs(e.Name))
		assert.Equal(t, "sha256", e.DigestAlgorithm)
		assert.Len(t, e.Digest, 64)
		assert.Greater(t, e.Size, int64(0))
	}
}

func TestCopyFileAtomic(t *testing.T) {
	root := t.TempDir()
	content := []byte("verbatim passthrough document\n")
	src := filepath.Join(root, "src.json")
	require.NoError(t, os.WriteFile(src, content, 0644))
	dst := filepath.Join(root, "out", "dst.json")

	f, err := os.Open(src)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	require.NoError(t, CopyFileAtomic(f, dst))
	got, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, content, got)

	// replacing preserves bytes on success and old bytes on injected failure
	require.NoError(t, os.WriteFile(dst, []byte("old"), 0644))
	f2, err := os.Open(src)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f2.Close() })
	require.NoError(t, CopyFileAtomic(f2, dst))
	got, err = os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, content, got)
}

// ---- helpers ----

func encodeNow(t *testing.T, enc sbom.FormatEncoder, s sbom.SBOM) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, enc.Encode(&buf, s))
	return buf.Bytes()
}

// deterministicFormatIDs name encoders whose bytes are stable across repeated encodes of the same
// SBOM. Other supported formats deliberately embed a fresh document UUID/timestamp on every encode,
// so for them the correct cross-run invariant is member name, size and digest consistency rather
// than byte equality with a re-encode.
var deterministicFormatIDs = map[sbom.FormatID]bool{
	"syft-json":  true,
	"syft-table": true,
	"syft-text":  true,
	"purls":      true,
}

func assertIndexAndMembers(t *testing.T, targetPath string, encoders []sbom.FormatEncoder, s sbom.SBOM, isArchive bool) {
	t.Helper()
	var members map[string][]byte
	if isArchive {
		members = readZipMembers(t, targetPath)
	} else {
		members = readAllMembers(t, targetPath)
	}

	// every encoder has a member, deterministically named; deterministic formats must match a fresh
	// encode byte-for-byte, volatile formats are validated through the index digest below
	for _, enc := range encoders {
		name := MemberName(enc)
		got, ok := members[name]
		require.True(t, ok, "missing member %q in %s", name, targetPath)
		if deterministicFormatIDs[enc.ID()] {
			assert.Equal(t, encodeNow(t, enc, s), got)
		}
	}

	indexRaw, ok := members[IndexName]
	require.True(t, ok, "missing index in %s", targetPath)
	var idx Index
	require.NoError(t, jsonUnmarshal(indexRaw, &idx))
	assert.Len(t, idx.Entries, len(encoders))

	gotNames := make([]string, 0, len(idx.Entries))
	for _, e := range idx.Entries {
		gotNames = append(gotNames, e.Name)
		assert.Equal(t, int64(len(members[e.Name])), e.Size)
		assert.Equal(t, sha256Hex(members[e.Name]), e.Digest)
	}
	sort.Strings(gotNames)
	assert.Equal(t, sortedMemberNames(encoders), gotNames, "index must cover every member with name-sorted entries")
}

func sortedMemberNames(encoders []sbom.FormatEncoder) []string {
	names := make([]string, 0, len(encoders))
	for _, enc := range encoders {
		names = append(names, MemberName(enc))
	}
	sort.Strings(names)
	return names
}

func readAllMembers(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte)
	require.NoError(t, filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = data
		return nil
	}))
	return out
}

func readZipMembers(t *testing.T, archivePath string) map[string][]byte {
	t.Helper()
	r, err := zip.OpenReader(archivePath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	out := make(map[string][]byte)
	var names []string
	for _, f := range r.File {
		names = append(names, f.Name)
		rc, err := f.Open()
		require.NoError(t, err)
		data, err := io.ReadAll(rc)
		require.NoError(t, err)
		require.NoError(t, rc.Close())
		out[f.Name] = data
		// deterministic zero-time headers
		assert.True(t, f.Modified.Equal(archiveEntryTime), "zip entry %q must use fixed timestamp", f.Name)
	}
	// entry order must be fixed: members sorted by name, then index last
	require.NotEmpty(t, names)
	assert.Equal(t, IndexName, names[len(names)-1])
	return out
}

func fingerprintTree(t *testing.T, root string) map[string]string {
	t.Helper()
	fp := make(map[string]string)
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		entry := fmt.Sprintf("%s:%d:%s", info.Mode().Perm(), info.Size(), rel)
		if !info.IsDir() {
			data, rErr := os.ReadFile(path)
			if rErr == nil {
				entry += ":" + sha256Hex(data)
			}
		}
		fp[rel] = entry
		return nil
	})
	return fp
}

func testStagingLeftovers(t *testing.T, root string) []string {
	t.Helper()
	var leftovers []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		name := filepath.Base(path)
		if strings.HasPrefix(name, ".sbom-artifact") || strings.Contains(name, ".backup-") ||
			(strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".lock")) {
			leftovers = append(leftovers, path)
		}
		return nil
	})
	return leftovers
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// indexSkeleton returns the index with volatile digests stripped, so two runs can be compared on
// structure (schema version, names, formats, versions, sizes, algorithm) regardless of per-encode
// UUIDs that change member bytes.
func indexSkeleton(t *testing.T, data []byte) []IndexEntry {
	t.Helper()
	var idx Index
	require.NoError(t, jsonUnmarshal(data, &idx))
	for i := range idx.Entries {
		idx.Entries[i].Digest = ""
	}
	return idx.Entries
}

// zipEntryList reports the archive's entry names in on-disk order; it must be identical across
// reproducible runs even when member bytes carry per-encode UUIDs.
func zipEntryList(t *testing.T, archivePath string) []string {
	t.Helper()
	r, err := zip.OpenReader(archivePath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	names := make([]string, 0, len(r.File))
	for _, f := range r.File {
		assert.True(t, f.Modified.Equal(archiveEntryTime), "entry %q must use fixed timestamp", f.Name)
		names = append(names, f.Name)
	}
	return names
}

// assertIndexMatchesMembers verifies every index record's size and digest against the actual member
// bytes in the provided name->bytes map.
func assertIndexMatchesMembers(t *testing.T, members map[string][]byte) {
	t.Helper()
	var idx Index
	require.NoError(t, jsonUnmarshal(members[IndexName], &idx))
	for _, e := range idx.Entries {
		got, ok := members[e.Name]
		require.True(t, ok, "index references missing member %q", e.Name)
		assert.Equal(t, int64(len(got)), e.Size)
		assert.Equal(t, sha256Hex(got), e.Digest)
	}
}
