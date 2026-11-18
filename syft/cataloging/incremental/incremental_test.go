package incremental

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func TestSameImageDifferentTagReusesAllPackages(t *testing.T) {
	layers := []source.LayerMetadata{layer("sha256:l1"), layer("sha256:l2")}
	files := map[string]testFile{
		"/app/base.txt": {content: "base", layer: "sha256:l1"},
		"/lib/leftpad.json": {
			content: "pkg=leftpad@1.0.0\n",
			layer:   "sha256:l2",
		},
	}
	baselineDesc := imageDescription("sha256:image", "registry.example/app:old", "sha256:manifest", layers)
	currentDesc := imageDescription("sha256:image", "registry.example/app:new", "sha256:manifest", layers)

	baseline := catalogTestSource(t, newMemoryResolver(files), baselineDesc)
	resolver := newMemoryResolver(files)
	plan, err := Analyze(context.Background(), baseline, currentDesc, resolver, Options{})
	require.NoError(t, err)
	assert.Equal(t, ModeIncremental, plan.Mode)
	assert.Empty(t, plan.ChangedPaths)

	current := catalogTestSource(t, Resolver(resolver, plan.ChangedPathSet()), currentDesc)
	merged := Merge(baseline, current, plan)
	require.Equal(t, ModeIncremental, merged.Stats.Mode)
	assert.False(t, merged.Stats.FallbackRequired)
	assert.Equal(t, 1, merged.Stats.ReusedPackages)
	assert.Equal(t, 1.0, merged.Stats.ReuseRatio)

	full := catalogTestSource(t, resolver, currentDesc)
	assert.Equal(t, packageIDs(full), packageIDs(merged.SBOM))
	assertPackageOrigin(t, merged.SBOM, "leftpad", OriginReused)
}

func TestLayerAddRemoveAndReplace(t *testing.T) {
	baseLayers := []source.LayerMetadata{layer("sha256:l1"), layer("sha256:l2")}
	baseFiles := map[string]testFile{
		"/app/base.txt": {content: "base", layer: "sha256:l1"},
		"/lib/base.json": {
			content: "pkg=base@1.0.0\n",
			layer:   "sha256:l2",
		},
	}

	t.Run("added layer", func(t *testing.T) {
		currentLayers := append(append([]source.LayerMetadata{}, baseLayers...), layer("sha256:l3"))
		currentFiles := cloneFiles(baseFiles)
		currentFiles["/lib/added.json"] = testFile{content: "pkg=added@2.0.0\n", layer: "sha256:l3"}

		plan, merged, full := runIncremental(t, baseFiles, baseLayers, currentFiles, currentLayers)
		assert.Equal(t, []string{"/lib/added.json"}, plan.ChangedPaths)
		assert.Contains(t, plan.LayerChanges, LayerChange{Kind: LayerAdded, Index: 2, Current: "sha256:l3"})
		assert.Equal(t, packageIDs(full), packageIDs(merged.SBOM))
		assert.Equal(t, 1, merged.Stats.ReusedPackages)
	})

	t.Run("removed layer", func(t *testing.T) {
		baselineFiles := cloneFiles(baseFiles)
		baselineFiles["/lib/removed.json"] = testFile{content: "pkg=removed@3.0.0\n", layer: "sha256:l3"}
		baselineLayers := append(append([]source.LayerMetadata{}, baseLayers...), layer("sha256:l3"))

		plan, merged, full := runIncremental(t, baselineFiles, baselineLayers, baseFiles, baseLayers)
		assert.Equal(t, []string{"/lib/removed.json"}, plan.ChangedPaths)
		assert.Contains(t, plan.LayerChanges, LayerChange{Kind: LayerRemoved, Index: 2, Previous: "sha256:l3"})
		assert.Equal(t, packageIDs(full), packageIDs(merged.SBOM))
		assert.Equal(t, 1, merged.Stats.ReusedPackages)
	})

	t.Run("replaced layer", func(t *testing.T) {
		currentLayers := []source.LayerMetadata{layer("sha256:l1"), layer("sha256:l2-replaced")}
		currentFiles := cloneFiles(baseFiles)
		currentFiles["/lib/base.json"] = testFile{content: "pkg=base@2.0.0\n", layer: "sha256:l2-replaced"}

		plan, merged, full := runIncremental(t, baseFiles, baseLayers, currentFiles, currentLayers)
		assert.Equal(t, []string{"/lib/base.json"}, plan.ChangedPaths)
		assert.Contains(t, plan.LayerChanges, LayerChange{
			Kind:     LayerReplaced,
			Index:    1,
			Previous: "sha256:l2",
			Current:  "sha256:l2-replaced",
		})
		assert.Equal(t, packageIDs(full), packageIDs(merged.SBOM))
	})
}

func TestPathChangeKeepsPackageVersionStable(t *testing.T) {
	layers := []source.LayerMetadata{layer("sha256:l1"), layer("sha256:l2")}
	baselineFiles := map[string]testFile{
		"/app/base.txt": {content: "base", layer: "sha256:l1"},
		"/lib/stable.json": {
			content: "pkg=stable@1.2.3\nchannel=old\n",
			layer:   "sha256:l2",
		},
	}
	currentFiles := cloneFiles(baselineFiles)
	currentFiles["/lib/stable.json"] = testFile{
		content: "pkg=stable@1.2.3\nchannel=new\n",
		layer:   "sha256:l2-changed",
	}
	currentLayers := []source.LayerMetadata{layer("sha256:l1"), layer("sha256:l2-changed")}

	plan, merged, full := runIncremental(t, baselineFiles, layers, currentFiles, currentLayers)
	assert.Equal(t, []string{"/lib/stable.json"}, plan.ChangedPaths)
	assert.Equal(t, packageSignatures(full), packageSignatures(merged.SBOM))

	baseline := catalogTestSource(t, newMemoryResolver(baselineFiles), imageDescription("sha256:image", "tag", "sha256:manifest", layers))
	baselineIDs := packageIDs(baseline)
	require.Len(t, baselineIDs, 1)
	assert.Equal(t, baselineIDs, packageIDs(merged.SBOM))
}

func TestReferenceAnomaliesFallBackToFull(t *testing.T) {
	layers := []source.LayerMetadata{layer("sha256:l1")}
	files := map[string]testFile{"/app/base.txt": {content: "base", layer: "sha256:l1"}}
	current := imageDescription("sha256:current", "tag", "sha256:manifest-current", layers)

	t.Run("missing reference", func(t *testing.T) {
		plan, err := Analyze(context.Background(), nil, current, newMemoryResolver(files), Options{})
		require.NoError(t, err)
		assert.Equal(t, ModeFull, plan.Mode)
		assert.Contains(t, plan.Reason, "missing")

		_, err = LoadBaseline(filepath.Join(t.TempDir(), "missing.syft.json"))
		assert.ErrorIs(t, err, ErrBaselineMissing)
	})

	t.Run("corrupt reference", func(t *testing.T) {
		_, err := DecodeBaseline(strings.NewReader(`{"artifacts":`))
		assert.ErrorIs(t, err, ErrBaselineCorrupt)
	})

	t.Run("different image", func(t *testing.T) {
		otherImage := imageDescription("sha256:other", "tag", "sha256:manifest-other", layers)
		otherImage.Name = "registry.example/other"
		baseline := catalogTestSource(
			t,
			newMemoryResolver(files),
			otherImage,
		)
		plan, err := Analyze(context.Background(), baseline, current, newMemoryResolver(files), Options{})
		require.NoError(t, err)
		assert.Equal(t, ModeFull, plan.Mode)
		assert.Contains(t, plan.Reason, "different image")
	})

	t.Run("unknown schema version", func(t *testing.T) {
		baseline := catalogTestSource(
			t,
			newMemoryResolver(files),
			imageDescription("sha256:current", "tag", "sha256:manifest-current", layers),
		)
		encoded := encodeTestSBOM(t, baseline)
		encoded = bytes.Replace(encoded, []byte(`"version":"16.1.13"`), []byte(`"version":"999.0.0"`), 1)

		_, err := DecodeBaseline(bytes.NewReader(encoded))
		assert.ErrorIs(t, err, ErrUnsupportedBaseline)
	})
}

func TestSourceOverrideAllowsRewrittenManifest(t *testing.T) {
	layers := []source.LayerMetadata{layer("sha256:l1")}
	files := map[string]testFile{"/lib/base.json": {content: "pkg=base@1.0.0\n", layer: "sha256:l1"}}
	baselineDesc := imageDescription("sha256:image-a", "tag-a", "sha256:manifest-a", layers)
	currentDesc := imageDescription("sha256:image-b", "tag-b", "sha256:manifest-b", layers)
	currentDesc.Name = "registry.example/other"
	baseline := catalogTestSource(t, newMemoryResolver(files), baselineDesc)

	plan, err := Analyze(context.Background(), baseline, currentDesc, newMemoryResolver(files), Options{})
	require.NoError(t, err)
	assert.Equal(t, ModeFull, plan.Mode)

	plan, err = Analyze(context.Background(), baseline, currentDesc, newMemoryResolver(files), Options{
		SourceOverride: func(_, _ source.Description) (bool, bool) {
			return true, true
		},
	})
	require.NoError(t, err)
	assert.Equal(t, ModeIncremental, plan.Mode)
	assert.Empty(t, plan.ChangedPaths)

	plan, err = Analyze(context.Background(), baseline, currentDesc, newMemoryResolver(files), Config{
		AllowDifferentSource: true,
	}.Options())
	require.NoError(t, err)
	assert.Equal(t, ModeIncremental, plan.Mode)
}

func TestMergeFallsBackWhenChangedPathIsNotReparsed(t *testing.T) {
	layers := []source.LayerMetadata{layer("sha256:l1")}
	baselineFiles := map[string]testFile{
		"/lib/base.json": {content: "pkg=base@1.0.0\n", layer: "sha256:l1"},
	}
	currentFiles := map[string]testFile{
		"/lib/base.json": {content: "no-package-here\n", layer: "sha256:l1-changed"},
	}
	desc := imageDescription("sha256:image", "tag", "sha256:manifest", layers)
	baseline := catalogTestSource(t, newMemoryResolver(baselineFiles), desc)

	resolver := newMemoryResolver(currentFiles)
	currentDesc := imageDescription("sha256:image", "tag", "sha256:manifest", []source.LayerMetadata{layer("sha256:l1-changed")})
	plan, err := Analyze(context.Background(), baseline, currentDesc, resolver, Options{})
	require.NoError(t, err)
	current := catalogTestSource(t, Resolver(resolver, plan.ChangedPathSet()), desc)

	merged := Merge(baseline, current, plan)
	assert.True(t, merged.Stats.FallbackRequired)
	assert.Contains(t, merged.Reason, "not rediscovered")
}

func TestProvenanceDistinguishesCurrentAndReusedPackages(t *testing.T) {
	layers := []source.LayerMetadata{layer("sha256:l1")}
	baselineFiles := map[string]testFile{
		"/lib/reused.json": {content: "pkg=reused@1.0.0\n", layer: "sha256:l1"},
	}
	currentFiles := cloneFiles(baselineFiles)
	currentFiles["/lib/current.json"] = testFile{content: "pkg=current@1.0.0\n", layer: "sha256:l1"}
	desc := imageDescription("sha256:image", "tag", "sha256:manifest", layers)
	baseline := catalogTestSource(t, newMemoryResolver(baselineFiles), desc)

	resolver := newMemoryResolver(currentFiles)
	plan, err := Analyze(context.Background(), baseline, desc, resolver, Options{})
	require.NoError(t, err)
	current := catalogTestSource(t, Resolver(resolver, plan.ChangedPathSet()), desc)
	merged := Merge(baseline, current, plan)

	require.False(t, merged.Stats.FallbackRequired)
	assertPackageOrigin(t, merged.SBOM, "reused", OriginReused)
	assertPackageOrigin(t, merged.SBOM, "current", OriginCurrent)
}

func TestBaselineAtomicWriteAndReload(t *testing.T) {
	layers := []source.LayerMetadata{layer("sha256:l1")}
	files := map[string]testFile{"/lib/base.json": {content: "pkg=base@1.0.0\n", layer: "sha256:l1"}}
	desc := imageDescription("sha256:image", "tag", "sha256:manifest", layers)
	document := catalogTestSource(t, newMemoryResolver(files), desc)

	path := filepath.Join(t.TempDir(), "baseline.syft.json")
	require.NoError(t, WriteAtomic(path, document))

	loaded, err := LoadBaseline(path)
	require.NoError(t, err)
	assert.Equal(t, packageIDs(document), packageIDs(loaded.SBOM))
}

func TestCheckpointIsNotAcceptedAsCompleteBaseline(t *testing.T) {
	layers := []source.LayerMetadata{layer("sha256:l1")}
	files := map[string]testFile{"/lib/base.json": {content: "pkg=base@1.0.0\n", layer: "sha256:l1"}}
	desc := imageDescription("sha256:image", "tag", "sha256:manifest", layers)
	document := catalogTestSource(t, newMemoryResolver(files), desc)

	path := filepath.Join(t.TempDir(), "checkpoint.syft.json")
	require.NoError(t, WriteCheckpointAtomic(path, document, false, []string{"/lib/base.json"}))

	_, err := LoadBaseline(path)
	assert.ErrorIs(t, err, ErrBaselineIncomplete)

	checkpoint, err := LoadCheckpoint(path)
	require.NoError(t, err)
	assert.False(t, checkpoint.Complete)
	assert.Equal(t, packageIDs(document), packageIDs(checkpoint.SBOM))

	require.NoError(t, WriteCheckpointAtomic(path, document, true, nil))
	complete, err := LoadBaseline(path)
	require.NoError(t, err)
	assert.True(t, complete.Complete)
}

type testFile struct {
	content string
	layer   string
	kind    stereoscopeFile.Type
	link    string
}

type memoryResolver struct {
	files map[string]testFile
	paths []string
}

func newMemoryResolver(files map[string]testFile) *memoryResolver {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return &memoryResolver{files: files, paths: paths}
}

func (r *memoryResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	f, exists := r.files[location.FullNestedPath()]
	if !exists {
		return nil, fmt.Errorf("no file for %q", location.FullNestedPath())
	}
	return io.NopCloser(strings.NewReader(f.content)), nil
}

func (r *memoryResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	f, exists := r.files[location.FullNestedPath()]
	if !exists {
		return file.Metadata{}, fmt.Errorf("no file for %q", location.FullNestedPath())
	}
	kind := f.kind
	if kind == 0 {
		kind = stereoscopeFile.TypeRegular
	}
	return file.Metadata{Type: kind, LinkDestination: f.link}, nil
}

func (r *memoryResolver) HasPath(path string) bool {
	_, exists := r.files[path]
	return exists
}

func (r *memoryResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	var out []file.Location
	for _, path := range paths {
		if _, exists := r.files[path]; exists {
			out = append(out, r.location(path))
		}
	}
	return out, nil
}

func (r *memoryResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	var out []file.Location
	for _, path := range r.paths {
		for _, pattern := range patterns {
			matches, err := doublestar.Match(pattern, path)
			if err != nil {
				return nil, err
			}
			if matches {
				out = append(out, r.location(path))
				break
			}
		}
	}
	return out, nil
}

func (r *memoryResolver) FilesByMIMEType(_ ...string) ([]file.Location, error) {
	return nil, nil
}

func (r *memoryResolver) RelativeFileByPath(location file.Location, path string) *file.Location {
	fullPath := path
	if !strings.HasPrefix(fullPath, "/") {
		fullPath = strings.TrimSuffix(location.RealPath, "/") + "/" + path
	}
	if _, exists := r.files[fullPath]; !exists {
		return nil
	}
	loc := r.location(fullPath)
	return &loc
}

func (r *memoryResolver) AllLocations(ctx context.Context) <-chan file.Location {
	out := make(chan file.Location)
	go func() {
		defer close(out)
		for _, path := range r.paths {
			select {
			case <-ctx.Done():
				return
			case out <- r.location(path):
			}
		}
	}()
	return out
}

func (r *memoryResolver) location(path string) file.Location {
	coordinates := file.NewCoordinates(path, r.files[path].layer)
	return file.NewVirtualLocationFromCoordinates(coordinates, path)
}

func runIncremental(
	t *testing.T,
	baselineFiles map[string]testFile,
	baselineLayers []source.LayerMetadata,
	currentFiles map[string]testFile,
	currentLayers []source.LayerMetadata,
) (Plan, MergeResult, *sbom.SBOM) {
	t.Helper()
	baselineDesc := imageDescription("sha256:image-old", "old", "sha256:manifest-old", baselineLayers)
	currentDesc := imageDescription("sha256:image-new", "new", "sha256:manifest-new", currentLayers)
	baseline := catalogTestSource(t, newMemoryResolver(baselineFiles), baselineDesc)
	resolver := newMemoryResolver(currentFiles)

	plan, err := Analyze(context.Background(), baseline, currentDesc, resolver, Options{})
	require.NoError(t, err)
	require.Equal(t, ModeIncremental, plan.Mode)

	current := catalogTestSource(t, Resolver(resolver, plan.ChangedPathSet()), currentDesc)
	merged := Merge(baseline, current, plan)
	require.False(t, merged.Stats.FallbackRequired, merged.Reason)

	full := catalogTestSource(t, resolver, currentDesc)
	return plan, merged, full
}

func catalogTestSource(t *testing.T, resolver file.Resolver, description source.Description) *sbom.SBOM {
	t.Helper()
	document := &sbom.SBOM{
		Source: description,
		Descriptor: sbom.Descriptor{
			Name:    "syft-test",
			Version: "1.0.0",
		},
		Artifacts: sbom.Artifacts{
			Packages:     pkg.NewCollection(),
			FileMetadata: make(map[file.Coordinates]file.Metadata),
			FileDigests:  make(map[file.Coordinates][]file.Digest),
		},
	}

	ctx := context.Background()
	for location := range resolver.AllLocations(ctx) {
		metadata, err := resolver.FileMetadataByLocation(location)
		require.NoError(t, err)
		document.Artifacts.FileMetadata[location.Coordinates] = metadata

		reader, err := resolver.FileContentsByLocation(location)
		require.NoError(t, err)
		content, err := io.ReadAll(reader)
		require.NoError(t, err)
		require.NoError(t, reader.Close())
		sum := sha256.Sum256(content)
		document.Artifacts.FileDigests[location.Coordinates] = []file.Digest{{
			Algorithm: "sha256",
			Value:     fmt.Sprintf("%x", sum),
		}}

		name, version, found := parseTestPackage(string(content))
		if !found {
			continue
		}
		p := pkg.Package{
			Name:      name,
			Version:   version,
			Type:      pkg.NpmPkg,
			FoundBy:   "test-cataloger",
			Locations: file.NewLocationSet(location),
		}
		p.SetID()
		document.Artifacts.Packages.Add(p)
		document.Relationships = append(document.Relationships, artifact.Relationship{
			From: p,
			To:   location.Coordinates,
			Type: artifact.ContainsRelationship,
		})
	}

	return document
}

func parseTestPackage(content string) (name, version string, found bool) {
	for _, line := range strings.Split(content, "\n") {
		if !strings.HasPrefix(line, "pkg=") {
			continue
		}
		value := strings.TrimPrefix(line, "pkg=")
		parts := strings.SplitN(value, "@", 2)
		if len(parts) != 2 {
			return "", "", false
		}
		return parts[0], parts[1], true
	}
	return "", "", false
}

func imageDescription(id, tag, manifest string, layers []source.LayerMetadata) source.Description {
	return source.Description{
		ID:      id,
		Name:    "registry.example/app",
		Version: tag,
		Metadata: source.ImageMetadata{
			ID:             id,
			ManifestDigest: manifest,
			Tags:           []string{tag},
			Layers:         layers,
		},
	}
}

func layer(digest string) source.LayerMetadata {
	return source.LayerMetadata{Digest: digest}
}

func cloneFiles(files map[string]testFile) map[string]testFile {
	out := make(map[string]testFile, len(files))
	for path, value := range files {
		out[path] = value
	}
	return out
}

func packageIDs(document *sbom.SBOM) []string {
	var ids []string
	for p := range document.Artifacts.Packages.Enumerate() {
		ids = append(ids, string(p.ID()))
	}
	sort.Strings(ids)
	return ids
}

func packageSignatures(document *sbom.SBOM) []string {
	var signatures []string
	for p := range document.Artifacts.Packages.Enumerate() {
		signatures = append(signatures, fmt.Sprintf("%s@%s:%s", p.Name, p.Version, p.Type))
	}
	sort.Strings(signatures)
	return signatures
}

func assertPackageOrigin(t *testing.T, document *sbom.SBOM, packageName, expected string) {
	t.Helper()
	for p := range document.Artifacts.Packages.Enumerate() {
		if p.Name != packageName {
			continue
		}
		locations := p.Locations.ToSlice()
		require.NotEmpty(t, locations)
		assert.Equal(t, expected, locations[0].Annotations[OriginAnnotationKey])
		return
	}
	t.Fatalf("package %q not found", packageName)
}

func encodeTestSBOM(t *testing.T, document *sbom.SBOM) []byte {
	t.Helper()
	var buffer bytes.Buffer
	encoder, err := syftjson.NewFormatEncoderWithConfig(syftjson.EncoderConfig{})
	require.NoError(t, err)
	require.NoError(t, encoder.Encode(&buffer, *document))
	return buffer.Bytes()
}
