package incremental

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/file"
)

func inventoryFromResolver(
	ctx context.Context,
	resolver file.Resolver,
	referenceCoordinates coordinateInventory,
	unchangedLayers map[string]struct{},
) (inventory, []string, error) {
	inv := make(inventory)
	seen := make(map[file.Coordinates]struct{})
	warnings := make(map[string]struct{})

	for location := range resolver.AllLocations(ctx) {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if _, exists := seen[location.Coordinates]; exists {
			continue
		}
		seen[location.Coordinates] = struct{}{}

		metadata, err := resolver.FileMetadataByLocation(location)
		if err != nil {
			path := location.FullNestedPath()
			inv[path] = appendUniqueFingerprint(inv[path], fingerprint{kind: "unknown"})
			warnings[fmt.Sprintf("unable to read metadata for %q: %v", path, err)] = struct{}{}
			continue
		}

		path := location.FullNestedPath()
		fp, warning := currentFingerprint(resolver, location, metadata, referenceCoordinates, unchangedLayers)
		if warning != "" {
			warnings[warning] = struct{}{}
		}
		inv[path] = appendUniqueFingerprint(inv[path], fp)
	}

	for path := range inv {
		inv[path] = sortFingerprints(inv[path])
	}

	return inv, sortedSet(warnings), nil
}

func currentFingerprint(
	resolver file.Resolver,
	location file.Location,
	metadata file.Metadata,
	referenceCoordinates coordinateInventory,
	unchangedLayers map[string]struct{},
) (fingerprint, string) {
	path := location.FullNestedPath()

	if _, layerUnchanged := unchangedLayers[location.FileSystemID]; layerUnchanged && location.FileSystemID != "" {
		if reference, exists := referenceCoordinates[location.Coordinates]; exists && reference.valid() {
			return reference, ""
		}
	}

	switch metadata.Type {
	case stereoscopeFile.TypeDirectory:
		return fingerprint{kind: "directory"}, ""
	case stereoscopeFile.TypeSymLink, stereoscopeFile.TypeHardLink:
		if metadata.LinkDestination == "" {
			return fingerprint{kind: "unknown"}, fmt.Sprintf("link target is unavailable for %q", path)
		}
		return fingerprint{kind: "link", link: metadata.LinkDestination}, ""
	case stereoscopeFile.TypeRegular:
		reader, err := resolver.FileContentsByLocation(location)
		if err != nil {
			return fingerprint{kind: "unknown"}, fmt.Sprintf("unable to read %q for change detection: %v", path, err)
		}
		defer internal.CloseAndLogError(reader, path)

		hasher := sha256.New()
		if _, err := io.Copy(hasher, reader); err != nil {
			return fingerprint{kind: "unknown"}, fmt.Sprintf("unable to hash %q: %v", path, err)
		}
		return fingerprint{kind: "regular", digest: fmt.Sprintf("%x", hasher.Sum(nil))}, ""
	default:
		return fingerprint{kind: "other", link: metadata.Type.String()}, ""
	}
}
