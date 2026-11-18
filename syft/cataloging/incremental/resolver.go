package incremental

import (
	"context"
	"io"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

// Resolver returns a resolver that exposes only changed paths to cataloger
// discovery APIs. Explicit path lookups, relative lookups, metadata, and content
// reads are left intact: catalogers often need unchanged sibling files to parse
// a changed manifest correctly.
func Resolver(delegate file.Resolver, changed map[string]struct{}) file.Resolver {
	if delegate == nil {
		return delegate
	}
	return &filteredResolver{
		delegate: delegate,
		changed:  changed,
	}
}

type filteredResolver struct {
	delegate file.Resolver
	changed  map[string]struct{}
}

var _ file.Resolver = (*filteredResolver)(nil)

func (r *filteredResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	return r.delegate.FileContentsByLocation(location)
}

func (r *filteredResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	return r.delegate.FileMetadataByLocation(location)
}

func (r *filteredResolver) HasPath(path string) bool {
	return r.delegate.HasPath(path)
}

func (r *filteredResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	return r.delegate.FilesByPath(paths...)
}

func (r *filteredResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	locations, err := r.delegate.FilesByGlob(patterns...)
	return r.filterLocations(locations), err
}

func (r *filteredResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	locations, err := r.delegate.FilesByMIMEType(types...)
	return r.filterLocations(locations), err
}

func (r *filteredResolver) RelativeFileByPath(location file.Location, path string) *file.Location {
	return r.delegate.RelativeFileByPath(location, path)
}

func (r *filteredResolver) AllLocations(ctx context.Context) <-chan file.Location {
	out := make(chan file.Location)
	go func() {
		defer close(out)
		for location := range r.delegate.AllLocations(ctx) {
			if !r.allowed(location) {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case out <- location:
			}
		}
	}()
	return out
}

func (r *filteredResolver) filterLocations(locations []file.Location) []file.Location {
	filtered := locations[:0]
	for _, location := range locations {
		if r.allowed(location) {
			filtered = append(filtered, location)
		}
	}
	return filtered
}

func (r *filteredResolver) allowed(location file.Location) bool {
	for _, path := range []string{location.FullNestedPath(), location.AccessPath, location.LocalPath()} {
		if path == "" {
			continue
		}
		if _, exists := r.changed[path]; exists {
			return true
		}
		for changedPath := range r.changed {
			if strings.HasPrefix(changedPath, path+file.ArchivePathSeparator) ||
				strings.HasPrefix(path, changedPath+file.ArchivePathSeparator) {
				return true
			}
		}
	}
	return false
}

// Source returns a source that uses the provided resolver. It is intended for
// running the normal catalog pipeline against the changed-path resolver.
func Source(original source.Source, resolver file.Resolver) source.Source {
	return &resolverSource{
		Source:   original,
		resolver: resolver,
	}
}

type resolverSource struct {
	source.Source
	resolver file.Resolver
}

func (s *resolverSource) FileResolver(_ source.Scope) (file.Resolver, error) {
	return s.resolver, nil
}

func (s *resolverSource) Close() error {
	return nil
}

// ExcludedPaths preserves source exclusion behavior when the resolver source
// wrapper is passed through the normal catalog pipeline.
func (s *resolverSource) ExcludedPaths() []string {
	if excluder, ok := s.Source.(source.PathExcluder); ok {
		return excluder.ExcludedPaths()
	}
	return nil
}
