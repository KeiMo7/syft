// Package diff compares two SBOM documents and reports how their package sets differ.
//
// The diff layer is a side path: it consumes two already-serialized SBOM documents and never
// touches source resolution, cataloging, or SBOM assembly. Component identity is derived only
// from stable fields recorded in the documents (name, version, ecosystem, purl, and the
// location of the discovering manifest relative to the scan root) — never from generation
// timestamps, absolute host paths, or document ordering, so the same pair of documents always
// produces a byte-for-byte identical report.
package diff

import (
	"path"
	"sort"
	"strings"

	"github.com/anchore/packageurl-go"

	"github.com/anchore/syft/syft/pkg"
)

// Record is the minimal, stable identity of one package entry in an SBOM document. Everything
// needed to compare two documents and to trace a conclusion back to a concrete entry in the
// source document is here; the rest of the document is never retained.
type Record struct {
	// ID is the artifact identifier as recorded in the source document; it is the handle a
	// reviewer uses to locate this exact entry in the original SBOM.
	ID string

	Name    string
	Version string
	Type    string
	PURL    string
	FoundBy string

	// Locations are the normalized paths (relative to the scan root, sorted, deduplicated)
	// of the files that led to this package's discovery.
	Locations []string

	// Subproject locates the package within the scanned artifact: the directory of the
	// discovering manifest, relative to the scan root ("." for the root itself, "" when the
	// package has no recorded locations).
	Subproject string

	// nameKey and typeKey are the normalized identity fields. When the record carries a
	// parseable purl they are derived from it (so a component recorded as "pkg" in one
	// document and "@scope/pkg" in another still compares equal when both purls agree);
	// otherwise they fall back to the raw recorded values.
	nameKey string
	typeKey string
	hasPURL bool
}

// NewRecord builds a Record from raw document fields, deriving all normalized identity data.
func NewRecord(id, name, version, pkgType, purl, foundBy string, rawLocations []string) Record {
	r := Record{
		ID:        id,
		Name:      name,
		Version:   version,
		Type:      pkgType,
		PURL:      purl,
		FoundBy:   foundBy,
		Locations: normalizeLocations(rawLocations),
		nameKey:   name,
		typeKey:   pkgType,
	}
	r.Subproject = subprojectOf(r.Locations)

	if purl != "" {
		if u, err := packageurl.FromString(purl); err == nil {
			// Normalize applies the purl-spec canonicalization (lowercasing the type and any
			// type-specific case rules), which is a documented transformation, not a guess.
			_ = u.Normalize()
			r.typeKey = u.Type
			if u.Namespace != "" {
				r.nameKey = u.Namespace + "/" + u.Name
			} else {
				r.nameKey = u.Name
			}
			r.hasPURL = true
		}
	}
	return r
}

// RecordFromPackage builds a Record from an in-memory package (used when a document was
// decoded into a full SBOM rather than streamed).
func RecordFromPackage(p pkg.Package) Record {
	var locations []string
	for _, l := range p.Locations.ToSlice() {
		locations = append(locations, l.RealPath)
	}
	return NewRecord(string(p.ID()), p.Name, p.Version, string(p.Type), p.PURL, p.FoundBy, locations)
}

// exactKey identifies one immutable entry: the same component, same version, same subproject.
func (r Record) exactKey() string {
	return r.typeKey + "\x1f" + r.nameKey + "\x1f" + r.Version + "\x1f" + r.Subproject
}

// componentKey identifies a component regardless of version, within one subproject. Two
// entries sharing a componentKey but differing in version are a version change, not an
// addition plus a removal.
func (r Record) componentKey() string {
	return r.typeKey + "\x1f" + r.nameKey + "\x1f" + r.Subproject
}

// normalizeLocations cleans each recorded path and makes it relative to the scan root, so
// identity never depends on where the artifact was mounted when it was scanned. The result
// is sorted and deduplicated, so identity never depends on document ordering either.
func normalizeLocations(raw []string) []string {
	set := make(map[string]struct{}, len(raw))
	for _, p := range raw {
		if n := normalizePath(p); n != "" {
			set[n] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// normalizePath cleans a single recorded path and strips any leading root or drive prefix.
// Archive nesting chains ("outer.jar!/inner/path") are preserved; only the textual form is
// canonicalized.
func normalizePath(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	if p == "" {
		return ""
	}
	// clean the outermost path and each nested archive segment independently
	segments := strings.Split(p, "!/")
	for i, s := range segments {
		s = path.Clean("/" + strings.TrimPrefix(s, "/"))
		segments[i] = strings.TrimPrefix(s, "/")
	}
	return strings.Join(segments, "!/")
}

// subprojectOf derives the subproject locator from sorted normalized locations: the directory
// of the first (lexicographically smallest) discovering manifest, relative to the scan root.
func subprojectOf(locations []string) string {
	if len(locations) == 0 {
		return ""
	}
	outer, _, _ := strings.Cut(locations[0], "!/")
	dir := path.Dir(outer)
	if dir == "/" {
		return "."
	}
	return dir
}

// namesRelatedWithoutPURL reports whether two records whose normalized names differed might
// still be the same component recorded with and without a namespace (e.g. "pkg" versus
// "@scope/pkg"). This is only ever used to flag a pair as incomparable — never to merge
// entries, which would be guessing.
func namesRelatedWithoutPURL(a, b Record) bool {
	if a.hasPURL && b.hasPURL {
		// both purls parsed and still did not match: these are genuinely different components
		return false
	}
	// the raw recorded names may even be identical; what matters is that the normalized
	// identities differed and the raw names point at the same final name segment
	return lastNameSegment(a.Name) == lastNameSegment(b.Name)
}

func lastNameSegment(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}
