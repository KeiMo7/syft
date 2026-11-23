package identity

import (
	"reflect"
	"sort"
	"strings"

	"github.com/anchore/syft/internal/packagemetadata"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// RecordFromPackage converts a cataloger finding into the flat form the identity engine operates
// on. All evidence that could distinguish or join records is carried across: locations, licenses,
// checksums extracted from the metadata payload, and external identifiers (purl, CPEs).
func RecordFromPackage(p pkg.Package) Record {
	record := Record{
		ID:           string(p.ID()),
		Name:         p.Name,
		Version:      p.Version,
		Type:         p.Type,
		PURL:         p.PURL,
		FoundBy:      p.FoundBy,
		MetadataType: metadataTypeName(p.Metadata),
		Locations:    locationsFromSet(p.Locations),
		Licenses:     licensesFromSet(p.Licenses),
		Checksums:    checksumsFromMetadata(p.Metadata, p.FoundBy),
	}
	if p.PURL != "" {
		record.ExternalIDs = append(record.ExternalIDs, ExternalID{Type: "purl", Value: p.PURL, Source: "package-url"})
	}
	for _, c := range p.CPEs {
		record.ExternalIDs = append(record.ExternalIDs, ExternalID{
			Type:   "cpe",
			Value:  c.Attributes.BindToFmtString(),
			Source: c.Source.String(),
		})
	}
	return record
}

// RecordsFromPackages converts every package in the given slice.
func RecordsFromPackages(packages []pkg.Package) []Record {
	records := make([]Record, 0, len(packages))
	for _, p := range packages {
		records = append(records, RecordFromPackage(p))
	}
	return records
}

// MetadataTypeName returns the JSON type name of a metadata payload, or "" when there is none.
func MetadataTypeName(metadata any) string {
	if metadata == nil {
		return ""
	}
	return packagemetadata.JSONName(metadata)
}

func metadataTypeName(metadata any) string {
	if metadata == nil {
		return ""
	}
	return packagemetadata.JSONName(metadata)
}

func locationsFromSet(set file.LocationSet) []Location {
	locations := set.ToSlice()
	out := make([]Location, 0, len(locations))
	for _, l := range locations {
		out = append(out, Location{
			Path:       l.FullNestedPath(),
			RealPath:   l.RealPath,
			AccessPath: l.AccessPath,
			LayerID:    l.FileSystemID,
			Evidence:   l.Annotations[pkg.EvidenceAnnotationKey],
		})
	}
	return out
}

func licensesFromSet(set pkg.LicenseSet) []License {
	licenses := set.ToSlice()
	out := make([]License, 0, len(licenses))
	for _, l := range licenses {
		out = append(out, License{
			Value:          l.Value,
			SPDXExpression: l.SPDXExpression,
			Type:           string(l.Type),
			URLs:           sortedUnique(l.URLs),
			Locations:      locationsFromSet(l.Locations),
		})
	}
	return out
}

// checksumFieldNames are the metadata field names that carry a content hash in the syft package
// model. They are matched case-sensitively because the field names are part of the model.
var checksumFieldNames = map[string]struct{}{
	"Checksum":       {},
	"Integrity":      {},
	"H1Digest":       {},
	"PkgHash":        {},
	"PkgHashExt":     {},
	"MetadataHash":   {},
	"Checksums":      {},
	"Digest":         {},
	"Digests":        {},
	"ArchiveDigests": {},
}

// checksumsFromMetadata extracts every content digest from a metadata payload, tagging each with
// the cataloger that supplied it. The output is sorted so the result does not depend on field order.
func checksumsFromMetadata(metadata any, source string) []Checksum {
	if metadata == nil {
		return nil
	}

	var out []Checksum
	collectChecksums(reflect.ValueOf(metadata), source, &out, map[reflect.Type]bool{}, 0)
	return dedupeChecksums(out)
}

const maxChecksumDepth = 4

func collectChecksums(v reflect.Value, source string, out *[]Checksum, visited map[reflect.Type]bool, depth int) {
	if depth > maxChecksumDepth || !v.IsValid() {
		return
	}

	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return
		}
		collectChecksums(v.Elem(), source, out, visited, depth+1)
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			collectChecksums(v.Index(i), source, out, visited, depth+1)
		}
	case reflect.String:
		// handled by the caller, which knows the field name
	case reflect.Struct:
		typ := v.Type()
		if typ.PkgPath() != "" && !strings.HasPrefix(typ.PkgPath(), "github.com/anchore/syft/") {
			// a third-party digest-shaped struct (e.g. file.Digest) is handled by name below
			collectDigestStruct(v, source, out)
			return
		}
		if visited[typ] {
			return
		}
		visited[typ] = true
		for i := 0; i < v.NumField(); i++ {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			value := v.Field(i)
			if _, ok := checksumFieldNames[field.Name]; ok {
				collectChecksumValue(value, source, out, depth+1)
				continue
			}
			// digest-shaped structs are reached by their field name above; other nested metadata
			// structs are not descended into to keep the walk bounded.
		}
	}
}

func collectChecksumValue(v reflect.Value, source string, out *[]Checksum, depth int) {
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		collectChecksumValue(v.Elem(), source, out, depth)
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			collectChecksumValue(v.Index(i), source, out, depth+1)
		}
	case reflect.String:
		if s := strings.TrimSpace(v.String()); s != "" {
			algorithm := algorithmFromValue(s)
			*out = append(*out, Checksum{Algorithm: algorithm, Value: s, Source: source})
		}
	case reflect.Struct:
		collectDigestStruct(v, source, out)
	}
}

// collectDigestStruct handles the file.Digest / pkg.PythonFileDigest shape: a struct with
// Algorithm and Value fields. If the shape does not match, nothing is recorded.
func collectDigestStruct(v reflect.Value, source string, out *[]Checksum) {
	typ := v.Type()
	algorithm := v.FieldByName("Algorithm")
	value := v.FieldByName("Value")
	if !algorithm.IsValid() || !value.IsValid() || algorithm.Kind() != reflect.String || value.Kind() != reflect.String {
		return
	}
	if value.String() == "" {
		return
	}
	_ = typ
	*out = append(*out, Checksum{
		Algorithm: algorithm.String(),
		Value:     value.String(),
		Source:    source,
	})
}

// algorithmFromValue infers the algorithm of a bare digest string from its shape. SRI values carry
// an explicit prefix; hex digests are classified by length; anything else is left "unknown".
func algorithmFromValue(value string) string {
	if prefix, _, ok := strings.Cut(value, "-"); ok {
		switch prefix {
		case "sha512", "sha384", "sha256", "sha1", "md5":
			return prefix
		}
	}
	if strings.HasPrefix(value, "h1:") {
		return "sha256"
	}
	trimmed := strings.TrimPrefix(strings.TrimPrefix(value, "sha256:"), "sha512:")
	switch len(trimmed) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	case 96:
		return "sha384"
	case 128:
		return "sha512"
	}
	return "unknown"
}

func dedupeChecksums(in []Checksum) []Checksum {
	seen := map[string]Checksum{}
	for _, c := range in {
		seen[c.Algorithm+"\x00"+c.Value+"\x00"+c.Source] = c
	}
	out := make([]Checksum, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Algorithm != out[j].Algorithm {
			return out[i].Algorithm < out[j].Algorithm
		}
		if out[i].Value != out[j].Value {
			return out[i].Value < out[j].Value
		}
		return out[i].Source < out[j].Source
	})
	return out
}

// FormatIdentity renders a component identity for logs and the summary table.
func FormatIdentity(typeName, namespace, name, version string) string {
	parts := []string{typeName}
	if namespace != "" {
		parts = append(parts, "@"+namespace)
	}
	parts = append(parts, name)
	if version != "" {
		parts = append(parts, version)
	}
	return strings.Join(parts, "/")
}

// ComponentFromRecord is a convenience for callers that want the single-record output shape.
func ComponentFromRecord(record Record) MergedComponent {
	return Merge([]Record{record}, DefaultOptions()).Components[0]
}
