package sbomartifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// indexSchemaVersion is the version of the index document layout produced by this package. It is
// independent of any SBOM format version and only changes when the index structure itself changes.
const indexSchemaVersion = 1

// Index is the catalog document emitted alongside the encoded SBOM members in directory and
// archive targets. It records only member-relative names — never host absolute paths — so an index
// can travel with its artifact across machines and pipelines.
type Index struct {
	// SchemaVersion is the version of this index document's structure.
	SchemaVersion int `json:"schemaVersion"`
	// Entries lists every encoded member, sorted by name.
	Entries []IndexEntry `json:"entries"`
}

// IndexEntry describes one encoded member of the artifact.
type IndexEntry struct {
	// Name is the member name relative to the artifact root; it matches the archive entry name.
	Name string `json:"name"`
	// Format is the SBOM format id used to encode the member (e.g. "spdx-json").
	Format string `json:"format"`
	// Version is the encoder's format version, or empty for single-version formats.
	Version string `json:"version"`
	// Size is the encoded member's length in bytes.
	Size int64 `json:"size"`
	// DigestAlgorithm names the hash algorithm used for Digest (currently always "sha256").
	DigestAlgorithm string `json:"digestAlgorithm"`
	// Digest is the hex-encoded content digest of the encoded member.
	Digest string `json:"digest"`
}

// newIndex builds an index from the staged member records and returns its canonical JSON bytes.
// Entries are sorted by name and the encoding is fixed (no HTML escaping, two-space indentation) so
// that the same manifest written twice yields byte-identical indexes.
func newIndex(records []memberRecord) ([]byte, Index, error) {
	entries := make([]IndexEntry, 0, len(records))
	for _, r := range records {
		entries = append(entries, IndexEntry{
			Name:            r.name,
			Format:          string(r.encoder.ID()),
			Version:         r.encoder.Version(),
			Size:            int64(len(r.contents)),
			DigestAlgorithm: "sha256",
			Digest:          sha256Hex(r.contents),
		})
	}
	return finalizeIndex(entries)
}

func finalizeIndex(entries []IndexEntry) ([]byte, Index, error) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

	idx := Index{SchemaVersion: indexSchemaVersion, Entries: entries}
	data, err := marshalIndex(idx)
	if err != nil {
		return nil, Index{}, err
	}
	return data, idx, nil
}

func marshalIndex(idx Index) ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(idx); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
