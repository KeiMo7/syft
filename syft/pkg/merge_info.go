package pkg

import "encoding/json"

// MergeConflict records a field whose values disagreed across the source records that were folded
// into one package entry. Values always holds every distinct value that was found; Resolution says
// whether all of them were kept, one was selected by a documented rule, or the conflict is
// unresolved and left for a reviewer.
type MergeConflict struct {
	// Field is the package field that conflicted (e.g. "version", "checksum:sha256").
	Field string `json:"field"`

	// Values holds every distinct value, sorted.
	Values []string `json:"values"`

	// Resolution is one of "kept-both", "selected-deterministically" or "unresolved".
	Resolution string `json:"resolution"`

	// Rule is the identity rule that explains the conflict.
	Rule string `json:"rule,omitempty"`

	// Note is a human-readable explanation for a reviewer.
	Note string `json:"note,omitempty"`
}

// MergeChecksum is a content digest retained from a merged source record. The package model has no
// top-level checksum field, so merged digests live here rather than being dropped.
type MergeChecksum struct {
	// Algorithm is the hash algorithm (e.g. "sha256").
	Algorithm string `json:"algorithm"`

	// Value is the digest string.
	Value string `json:"value"`

	// Source is the clue that supplied the digest (usually a cataloger name).
	Source string `json:"source,omitempty"`
}

// MergeExternalID is an identifier supplied by another system (purl, CPE, ...) retained from a
// merged source record.
type MergeExternalID struct {
	// Type is the identifier family (e.g. "purl", "cpe").
	Type string `json:"type"`

	// Value is the identifier.
	Value string `json:"value"`

	// Source is the clue that supplied the identifier.
	Source string `json:"source,omitempty"`
}

// MergeMetadata retains a source record's metadata payload when several records were folded into
// one entry, so the representative metadata field does not become the only surviving payload.
type MergeMetadata struct {
	// Type is the metadata JSON type name.
	Type string `json:"type"`

	// Payload is the original metadata payload.
	Payload json.RawMessage `json:"payload"`
}

// MergeInfo records why a package entry looks the way it does after identity merging. It is
// additive: consumers that do not know the field ignore it, and it is not part of the package ID.
type MergeInfo struct {
	// State is "merged", "needs-confirmation" or "unique".
	State string `json:"state"`

	// Identity is the normalized identity the entry was grouped under.
	Identity string `json:"identity"`

	// Namespace is the normalized namespace prefix, if any.
	Namespace string `json:"namespace,omitempty"`

	// Versions holds every raw version spelling that was folded together.
	Versions []string `json:"versions,omitempty"`

	// Sources holds every cataloger that contributed evidence, sorted.
	Sources []string `json:"sources,omitempty"`

	// Rules lists the identity rules that were applied, sorted.
	Rules []string `json:"rules,omitempty"`

	// Members holds the IDs of the source records, sorted.
	Members []string `json:"members,omitempty"`

	// MetadataTypes holds every metadata payload type that was folded together.
	MetadataTypes []string `json:"metadataTypes,omitempty"`

	// MetadataPayloads holds every source metadata payload, sorted by member ID.
	MetadataPayloads []MergeMetadata `json:"metadataPayloads,omitempty"`

	// Checksums holds every content digest the sources reported.
	Checksums []MergeChecksum `json:"checksums,omitempty"`

	// ExternalIdentifiers holds every identifier the sources reported.
	ExternalIdentifiers []MergeExternalID `json:"externalIdentifiers,omitempty"`

	// CrossReferences holds IDs of entries that name the same component under a different package
	// type. They are deliberately not merged.
	CrossReferences []string `json:"crossReferences,omitempty"`

	// Conflicts records every disagreement that was surfaced rather than silently resolved.
	Conflicts []MergeConflict `json:"conflicts,omitempty"`

	// LocationCount, LicenseCount and ChecksumCount let a reviewer see, without expanding the
	// entry, how much evidence the merge retained.
	LocationCount int `json:"locationCount"`
	LicenseCount  int `json:"licenseCount"`
	ChecksumCount int `json:"checksumCount"`
}
