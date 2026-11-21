package timeline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/anchore/syft/internal/sourcemetadata"
	"github.com/anchore/syft/syft/sbom"
)

// RecordVersion is the schema version of one journal record. Readers accept only the versions
// they know how to interpret; an unknown version is reported as a problem with that line rather
// than being silently dropped.
const RecordVersion = 1

// SourceInfo describes what was scanned for a snapshot. It is informational: component identity
// and change detection never depend on it.
type SourceInfo struct {
	Type    string `json:"type,omitempty"`
	ID      string `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// Record is one immutable observation of the full component set at one point in time. The
// journal is append-only and every record is self-contained, so the history can be replayed
// without consulting the SBOMs the records were derived from.
type Record struct {
	RecordVersion int         `json:"recordVersion"`
	SnapshotID    string      `json:"snapshotID"`
	Timestamp     string      `json:"timestamp"`
	Source        SourceInfo  `json:"source,omitempty"`
	Components    []Component `json:"components"`
}

// NewRecord builds a record for an SBOM at the given time. The timestamp is normalized to the
// single canonical timeline representation and the snapshot identity is derived from the
// record content, including that timestamp.
func NewRecord(s sbom.SBOM, at time.Time) Record {
	rec := Record{
		RecordVersion: RecordVersion,
		Timestamp:     FormatTimestamp(at),
		Source:        sourceInfo(s),
		Components:    ComponentsFromSBOM(s),
	}
	rec.SnapshotID = ComputeSnapshotID(rec)
	return rec
}

// NewRecordFromComponents builds a record from an already-extracted component set.
func NewRecordFromComponents(components []Component, src SourceInfo, at time.Time) Record {
	rec := Record{
		RecordVersion: RecordVersion,
		Timestamp:     FormatTimestamp(at),
		Source:        src,
		Components:    NormalizeComponents(components),
	}
	rec.SnapshotID = ComputeSnapshotID(rec)
	return rec
}

// NormalizeComponents returns a key-sorted, key-deduplicated copy of the components. When
// several entries share a key the deterministic representative is kept, so the same input always
// produces the same record regardless of ordering.
func NormalizeComponents(components []Component) []Component {
	byKey := make(map[string]Component, len(components))
	for _, c := range components {
		if c.Key == "" {
			continue
		}
		if existing, ok := byKey[c.Key]; !ok || componentLess(c, existing) {
			byKey[c.Key] = c
		}
	}
	out := make([]Component, 0, len(byKey))
	for _, c := range byKey {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// ComputeSnapshotID returns the content identity of a record. Two imports of the same snapshot
// (same timestamp, source, and component state) therefore collapse to one record no matter how
// often or in which order they are imported.
func ComputeSnapshotID(rec Record) string {
	timestamp := rec.Timestamp
	if t, err := ParseTimestamp(timestamp); err == nil {
		// hash the canonical form so an equivalent timestamp written in another accepted layout
		// still hashes to the same identity
		timestamp = FormatTimestamp(t)
	}

	canonical := struct {
		RecordVersion int         `json:"recordVersion"`
		Timestamp     string      `json:"timestamp"`
		Source        SourceInfo  `json:"source,omitempty"`
		Components    []Component `json:"components"`
	}{
		RecordVersion: rec.RecordVersion,
		Timestamp:     timestamp,
		Source:        rec.Source,
		Components:    NormalizeComponents(rec.Components),
	}
	// encoding/json emits struct fields in declaration order and the component list is sorted,
	// so the encoding is canonical without a separate normalization step.
	payload, err := json.Marshal(canonical)
	if err != nil {
		// the structure above contains only strings and a slice of strings; marshaling cannot fail
		panic(err)
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Validate checks that a record is internally consistent and can be placed on the timeline.
func (r Record) Validate() error {
	if r.RecordVersion != RecordVersion {
		return fmt.Errorf("unsupported record version %d (this build understands version %d)", r.RecordVersion, RecordVersion)
	}
	if _, err := ParseTimestamp(r.Timestamp); err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	if !strings.HasPrefix(r.SnapshotID, "sha256:") {
		return fmt.Errorf("invalid snapshot ID %q", r.SnapshotID)
	}
	if expected := ComputeSnapshotID(r); r.SnapshotID != expected {
		return fmt.Errorf("snapshot ID %q does not match record content (expected %q)", r.SnapshotID, expected)
	}
	for i, c := range r.Components {
		if c.Key == "" {
			return fmt.Errorf("component %d has an empty key", i)
		}
	}
	return nil
}

// Time returns the normalized record timestamp. The error is reported for corrupt records.
func (r Record) Time() (time.Time, error) {
	return ParseTimestamp(r.Timestamp)
}

// normalized returns a copy with canonical timestamp formatting and component ordering.
func (r Record) normalized() Record {
	if t, err := ParseTimestamp(r.Timestamp); err == nil {
		r.Timestamp = FormatTimestamp(t)
	}
	r.Components = NormalizeComponents(r.Components)
	return r
}

func sourceInfo(s sbom.SBOM) SourceInfo {
	return SourceInfo{
		Type:    sourceType(s.Source.Metadata),
		ID:      s.Source.ID,
		Name:    s.Source.Name,
		Version: s.Source.Version,
	}
}

func sourceType(metadata any) string {
	if metadata == nil {
		return ""
	}
	if name := sourcemetadata.JSONName(metadata); name != "" {
		return name
	}
	return fmt.Sprintf("%T", metadata)
}
