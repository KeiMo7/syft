package sbomartifact

import (
	"fmt"
	"os"

	"github.com/anchore/syft/syft/sbom"
)

// encodedMember is the single shared result of encoding one format for an entire batch. Every
// target that needs the format (directory and archive alike) consumes these same bytes, so the
// directory and archive forms of one run are byte-identical member for member. The encode itself
// streams into a staging file — the SBOM is never assembled in memory, and only one document's
// bytes are held at a time while the index is built.
type encodedMember struct {
	encoder sbom.FormatEncoder
	name    string
	file    *stagedFile // staging file holding the encoded bytes
	bytes   []byte      // populated transiently while an index is being assembled
}

// encodeAllMembers encodes every distinct encoder exactly once into staging files under stageDir.
// The returned members retain ownership of their staging files: callers must call cleanup on
// failure and the batch removes them once every target has committed.
func encodeAllMembers(encoders []sbom.FormatEncoder, s sbom.SBOM, stageDir string) ([]*encodedMember, error) {
	seen := make(map[string]struct{}, len(encoders))
	members := make([]*encodedMember, 0, len(encoders))

	for _, enc := range encoders {
		label := formatLabel(enc)
		if _, dup := seen[label]; dup {
			continue
		}
		seen[label] = struct{}{}

		name := MemberName(enc)
		f, err := stageFile(stageDir, "member-*")
		if err != nil {
			return nil, err
		}
		if err := enc.Encode(f, s); err != nil {
			_ = f.Close()
			_ = os.Remove(f.path)
			return nil, &EncodeError{Path: "(batch)", Kind: KindDirectory, Format: string(enc.ID()), Version: enc.Version(), Err: err}
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			_ = os.Remove(f.path)
			return nil, fmt.Errorf("unable to flush encoded member %q: %w", name, err)
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(f.path)
			return nil, fmt.Errorf("unable to finalize encoded member %q: %w", name, err)
		}
		members = append(members, &encodedMember{
			encoder: enc,
			name:    name,
			file:    f,
		})
	}
	return members, nil
}

// loadBytes reads the encoded document into the member's bytes field for index construction.
// Documents are loaded one at a time and released via releaseBytes, so peak memory stays bounded
// to a single document rather than the whole manifest.
func (m *encodedMember) loadBytes() error {
	if m.bytes != nil {
		return nil
	}
	data, err := os.ReadFile(m.file.path)
	if err != nil {
		return fmt.Errorf("unable to read staged member %q: %w", m.name, err)
	}
	m.bytes = data
	return nil
}

func (m *encodedMember) releaseBytes() {
	m.bytes = nil
}

func (m *encodedMember) remove() {
	if m.file != nil {
		_ = os.Remove(m.file.path)
	}
}

// memberRecords converts encoded members into index records, loading each document in turn to
// compute its size and digest without holding the whole set at once.
func memberRecordsFromEncoded(members []*encodedMember) ([]memberRecord, error) {
	records := make([]memberRecord, 0, len(members))
	for _, m := range members {
		if err := m.loadBytes(); err != nil {
			return nil, err
		}
		records = append(records, memberRecord{
			encoder:  m.encoder,
			name:     m.name,
			path:     m.file.path,
			contents: m.bytes,
			size:     int64(len(m.bytes)),
		})
		m.releaseBytes()
	}
	return records, nil
}
