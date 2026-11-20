package diff

import (
	"encoding/json"
	"fmt"
	"io"
)

// streamArtifact is the subset of a syft-json artifact entry needed to build a Record. The
// full artifact (licenses, cpes, metadata, ...) is decoded away and never retained.
type streamArtifact struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Version   string           `json:"version"`
	Type      string           `json:"type"`
	FoundBy   string           `json:"foundBy"`
	PURL      string           `json:"purl"`
	Locations []streamLocation `json:"locations"`
}

type streamLocation struct {
	Path string `json:"path"`
}

// readSyftJSONStream extracts package records from a syft-json document in a single streaming
// pass. Only the small per-package identity fields are retained; arbitrarily large sections
// (files, relationships, license contents, metadata) are skipped token by token, so memory
// use stays proportional to the number of packages, not the size of the document.
func readSyftJSONStream(r io.Reader) (*Document, error) {
	dec := json.NewDecoder(r)

	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("unable to read document start: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("document does not start with a JSON object")
	}

	doc := &Document{Format: "syft-json"}

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("unable to read document key: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected non-string document key")
		}

		switch key {
		case "artifacts":
			if err := streamArtifacts(dec, doc); err != nil {
				return nil, err
			}
		case "descriptor":
			var descriptor struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}
			if err := dec.Decode(&descriptor); err != nil {
				return nil, fmt.Errorf("unable to read descriptor: %w", err)
			}
			doc.ToolName = descriptor.Name
			doc.ToolVersion = descriptor.Version
		case "schema":
			var schema struct {
				Version string `json:"version"`
			}
			if err := dec.Decode(&schema); err != nil {
				return nil, fmt.Errorf("unable to read schema: %w", err)
			}
			doc.SchemaVersion = schema.Version
		case "source":
			var source struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if err := dec.Decode(&source); err != nil {
				return nil, fmt.Errorf("unable to read source: %w", err)
			}
			doc.SourceName = source.Name
			if doc.SourceName == "" {
				doc.SourceName = source.ID
			}
		default:
			if err := skipValue(dec); err != nil {
				return nil, fmt.Errorf("unable to skip %q section: %w", key, err)
			}
		}
	}

	if _, err := dec.Token(); err != nil { // closing '}'
		return nil, fmt.Errorf("unable to read document end: %w", err)
	}

	if doc.SchemaVersion == "" {
		return nil, fmt.Errorf("document has no schema block")
	}

	return doc, nil
}

func streamArtifacts(dec *json.Decoder, doc *Document) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("unable to read artifacts: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("artifacts is not a JSON array")
	}

	for dec.More() {
		var a streamArtifact
		if err := dec.Decode(&a); err != nil {
			return fmt.Errorf("unable to read artifact entry: %w", err)
		}
		locations := make([]string, 0, len(a.Locations))
		for _, l := range a.Locations {
			locations = append(locations, l.Path)
		}
		doc.Records = append(doc.Records, NewRecord(a.ID, a.Name, a.Version, a.Type, a.PURL, a.FoundBy, locations))
	}

	if _, err := dec.Token(); err != nil { // closing ']'
		return fmt.Errorf("unable to read artifacts end: %w", err)
	}
	return nil
}

// skipValue consumes exactly one JSON value (of any shape) from the decoder without
// materializing it.
func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}
