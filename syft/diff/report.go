package diff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// RenderJSON renders the report as indented JSON. The encoding is deterministic: struct
// field order is fixed, every list was sorted by Compare, and the report contains no
// timestamps, host paths, or generated identifiers — rendering the same Diff twice yields
// byte-for-byte identical output.
func RenderJSON(d *Diff) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(d); err != nil {
		return nil, fmt.Errorf("unable to render diff report as JSON: %w", err)
	}
	return buf.Bytes(), nil
}

// RenderText renders the report as a human-readable plain-text summary. Like RenderJSON it
// is fully deterministic.
func RenderText(d *Diff) []byte {
	var b strings.Builder

	b.WriteString("SBOM diff report\n")
	b.WriteString("================\n")
	fmt.Fprintf(&b, "old: %s\n", describeRef(d.Old))
	fmt.Fprintf(&b, "new: %s\n", describeRef(d.New))
	b.WriteString("\n")

	if d.Tool.Changed {
		fmt.Fprintf(&b, "WARNING: %s\n", d.Tool.Note)
	}
	if d.Tool.SchemaChanged {
		fmt.Fprintf(&b, "note: the SBOM schema versions differ (old=%s new=%s); field-level differences may come from the format, not the project\n",
			d.Old.SchemaVersion, d.New.SchemaVersion)
	}
	if d.Tool.Changed || d.Tool.SchemaChanged {
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "summary: added=%d removed=%d changed=%d unchanged=%d incomparable=%d\n",
		d.Summary.Added, d.Summary.Removed, d.Summary.Changed, d.Summary.Unchanged, d.Summary.Incomparable)
	fmt.Fprintf(&b, "subprojects: added=[%s] removed=[%s]\n",
		strings.Join(d.Subprojects.Added, ", "), strings.Join(d.Subprojects.Removed, ", "))
	b.WriteString("\n")

	writeEntries := func(title string, marker string, entries []Entry, annotate func(Entry) string) {
		fmt.Fprintf(&b, "%s (%d):\n", title, len(entries))
		for _, e := range entries {
			fmt.Fprintf(&b, "  %s %s\n", marker, describeEntry(e, annotate(e)))
		}
		b.WriteString("\n")
	}

	writeEntries("added", "+", d.Added, func(e Entry) string {
		var notes []string
		if e.NewSubproject {
			notes = append(notes, "new subproject")
		}
		if e.PossiblyToolInduced {
			notes = append(notes, "possibly tool-induced")
		}
		return strings.Join(notes, ", ")
	})
	writeEntries("removed", "-", d.Removed, func(e Entry) string {
		if e.PossiblyToolInduced {
			return "possibly tool-induced"
		}
		return ""
	})

	fmt.Fprintf(&b, "changed (%d):\n", len(d.Changed))
	for _, c := range d.Changed {
		note := ""
		if c.PossiblyToolInduced {
			note = " (possibly tool-induced)"
		}
		fmt.Fprintf(&b, "  ~ %s %s -> %s type=%s subproject=%s old-refs=[%s] new-refs=[%s]%s\n",
			c.Name, c.From.Version, c.To.Version, c.Type, c.Subproject,
			joinRefIDs(c.From.Refs), joinRefIDs(c.To.Refs), note)
	}
	b.WriteString("\n")

	writeEntries("unchanged", "=", d.Unchanged, func(Entry) string { return "" })

	fmt.Fprintf(&b, "incomparable (%d):\n", len(d.Incomparable))
	for _, p := range d.Incomparable {
		fmt.Fprintf(&b, "  ? old: %s\n    new: %s\n    reason: %s\n",
			describeEntry(p.Old, ""), describeEntry(p.New, ""), p.Reason)
	}

	return []byte(b.String())
}

func describeRef(r DocumentRef) string {
	source := r.Source
	if source == "" {
		source = "(unknown source)"
	}
	return fmt.Sprintf("source=%q tool=%s@%s format=%s schema=%s",
		source, r.ToolName, r.ToolVersion, r.Format, r.SchemaVersion)
}

func describeEntry(e Entry, note string) string {
	s := fmt.Sprintf("%s type=%s subproject=%s", entryDisplayName(e), e.Type, e.Subproject)
	if refs := joinRefIDs(append(append([]Ref(nil), e.OldRefs...), e.NewRefs...)); refs != "" {
		s += " refs=[" + refs + "]"
	}
	if note != "" {
		s += " (" + note + ")"
	}
	return s
}

func joinRefIDs(refs []Ref) string {
	seen := make(map[string]bool, len(refs))
	var ids []string
	for _, r := range refs {
		if !seen[r.ID] {
			seen[r.ID] = true
			ids = append(ids, r.ID)
		}
	}
	return strings.Join(ids, ", ")
}
