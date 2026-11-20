package diff

import (
	"fmt"
	"sort"
)

// ReportVersion is the schema version of the diff report itself, so consumers can pin on it.
const ReportVersion = "1"

// Ref points back at one concrete entry in one of the compared SBOM documents, so every
// conclusion in the report can be traced back and verified by hand.
type Ref struct {
	// ID is the artifact identifier as recorded in the source document.
	ID string `json:"id"`
	// Locations are the normalized paths at which that entry was discovered.
	Locations []string `json:"locations,omitempty"`
}

// Entry is one diff conclusion about a component: same component, same version, same
// subproject. Records from the source document(s) that share this identity are aggregated
// here, keeping every source ID for traceability.
type Entry struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Type       string   `json:"type"`
	PURL       string   `json:"purl,omitempty"`
	Subproject string   `json:"subproject"`
	Locations  []string `json:"locations,omitempty"`

	// OldRefs point at the matching entries in the old (baseline) document.
	OldRefs []Ref `json:"oldRefs,omitempty"`
	// NewRefs point at the matching entries in the new document.
	NewRefs []Ref `json:"newRefs,omitempty"`

	// PossiblyToolInduced is set when the tool that produced the two documents changed
	// between runs, so this difference may come from the tool rather than the project.
	PossiblyToolInduced bool `json:"possiblyToolInduced,omitempty"`
	// NewSubproject is set on added entries whose subproject does not exist anywhere in the
	// old document: the project gained a subproject, not just a dependency.
	NewSubproject bool `json:"newSubproject,omitempty"`

	// identity material, kept for comparison logic (never serialized)
	nameKey string
	typeKey string
	hasPURL bool
}

// Endpoint is one side of a version change.
type Endpoint struct {
	Version string `json:"version"`
	Refs    []Ref  `json:"refs"`
}

// Change pairs a removed entry with an added entry for the same component in the same
// subproject: a version change, explicitly from one version to another — never reported as a
// removal plus an addition.
type Change struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Subproject string   `json:"subproject"`
	From       Endpoint `json:"from"`
	To         Endpoint `json:"to"`

	PossiblyToolInduced bool `json:"possiblyToolInduced,omitempty"`
}

// IncomparablePair records a removed and an added entry that might be the same component
// recorded in two different forms (e.g. with and without a namespace) where the documents
// lack the purl evidence to confirm it. They are flagged, never merged: merging would be
// guessing. Both entries remain counted in the added/removed lists they came from.
type IncomparablePair struct {
	Old    Entry  `json:"old"`
	New    Entry  `json:"new"`
	Reason string `json:"reason"`
}

// DocumentRef describes the provenance of one compared document.
type DocumentRef struct {
	Source        string `json:"source,omitempty"`
	Format        string `json:"format"`
	SchemaVersion string `json:"schemaVersion,omitempty"`
	ToolName      string `json:"toolName"`
	ToolVersion   string `json:"toolVersion"`
}

// ToolChange captures whether the tool that generated the two documents changed.
type ToolChange struct {
	Changed       bool   `json:"changed"`
	SchemaChanged bool   `json:"schemaChanged,omitempty"`
	Note          string `json:"note,omitempty"`
}

// SubprojectChange lists subprojects that exist only on one side of the comparison.
type SubprojectChange struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

// Summary counts each class of conclusion.
type Summary struct {
	Added        int `json:"added"`
	Removed      int `json:"removed"`
	Changed      int `json:"changed"`
	Unchanged    int `json:"unchanged"`
	Incomparable int `json:"incomparable"`
}

// Diff is the full comparison report. Added, Removed, Changed and Unchanged partition the
// union of both documents' entries: every old-document entry appears in exactly one of
// Unchanged, Removed or Changed.From, and every new-document entry in exactly one of
// Unchanged, Added or Changed.To.
type Diff struct {
	ReportVersion string             `json:"reportVersion"`
	Old           DocumentRef        `json:"old"`
	New           DocumentRef        `json:"new"`
	Tool          ToolChange         `json:"tool"`
	Subprojects   SubprojectChange   `json:"subprojects"`
	Summary       Summary            `json:"summary"`
	Added         []Entry            `json:"added"`
	Removed       []Entry            `json:"removed"`
	Changed       []Change           `json:"changed"`
	Unchanged     []Entry            `json:"unchanged"`
	Incomparable  []IncomparablePair `json:"incomparable"`
}

// Compare computes the diff between two documents. The result is fully deterministic: every
// list is sorted by stable identity fields, and nothing in the report depends on document
// ordering, timestamps, or map iteration.
func Compare(oldDoc, newDoc *Document) *Diff {
	d := &Diff{
		ReportVersion: ReportVersion,
		Old:           refOf(oldDoc),
		New:           refOf(newDoc),
		Added:         []Entry{},
		Removed:       []Entry{},
		Changed:       []Change{},
		Unchanged:     []Entry{},
		Incomparable:  []IncomparablePair{},
	}
	d.Tool = toolChange(oldDoc, newDoc)

	oldEntries := aggregate(oldDoc.Records)
	newEntries := aggregate(newDoc.Records)
	// aggregate stages refs in OldRefs; for the new document they belong in NewRefs
	for _, e := range newEntries {
		e.NewRefs = e.OldRefs
		e.OldRefs = nil
	}

	var removedCandidates, addedCandidates []*Entry
	for key, oldEntry := range oldEntries {
		if newEntry, ok := newEntries[key]; ok {
			newEntry.OldRefs = oldEntry.OldRefs
			newEntry.Locations = unionStrings(oldEntry.Locations, newEntry.Locations)
			d.Unchanged = append(d.Unchanged, *newEntry)
			delete(newEntries, key)
		} else {
			removedCandidates = append(removedCandidates, oldEntry)
		}
	}
	for _, newEntry := range newEntries {
		addedCandidates = append(addedCandidates, newEntry)
	}

	// pair removals with additions for the same component in the same subproject: exactly one
	// of each means a version change. Anything more ambiguous is left as separate additions
	// and removals rather than guessed at.
	removedByComponent := groupByComponent(removedCandidates)
	addedByComponent := groupByComponent(addedCandidates)
	for componentKey, removed := range removedByComponent {
		added, ok := addedByComponent[componentKey]
		if !ok || len(removed) != 1 || len(added) != 1 {
			continue
		}
		from, to := removed[0], added[0]
		d.Changed = append(d.Changed, Change{
			Name:       from.Name,
			Type:       from.Type,
			Subproject: from.Subproject,
			From:       Endpoint{Version: from.Version, Refs: from.OldRefs},
			To:         Endpoint{Version: to.Version, Refs: to.NewRefs},
		})
		delete(addedByComponent, componentKey)
		markSpent(removedCandidates, from)
		markSpent(addedCandidates, to)
	}
	for _, e := range removedCandidates {
		if e != nil {
			d.Removed = append(d.Removed, *e)
		}
	}
	for _, e := range addedCandidates {
		if e != nil {
			d.Added = append(d.Added, *e)
		}
	}

	d.Subprojects = subprojectChange(oldDoc.Records, newDoc.Records)
	newSubprojects := make(map[string]bool, len(d.Subprojects.Added))
	for _, s := range d.Subprojects.Added {
		newSubprojects[s] = true
	}
	for i := range d.Added {
		d.Added[i].NewSubproject = newSubprojects[d.Added[i].Subproject]
	}

	d.Incomparable = findIncomparable(d.Removed, d.Added)

	if d.Tool.Changed {
		for i := range d.Added {
			d.Added[i].PossiblyToolInduced = true
		}
		for i := range d.Removed {
			d.Removed[i].PossiblyToolInduced = true
		}
		for i := range d.Changed {
			d.Changed[i].PossiblyToolInduced = true
		}
	}

	sortDiff(d)
	d.Summary = Summary{
		Added:        len(d.Added),
		Removed:      len(d.Removed),
		Changed:      len(d.Changed),
		Unchanged:    len(d.Unchanged),
		Incomparable: len(d.Incomparable),
	}
	return d
}

func refOf(doc *Document) DocumentRef {
	return DocumentRef{
		Source:        doc.SourceName,
		Format:        doc.Format,
		SchemaVersion: doc.SchemaVersion,
		ToolName:      doc.ToolName,
		ToolVersion:   doc.ToolVersion,
	}
}

func toolChange(oldDoc, newDoc *Document) ToolChange {
	tc := ToolChange{
		Changed:       oldDoc.ToolName != newDoc.ToolName || oldDoc.ToolVersion != newDoc.ToolVersion,
		SchemaChanged: oldDoc.SchemaVersion != "" && newDoc.SchemaVersion != "" && oldDoc.SchemaVersion != newDoc.SchemaVersion,
	}
	switch {
	case oldDoc.ToolName != newDoc.ToolName:
		tc.Note = fmt.Sprintf("the documents were generated by different tools (%s %s vs %s %s); any difference may come from the tooling, not the project",
			oldDoc.ToolName, oldDoc.ToolVersion, newDoc.ToolName, newDoc.ToolVersion)
	case tc.Changed:
		tc.Note = fmt.Sprintf("the generating tool changed (%s %s -> %s); differences marked as possibly tool-induced may come from the tool, not the project",
			oldDoc.ToolName, oldDoc.ToolVersion, newDoc.ToolVersion)
	}
	return tc
}

// aggregate groups a document's records by exact identity, preserving every source ID.
func aggregate(records []Record) map[string]*Entry {
	entries := make(map[string]*Entry)
	for _, r := range records {
		key := r.exactKey()
		e, ok := entries[key]
		if !ok {
			e = &Entry{
				Name:       r.Name,
				Version:    r.Version,
				Type:       r.Type,
				PURL:       r.PURL,
				Subproject: r.Subproject,
				nameKey:    r.nameKey,
				typeKey:    r.typeKey,
				hasPURL:    r.hasPURL,
			}
			entries[key] = e
		}
		if e.PURL == "" {
			e.PURL = r.PURL
		}
		e.Locations = unionStrings(e.Locations, r.Locations)
		ref := Ref{ID: r.ID, Locations: r.Locations}
		if r.ID == "" {
			ref.ID = unknownRefID(r)
		}
		e.OldRefs = appendRef(e.OldRefs, ref)
	}
	// at this stage refs are staged in OldRefs; the caller relocates them for the new document
	for _, e := range entries {
		sortRefs(e.OldRefs)
	}
	return entries
}

// unknownRefID gives a deterministic stand-in reference for documents that record no
// artifact IDs (e.g. minimal purl lists), so the entry can still be pointed at.
func unknownRefID(r Record) string {
	return fmt.Sprintf("(no id: %s %s %s)", r.Type, r.Name, r.Version)
}

func appendRef(refs []Ref, ref Ref) []Ref {
	for _, existing := range refs {
		if existing.ID == ref.ID {
			return refs
		}
	}
	return append(refs, ref)
}

func groupByComponent(entries []*Entry) map[string][]*Entry {
	groups := make(map[string][]*Entry)
	for _, e := range entries {
		if e == nil {
			continue
		}
		key := e.typeKey + "\x1f" + e.nameKey + "\x1f" + e.Subproject
		groups[key] = append(groups[key], e)
	}
	return groups
}

func markSpent(entries []*Entry, spent *Entry) {
	for i, e := range entries {
		if e == spent {
			entries[i] = nil
			return
		}
	}
}

func subprojectChange(oldRecords, newRecords []Record) SubprojectChange {
	oldSet := subprojectSet(oldRecords)
	newSet := subprojectSet(newRecords)
	sc := SubprojectChange{
		Added:   []string{},
		Removed: []string{},
	}
	for s := range newSet {
		if !oldSet[s] {
			sc.Added = append(sc.Added, s)
		}
	}
	for s := range oldSet {
		if !newSet[s] {
			sc.Removed = append(sc.Removed, s)
		}
	}
	sort.Strings(sc.Added)
	sort.Strings(sc.Removed)
	return sc
}

func subprojectSet(records []Record) map[string]bool {
	set := make(map[string]bool)
	for _, r := range records {
		if r.Subproject != "" {
			set[r.Subproject] = true
		}
	}
	return set
}

// findIncomparable flags removed/added pairs that look like the same component recorded in
// two forms but cannot be confirmed (no purl evidence). They are reported, not merged.
func findIncomparable(removed, added []Entry) []IncomparablePair {
	var pairs []IncomparablePair
	for _, r := range removed {
		for _, a := range added {
			if r.Subproject != a.Subproject {
				continue
			}
			if r.typeKey != a.typeKey {
				continue
			}
			if !namesRelatedWithoutPURL(recordOf(r), recordOf(a)) {
				continue
			}
			pairs = append(pairs, IncomparablePair{
				Old: r,
				New: a,
				Reason: fmt.Sprintf("recorded as %q in the old SBOM and %q in the new one without purl evidence to confirm they are the same component; left as a removal plus an addition rather than guessed",
					r.Name, a.Name),
			})
		}
	}
	return pairs
}

// recordOf reconstructs the identity view of an aggregated entry for incomparability checks.
func recordOf(e Entry) Record {
	return Record{Name: e.Name, nameKey: e.nameKey, typeKey: e.typeKey, hasPURL: e.hasPURL}
}

func unionStrings(a, b []string) []string {
	if len(a) == 0 {
		return sortedCopy(b)
	}
	set := make(map[string]struct{}, len(a)+len(b))
	for _, s := range a {
		set[s] = struct{}{}
	}
	for _, s := range b {
		set[s] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func sortRefs(refs []Ref) {
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
}

// sortDiff orders every list in the report by stable identity fields so the rendered output
// is byte-for-byte reproducible regardless of document ordering.
func sortDiff(d *Diff) {
	entryLess := func(entries []Entry) func(i, j int) bool {
		return func(i, j int) bool {
			if entries[i].Subproject != entries[j].Subproject {
				return entries[i].Subproject < entries[j].Subproject
			}
			if entries[i].typeKey != entries[j].typeKey {
				return entries[i].typeKey < entries[j].typeKey
			}
			if entries[i].nameKey != entries[j].nameKey {
				return entries[i].nameKey < entries[j].nameKey
			}
			if entries[i].Version != entries[j].Version {
				return entries[i].Version < entries[j].Version
			}
			return firstRefID(entries[i].OldRefs, entries[i].NewRefs) < firstRefID(entries[j].OldRefs, entries[j].NewRefs)
		}
	}
	sort.Slice(d.Added, entryLess(d.Added))
	sort.Slice(d.Removed, entryLess(d.Removed))
	sort.Slice(d.Unchanged, entryLess(d.Unchanged))

	sort.Slice(d.Changed, func(i, j int) bool {
		if d.Changed[i].Subproject != d.Changed[j].Subproject {
			return d.Changed[i].Subproject < d.Changed[j].Subproject
		}
		if d.Changed[i].Type != d.Changed[j].Type {
			return d.Changed[i].Type < d.Changed[j].Type
		}
		if d.Changed[i].Name != d.Changed[j].Name {
			return d.Changed[i].Name < d.Changed[j].Name
		}
		return d.Changed[i].From.Version < d.Changed[j].From.Version
	})

	sort.Slice(d.Incomparable, func(i, j int) bool {
		if d.Incomparable[i].Old.Subproject != d.Incomparable[j].Old.Subproject {
			return d.Incomparable[i].Old.Subproject < d.Incomparable[j].Old.Subproject
		}
		return d.Incomparable[i].Old.Name < d.Incomparable[j].Old.Name
	})

	for i := range d.Added {
		sortRefs(d.Added[i].OldRefs)
		sortRefs(d.Added[i].NewRefs)
	}
	for i := range d.Removed {
		sortRefs(d.Removed[i].OldRefs)
		sortRefs(d.Removed[i].NewRefs)
	}
	for i := range d.Unchanged {
		sortRefs(d.Unchanged[i].OldRefs)
		sortRefs(d.Unchanged[i].NewRefs)
	}
	for i := range d.Changed {
		sortRefs(d.Changed[i].From.Refs)
		sortRefs(d.Changed[i].To.Refs)
	}
}

func firstRefID(oldRefs, newRefs []Ref) string {
	if len(oldRefs) > 0 {
		return oldRefs[0].ID
	}
	if len(newRefs) > 0 {
		return newRefs[0].ID
	}
	return ""
}

// entryDisplayName renders an entry as "name@version" for text output.
func entryDisplayName(e Entry) string {
	return e.Name + "@" + e.Version
}
