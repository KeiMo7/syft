package timeline

import (
	"sort"
	"time"
)

// ChangeKind describes what happened to one component at one point in time.
type ChangeKind string

const (
	// KindAdded means the component was not present in the immediately preceding snapshot.
	// This covers both a first-ever appearance and a reappearance after an absence.
	KindAdded ChangeKind = "added"

	// KindRemoved means the component was present in the preceding snapshot and is absent now.
	KindRemoved ChangeKind = "removed"

	// KindChanged means the component is still present but its version or source changed.
	KindChanged ChangeKind = "changed"
)

// Change is one state transition of one component. It is the single unit both timeline views are
// built from, which is what keeps the component-oriented and time-oriented views consistent.
type Change struct {
	// Timestamp is the timestamp of the snapshot in which the change was observed.
	Timestamp string `json:"timestamp"`

	// SnapshotID identifies the exact snapshot record that introduced this change.
	SnapshotID string `json:"snapshotID"`

	// Component is the stable identity key (see Component.Key).
	Component string `json:"component"`

	Name      string     `json:"name"`
	Type      string     `json:"type"`
	Namespace string     `json:"namespace,omitempty"`
	Kind      ChangeKind `json:"kind"`

	PURL        string `json:"purl,omitempty"`
	FromVersion string `json:"fromVersion,omitempty"`
	ToVersion   string `json:"toVersion,omitempty"`
	FromSource  string `json:"fromSource,omitempty"`
	ToSource    string `json:"toSource,omitempty"`
}

// ComponentTimeline is the per-component view of the history.
type ComponentTimeline struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Namespace string `json:"namespace,omitempty"`
	PURL      string `json:"purl,omitempty"`

	// FirstSeen is the first snapshot in which the component was observed, regardless of any
	// query time range.
	FirstSeen string `json:"firstSeen"`

	// LastSeen is the last snapshot in which the component was observed as present.
	LastSeen string `json:"lastSeen"`

	// RemovedAt is set when the component is absent from the most recent snapshot.
	RemovedAt string `json:"removedAt,omitempty"`

	// Present reports whether the component exists in the most recent snapshot.
	Present bool `json:"present"`

	Version string `json:"version"`
	Source  string `json:"source,omitempty"`

	// Changes contains only the transitions inside the requested query, in chronological order.
	Changes []Change `json:"changes"`
}

// Timepoint is the time-oriented view: everything that changed at one snapshot timestamp.
type Timepoint struct {
	Timestamp string   `json:"timestamp"`
	Changes   []Change `json:"changes"`
}

// TimeRange is the covered span of valid snapshot records.
type TimeRange struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// Timeline is the derived history.
type Timeline struct {
	// Snapshots is the number of valid snapshot records that were considered.
	Snapshots int `json:"snapshots"`

	// Range is the timestamp span of those snapshots.
	Range TimeRange `json:"range"`

	// Components is the per-component view, sorted by key.
	Components []ComponentTimeline `json:"components"`

	// Timepoints is the per-timestamp view, in chronological order. It contains exactly the same
	// changes as Components, only grouped differently.
	Timepoints []Timepoint `json:"timepoints"`

	// Problems describes damaged or ambiguous parts of the history. A problem never discards
	// the rest of the history.
	Problems []Problem `json:"problems,omitempty"`

	// Truncated reports that the limit cut off changes.
	Truncated bool `json:"truncated,omitempty"`
}

// Empty reports that there were no valid snapshots.
func (t *Timeline) Empty() bool {
	return t == nil || t.Snapshots == 0
}

// Query selects the slice of history to derive.
type Query struct {
	// Component, when set, restricts the timeline to components matching the value. The value may
	// be the identity key, the component name, "<type>/<name>", a namespace-qualified name, or a
	// full purl.
	Component string

	// Since and Until restrict reported changes (inclusive). State before Since is still read so
	// that "first seen" and pre-existing components are reported correctly.
	Since *time.Time
	Until *time.Time

	// Limit caps the number of reported changes. Zero means no limit.
	Limit int
}

type componentState struct {
	component Component
	firstSeen string
	lastSeen  string
	removedAt string
	present   bool
	changes   []Change
}

type timelineBuilder struct {
	query Query
	since *time.Time
	until *time.Time

	states     map[string]*componentState
	snapshots  int
	timeRange  TimeRange
	timepoints []Timepoint
	changes    int
	truncated  bool

	// emitFn, when set, receives each change instead of it being retained.
	emitFn func(Change) error
}

func newTimelineBuilder(q Query) *timelineBuilder {
	b := &timelineBuilder{
		query:  q,
		states: make(map[string]*componentState),
	}
	if q.Since != nil {
		t := NormalizeTimestamp(*q.Since)
		b.since = &t
	}
	if q.Until != nil {
		t := NormalizeTimestamp(*q.Until)
		b.until = &t
	}
	return b
}

func (b *timelineBuilder) apply(rec Record) error {
	b.snapshots++
	if b.timeRange.From == "" {
		b.timeRange.From = rec.Timestamp
	}
	b.timeRange.To = rec.Timestamp

	present := make(map[string]struct{}, len(rec.Components))
	for _, c := range rec.Components {
		present[c.Key] = struct{}{}
	}

	// additions and changes, in the record's (sorted) component order
	for _, c := range rec.Components {
		if !b.matches(c) {
			continue
		}
		state, exists := b.states[c.Key]
		switch {
		case !exists:
			state = &componentState{firstSeen: rec.Timestamp}
			b.states[c.Key] = state
			if err := b.emit(rec, state, addedChange(c, Component{})); err != nil {
				return err
			}
		case !state.present:
			// reappearance after an absence
			if err := b.emit(rec, state, addedChange(c, state.component)); err != nil {
				return err
			}
		case state.component.Version != c.Version || state.component.Source != c.Source:
			if err := b.emit(rec, state, changedChange(c, state.component)); err != nil {
				return err
			}
		}
		state.component = c
		state.present = true
		state.lastSeen = rec.Timestamp
	}

	// removals, in key order (deterministic even though map iteration is not)
	removed := make([]string, 0)
	for key, state := range b.states {
		if _, stillPresent := present[key]; state.present && !stillPresent {
			removed = append(removed, key)
		}
	}
	sort.Strings(removed)
	for _, key := range removed {
		state := b.states[key]
		if err := b.emit(rec, state, removedChange(key, state.component)); err != nil {
			return err
		}
		state.present = false
		state.removedAt = rec.Timestamp
	}

	return nil
}

func addedChange(c, previous Component) Change {
	return Change{
		Component:   c.Key,
		Name:        c.Name,
		Type:        c.Type,
		Namespace:   c.Namespace,
		Kind:        KindAdded,
		PURL:        c.PURL,
		FromVersion: previous.Version,
		FromSource:  previous.Source,
		ToVersion:   c.Version,
		ToSource:    c.Source,
	}
}

func changedChange(c, previous Component) Change {
	return Change{
		Component:   c.Key,
		Name:        c.Name,
		Type:        c.Type,
		Namespace:   c.Namespace,
		Kind:        KindChanged,
		PURL:        c.PURL,
		FromVersion: previous.Version,
		ToVersion:   c.Version,
		FromSource:  previous.Source,
		ToSource:    c.Source,
	}
}

func removedChange(key string, previous Component) Change {
	return Change{
		Component:   key,
		Name:        previous.Name,
		Type:        previous.Type,
		Namespace:   previous.Namespace,
		Kind:        KindRemoved,
		PURL:        previous.PURL,
		FromVersion: previous.Version,
		FromSource:  previous.Source,
	}
}

func (b *timelineBuilder) matches(c Component) bool {
	if b.query.Component == "" {
		return true
	}
	filter := b.query.Component
	if filter == c.Key || filter == c.Name || filter == c.PURL {
		return true
	}
	if filter == c.Type+"/"+c.Name {
		return true
	}
	return c.Namespace != "" && filter == c.Namespace+"/"+c.Name
}

func (b *timelineBuilder) emit(rec Record, state *componentState, change Change) error {
	change.Timestamp = rec.Timestamp
	change.SnapshotID = rec.SnapshotID

	if !b.inRange(rec.Timestamp) {
		return nil
	}

	if b.query.Limit > 0 && b.changes >= b.query.Limit {
		b.truncated = true
		return nil
	}

	b.changes++

	if b.emitFn != nil {
		return b.emitFn(change)
	}

	state.changes = append(state.changes, change)
	b.appendTimepoint(change)
	return nil
}

func (b *timelineBuilder) inRange(timestamp string) bool {
	t, err := ParseTimestamp(timestamp)
	if err != nil {
		return false
	}
	if b.since != nil && t.Before(*b.since) {
		return false
	}
	if b.until != nil && t.After(*b.until) {
		return false
	}
	return true
}

func (b *timelineBuilder) appendTimepoint(change Change) {
	if n := len(b.timepoints); n > 0 && b.timepoints[n-1].Timestamp == change.Timestamp {
		b.timepoints[n-1].Changes = append(b.timepoints[n-1].Changes, change)
		return
	}
	b.timepoints = append(b.timepoints, Timepoint{
		Timestamp: change.Timestamp,
		Changes:   []Change{change},
	})
}

func (b *timelineBuilder) timeline() *Timeline {
	t := &Timeline{
		Snapshots:  b.snapshots,
		Range:      b.timeRange,
		Timepoints: b.timepoints,
		Truncated:  b.truncated,
	}

	keys := make([]string, 0, len(b.states))
	for key := range b.states {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		state := b.states[key]
		changes := state.changes
		if changes == nil {
			changes = []Change{}
		}
		t.Components = append(t.Components, ComponentTimeline{
			Key:       key,
			Name:      state.component.Name,
			Type:      state.component.Type,
			Namespace: state.component.Namespace,
			PURL:      state.component.PURL,
			FirstSeen: state.firstSeen,
			LastSeen:  state.lastSeen,
			RemovedAt: state.removedAt,
			Present:   state.present,
			Version:   state.component.Version,
			Source:    state.component.Source,
			Changes:   changes,
		})
	}

	if t.Timepoints == nil {
		t.Timepoints = []Timepoint{}
	}
	if t.Components == nil {
		t.Components = []ComponentTimeline{}
	}
	return t
}
