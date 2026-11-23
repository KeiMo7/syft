package identity

import (
	"sort"

	"github.com/anchore/syft/syft/pkg"
)

// MergeVersion is the version of the report schema. It is independent of the SBOM schema version:
// the report describes how the merge was decided, not the shape of the SBOM.
const MergeVersion = "identity-merge/v1"

// Identity states recorded on output components.
const (
	// StateMerged means two or more source records were folded into this entry.
	StateMerged = "merged"
	// StateNeedsConfirmation means the entry was kept independent because the evidence was
	// insufficient or contradictory. A reviewer must decide whether it duplicates another entry.
	StateNeedsConfirmation = "needs-confirmation"
	// StateUnique means the entry had no candidate conflict: it is a normal single-source component.
	StateUnique = "unique"
)

// Conflict resolutions. A conflict is never resolved silently: either the report names the rule
// that picked a value, or the values are retained as undecided.
const (
	ResolutionKeptBoth      = "kept-both"
	ResolutionUnresolved    = "unresolved"
	ResolutionDeterministic = "selected-deterministically"
)

// Record is one package finding as delivered by a cataloger. It is deliberately flat and
// format-independent so the merge can be exercised without an SBOM encoder.
type Record struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Type         pkg.Type `json:"type"`
	PURL         string   `json:"purl,omitempty"`
	FoundBy      string   `json:"foundBy,omitempty"`
	MetadataType string   `json:"metadataType,omitempty"`

	Locations   []Location   `json:"locations"`
	Licenses    []License    `json:"licenses"`
	Checksums   []Checksum   `json:"checksums"`
	ExternalIDs []ExternalID `json:"externalIdentifiers"`
}

// Location is one place a record's evidence was found. RealPath, FullPath, AccessPath and
// the layer together identify it; Evidence (primary/supporting) is explanatory only.
type Location struct {
	Path       string `json:"path"`
	RealPath   string `json:"realPath,omitempty"`
	AccessPath string `json:"accessPath,omitempty"`
	LayerID    string `json:"layerID,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
}

// License is one license finding for a record. Locations are retained so merging does not
// discard where a license was declared.
type License struct {
	Value          string     `json:"value"`
	SPDXExpression string     `json:"spdxExpression,omitempty"`
	Type           string     `json:"type,omitempty"`
	URLs           []string   `json:"urls,omitempty"`
	Locations      []Location `json:"locations,omitempty"`
}

// Checksum is a content digest with the clue that supplied it.
type Checksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
	Source    string `json:"source,omitempty"`
}

// ExternalID is an identifier assigned by another system (a purl, a CPE, an OS package
// name, ...) with the clue that supplied it.
type ExternalID struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Source string `json:"source,omitempty"`
}

// Conflict records a field whose values disagreed across merged records. Values holds
// every distinct value found, sorted, so both sides survive.
type Conflict struct {
	Field      string   `json:"field"`
	Values     []string `json:"values"`
	Resolution string   `json:"resolution"`
	Rule       string   `json:"rule,omitempty"`
	Note       string   `json:"note,omitempty"`
}

// Match records that two member records were judged the same, and the rules that made
// them equal. It is the audit trail behind "why did these merge?".
type Match struct {
	Left  string   `json:"left"`
	Right string   `json:"right"`
	Rules []string `json:"rules"`
}

// MemberSummary is the per-record view retained in the report.
type MemberSummary struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Version       string   `json:"version"`
	Type          pkg.Type `json:"type"`
	PURL          string   `json:"purl,omitempty"`
	FoundBy       string   `json:"foundBy,omitempty"`
	MetadataType  string   `json:"metadataType,omitempty"`
	LocationCount int      `json:"locationCount"`
}

// Group is one component identity with the records that were folded into it. Every group
// that merged cites the rules and the member pairs they applied to.
type Group struct {
	Identity       string          `json:"identity"`
	Type           pkg.Type        `json:"type"`
	Namespace      string          `json:"namespace,omitempty"`
	Name           string          `json:"name"`
	NormalizedName string          `json:"normalizedName"`
	Version        string          `json:"version"`
	VersionValues  []string        `json:"versionValues"`
	Rules          []string        `json:"rules"`
	Matches        []Match         `json:"matches,omitempty"`
	Members        []MemberSummary `json:"members"`
	MergedID       string          `json:"mergedID"`
	Conflicts      []Conflict      `json:"conflicts,omitempty"`
	Sources        []string        `json:"sources"`
	LocationCount  int             `json:"locationCount"`
	State          string          `json:"state"`
}

// Standalone describes an entry that was deliberately kept separate.
type Standalone struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	Type      pkg.Type   `json:"type"`
	Reason    string     `json:"reason"`
	State     string     `json:"state"`
	Conflicts []Conflict `json:"conflicts,omitempty"`
}

// CrossReference links two entries that name the same component but belong to different
// package types. They must not merge because their evidence describes different artifacts, but a
// reviewer should see them together.
type CrossReference struct {
	LeftID  string `json:"leftID"`
	RightID string `json:"rightID"`
	Reason  string `json:"reason"`
}

// Rule documents a rule identifier used anywhere in the report, so the report is
// self-describing to a reviewer who has never read the code.
type Rule struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

// Reconciliation proves the count arithmetic: input records minus the number of fold-away
// records equals output entries.
type Reconciliation struct {
	InputCount     int    `json:"inputCount"`
	MergePairCount int    `json:"mergePairCount"`
	OutputCount    int    `json:"outputCount"`
	Balanced       bool   `json:"balanced"`
	Formula        string `json:"formula"`
}

// MergeReport is the complete, deterministic account of one merge run.
type MergeReport struct {
	Version             string           `json:"version"`
	GeneratedBy         string           `json:"generatedBy,omitempty"`
	InputCount          int              `json:"inputCount"`
	OutputCount         int              `json:"outputCount"`
	MergePairCount      int              `json:"mergePairCount"`
	MergedCount         int              `json:"mergedCount"`
	UniqueCount         int              `json:"uniqueCount"`
	GroupCount          int              `json:"groupCount"`
	ConflictCount       int              `json:"conflictCount"`
	PendingCount        int              `json:"pendingCount"`
	CrossReferenceCount int              `json:"crossReferenceCount"`
	ConflictThreshold   int              `json:"conflictThreshold"`
	ThresholdExceeded   bool             `json:"thresholdExceeded"`
	Warning             string           `json:"warning,omitempty"`
	Rules               []Rule           `json:"rules"`
	Groups              []Group          `json:"groups"`
	Standalone          []Standalone     `json:"standalone"`
	CrossReferences     []CrossReference `json:"crossReferences"`
	Reconciliation      Reconciliation   `json:"reconciliation"`
}

// MergedComponent is one output entry. It is either a fold of several records or a single record
// that was kept as-is. It carries every piece of evidence the members had.
type MergedComponent struct {
	ID            string       `json:"id"`
	Identity      string       `json:"identity"`
	Type          pkg.Type     `json:"type"`
	Namespace     string       `json:"namespace,omitempty"`
	Name          string       `json:"name"`
	Version       string       `json:"version"`
	Versions      []string     `json:"versions,omitempty"`
	PURL          string       `json:"purl,omitempty"`
	Sources       []string     `json:"sources"`
	Locations     []Location   `json:"locations"`
	Licenses      []License    `json:"licenses"`
	Checksums     []Checksum   `json:"checksums"`
	ExternalIDs   []ExternalID `json:"externalIdentifiers"`
	MetadataTypes []string     `json:"metadataTypes,omitempty"`
	Conflicts     []Conflict   `json:"conflicts,omitempty"`
	Members       []string     `json:"members"`
	Rules         []string     `json:"rules,omitempty"`
	State         string       `json:"state"`
}

// Result is the merged output and the report describing it. Components are ordered
// deterministically: merged groups first (by identity), then standalone entries (by id).
type Result struct {
	Report     MergeReport
	Components []MergedComponent
}

// RuleCatalog returns the human-readable description of every rule identifier, sorted by id.
func RuleCatalog() []Rule {
	rules := []Rule{
		{RuleNameExact, "package names are identical"},
		{RuleNameCaseFold, "package names differ only in letter case"},
		{RuleNameSeparatorFold, "package names differ only in runs of '-', '_' or '.'"},
		{RuleNameNamespaceFold, "package names carry the same namespace in different spellings (e.g. '@scope/name' and 'scope/name')"},
		{RuleVersionExact, "package versions are identical"},
		{RuleVersionSemver, "package versions are the same semantic version in different spellings (e.g. 'v1.2' and '1.2.0')"},
		{RuleVersionRevision, "package versions differ only by the package-manager revision (e.g. '1.2.3-1' and '1.2.3'); both values are retained"},
		{RuleTypeExact, "package types are identical; different types are never merged"},
		{RulePURLAgrees, "the package URL agrees with the name and version of the record"},
		{RuleNoMergeType, "records name the same component but belong to different package types; they are cross-referenced instead of merged"},
		{"name.mismatch", "package names do not normalize to the same value"},
		{"version.mismatch", "package versions belong to different version classes"},
		{"version.missing", "at least one record has no version; the identity cannot be confirmed"},
		{"type.mismatch", "records have different package types"},
		{"purl.disagrees", "the package URL names a different component than the package fields; merge is refused"},
		{"checksum.conflict", "records of the same component carry different checksums for one algorithm; both are retained"},
		{"identity.insufficient", "a record is missing name or type; it cannot participate in a merge"},
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}
