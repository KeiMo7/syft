package identity

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
)

// rec builds a record with the fields the merge cares about. Every test states only what it
// exercises so the intent of the case stays readable.
func rec(id, name, version string, ty pkg.Type, foundBy string, opts ...func(*Record)) Record {
	r := Record{
		ID:      id,
		Name:    name,
		Version: version,
		Type:    ty,
		FoundBy: foundBy,
	}
	for _, opt := range opts {
		opt(&r)
	}
	return r
}

func withLocation(path string) func(*Record) {
	return func(r *Record) {
		r.Locations = append(r.Locations, Location{Path: path, AccessPath: path})
	}
}

func withLicense(value, path string) func(*Record) {
	return func(r *Record) {
		r.Licenses = append(r.Licenses, License{Value: value, Locations: []Location{{Path: path}}})
	}
}

func withChecksum(algorithm, value, source string) func(*Record) {
	return func(r *Record) {
		r.Checksums = append(r.Checksums, Checksum{Algorithm: algorithm, Value: value, Source: source})
	}
}

func withPURL(purl string) func(*Record) {
	return func(r *Record) { r.PURL = purl }
}

func withExternalID(ty, value, source string) func(*Record) {
	return func(r *Record) {
		r.ExternalIDs = append(r.ExternalIDs, ExternalID{Type: ty, Value: value, Source: source})
	}
}

// mergeCase is one of the twelve required scenarios.
type mergeCase struct {
	name string

	records []Record
	opts    Options

	// expected output entry count and the reconciliation numbers
	wantOutputCount   int
	wantMergePairs    int
	wantConflictCount int
	wantPendingCount  int
	wantCrossRefs     int
	wantStates        []string // state of each output entry, sorted
}

func TestMerge_TwelveScenarios(t *testing.T) {
	scenarios := Scenarios()
	require.Len(t, scenarios, 12, "the acceptance criteria require twelve scenarios")

	for _, tc := range scenarios {
		t.Run(tc.Name, func(t *testing.T) {
			result := Merge(tc.Records, DefaultOptions().WithConflictThreshold(1000))

			assert.Equal(t, tc.Want.OutputCount, len(result.Components), "merged entry count")
			assert.Equal(t, tc.Want.OutputCount, result.Report.OutputCount)
			assert.Equal(t, tc.Want.MergePairs, result.Report.MergePairCount, "merge pair count")
			assert.Equal(t, tc.Want.ConflictCount, result.Report.ConflictCount, "conflict count")
			assert.Equal(t, tc.Want.PendingCount, result.Report.PendingCount, "pending count")
			assert.Equal(t, tc.Want.CrossReference, result.Report.CrossReferenceCount, "cross reference count")

			states := make([]string, 0, len(result.Components))
			for _, c := range result.Components {
				states = append(states, c.State)
			}
			assert.ElementsMatch(t, tc.Want.States, states)

			// reconciliation must always hold
			assert.True(t, result.Report.Reconciliation.Balanced)
			assert.Equal(t, len(tc.Records)-tc.Want.MergePairs, tc.Want.OutputCount)
		})
	}
}

func TestMerge_ReconciliationFormula(t *testing.T) {
	// a mixed population large enough that the four numbers cannot agree by accident
	records := []Record{
		rec("a1", "Django", "4.2.0", pkg.PythonPkg, "c1", withLocation("/a1")),
		rec("a2", "django", "v4.2", pkg.PythonPkg, "c2", withLocation("/a2")),
		rec("a3", "django", "4.2.0", pkg.PythonPkg, "c3", withLocation("/a3")),
		rec("b1", "requests", "2.22.0", pkg.PythonPkg, "c1", withLocation("/b1")),
		rec("b2", "requests", "2.22.0", pkg.DebPkg, "c2", withLocation("/b2")),
		rec("c1", "libc6", "2.31-13", pkg.DebPkg, "c3", withLocation("/c1")),
		rec("c2", "libc6", "2.31", pkg.DebPkg, "c4", withLocation("/c2")),
		rec("d1", "busybox", "", pkg.ApkPkg, "c5", withLocation("/d1")),
		rec("e1", "alpha", "1.0.0", pkg.GemPkg, "c1", withLocation("/e1")),
	}

	result := Merge(records, DefaultOptions())

	report := result.Report
	assert.Equal(t, 9, report.InputCount)
	assert.Equal(t, len(result.Components), report.OutputCount)
	assert.Equal(t, report.InputCount-report.MergePairCount, report.OutputCount, report.Reconciliation.Formula)
	assert.True(t, report.Reconciliation.Balanced)

	// the sum of group members minus one per group must equal the merge pair count
	folded := 0
	for _, g := range report.Groups {
		folded += len(g.Members) - 1
	}
	assert.Equal(t, folded, report.MergePairCount)

	// every input record appears in exactly one output entry
	accounted := map[string]int{}
	for _, c := range result.Components {
		for _, member := range c.Members {
			accounted[member]++
		}
	}
	for _, r := range records {
		assert.Equal(t, 1, accounted[r.ID], "record %s must appear in exactly one output entry", r.ID)
	}
}

func TestMerge_OrderIndependence(t *testing.T) {
	records := []Record{
		rec("a1", "Django", "4.2.0", pkg.PythonPkg, "c1", withLocation("/a1"), withLicense("MIT", "/a1/LICENSE")),
		rec("a2", "django", "v4.2", pkg.PythonPkg, "c2", withLocation("/a2"), withLicense("Apache-2.0", "/a2/LICENSE")),
		rec("a3", "DJANGO", "4.2.0", pkg.PythonPkg, "c3", withLocation("/a3")),
		rec("b1", "libc6", "2.31-13", pkg.DebPkg, "c4", withLocation("/b1"), withChecksum("sha256", "abc", "c4")),
		rec("b2", "libc6", "2.31", pkg.DebPkg, "c5", withLocation("/b2")),
		rec("c1", "requests", "2.22.0", pkg.PythonPkg, "c6", withLocation("/c1")),
		rec("c2", "requests", "2.22.0", pkg.DebPkg, "c7", withLocation("/c2")),
	}

	baseline := Merge(records, DefaultOptions())
	baselineJSON, err := json.Marshal(baseline)
	require.NoError(t, err)

	// every rotation and a reversal: each is a different input order with the same content
	orders := make([][]Record, 0, len(records)+1)
	for i := range records {
		rotated := append(append([]Record{}, records[i:]...), records[:i]...)
		orders = append(orders, rotated)
	}
	reversed := make([]Record, len(records))
	for i, r := range records {
		reversed[len(records)-1-i] = r
	}
	orders = append(orders, reversed)

	for _, order := range orders {
		got := Merge(order, DefaultOptions())
		gotJSON, err := json.Marshal(got)
		require.NoError(t, err)
		assert.JSONEq(t, string(baselineJSON), string(gotJSON), "output must not depend on input order")
	}
}

func TestMerge_SameInputTwiceIdentical(t *testing.T) {
	records := []Record{
		rec("a1", "openssl", "3.0.2", pkg.ApkPkg, "apk-db-cataloger", withLocation("/a"), withChecksum("sha256", "aa", "db")),
		rec("a2", "openssl", "3.0.2-r3", pkg.ApkPkg, "binary-classifier-cataloger", withLocation("/b")),
		rec("b1", "curl", "8.0.0", pkg.ApkPkg, "apk-db-cataloger", withLocation("/c")),
	}

	first, err := json.Marshal(Merge(records, DefaultOptions()))
	require.NoError(t, err)
	second, err := json.Marshal(Merge(records, DefaultOptions()))
	require.NoError(t, err)

	assert.Equal(t, first, second, "the same input must serialize to identical bytes")
}

func TestMerge_ConflictThresholdWarning(t *testing.T) {
	// three revision conflicts, with the threshold set to two
	records := []Record{
		rec("a1", "libc6", "2.31-13", pkg.DebPkg, "c1", withLocation("/a1")),
		rec("a2", "libc6", "2.31", pkg.DebPkg, "c2", withLocation("/a2")),
		rec("b1", "bash", "5.1-2", pkg.DebPkg, "c1", withLocation("/b1")),
		rec("b2", "bash", "5.1", pkg.DebPkg, "c2", withLocation("/b2")),
		rec("c1", "zlib", "1.2.11-1", pkg.DebPkg, "c1", withLocation("/c1")),
		rec("c2", "zlib", "1.2.11", pkg.DebPkg, "c2", withLocation("/c2")),
	}

	result := Merge(records, Options{ConflictThreshold: 2})
	assert.Equal(t, 3, result.Report.ConflictCount)
	assert.True(t, result.Report.ThresholdExceeded)
	assert.Contains(t, result.Report.Warning, "threshold")

	// the result is still complete: above-threshold is a warning, not a failure
	assert.Equal(t, 3, result.Report.OutputCount)
	assert.True(t, result.Report.Reconciliation.Balanced)

	// with a higher threshold there is no warning
	quiet := Merge(records, Options{ConflictThreshold: 10})
	assert.False(t, quiet.Report.ThresholdExceeded)
	assert.Empty(t, quiet.Report.Warning)
}

func TestMerge_EvidenceRetention(t *testing.T) {
	records := []Record{
		rec("a1", "openssl", "3.0.2", pkg.ApkPkg, "apk-db-cataloger",
			withLocation("/lib/apk/db/installed"),
			withLicense("Apache-2.0", "/usr/share/licenses/openssl/LICENSE"),
			withChecksum("sha256", "aaaa", "apk-db-cataloger"),
			withPURL("pkg:apk/alpine/openssl@3.0.2")),
		rec("a2", "openssl", "3.0.2", pkg.ApkPkg, "binary-classifier-cataloger",
			withLocation("/usr/bin/openssl"),
			withLicense("Apache-2.0", "/usr/share/licenses/openssl/LICENSE"),
			withExternalID("cpe", "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*", "declared")),
	}

	result := Merge(records, DefaultOptions())
	require.Len(t, result.Components, 1)
	c := result.Components[0]

	// positions from both sources
	paths := map[string]bool{}
	for _, l := range c.Locations {
		paths[l.Path] = true
	}
	assert.True(t, paths["/lib/apk/db/installed"])
	assert.True(t, paths["/usr/bin/openssl"])

	// license retained with its location
	require.Len(t, c.Licenses, 1)
	assert.Equal(t, "Apache-2.0", c.Licenses[0].Value)
	require.Len(t, c.Licenses[0].Locations, 1)

	// checksum retained with its source
	require.Len(t, c.Checksums, 1)
	assert.Equal(t, "aaaa", c.Checksums[0].Value)

	// both external identifiers survive
	types := map[string]bool{}
	for _, id := range c.ExternalIDs {
		types[id.Type] = true
	}
	assert.True(t, types["purl"])
	assert.True(t, types["cpe"])

	// both sources listed
	assert.ElementsMatch(t, []string{"apk-db-cataloger", "binary-classifier-cataloger"}, c.Sources)
}

func TestMerge_CrossReferenceUsesComponentIDs(t *testing.T) {
	records := []Record{
		// two python records that fold, and one deb record for the same component
		rec("py1", "requests", "2.22.0", pkg.PythonPkg, "c1", withLocation("/py1")),
		rec("py2", "Requests", "v2.22", pkg.PythonPkg, "c2", withLocation("/py2")),
		rec("deb1", "requests", "2.22.0", pkg.DebPkg, "c3", withLocation("/deb1")),
	}

	result := Merge(records, DefaultOptions())
	require.Len(t, result.Components, 2)
	require.Len(t, result.Report.CrossReferences, 1)

	ids := map[string]bool{}
	for _, c := range result.Components {
		ids[c.ID] = true
	}
	ref := result.Report.CrossReferences[0]
	assert.True(t, ids[ref.LeftID], "cross reference must name a real component id")
	assert.True(t, ids[ref.RightID], "cross reference must name a real component id")
	assert.NotEqual(t, ref.LeftID, ref.RightID)
}

func TestMerge_RuleCitation(t *testing.T) {
	records := []Record{
		rec("a1", "Foo_Bar", "1.0", pkg.PythonPkg, "c1", withLocation("/a")),
		rec("a2", "foo-bar", "1.0.0", pkg.PythonPkg, "c2", withLocation("/b")),
	}
	result := Merge(records, DefaultOptions())
	require.Len(t, result.Components, 1)

	rules := result.Components[0].Rules
	assert.Contains(t, rules, RuleNameSeparatorFold)
	assert.Contains(t, rules, RuleVersionSemver)
	assert.Contains(t, rules, RuleTypeExact)

	// the report must explain every rule it cites
	known := map[string]bool{}
	for _, r := range result.Report.Rules {
		known[r.ID] = true
	}
	for _, rule := range rules {
		assert.True(t, known[rule], "rule %q must be documented in the report", rule)
	}

	// the match record cites the same rules
	require.Len(t, result.Report.Groups, 1)
	require.Len(t, result.Report.Groups[0].Matches, 1)
	assert.Contains(t, result.Report.Groups[0].Matches[0].Rules, RuleVersionSemver)
}

func TestMerge_ExactNamesCiteExactRule(t *testing.T) {
	records := []Record{
		rec("a1", "requests", "2.22.0", pkg.PythonPkg, "c1", withLocation("/a")),
		rec("a2", "requests", "2.22.0", pkg.PythonPkg, "c2", withLocation("/b")),
	}
	result := Merge(records, DefaultOptions())
	require.Len(t, result.Components, 1)
	assert.Contains(t, result.Components[0].Rules, RuleNameExact)
	assert.Contains(t, result.Components[0].Rules, RuleVersionExact)
	assert.NotContains(t, result.Components[0].Rules, RuleNameCaseFold)
}

func TestMerge_DifferentRevisionsDoNotMerge(t *testing.T) {
	// two genuinely different Debian revisions are different components; neither may fold with the
	// other, and the bare version must not fold with both
	records := []Record{
		Rec("a", "libc6", "2.31-13", pkg.DebPkg, "c1", Loc("/a")),
		Rec("b", "libc6", "2.31-14", pkg.DebPkg, "c2", Loc("/b")),
	}

	result := Merge(records, DefaultOptions())
	assert.Equal(t, 2, result.Report.OutputCount, "distinct revisions must stay independent")
	assert.Equal(t, 0, result.Report.MergePairCount)
	assert.True(t, result.Report.Reconciliation.Balanced)

	// with a bare version in the mix and two distinct revisions, the bare version cannot be known to
	// match either revision, so nothing folds: the conservative result is three independent entries
	records = append(records, Rec("c", "libc6", "2.31", pkg.DebPkg, "c3", Loc("/c")))
	result = Merge(records, DefaultOptions())
	assert.Equal(t, 3, result.Report.OutputCount, "two distinct revisions block any merge, including the bare version")
	assert.Equal(t, 0, result.Report.MergePairCount)
	assert.True(t, result.Report.Reconciliation.Balanced)
}

func TestMerge_SameRevisionMerges(t *testing.T) {
	// the same revision spelled twice folds normally
	records := []Record{
		Rec("a", "libc6", "2.31-13", pkg.DebPkg, "c1", Loc("/a")),
		Rec("b", "libc6", "2.31-13", pkg.DebPkg, "c2", Loc("/b")),
	}
	result := Merge(records, DefaultOptions())
	assert.Equal(t, 1, result.Report.OutputCount)
	assert.Equal(t, 1, result.Report.MergePairCount)
	assert.Equal(t, 0, result.Report.ConflictCount)
}
