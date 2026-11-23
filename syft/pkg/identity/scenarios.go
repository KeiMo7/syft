package identity

import "github.com/anchore/syft/syft/pkg"

// Scenario is one of the twelve acceptance shapes. The same definitions drive the unit tests and
// the checked-in report, so the report cannot drift from what the tests assert.
type Scenario struct {
	Name    string
	Records []Record
	Want    ScenarioExpectation
}

// ScenarioExpectation is the per-scenario assertion.
type ScenarioExpectation struct {
	OutputCount    int
	MergePairs     int
	ConflictCount  int
	PendingCount   int
	CrossReference int
	States         []string
}

// Scenarios returns the twelve component-identity shapes required by the acceptance criteria. The
// function is long because it is a data table: each entry is one shape, and splitting it would
// scatter the shapes a reviewer needs to read together.
//
//nolint:funlen
func Scenarios() []Scenario {
	return []Scenario{
		{
			// 1. three clues, three spellings of one version, one component
			Name: "same component from three clues with equivalent version spellings",
			Records: []Record{
				Rec("pkg-a", "Django", "4.2.0", pkg.PythonPkg, "python-package-cataloger",
					Loc("/site-packages/Django-4.2.0.dist-info/METADATA")),
				Rec("pkg-b", "django", "v4.2", pkg.PythonPkg, "python-installed-package-cataloger",
					Loc("/site-packages/django/__init__.py")),
				Rec("pkg-c", "DJANGO", "4.2", pkg.PythonPkg, "binary-classifier-cataloger",
					Loc("/usr/bin/python3")),
			},
			Want: ScenarioExpectation{OutputCount: 1, MergePairs: 2, States: []string{StateMerged}},
		},
		{
			// 2. already-identical records fold and keep every location and source
			Name: "duplicate records fold and retain every location and source",
			Records: []Record{
				Rec("pkg-a", "requests", "2.22.0", pkg.PythonPkg, "python-package-cataloger", Loc("/a")),
				Rec("pkg-b", "requests", "2.22.0", pkg.PythonPkg, "python-installed-package-cataloger", Loc("/b")),
				Rec("pkg-c", "requests", "2.22.0", pkg.PythonPkg, "binary-classifier-cataloger", Loc("/c")),
			},
			Want: ScenarioExpectation{OutputCount: 1, MergePairs: 2, States: []string{StateMerged}},
		},
		{
			// 3. a real version difference (package-manager revision) merges with a conflict mark
			Name: "revision-only version difference merges and is marked conflicting",
			Records: []Record{
				Rec("pkg-a", "libc6", "2.31-13", pkg.DebPkg, "dpkg-db-cataloger", Loc("/var/lib/dpkg/status")),
				Rec("pkg-b", "libc6", "2.31", pkg.DebPkg, "binary-classifier-cataloger", Loc("/lib/x86_64-linux-gnu/libc.so.6")),
			},
			Want: ScenarioExpectation{OutputCount: 1, MergePairs: 1, ConflictCount: 1, States: []string{StateMerged}},
		},
		{
			// 4. case, separators and namespace spelling normalize to one identity
			Name: "case separator and namespace spelling differences normalize",
			Records: []Record{
				Rec("pkg-a", "Foo_Bar", "1.0.0", pkg.PythonPkg, "python-package-cataloger", Loc("/a")),
				Rec("pkg-b", "foo-bar", "1.0.0", pkg.PythonPkg, "python-installed-package-cataloger", Loc("/b")),
				Rec("pkg-c", "foo.bar", "1.0.0", pkg.PythonPkg, "python-uv-lock-cataloger", Loc("/c")),
			},
			Want: ScenarioExpectation{OutputCount: 1, MergePairs: 2, States: []string{StateMerged}},
		},
		{
			// 5. checksum on one clue, path on another: both survive the merge
			Name: "checksum and path from separate sources merge without losing either",
			Records: []Record{
				Rec("pkg-a", "openssl", "3.0.2", pkg.ApkPkg, "apk-db-cataloger",
					Loc("/lib/apk/db/installed"), Sum("sha256", "aaaa", "apk-db-cataloger")),
				Rec("pkg-b", "openssl", "3.0.2-r1", pkg.ApkPkg, "binary-classifier-cataloger",
					Loc("/usr/bin/openssl")),
			},
			Want: ScenarioExpectation{OutputCount: 1, MergePairs: 1, ConflictCount: 1, States: []string{StateMerged}},
		},
		{
			// 6. genuinely distinct versions stay independent (no aggressive merge)
			Name: "distinct versions stay independent",
			Records: []Record{
				Rec("pkg-a", "numpy", "1.24.0", pkg.PythonPkg, "python-package-cataloger", Loc("/a")),
				Rec("pkg-b", "numpy", "1.25.0", pkg.PythonPkg, "python-installed-package-cataloger", Loc("/b")),
			},
			Want: ScenarioExpectation{OutputCount: 2, States: []string{StateUnique, StateUnique}},
		},
		{
			// 7. same component under two ecosystems: cross-referenced, not merged
			Name: "different package types are cross-referenced not merged",
			Records: []Record{
				Rec("pkg-a", "requests", "2.22.0", pkg.PythonPkg, "python-package-cataloger", Loc("/a")),
				Rec("pkg-b", "requests", "2.22.0", pkg.DebPkg, "dpkg-db-cataloger", Loc("/b")),
			},
			Want: ScenarioExpectation{OutputCount: 2, CrossReference: 1, States: []string{StateUnique, StateUnique}},
		},
		{
			// 8. missing version: independent and pending
			Name: "missing version keeps the entry independent and pending",
			Records: []Record{
				Rec("pkg-a", "busybox", "1.35.0", pkg.ApkPkg, "apk-db-cataloger", Loc("/a")),
				Rec("pkg-b", "busybox", "", pkg.ApkPkg, "binary-classifier-cataloger", Loc("/b")),
			},
			Want: ScenarioExpectation{OutputCount: 2, PendingCount: 1, States: []string{StateNeedsConfirmation, StateUnique}},
		},
		{
			// 9. contradictory purl: conservative non-merge, both pending
			Name: "contradictory purl blocks the merge",
			Records: []Record{
				Rec("pkg-a", "pygments", "2.6.1", pkg.PythonPkg, "python-package-cataloger",
					Loc("/a"), PURL("pkg:pypi/requests@2.22.0")),
				Rec("pkg-b", "pygments", "2.6.1", pkg.PythonPkg, "python-installed-package-cataloger", Loc("/b")),
			},
			Want: ScenarioExpectation{OutputCount: 2, ConflictCount: 1, PendingCount: 2, States: []string{StateNeedsConfirmation, StateNeedsConfirmation}},
		},
		{
			// 10. disagreeing checksums: both retained, conflict surfaced
			Name: "checksum disagreement is surfaced and both values retained",
			Records: []Record{
				Rec("pkg-a", "lodash", "4.17.21", pkg.NpmPkg, "javascript-package-cataloger",
					Loc("/a"), Sum("sha512", "aaaa", "lock-file")),
				Rec("pkg-b", "lodash", "4.17.21", pkg.NpmPkg, "javascript-lock-cataloger",
					Loc("/b"), Sum("sha512", "bbbb", "node-modules")),
			},
			Want: ScenarioExpectation{OutputCount: 1, MergePairs: 1, ConflictCount: 1, States: []string{StateMerged}},
		},
		{
			// 11. agreeing evidence unions external identifiers
			Name: "agreeing evidence unions external identifiers",
			Records: []Record{
				Rec("pkg-a", "@angular/core", "12.0.0", pkg.NpmPkg, "javascript-package-cataloger",
					Loc("/a"), PURL("pkg:npm/%40angular/core@12.0.0")),
				Rec("pkg-b", "angular/core", "12.0.0", pkg.NpmPkg, "javascript-lock-cataloger",
					Loc("/b"), ExtID("cpe", "cpe:2.3:a:angular:core:12.0.0:*:*:*:*:*:*:*", "declared")),
			},
			Want: ScenarioExpectation{OutputCount: 1, MergePairs: 1, States: []string{StateMerged}},
		},
		{
			// 12. no duplicates at all
			Name: "no duplicates leaves every entry unique",
			Records: []Record{
				Rec("pkg-a", "alpha", "1.0.0", pkg.PythonPkg, "python-package-cataloger", Loc("/a")),
				Rec("pkg-b", "beta", "2.0.0", pkg.PythonPkg, "python-package-cataloger", Loc("/b")),
				Rec("pkg-c", "gamma", "3.0.0", pkg.GemPkg, "ruby-package-cataloger", Loc("/c")),
			},
			Want: ScenarioExpectation{OutputCount: 3, States: []string{StateUnique, StateUnique, StateUnique}},
		},
	}
}
