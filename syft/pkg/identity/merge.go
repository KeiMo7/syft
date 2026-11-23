package identity

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

// DefaultConflictThreshold is the number of conflicts above which a merge result is still
// produced but the summary carries a prominent warning.
const DefaultConflictThreshold = 10

// Options configures a merge run.
type Options struct {
	// ConflictThreshold is the conflict count above which the report warns. Values <= 0 disable the
	// warning entirely.
	ConflictThreshold int
}

// DefaultOptions returns the default merge options.
func DefaultOptions() Options {
	return Options{ConflictThreshold: DefaultConflictThreshold}
}

// WithConflictThreshold returns a copy of the options with the given conflict threshold.
func (o Options) WithConflictThreshold(threshold int) Options {
	o.ConflictThreshold = threshold
	return o
}

// normalized is one input record with everything the merge needs precomputed.
type normalized struct {
	record       Record
	namespace    string
	name         string
	nameRules    []string
	versionClass string
	versionRules []string
	problems     []Conflict
}

func (n normalized) key() string {
	return strings.Join([]string{string(n.record.Type), n.namespace, n.name}, "|")
}

func (n normalized) identity() string {
	return strings.Join([]string{string(n.record.Type), n.namespace, n.name, n.versionClass}, "|")
}

// sortKey orders records without depending on the caller's input order.
func (n normalized) sortKey() string {
	return strings.Join([]string{
		string(n.record.Type), n.namespace, n.name, n.versionClass,
		n.record.Version, n.record.Name, n.record.ID,
	}, "\x00")
}

// Merge folds the given records into one output entry per component identity. The result is
// independent of the order of the input: records are sorted deterministically before any decision
// is made, and every tie is broken by value rather than by position.
func Merge(records []Record, opts Options) Result {
	prepared := prepare(records)

	components, groups, standalone, foldAway, conflictCnt, pendingCnt := mergeAll(prepared)
	crossRefs := crossReference(components)

	// stable output ordering
	sort.Slice(components, func(i, j int) bool {
		if components[i].Identity != components[j].Identity {
			return components[i].Identity < components[j].Identity
		}
		return components[i].ID < components[j].ID
	})
	sort.Slice(groups, func(i, j int) bool { return groups[i].Identity < groups[j].Identity })
	sort.Slice(standalone, func(i, j int) bool { return standalone[i].ID < standalone[j].ID })
	sort.Slice(crossRefs, func(i, j int) bool {
		if crossRefs[i].LeftID != crossRefs[j].LeftID {
			return crossRefs[i].LeftID < crossRefs[j].LeftID
		}
		return crossRefs[i].RightID < crossRefs[j].RightID
	})

	report := buildReport(
		len(records), components, groups, standalone, crossRefs,
		foldAway, conflictCnt, pendingCnt, opts,
	)

	return Result{Report: report, Components: components}
}

// prepare normalizes each record and sorts the result into a deterministic order.
func prepare(records []Record) []normalized {
	prepared := make([]normalized, len(records))
	for i, record := range records {
		prepared[i] = normalizeRecord(record)
	}
	sort.SliceStable(prepared, func(i, j int) bool {
		return prepared[i].sortKey() < prepared[j].sortKey()
	})
	return prepared
}

// mergeAll groups records by normalized name and type and merges each group. Different types never
// share a group: they are cross-referenced later instead of merged.
func mergeAll(prepared []normalized) (
	components []MergedComponent,
	groups []Group,
	standalone []Standalone,
	foldAway, conflictCnt, pendingCnt int,
) {
	byKey := map[string][]normalized{}
	var keyOrder []string
	for _, n := range prepared {
		k := n.key()
		if _, ok := byKey[k]; !ok {
			keyOrder = append(keyOrder, k)
		}
		byKey[k] = append(byKey[k], n)
	}
	sort.Strings(keyOrder)

	for _, k := range keyOrder {
		result, fold, conflicts, pending := mergeKeyGroup(byKey[k])
		components = append(components, result.components...)
		groups = append(groups, result.groups...)
		standalone = append(standalone, result.standalone...)
		foldAway += fold
		conflictCnt += conflicts
		pendingCnt += pending
	}
	return components, groups, standalone, foldAway, conflictCnt, pendingCnt
}

// buildReport assembles the self-describing report, including the threshold warning and the
// reconciliation arithmetic.
func buildReport(
	inputCount int,
	components []MergedComponent,
	groups []Group,
	standalone []Standalone,
	crossRefs []CrossReference,
	foldAway, conflictCnt, pendingCnt int,
	opts Options,
) MergeReport {
	threshold := max(opts.ConflictThreshold, 0)
	exceeded := threshold > 0 && conflictCnt > threshold

	if groups == nil {
		groups = []Group{}
	}
	if standalone == nil {
		standalone = []Standalone{}
	}
	if crossRefs == nil {
		crossRefs = []CrossReference{}
	}

	report := MergeReport{
		Version:             MergeVersion,
		InputCount:          inputCount,
		OutputCount:         len(components),
		MergePairCount:      foldAway,
		MergedCount:         mergedCount(components),
		UniqueCount:         uniqueCount(components),
		GroupCount:          len(groups),
		ConflictCount:       conflictCnt,
		PendingCount:        pendingCnt,
		CrossReferenceCount: len(crossRefs),
		ConflictThreshold:   threshold,
		ThresholdExceeded:   exceeded,
		Rules:               RuleCatalog(),
		Groups:              groups,
		Standalone:          standalone,
		CrossReferences:     crossRefs,
	}
	if exceeded {
		report.Warning = fmt.Sprintf(
			"%d conflicts exceed the configured threshold of %d; the merged result is complete but requires review",
			conflictCnt, threshold,
		)
	}

	report.Reconciliation = Reconciliation{
		InputCount:     inputCount,
		MergePairCount: foldAway,
		OutputCount:    len(components),
		Balanced:       inputCount-foldAway == len(components),
		Formula:        "inputCount - mergePairCount = outputCount",
	}

	return report
}

// keyResult is the output of merging one (type, namespace, name) group.
type keyResult struct {
	components []MergedComponent
	groups     []Group
	standalone []Standalone
}

// mergeKeyGroup merges all records that share a type and normalized name.
func mergeKeyGroup(members []normalized) (keyResult, int, int, int) {
	var out keyResult
	var fold, conflicts, pending int

	// A record whose purl contradicts its own fields makes the group unsafe to merge: two identity
	// rules disagree about what the record is, and the conservative action is to keep every member
	// independent and mark it for confirmation.
	for _, m := range members {
		if hasConflict(m.problems, "purl.disagrees") {
			for _, member := range members {
				component := standaloneComponent(member, StateNeedsConfirmation)
				out.components = append(out.components, component)
				out.standalone = append(out.standalone, Standalone{
					ID:        member.record.ID,
					Name:      member.record.Name,
					Version:   member.record.Version,
					Type:      member.record.Type,
					Reason:    "purl disagrees with package fields; identity is contradictory",
					State:     StateNeedsConfirmation,
					Conflicts: member.problems,
				})
				pending++
				// only the record whose own evidence contradicts itself contributes a conflict
				conflicts += len(member.problems)
			}
			return out, 0, conflicts, pending
		}
	}

	// partition by version class. Records without a version cannot be checked for equivalence and
	// are kept separate and pending, per the "insufficient evidence" rule.
	byClass := map[string][]normalized{}
	var classOrder []string
	var unversioned []normalized
	for _, m := range members {
		if m.versionClass == "" {
			unversioned = append(unversioned, m)
			continue
		}
		if _, ok := byClass[m.versionClass]; !ok {
			classOrder = append(classOrder, m.versionClass)
		}
		byClass[m.versionClass] = append(byClass[m.versionClass], m)
	}
	sort.Strings(classOrder)

	for _, class := range classOrder {
		// A version class groups a bare version with a revisioned one (2.31 with 2.31-13). It must
		// not group two different revisions (2.31-13 with 2.31-14): those are genuinely different
		// components. splitByRevision keeps the class whole only when at most one distinct revision
		// is present, which is the case the requirement permits merging.
		for _, subgroup := range splitByRevision(byClass[class]) {
			merged, group, conflictList := mergeClass(subgroup)

			out.components = append(out.components, merged)
			conflicts += len(conflictList)
			if len(subgroup) > 1 {
				fold += len(subgroup) - 1
				out.groups = append(out.groups, group)
			}
		}
	}

	// Records without a version are kept separate, but only those that name a component with no
	// versioned counterpart need confirmation. A missing-version record that shares its name with a
	// versioned entry is still independent: merging on name alone would be the aggressive merge the
	// rules forbid.
	for _, m := range unversioned {
		out.components = append(out.components, standaloneComponent(m, StateNeedsConfirmation))
		out.standalone = append(out.standalone, Standalone{
			ID:      m.record.ID,
			Name:    m.record.Name,
			Version: m.record.Version,
			Type:    m.record.Type,
			Reason:  "version is missing; identity cannot be confirmed (insufficient evidence, not a conflict)",
			State:   StateNeedsConfirmation,
		})
		pending++
	}

	return out, fold, conflicts, pending
}

// splitByRevision partitions a version class so that at most one distinct revision is folded with
// the bare (unrevisioned) version.
//
// The split only applies to OS package types, whose versions carry a package-manager revision. For
// every other type, versions in the same class are governed by semver canonicalization, so the
// whole group is equivalent. Members carrying no revision (their version is the class) form one
// subgroup. If exactly one revision suffix is present it shares that subgroup (the conflict the
// requirement permits merging); two or more distinct revisions never merge, and the bare records
// stay independent too.
func splitByRevision(members []normalized) [][]normalized {
	if len(members) < 2 || !osTypes[members[0].record.Type] {
		return [][]normalized{members}
	}

	class := members[0].versionClass
	var bare []normalized
	revisions := map[string][]normalized{}
	var revisionOrder []string
	for _, m := range members {
		if stripEpoch(m.record.Version) == class {
			bare = append(bare, m)
			continue
		}
		rev := revisionSuffix(class, m.record.Version)
		if _, ok := revisions[rev]; !ok {
			revisionOrder = append(revisionOrder, rev)
		}
		revisions[rev] = append(revisions[rev], m)
	}
	sort.Strings(revisionOrder)

	switch len(revisionOrder) {
	case 0:
		return [][]normalized{bare}
	case 1:
		// one revisioned spelling plus any bare records: the permitted revision-only merge
		group := append(append([]normalized{}, bare...), revisions[revisionOrder[0]]...)
		sort.SliceStable(group, func(i, j int) bool { return group[i].sortKey() < group[j].sortKey() })
		return [][]normalized{group}
	default:
		var groups [][]normalized
		if len(bare) > 0 {
			groups = append(groups, bare)
		}
		for _, rev := range revisionOrder {
			groups = append(groups, revisions[rev])
		}
		return groups
	}
}

// revisionSuffix returns the part of version not accounted for by the version class (the Debian/RPM
// release, the Alpine -rN, etc.), or the whole version when it is unrelated to the class.
func revisionSuffix(class, version string) string {
	if rest, ok := strings.CutPrefix(stripEpoch(version), class); ok {
		return rest
	}
	return version
}

// mergeClass folds all records of one component identity (same type, name and version class).
func mergeClass(members []normalized) (MergedComponent, Group, []Conflict) {
	first := members[0]
	facts := collectFacts(members)
	conflicts := versionConflicts(members, facts)

	component := MergedComponent{
		Identity:      first.identity(),
		Type:          first.record.Type,
		Namespace:     first.namespace,
		Name:          facts.displayName,
		Version:       facts.displayVersion,
		PURL:          canonicalPURL(facts.purls),
		Sources:       sortedUnique(facts.sources),
		Locations:     unionLocations(members),
		Licenses:      unionLicenses(members),
		Checksums:     unionChecksums(members),
		ExternalIDs:   unionExternalIDs(members),
		MetadataTypes: facts.metadataTypes,
		Members:       memberIDs(members),
		Rules:         sortedUnique(append(append([]string{RuleTypeExact}, facts.nameRules...), facts.versionRules...)),
		State:         StateUnique,
	}
	if len(members) > 1 {
		component.State = StateMerged
	}
	component.ID = componentID(component)
	component.Versions = facts.versionSet

	conflicts = append(conflicts, checksumConflicts(component.Checksums)...)
	component.Conflicts = conflicts
	component.ExternalIDs = dedupeExternalIDs(append(component.ExternalIDs, purlExternalIDs(component)...))

	group := Group{
		Identity:       component.Identity,
		Type:           component.Type,
		Namespace:      component.Namespace,
		Name:           component.Name,
		NormalizedName: first.name,
		Version:        component.Version,
		VersionValues:  facts.versionSet,
		Rules:          component.Rules,
		Matches:        facts.matches,
		Members:        memberSummaries(members),
		MergedID:       component.ID,
		Conflicts:      conflicts,
		Sources:        component.Sources,
		LocationCount:  len(component.Locations),
		State:          component.State,
	}

	return component, group, conflicts
}

// classFacts is everything about a merged class that is read from the member set at once: the
// display name and version, the raw version spellings, the sources, the cited rules and the pairs.
type classFacts struct {
	displayName    string
	displayVersion string
	versionSet     []string
	versionRules   []string
	nameRules      []string
	sources        []string
	purls          []string
	metadataTypes  []string
	matches        []Match
}

// collectFacts derives the deterministic display values and rule citations for a class.
func collectFacts(members []normalized) classFacts {
	var (
		rawNames     []string
		rawVersions  []string
		nameRuleSet  []string
		versionRules []string
		sources      []string
		purls        []string
		metadata     []string
		matches      []Match
	)

	for i, m := range members {
		rawNames = append(rawNames, m.record.Name)
		rawVersions = append(rawVersions, m.record.Version)
		sources = append(sources, m.record.FoundBy)
		if m.record.MetadataType != "" {
			metadata = append(metadata, m.record.MetadataType)
		}
		if m.record.PURL != "" {
			purls = append(purls, m.record.PURL)
		}
		if i > 0 {
			matches = append(matches, identityMatch(members[0], m))
			// Cite only the rules this pair actually needed, so a class whose members all spell the
			// name identically reports name.exact rather than a fold that never happened.
			nameRuleSet = append(nameRuleSet, nameRulesForPair(members[0].record.Name, m.record.Name)...)
			versionRules = append(versionRules, versionRulesForPair(members[0], m)...)
		}
	}

	sort.Strings(rawNames)
	sort.Strings(rawVersions)

	nameRules := sortedUnique(nameRuleSet)
	if len(nameRules) == 0 {
		nameRules = []string{RuleNameExact}
	}
	versionRules = sortedUnique(versionRules)
	if len(versionRules) == 0 {
		versionRules = []string{RuleVersionExact}
	}

	return classFacts{
		displayName:    rawNames[0],
		displayVersion: canonicalVersion(members),
		versionSet:     sortedUnique(rawVersions),
		versionRules:   versionRules,
		nameRules:      nameRules,
		sources:        sources,
		purls:          purls,
		metadataTypes:  sortedUnique(metadata),
		matches:        matches,
	}
}

// versionConflicts reports the revision-only version disagreement. A pure spelling difference
// (v1.2 vs 1.2.0) is not a conflict; only a package-manager revision is.
func versionConflicts(members []normalized, facts classFacts) []Conflict {
	if len(facts.versionSet) <= 1 {
		return nil
	}

	hasRevisionConflict := false
	for _, m := range members {
		rel := RelateVersions(members[0].record.Type, facts.displayVersion, m.record.Version)
		if !rel.Same && m.record.Version != facts.displayVersion {
			return nil
		}
		if rel.Conflict {
			hasRevisionConflict = true
		}
	}
	if !hasRevisionConflict {
		return nil
	}

	return []Conflict{{
		Field:      "version",
		Values:     facts.versionSet,
		Resolution: ResolutionKeptBoth,
		Rule:       RuleVersionRevision,
		Note:       "versions differ by the package-manager revision; both values are retained",
	}}
}

// mergedCount is the number of output entries folded from more than one source record.
func mergedCount(components []MergedComponent) int {
	n := 0
	for _, c := range components {
		if c.State == StateMerged {
			n++
		}
	}
	return n
}

// uniqueCount is the number of output entries that were not folded and are not pending.
func uniqueCount(components []MergedComponent) int {
	n := 0
	for _, c := range components {
		if c.State == StateUnique {
			n++
		}
	}
	return n
}

// canonicalVersion picks a stable display version. When a revision conflict exists the upstream
// version (the version class) is preferred; otherwise the lexicographically smallest raw version
// in the class is chosen so the result does not depend on input order.
func canonicalVersion(members []normalized) string {
	class := members[0].versionClass
	for _, m := range members {
		if m.record.Version == class {
			return m.record.Version
		}
	}
	versions := make([]string, 0, len(members))
	for _, m := range members {
		versions = append(versions, m.record.Version)
	}
	sort.Strings(versions)
	if len(versions) > 0 {
		return versions[0]
	}
	return class
}

// canonicalPURL picks the lexicographically smallest purl, which is stable across input orders.
func canonicalPURL(purls []string) string {
	if len(purls) == 0 {
		return ""
	}
	sort.Strings(purls)
	return purls[0]
}

// componentID derives a content-addressable ID from the identity, not from the merged evidence, so
// adding a location does not change which component this is.
func componentID(c MergedComponent) string {
	id, err := artifact.IDByHash(struct {
		Identity string
		Type     pkg.Type
		Version  string
	}{
		Identity: c.Identity,
		Type:     c.Type,
		Version:  c.Version,
	})
	if err != nil {
		// hashing a struct of strings cannot fail in practice; fall back to a stable literal.
		return c.Identity
	}
	return string(id)
}

// identityMatch records the rules that made a specific pair of records equivalent. The rules are
// computed pairwise so the citation says exactly what was needed for this pair: two records that
// both spell "1.2.3" cite version.exact, while "v1.2" against "1.2.0" cites version.semver-canonical.
func identityMatch(a, b normalized) Match {
	rules := nameRulesForPair(a.record.Name, b.record.Name)
	rules = append(rules, versionRulesForPair(a, b)...)
	return Match{
		Left:  a.record.ID,
		Right: b.record.ID,
		Rules: sortedUnique(rules),
	}
}

func memberIDs(members []normalized) []string {
	ids := make([]string, 0, len(members))
	for _, m := range members {
		ids = append(ids, m.record.ID)
	}
	sort.Strings(ids)
	return ids
}

func memberSummaries(members []normalized) []MemberSummary {
	out := make([]MemberSummary, 0, len(members))
	for _, m := range members {
		out = append(out, MemberSummary{
			ID:            m.record.ID,
			Name:          m.record.Name,
			Version:       m.record.Version,
			Type:          m.record.Type,
			PURL:          m.record.PURL,
			FoundBy:       m.record.FoundBy,
			MetadataType:  m.record.MetadataType,
			LocationCount: len(m.record.Locations),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// standaloneComponent builds the output entry for a record that is kept independent.
func standaloneComponent(m normalized, state string) MergedComponent {
	component := MergedComponent{
		Identity:      m.identity(),
		Type:          m.record.Type,
		Namespace:     m.namespace,
		Name:          m.record.Name,
		Version:       m.record.Version,
		Versions:      sortedUnique([]string{m.record.Version}),
		PURL:          m.record.PURL,
		Sources:       sortedUnique([]string{m.record.FoundBy}),
		Locations:     unionLocations([]normalized{m}),
		Licenses:      unionLicenses([]normalized{m}),
		Checksums:     unionChecksums([]normalized{m}),
		ExternalIDs:   dedupeExternalIDs(append(unionExternalIDs([]normalized{m}), purlExternalIDsFrom(m.record.PURL)...)),
		MetadataTypes: sortedUnique([]string{m.record.MetadataType}),
		Conflicts:     m.problems,
		Members:       []string{m.record.ID},
		Rules:         sortedUnique(m.nameRules),
		State:         state,
	}
	component.ID = componentID(component)
	return component
}

// normalizeRecord precomputes the identity facets of one record and any per-record contradictions.
func normalizeRecord(record Record) normalized {
	namespace, name, nameRules := normalizeName(record.Name)
	n := normalized{
		record:    record,
		namespace: namespace,
		name:      name,
		nameRules: nameRules,
	}

	if strings.TrimSpace(record.Name) == "" || record.Type == "" {
		n.problems = append(n.problems, Conflict{
			Field:      "identity",
			Values:     sortedUnique([]string{record.Name, string(record.Type)}),
			Resolution: ResolutionUnresolved,
			Rule:       "identity.insufficient",
			Note:       "name and type are required to establish identity",
		})
	}

	class, vRule := versionClass(record.Type, record.Version)
	n.versionClass = class
	if vRule != "" {
		n.versionRules = append(n.versionRules, vRule)
	}

	if ok, reason := purlAgrees(record); !ok {
		n.problems = append(n.problems, Conflict{
			Field:      "purl",
			Values:     sortedUnique([]string{record.PURL, record.Name, record.Version}),
			Resolution: ResolutionUnresolved,
			Rule:       "purl.disagrees",
			Note:       reason,
		})
	}
	return n
}

// purlAgrees reports whether a record's purl names the same component as its own name, version
// and type. An absent or unparseable purl is not evidence of disagreement.
func purlAgrees(record Record) (bool, string) {
	if strings.TrimSpace(record.PURL) == "" {
		return true, ""
	}
	purl, err := packageurl.FromString(record.PURL)
	if err != nil {
		return true, ""
	}

	purlName := purl.Name
	if purl.Namespace != "" {
		purlName = purl.Namespace + "/" + purl.Name
	}
	if !RelateNames(record.Name, purlName).Same && !RelateNames(record.Name, purl.Name).Same {
		return false, fmt.Sprintf("package url names %q but the package name is %q", purlName, record.Name)
	}

	if purl.Type != "" {
		if ty := pkg.TypeFromPURL(record.PURL); ty != pkg.UnknownPkg && ty != record.Type {
			return false, fmt.Sprintf("package url type implies %q but the package type is %q", ty, record.Type)
		}
	}

	if purl.Version != "" && record.Version != "" {
		if !RelateVersions(record.Type, record.Version, purl.Version).Same {
			return false, fmt.Sprintf("package url version %q differs from package version %q", purl.Version, record.Version)
		}
	}

	return true, ""
}

// hasConflict reports whether any conflict carries the given rule.
func hasConflict(conflicts []Conflict, rule string) bool {
	for _, c := range conflicts {
		if c.Rule == rule {
			return true
		}
	}
	return false
}

// crossReference links output entries that name the same component but have different package
// types. Linking component IDs (not member IDs) means a merged entry is referenced once, and a
// reviewer sees the link between the entries that actually appear in the output.
func crossReference(components []MergedComponent) []CrossReference {
	byName := map[string][]MergedComponent{}
	for _, c := range components {
		if c.Name == "" {
			continue
		}
		ns, name, _ := normalizeName(c.Name)
		byName[ns+"|"+name] = append(byName[ns+"|"+name], c)
	}

	var out []CrossReference
	seen := map[string]struct{}{}
	for _, group := range byName {
		for i := 0; i < len(group); i++ {
			for j := i + 1; j < len(group); j++ {
				a, b := group[i], group[j]
				if a.Type == b.Type {
					continue
				}
				if !componentsComparable(a, b) {
					continue
				}
				left, right := a.ID, b.ID
				if left > right {
					left, right = right, left
				}
				key := left + "\x00" + right
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, CrossReference{
					LeftID:  left,
					RightID: right,
					Reason:  fmt.Sprintf("%s and %s name the same component but are different package types; they are not merged", a.Type, b.Type),
				})
			}
		}
	}
	return out
}

// componentsComparable reports whether two entries have compatible version evidence. An entry
// without a version does not block a cross reference, but two distinct version classes do.
func componentsComparable(a, b MergedComponent) bool {
	aClass, _ := versionClass(a.Type, a.Version)
	bClass, _ := versionClass(b.Type, b.Version)
	if aClass == "" || bClass == "" {
		return true
	}
	return aClass == bClass
}

// locationKey is the de-duplication key for a location: the filesystem coordinates plus the
// access path, which is how syft already distinguishes two virtual locations for one file.
func locationKey(l Location) string {
	return l.RealPath + "\x00" + l.Path + "\x00" + l.AccessPath + "\x00" + l.LayerID
}

func locationLess(a, b Location) bool {
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	if a.RealPath != b.RealPath {
		return a.RealPath < b.RealPath
	}
	if a.AccessPath != b.AccessPath {
		return a.AccessPath < b.AccessPath
	}
	return a.LayerID < b.LayerID
}

// unionLocations returns every location from every member, de-duplicated by coordinates.
func unionLocations(members []normalized) []Location {
	seen := map[string]Location{}
	for _, m := range members {
		for _, l := range m.record.Locations {
			key := locationKey(l)
			existing, ok := seen[key]
			if !ok {
				seen[key] = l
				continue
			}
			// keep primary evidence if either side has it, otherwise keep the lexicographically
			// smaller annotation so the result does not depend on input order.
			if existing.Evidence != "primary" && l.Evidence == "primary" {
				existing.Evidence = l.Evidence
			}
			seen[key] = existing
		}
	}
	out := make([]Location, 0, len(seen))
	for _, l := range seen {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return locationLess(out[i], out[j]) })
	if out == nil {
		out = []Location{}
	}
	return out
}

// unionLicenses folds license findings, keeping every url and location each source reported.
func unionLicenses(members []normalized) []License {
	type key struct{ value, spdx, ty string }
	seen := map[key]*License{}
	for _, m := range members {
		for _, l := range m.record.Licenses {
			k := key{l.Value, l.SPDXExpression, l.Type}
			target, ok := seen[k]
			if !ok {
				copied := l
				copied.URLs = sortedUnique(l.URLs)
				copied.Locations = append([]Location{}, l.Locations...)
				sortLocations(copied.Locations)
				seen[k] = &copied
				continue
			}
			target.URLs = sortedUnique(append(target.URLs, l.URLs...))
			target.Locations = dedupeLocations(append(target.Locations, l.Locations...))
		}
	}
	out := make([]License, 0, len(seen))
	for _, l := range seen {
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value < out[j].Value
		}
		if out[i].SPDXExpression != out[j].SPDXExpression {
			return out[i].SPDXExpression < out[j].SPDXExpression
		}
		return out[i].Type < out[j].Type
	})
	if out == nil {
		out = []License{}
	}
	return out
}

func dedupeLocations(in []Location) []Location {
	seen := map[string]struct{}{}
	var out []Location
	for _, l := range in {
		key := locationKey(l)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, l)
	}
	sortLocations(out)
	return out
}

func sortLocations(locations []Location) {
	sort.Slice(locations, func(i, j int) bool { return locationLess(locations[i], locations[j]) })
}

// unionChecksums returns every checksum with its source, de-duplicated.
func unionChecksums(members []normalized) []Checksum {
	seen := map[string]Checksum{}
	for _, m := range members {
		for _, c := range m.record.Checksums {
			key := c.Algorithm + "\x00" + c.Value + "\x00" + c.Source
			seen[key] = c
		}
	}
	out := make([]Checksum, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Algorithm != out[j].Algorithm {
			return out[i].Algorithm < out[j].Algorithm
		}
		if out[i].Value != out[j].Value {
			return out[i].Value < out[j].Value
		}
		return out[i].Source < out[j].Source
	})
	if out == nil {
		out = []Checksum{}
	}
	return out
}

// checksumConflicts reports checksums that disagree for one algorithm. Both values are retained.
func checksumConflicts(checksums []Checksum) []Conflict {
	byAlgorithm := map[string][]string{}
	for _, c := range checksums {
		byAlgorithm[c.Algorithm] = append(byAlgorithm[c.Algorithm], c.Value)
	}
	var out []Conflict
	var algorithms []string
	for algorithm := range byAlgorithm {
		algorithms = append(algorithms, algorithm)
	}
	sort.Strings(algorithms)
	for _, algorithm := range algorithms {
		values := sortedUnique(byAlgorithm[algorithm])
		if len(values) < 2 {
			continue
		}
		out = append(out, Conflict{
			Field:      "checksum:" + algorithm,
			Values:     values,
			Resolution: ResolutionKeptBoth,
			Rule:       "checksum.conflict",
			Note:       "records disagree on the checksum; both values are retained",
		})
	}
	return out
}

func unionExternalIDs(members []normalized) []ExternalID {
	var out []ExternalID
	for _, m := range members {
		out = append(out, m.record.ExternalIDs...)
		out = append(out, purlExternalIDsFrom(m.record.PURL)...)
	}
	return dedupeExternalIDs(out)
}

func purlExternalIDs(component MergedComponent) []ExternalID {
	return purlExternalIDsFrom(component.PURL)
}

func purlExternalIDsFrom(purl string) []ExternalID {
	if strings.TrimSpace(purl) == "" {
		return nil
	}
	return []ExternalID{{Type: "purl", Value: purl, Source: "package-url"}}
}

func dedupeExternalIDs(in []ExternalID) []ExternalID {
	seen := map[string]ExternalID{}
	for _, id := range in {
		key := id.Type + "\x00" + id.Value + "\x00" + id.Source
		seen[key] = id
	}
	out := make([]ExternalID, 0, len(seen))
	for _, id := range seen {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		if out[i].Value != out[j].Value {
			return out[i].Value < out[j].Value
		}
		return out[i].Source < out[j].Source
	})
	if out == nil {
		out = []ExternalID{}
	}
	return out
}
