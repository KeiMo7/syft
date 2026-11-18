package exclusions

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type compiledRule struct {
	index           int
	config          RuleConfig
	action          Action
	path            string
	ecosystem       string
	ecosystemTokens []string
	layer           string
	specificity     int
}

type Matcher struct {
	rules []compiledRule
}

func NewMatcher(cfg Config) (*Matcher, error) {
	m := &Matcher{}

	for i, raw := range cfg.Rules {
		index := i + 1
		rule, err := compileRule(index, raw)
		if err != nil {
			return nil, err
		}
		m.rules = append(m.rules, rule)
	}

	return m, nil
}

func compileRule(index int, raw RuleConfig) (compiledRule, error) {
	if raw.Empty() {
		return compiledRule{}, fmt.Errorf("exclusion rule %d: rule must contain at least one of path, ecosystem, or layer", index)
	}

	action := raw.action()
	if action != ExcludeAction && action != IncludeAction {
		return compiledRule{}, fmt.Errorf("exclusion rule %d: invalid action %q (expected exclude or include)", index, raw.Action)
	}

	rule := compiledRule{
		index:     index,
		config:    raw,
		action:    action,
		ecosystem: strings.ToLower(strings.TrimSpace(raw.Ecosystem)),
		layer:     normalizePattern(raw.Layer),
	}

	if raw.Path != "" {
		rule.path = normalizePattern(raw.Path)
		if rule.path == "" {
			return compiledRule{}, fmt.Errorf("exclusion rule %d: path must not be empty", index)
		}
		if !doublestar.ValidatePattern(rule.path) {
			return compiledRule{}, fmt.Errorf("exclusion rule %d: invalid path wildcard %q: malformed glob pattern (check bracket and brace balancing)", index, raw.Path)
		}
	}
	if raw.Layer != "" {
		if !doublestar.ValidatePattern(rule.layer) {
			return compiledRule{}, fmt.Errorf("exclusion rule %d: invalid layer wildcard %q: malformed glob pattern (check bracket and brace balancing)", index, raw.Layer)
		}
	}
	if rule.ecosystem != "" {
		rule.ecosystemTokens = ecosystemTokens(rule.ecosystem)
		if len(rule.ecosystemTokens) == 0 {
			return compiledRule{}, fmt.Errorf("exclusion rule %d: ecosystem must not be empty", index)
		}
	}

	rule.specificity = rule.calculateSpecificity()
	return rule, nil
}

func (r compiledRule) calculateSpecificity() int {
	dimensions := 0
	if r.path != "" {
		dimensions++
	}
	if r.ecosystem != "" {
		dimensions++
	}
	if r.layer != "" {
		dimensions++
	}

	pathSpecificity := 0
	if r.path != "" {
		literal := 0
		for _, char := range r.path {
			switch char {
			case '*', '?', '[', ']', '{', '}':
			default:
				literal++
			}
		}
		segments := len(strings.Split(strings.Trim(r.path, "/"), "/"))
		pathSpecificity = literal + (segments * 100)
	}

	layerSpecificity := 0
	if r.layer != "" {
		layerSpecificity = 10
		if !hasGlobMeta(r.layer) {
			layerSpecificity = 100
		}
	}

	return (dimensions * 1_000_000) + pathSpecificity + layerSpecificity
}

func (r compiledRule) matchesLocation(location file.Location) bool {
	if r.path != "" && !matchPath(r.path, location) {
		return false
	}
	if r.layer != "" && !matchLayer(r.layer, location.FileSystemID) {
		return false
	}
	return true
}

func (r compiledRule) matchesEcosystem(tokens []string) bool {
	if r.ecosystem == "" {
		return true
	}
	for _, expected := range r.ecosystemTokens {
		if slices.Contains(tokens, expected) {
			return true
		}
	}
	return false
}

func (r compiledRule) matchesTask(selectors []string) bool {
	tokens := make([]string, 0, len(selectors))
	for _, selector := range selectors {
		tokens = append(tokens, ecosystemTokens(selector)...)
	}
	return r.matchesEcosystem(tokens)
}

func (r compiledRule) purePathExclusion() bool {
	return r.action == ExcludeAction && r.path != "" && r.ecosystem == "" && r.layer == ""
}

func (r compiledRule) pureEcosystemExclusion() bool {
	return r.action == ExcludeAction && r.ecosystem != "" && r.path == "" && r.layer == ""
}

func (m *Matcher) HasIncludeRules() bool {
	for _, rule := range m.rules {
		if rule.action == IncludeAction {
			return true
		}
	}
	return false
}

// SourcePathExclusions returns path patterns that can safely prune traversal before
// catalogers run. Rules with other dimensions or any include exception remain package-level.
func (m *Matcher) SourcePathExclusions() []string {
	rules := m.SourcePathRules()
	paths := make([]string, 0, len(rules))
	for _, rule := range rules {
		paths = append(paths, rule.Pattern)
	}
	return paths
}

type SourcePathRule struct {
	Pattern   string `json:"pattern" yaml:"pattern" mapstructure:"pattern"`
	RuleIndex int    `json:"rule-index" yaml:"rule-index" mapstructure:"rule-index"`
}

func (m *Matcher) SourcePathRules() []SourcePathRule {
	if m == nil || m.HasIncludeRules() {
		return nil
	}

	seen := map[string]struct{}{}
	var rules []SourcePathRule
	for _, rule := range m.rules {
		if !rule.purePathExclusion() {
			continue
		}
		path := rule.path
		if !strings.HasPrefix(path, "./") && !strings.HasPrefix(path, "*/") && !strings.HasPrefix(path, "**/") {
			path = "./" + path
		}
		if _, exists := seen[path]; exists {
			continue
		}
		seen[path] = struct{}{}
		rules = append(rules, SourcePathRule{Pattern: path, RuleIndex: rule.index})
	}
	return rules
}

func (m *Matcher) RuleAudits() []RuleAudit {
	if m == nil {
		return nil
	}
	out := make([]RuleAudit, 0, len(m.rules))
	for _, rule := range m.rules {
		out = append(out, RuleAudit{Index: rule.index, Rule: rule.config})
	}
	return out
}

// TaskExcluded reports whether a package cataloger can be disabled entirely. This is only
// possible for a pure ecosystem exclusion with no include exception; mixed rules still need
// the parser to run so package-level path/layer matching can be evaluated.
func (m *Matcher) TaskExcluded(selectors []string) (CatalogerSkip, bool) {
	if m == nil || m.HasIncludeRules() {
		return CatalogerSkip{}, false
	}

	for i := len(m.rules) - 1; i >= 0; i-- {
		rule := m.rules[i]
		if !rule.pureEcosystemExclusion() || !rule.matchesTask(selectors) {
			continue
		}
		return CatalogerSkip{
			RuleIndex: rule.index,
			Ecosystem: rule.config.Ecosystem,
		}, true
	}
	return CatalogerSkip{}, false
}

type Result struct {
	Keep      []pkg.Package
	RemoveIDs []string
	Audit     Audit
}

type decision struct {
	rule     compiledRule
	location *file.Location
}

type packageEvaluation struct {
	excluded     bool
	best         decision
	hasDecision  bool
	matchedRules map[int]struct{}
}

func (m *Matcher) Evaluate(packages []pkg.Package) Result {
	if m == nil || len(m.rules) == 0 {
		return Result{Keep: packages}
	}

	audit := Audit{
		SchemaVersion: AuditSchemaVersion,
		Rules:         m.RuleAudits(),
	}

	ruleMatches := make([]map[string]struct{}, len(m.rules))
	for i := range ruleMatches {
		ruleMatches[i] = map[string]struct{}{}
	}

	result := Result{Audit: audit}
	seenPackages := map[string]struct{}{}

	for _, p := range packages {
		packageID := string(p.ID())
		if _, exists := seenPackages[packageID]; exists {
			continue
		}
		seenPackages[packageID] = struct{}{}
		result.Audit.EvaluatedPackageCount++

		evaluation := m.evaluatePackage(p)
		for index := range evaluation.matchedRules {
			ruleMatches[index-1][packageID] = struct{}{}
		}

		if evaluation.excluded {
			result.RemoveIDs = append(result.RemoveIDs, packageID)
			result.Audit.ExcludedPackageCount++
			result.Audit.Matches = append(result.Audit.Matches, makeMatch(p, evaluation.best, ExcludeAction))
			continue
		}

		result.Keep = append(result.Keep, p)
		if evaluation.hasDecision && evaluation.best.rule.action == IncludeAction {
			result.Audit.IncludedPackageCount++
			result.Audit.Matches = append(result.Audit.Matches, makeMatch(p, evaluation.best, IncludeAction))
		}
	}

	for i := range result.Audit.Rules {
		result.Audit.Rules[i].MatchedPackageCount = len(ruleMatches[i])
	}
	sort.Slice(result.Audit.Matches, func(i, j int) bool {
		if result.Audit.Matches[i].RuleIndex != result.Audit.Matches[j].RuleIndex {
			return result.Audit.Matches[i].RuleIndex < result.Audit.Matches[j].RuleIndex
		}
		return result.Audit.Matches[i].Package.ID < result.Audit.Matches[j].Package.ID
	})
	result.Audit.RemainingPackageCount = len(result.Keep)
	return result
}

func (m *Matcher) evaluatePackage(p pkg.Package) packageEvaluation {
	locations := p.Locations.ToSlice()
	if len(locations) == 0 {
		locations = []file.Location{{}}
	}

	evaluation := packageEvaluation{
		matchedRules: map[int]struct{}{},
	}
	allLocationsExcluded := true

	for _, location := range locations {
		loc := location
		d, matched := m.bestDecision(p, &loc)
		if !matched {
			allLocationsExcluded = false
			continue
		}

		evaluation.matchedRules[d.rule.index] = struct{}{}
		if !evaluation.hasDecision || moreSpecific(d, evaluation.best) {
			evaluation.best = d
			evaluation.hasDecision = true
		}
		if d.rule.action == IncludeAction {
			allLocationsExcluded = false
		}
	}

	evaluation.excluded = allLocationsExcluded &&
		evaluation.hasDecision &&
		evaluation.best.rule.action == ExcludeAction
	return evaluation
}

func (m *Matcher) bestDecision(p pkg.Package, location *file.Location) (decision, bool) {
	var best decision
	found := false

	for _, rule := range m.rules {
		if rule.ecosystem != "" && !rule.matchesEcosystem(packageEcosystems(p)) {
			continue
		}
		if (rule.path != "" || rule.layer != "") && (location == nil || !rule.matchesLocation(*location)) {
			continue
		}
		candidate := decision{rule: rule, location: location}
		if !found || moreSpecific(candidate, best) {
			best = candidate
			found = true
		}
	}

	return best, found
}

func moreSpecific(a, b decision) bool {
	if a.rule.specificity != b.rule.specificity {
		return a.rule.specificity > b.rule.specificity
	}
	if a.rule.action != b.rule.action {
		return a.rule.action == IncludeAction
	}
	return a.rule.index > b.rule.index
}

func makeMatch(p pkg.Package, d decision, action Action) Match {
	match := Match{
		Package: PackageRef{
			ID:      string(p.ID()),
			Name:    p.Name,
			Version: p.Version,
			Type:    p.Type.String(),
		},
		Action:    action,
		RuleIndex: d.rule.index,
		Reason:    fmt.Sprintf("%s by exclusion rule %d", action, d.rule.index),
	}
	if d.location != nil {
		match.Path = d.location.FullNestedPath()
		match.Layer = d.location.FileSystemID
	}
	return match
}

func packageEcosystems(p pkg.Package) []string {
	values := []string{
		string(p.Type),
		string(p.Language),
		p.FoundBy,
	}
	if p.PURL != "" {
		values = append(values, pkg.TypeFromPURL(p.PURL).String())
	}

	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		for _, token := range ecosystemTokens(value) {
			if _, exists := seen[token]; exists {
				continue
			}
			seen[token] = struct{}{}
			out = append(out, token)
		}
	}
	return out
}

func ecosystemTokens(value string) []string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return nil
	}

	aliases := map[string][]string{
		"npm":        {"npm", "javascript", "node"},
		"yarn":       {"npm", "javascript", "node"},
		"pnpm":       {"npm", "javascript", "node"},
		"node":       {"npm", "javascript", "node"},
		"nodejs":     {"npm", "javascript", "node"},
		"node.js":    {"npm", "javascript", "node"},
		"javascript": {"npm", "javascript", "node"},
		"js":         {"npm", "javascript", "node"},
		"pip":        {"python", "pypi", "pip"},
		"pypi":       {"python", "pypi", "pip"},
		"go":         {"go", "golang", "go-module", "gomod"},
		"golang":     {"go", "golang", "go-module", "gomod"},
		"gomod":      {"go", "golang", "go-module", "gomod"},
		"maven":      {"java", "maven", "java-archive", "jvm", "gradle"},
		"java":       {"java", "maven", "java-archive", "jvm", "gradle"},
		"gradle":     {"java", "maven", "java-archive", "jvm", "gradle"},
		"cargo":      {"rust", "cargo", "rust-crate"},
		"rust":       {"rust", "cargo", "rust-crate"},
		"gem":        {"ruby", "gem", "gemspec"},
		"ruby":       {"ruby", "gem", "gemspec"},
		"composer":   {"php", "composer", "php-composer"},
		"php":        {"php", "composer", "php-composer"},
		"nuget":      {"dotnet", "nuget"},
		"dotnet":     {"dotnet", "nuget"},
		"conan":      {"cpp", "conan", "c++"},
		"vcpkg":      {"cpp", "vcpkg", "c++"},
		"cargo-lock": {"rust", "cargo", "rust-crate"},
		"os":         {"os", "rpm", "deb", "apk", "alpm", "portage", "distro"},
	}
	if tokens, ok := aliases[value]; ok {
		return tokens
	}

	tokens := []string{value}
	for _, token := range strings.FieldsFunc(value, func(r rune) bool {
		return r == '-' || r == '_' || r == '/' || r == '.' || r == ' '
	}) {
		tokens = append(tokens, token)
	}
	return uniqueStrings(tokens)
}

func normalizePattern(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, `\`, "/"))
	value = strings.TrimPrefix(value, "./")
	value = strings.TrimPrefix(value, "/")
	return strings.TrimSuffix(value, "/")
}

func matchPath(pattern string, location file.Location) bool {
	candidates := []string{
		location.FullNestedPath(),
		location.AccessPath,
		location.LocalPath(),
	}
	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		candidate = normalizePattern(candidate)
		if candidate == "" {
			continue
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}

		if matchGlob(pattern, candidate) {
			return true
		}
		// A non-wildcard path is a directory prefix. This makes "app/vendor"
		// exclude both the directory itself and everything below it.
		if !hasGlobMeta(pattern) && matchGlob(pattern+"/**", candidate) {
			return true
		}
	}
	return false
}

func matchLayer(pattern, layer string) bool {
	if pattern == "" {
		return true
	}
	return matchGlob(pattern, strings.TrimSpace(layer))
}

func matchGlob(pattern, value string) bool {
	ok, err := doublestar.Match(pattern, value)
	return err == nil && ok
}

func hasGlobMeta(value string) bool {
	return strings.ContainsAny(value, "*?[]{}")
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
