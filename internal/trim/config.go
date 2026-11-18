package trim

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/bmatcuk/doublestar/v4"
	"go.yaml.in/yaml/v3"
)

const (
	CategoryDev   = "dev"
	CategoryTest  = "test"
	CategoryBuild = "build"
)

// ValidCategories is the complete set of category names accepted in trim configuration.
var ValidCategories = []string{CategoryBuild, CategoryDev, CategoryTest}

// DefaultExcludePaths are applied when trim is enabled and a policy does not explicitly provide
// exclude-paths. An explicitly empty list disables these defaults.
var DefaultExcludePaths = []string{
	"**/test/**",
	"**/tests/**",
	"**/testdata/**",
	"**/__tests__/**",
	"**/spec/**",
	"**/specs/**",
	"**/example/**",
	"**/examples/**",
	"**/sample/**",
	"**/samples/**",
	"**/fixtures/**",
}

// Config controls output-only component trimming.
type Config struct {
	Enabled       bool   `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	RuleFile      string `yaml:"rule-file,omitempty" json:"rule-file,omitempty" mapstructure:"rule-file"`
	BusinessLine  string `yaml:"business-line,omitempty" json:"business-line,omitempty" mapstructure:"business-line"`
	Policy        `yaml:",inline" json:",inline" mapstructure:",squash"`
	Default       Policy             `yaml:"default,omitempty" json:"default,omitempty" mapstructure:"default"`
	BusinessLines []BusinessLineRule `yaml:"business-lines,omitempty" json:"business-lines,omitempty" mapstructure:"business-lines"`

	state *configState `yaml:"-" json:"-" mapstructure:"-"`
}

// Policy describes one output trimming policy.
type Policy struct {
	// Categories maps category names to whether components in that category should be removed.
	Categories map[string]bool `yaml:"categories,omitempty" json:"categories,omitempty" mapstructure:"categories"`

	// ExcludePaths contains doublestar globs matched against all package locations. nil applies
	// DefaultExcludePaths; an explicitly empty slice disables path-based trimming.
	ExcludePaths []string `yaml:"exclude-paths,omitempty" json:"exclude-paths,omitempty" mapstructure:"exclude-paths"`

	// Classifiers lets a repository or business line refine what a category means.
	Classifiers []Classifier `yaml:"classifiers,omitempty" json:"classifiers,omitempty" mapstructure:"classifiers"`

	// DirectOnly removes dependencies that can be proven transitive.
	DirectOnly bool `yaml:"direct-only,omitempty" json:"direct-only,omitempty" mapstructure:"direct-only"`
}

// BusinessLineRule applies a policy to matching image/repository references.
type BusinessLineRule struct {
	Name   string   `yaml:"name" json:"name" mapstructure:"name"`
	Images []string `yaml:"images,omitempty" json:"images,omitempty" mapstructure:"images"`
	Policy `yaml:",inline" json:",inline" mapstructure:",squash"`
}

// Classifier adds category signals for specific packages, paths, metadata scopes, or catalogers.
// Every field that is set must match for the classifier to apply.
type Classifier struct {
	Category       string   `yaml:"category" json:"category" mapstructure:"category"`
	PackageGlobs   []string `yaml:"packages,omitempty" json:"packages,omitempty" mapstructure:"packages"`
	PathGlobs      []string `yaml:"paths,omitempty" json:"paths,omitempty" mapstructure:"paths"`
	MetadataScopes []string `yaml:"metadata-scopes,omitempty" json:"metadata-scopes,omitempty" mapstructure:"metadata-scopes"`
	FoundBy        []string `yaml:"found-by,omitempty" json:"found-by,omitempty" mapstructure:"found-by"`
}

type ruleFile struct {
	Default       Policy             `yaml:"default"`
	BusinessLines []BusinessLineRule `yaml:"business-lines"`
}

type ruleFileState struct {
	Digest string
}

type configState struct {
	mu        sync.Mutex
	fileState ruleFileState
}

var configStateInit sync.Mutex

func (c *Config) loadState() *configState {
	configStateInit.Lock()
	defer configStateInit.Unlock()

	if c.state == nil {
		c.state = &configState{}
	}
	return c.state
}

// PostLoad loads and validates an optional external rule file.
func (c *Config) PostLoad() error {
	if c.Enabled && c.RuleFile != "" {
		return c.ReloadRules()
	}
	return c.Validate()
}

// ReloadRules explicitly reloads the rule file (or re-validates inline rules when no file is set).
func (c *Config) ReloadRules() error {
	state := c.loadState()
	state.mu.Lock()
	defer state.mu.Unlock()

	if !c.Enabled {
		return nil
	}

	if c.RuleFile == "" {
		state.fileState = ruleFileState{Digest: c.rulesDigestLocked()}
		return c.validateLocked()
	}

	contents, err := os.ReadFile(c.RuleFile)
	if err != nil {
		return fmt.Errorf("unable to read trim rule file %q: %w", c.RuleFile, err)
	}

	var rules ruleFile
	if err := yaml.Unmarshal(contents, &rules); err != nil {
		return fmt.Errorf("unable to parse trim rule file %q: %w", c.RuleFile, err)
	}

	previousDefault, previousBusinessLines := c.Default, c.BusinessLines
	c.Default = rules.Default
	c.BusinessLines = rules.BusinessLines

	if err := c.validateLocked(); err != nil {
		c.Default, c.BusinessLines = previousDefault, previousBusinessLines
		return fmt.Errorf("invalid trim rule file %q: %w", c.RuleFile, err)
	}

	sum := sha256.Sum256(contents)
	state.fileState = ruleFileState{Digest: "sha256:" + hex.EncodeToString(sum[:])}
	return nil
}

// ReloadRulesIfChanged reloads a changed rule file and otherwise leaves the current rules in place.
// It is called immediately before output so a long-running embedder sees rule edits without a restart.
func (c *Config) ReloadRulesIfChanged() (bool, error) {
	state := c.loadState()
	state.mu.Lock()
	defer state.mu.Unlock()

	if !c.Enabled || c.RuleFile == "" {
		return false, nil
	}

	contents, err := os.ReadFile(c.RuleFile)
	if err != nil {
		return false, fmt.Errorf("unable to read trim rule file %q: %w", c.RuleFile, err)
	}

	sum := sha256.Sum256(contents)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if digest == state.fileState.Digest {
		return false, nil
	}

	var rules ruleFile
	if err := yaml.Unmarshal(contents, &rules); err != nil {
		return false, fmt.Errorf("unable to parse trim rule file %q: %w", c.RuleFile, err)
	}

	previousDefault, previousBusinessLines := c.Default, c.BusinessLines
	c.Default, c.BusinessLines = rules.Default, rules.BusinessLines
	if err := c.validateLocked(); err != nil {
		c.Default, c.BusinessLines = previousDefault, previousBusinessLines
		return false, fmt.Errorf("invalid trim rule file %q: %w", c.RuleFile, err)
	}

	state.fileState = ruleFileState{Digest: digest}
	return true, nil
}

// Validate verifies all category names and glob patterns.
func (c *Config) Validate() error {
	state := c.loadState()
	state.mu.Lock()
	defer state.mu.Unlock()
	return c.validateLocked()
}

func (c *Config) validateLocked() error {
	valid := make(map[string]struct{}, len(ValidCategories))
	for _, category := range ValidCategories {
		valid[category] = struct{}{}
	}

	validatePolicy := func(where string, policy Policy) error {
		for category := range policy.Categories {
			if _, ok := valid[category]; !ok {
				return fmt.Errorf("unknown trim category %q in %s; valid categories are: %s", category, where, strings.Join(ValidCategories, ", "))
			}
		}
		for _, classifier := range policy.Classifiers {
			if _, ok := valid[classifier.Category]; !ok {
				return fmt.Errorf("unknown trim category %q in %s classifier; valid categories are: %s", classifier.Category, where, strings.Join(ValidCategories, ", "))
			}
			for _, pattern := range append(append([]string{}, classifier.PackageGlobs...), classifier.PathGlobs...) {
				if !doublestar.ValidatePattern(pattern) {
					return fmt.Errorf("invalid trim glob %q in %s classifier", pattern, where)
				}
			}
		}
		for _, pattern := range policy.ExcludePaths {
			if !doublestar.ValidatePattern(pattern) {
				return fmt.Errorf("invalid trim exclude path %q in %s", pattern, where)
			}
		}
		return nil
	}

	if err := validatePolicy("default policy", c.Default); err != nil {
		return err
	}
	if err := validatePolicy("top-level default policy", c.Policy); err != nil {
		return err
	}

	names := make(map[string]struct{}, len(c.BusinessLines))
	for i, rule := range c.BusinessLines {
		name := rule.Name
		if name == "" {
			return fmt.Errorf("business line at index %d must have a name", i)
		}
		if _, exists := names[name]; exists {
			return fmt.Errorf("duplicate business line %q", name)
		}
		names[name] = struct{}{}

		if err := validatePolicy(fmt.Sprintf("business line %q", name), rule.Policy); err != nil {
			return err
		}
		for _, pattern := range rule.Images {
			if !doublestar.ValidatePattern(pattern) {
				return fmt.Errorf("invalid image glob %q in business line %q", pattern, name)
			}
		}
	}

	if c.BusinessLine != "" {
		if _, exists := names[c.BusinessLine]; !exists {
			return fmt.Errorf("unknown trim business line %q; configured business lines are: %s", c.BusinessLine, strings.Join(sortedKeys(names), ", "))
		}
	}

	return nil
}

func (c *Config) rulesDigestLocked() string {
	payload, err := json.Marshal(ruleFile{
		Default:       c.effectiveDefaultLocked(),
		BusinessLines: c.BusinessLines,
	})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

type configSnapshot struct {
	Enabled         bool
	BusinessLine    string
	Default         Policy
	BusinessLines   []BusinessLineRule
	RulesSource     string
	RulesDigest     string
	ReloadedAtApply bool
}

func (c *Config) snapshot() (configSnapshot, error) {
	state := c.loadState()
	state.mu.Lock()
	defer state.mu.Unlock()

	if !c.Enabled {
		return configSnapshot{Enabled: false}, nil
	}

	reloaded, err := c.reloadRulesIfChangedLocked()
	if err != nil {
		return configSnapshot{}, err
	}
	if err := c.validateLocked(); err != nil {
		return configSnapshot{}, err
	}

	source := "inline"
	digest := state.fileState.Digest
	if c.RuleFile != "" {
		source = "file:" + c.RuleFile
		if digest == "" {
			digest = c.rulesDigestLocked()
		}
	} else if digest == "" {
		digest = c.rulesDigestLocked()
	}

	return configSnapshot{
		Enabled:         true,
		BusinessLine:    c.BusinessLine,
		Default:         c.effectiveDefaultLocked(),
		BusinessLines:   cloneBusinessLines(c.BusinessLines),
		RulesSource:     source,
		RulesDigest:     digest,
		ReloadedAtApply: reloaded,
	}, nil
}

func (c *Config) effectiveDefaultLocked() Policy {
	if c.RuleFile != "" {
		return clonePolicy(c.Default)
	}

	out := clonePolicy(c.Policy)
	if c.Default.Categories != nil {
		if out.Categories == nil {
			out.Categories = map[string]bool{}
		}
		for category, enabled := range c.Default.Categories {
			out.Categories[category] = enabled
		}
	}
	if c.Default.ExcludePaths != nil {
		out.ExcludePaths = append([]string(nil), c.Default.ExcludePaths...)
	}
	if len(c.Default.Classifiers) > 0 {
		out.Classifiers = append(out.Classifiers, cloneClassifiers(c.Default.Classifiers)...)
	}
	if c.Default.DirectOnly {
		out.DirectOnly = true
	}
	return out
}

func (c *Config) reloadRulesIfChangedLocked() (bool, error) {
	state := c.loadState()
	if c.RuleFile == "" {
		return false, nil
	}

	contents, err := os.ReadFile(c.RuleFile)
	if err != nil {
		return false, fmt.Errorf("unable to read trim rule file %q: %w", c.RuleFile, err)
	}

	sum := sha256.Sum256(contents)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if digest == state.fileState.Digest {
		return false, nil
	}

	var rules ruleFile
	if err := yaml.Unmarshal(contents, &rules); err != nil {
		return false, fmt.Errorf("unable to parse trim rule file %q: %w", c.RuleFile, err)
	}

	previousDefault, previousBusinessLines := c.Default, c.BusinessLines
	c.Default, c.BusinessLines = rules.Default, rules.BusinessLines
	if err := c.validateLocked(); err != nil {
		c.Default, c.BusinessLines = previousDefault, previousBusinessLines
		return false, fmt.Errorf("invalid trim rule file %q: %w", c.RuleFile, err)
	}

	state.fileState = ruleFileState{Digest: digest}
	return true, nil
}

func clonePolicy(policy Policy) Policy {
	out := policy
	if policy.Categories != nil {
		out.Categories = make(map[string]bool, len(policy.Categories))
		for key, value := range policy.Categories {
			out.Categories[key] = value
		}
	}
	out.ExcludePaths = append([]string(nil), policy.ExcludePaths...)
	out.Classifiers = cloneClassifiers(policy.Classifiers)
	return out
}

func cloneClassifiers(classifiers []Classifier) []Classifier {
	out := make([]Classifier, len(classifiers))
	for i, classifier := range classifiers {
		out[i] = classifier
		out[i].PackageGlobs = append([]string(nil), classifier.PackageGlobs...)
		out[i].PathGlobs = append([]string(nil), classifier.PathGlobs...)
		out[i].MetadataScopes = append([]string(nil), classifier.MetadataScopes...)
		out[i].FoundBy = append([]string(nil), classifier.FoundBy...)
	}
	return out
}

func cloneBusinessLines(rules []BusinessLineRule) []BusinessLineRule {
	out := make([]BusinessLineRule, len(rules))
	for i, rule := range rules {
		out[i] = BusinessLineRule{
			Name:   rule.Name,
			Images: append([]string(nil), rule.Images...),
			Policy: clonePolicy(rule.Policy),
		}
	}
	return out
}
