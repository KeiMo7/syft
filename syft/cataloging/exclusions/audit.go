package exclusions

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

const AuditSchemaVersion = "1"

type PackageRef struct {
	ID      string `json:"id" yaml:"id" mapstructure:"id"`
	Name    string `json:"name" yaml:"name" mapstructure:"name"`
	Version string `json:"version,omitempty" yaml:"version,omitempty" mapstructure:"version"`
	Type    string `json:"type,omitempty" yaml:"type,omitempty" mapstructure:"type"`
}

type RuleAudit struct {
	Index               int        `json:"index" yaml:"index" mapstructure:"index"`
	Rule                RuleConfig `json:"rule" yaml:"rule" mapstructure:"rule"`
	MatchedPackageCount int        `json:"matched-package-count" yaml:"matched-package-count" mapstructure:"matched-package-count"`
	MatchedPathCount    int        `json:"matched-path-count,omitempty" yaml:"matched-path-count,omitempty" mapstructure:"matched-path-count"`
}

type Match struct {
	Package   PackageRef `json:"package" yaml:"package" mapstructure:"package"`
	Action    Action     `json:"action" yaml:"action" mapstructure:"action"`
	RuleIndex int        `json:"rule-index" yaml:"rule-index" mapstructure:"rule-index"`
	Path      string     `json:"path,omitempty" yaml:"path,omitempty" mapstructure:"path"`
	Layer     string     `json:"layer,omitempty" yaml:"layer,omitempty" mapstructure:"layer"`
	Reason    string     `json:"reason" yaml:"reason" mapstructure:"reason"`
}

type CatalogerSkip struct {
	Cataloger string `json:"cataloger" yaml:"cataloger" mapstructure:"cataloger"`
	RuleIndex int    `json:"rule-index" yaml:"rule-index" mapstructure:"rule-index"`
	Ecosystem string `json:"ecosystem" yaml:"ecosystem" mapstructure:"ecosystem"`
}

type PathMatch struct {
	RuleIndex int    `json:"rule-index" yaml:"rule-index" mapstructure:"rule-index"`
	Pattern   string `json:"pattern" yaml:"pattern" mapstructure:"pattern"`
	Path      string `json:"path" yaml:"path" mapstructure:"path"`
}

type Audit struct {
	SchemaVersion         string          `json:"schema-version" yaml:"schema-version" mapstructure:"schema-version"`
	Interrupted           bool            `json:"interrupted,omitempty" yaml:"interrupted,omitempty" mapstructure:"interrupted"`
	Rules                 []RuleAudit     `json:"rules" yaml:"rules" mapstructure:"rules"`
	EvaluatedPackageCount int             `json:"evaluated-package-count" yaml:"evaluated-package-count" mapstructure:"evaluated-package-count"`
	ExcludedPackageCount  int             `json:"excluded-package-count" yaml:"excluded-package-count" mapstructure:"excluded-package-count"`
	IncludedPackageCount  int             `json:"included-package-count" yaml:"included-package-count" mapstructure:"included-package-count"`
	RemainingPackageCount int             `json:"remaining-package-count" yaml:"remaining-package-count" mapstructure:"remaining-package-count"`
	ExcludedPathCount     int             `json:"excluded-path-count,omitempty" yaml:"excluded-path-count,omitempty" mapstructure:"excluded-path-count"`
	Matches               []Match         `json:"matches,omitempty" yaml:"matches,omitempty" mapstructure:"matches"`
	PathMatches           []PathMatch     `json:"path-matches,omitempty" yaml:"path-matches,omitempty" mapstructure:"path-matches"`
	SkippedCatalogers     []CatalogerSkip `json:"skipped-catalogers,omitempty" yaml:"skipped-catalogers,omitempty" mapstructure:"skipped-catalogers"`
}

type PathRecorder struct {
	mu      sync.Mutex
	matches map[string]PathMatch
}

func NewPathRecorder() *PathRecorder {
	return &PathRecorder{matches: map[string]PathMatch{}}
}

func (r *PathRecorder) Record(ruleIndex int, pattern, path string) {
	if r == nil || ruleIndex <= 0 || path == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// One path contributes once, even when several overlapping rules match it.
	if _, exists := r.matches[path]; !exists {
		r.matches[path] = PathMatch{
			RuleIndex: ruleIndex,
			Pattern:   pattern,
			Path:      path,
		}
	}
}

func (r *PathRecorder) Apply(audit *Audit) {
	if r == nil || audit == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	matches := make([]PathMatch, 0, len(r.matches))
	perRule := map[int]int{}
	for _, match := range r.matches {
		matches = append(matches, match)
		perRule[match.RuleIndex]++
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].RuleIndex != matches[j].RuleIndex {
			return matches[i].RuleIndex < matches[j].RuleIndex
		}
		return matches[i].Path < matches[j].Path
	})
	audit.PathMatches = matches
	audit.ExcludedPathCount = len(matches)
	for i := range audit.Rules {
		audit.Rules[i].MatchedPathCount = perRule[audit.Rules[i].Index]
	}
}

// IsOverlyBroad reports whether exclusions removed every component that was available
// to evaluate. Callers must warn in this case instead of returning a silently empty SBOM.
func (a Audit) IsOverlyBroad() bool {
	if a.RemainingPackageCount != 0 {
		return false
	}
	return a.EvaluatedPackageCount > 0 || len(a.SkippedCatalogers) > 0 || a.ExcludedPathCount > 0
}

// Writer persists an audit trail atomically. This is intentionally independent from the
// final SBOM writer so an interrupted scan can still leave the exclusion evidence on disk.
type Writer struct {
	path string
	mu   sync.Mutex
}

func NewWriter(path string) *Writer {
	return &Writer{path: path}
}

func (w *Writer) Path() string {
	if w == nil {
		return ""
	}
	return w.path
}

func (w *Writer) Write(audit Audit) error {
	if w == nil || w.path == "" {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	contents, err := json.MarshalIndent(audit, "", "  ")
	if err != nil {
		return fmt.Errorf("unable to encode exclusion audit: %w", err)
	}
	contents = append(contents, '\n')

	dir := filepath.Dir(w.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("unable to create exclusion audit directory %q: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(w.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("unable to create temporary exclusion audit file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(contents); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("unable to write exclusion audit: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("unable to sync exclusion audit: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("unable to close exclusion audit: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("unable to set exclusion audit permissions: %w", err)
	}
	if err := os.Rename(tmpName, w.path); err != nil {
		return fmt.Errorf("unable to persist exclusion audit %q: %w", w.path, err)
	}

	return nil
}
