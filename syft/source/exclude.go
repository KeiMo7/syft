package source

type ExcludeConfig struct {
	Paths    []string
	Rules    []PathExclusionRule
	Observer PathExclusionObserver
}

// PathExclusionRule links a source-level exclusion pattern back to the original
// exclusion rule index so traversal decisions can be audited.
type PathExclusionRule struct {
	Pattern   string
	RuleIndex int
}

// PathExclusionEvent describes one path skipped during source traversal.
type PathExclusionEvent struct {
	Pattern   string
	RuleIndex int
	Path      string
}

type PathExclusionObserver interface {
	ObservePathExclusion(PathExclusionEvent)
}

type PathExclusionObserverFunc func(PathExclusionEvent)

func (f PathExclusionObserverFunc) ObservePathExclusion(event PathExclusionEvent) {
	if f != nil {
		f(event)
	}
}

// PathExcluder is implemented by a source configured with path exclusion patterns, so the archive
// cataloger can apply the same exclusions inside the archives it extracts.
type PathExcluder interface {
	ExcludedPaths() []string
}
