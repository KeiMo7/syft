package exclusions

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestMatcherPathRules(t *testing.T) {
	vendor := testPackage("vendor-pkg", pkg.NpmPkg, "/app/vendor/lib/index.js", "layer-1")
	root := testPackage("root-pkg", pkg.NpmPkg, "/app/index.js", "layer-1")

	matcher := requireMatcher(t, Config{Rules: []RuleConfig{
		{Path: "**/vendor/**"},
		{Path: "app/vendor"},
	}})

	result := matcher.Evaluate([]pkg.Package{vendor, root})

	require.Len(t, result.RemoveIDs, 1)
	assert.Equal(t, string(vendor.ID()), result.RemoveIDs[0])
	assert.Equal(t, 1, result.Audit.ExcludedPackageCount)
	assert.Equal(t, 1, result.Audit.RemainingPackageCount)
	assert.Len(t, result.Audit.Matches, 1, "overlapping rules must not duplicate the package hit")
	assert.Equal(t, "vendor-pkg", result.Audit.Matches[0].Package.Name)
}

func TestMatcherEcosystemRule(t *testing.T) {
	npmPkg := testPackage("left-pad", pkg.NpmPkg, "/app/node_modules/left-pad/index.js", "layer-1")
	npmPkg.Language = pkg.JavaScript
	goPkg := testPackage("example", pkg.GoModulePkg, "/app/main.go", "layer-1")
	goPkg.Language = pkg.Go

	matcher := requireMatcher(t, Config{Rules: []RuleConfig{{Ecosystem: "npm"}}})
	result := matcher.Evaluate([]pkg.Package{npmPkg, goPkg})

	assert.Equal(t, []string{string(npmPkg.ID())}, result.RemoveIDs)
	require.Len(t, result.Keep, 1)
	assert.Equal(t, goPkg.Name, result.Keep[0].Name)
	assert.Equal(t, 1, result.Audit.Rules[0].MatchedPackageCount)
}

func TestMatcherLayerRule(t *testing.T) {
	excluded := testPackage("old", pkg.DebPkg, "/usr/bin/old", "sha256:layer-a")
	kept := testPackage("new", pkg.DebPkg, "/usr/bin/new", "sha256:layer-b")

	matcher := requireMatcher(t, Config{Rules: []RuleConfig{{Layer: "sha256:layer-a"}}})
	result := matcher.Evaluate([]pkg.Package{excluded, kept})

	assert.Equal(t, []string{string(excluded.ID())}, result.RemoveIDs)
	require.Len(t, result.Keep, 1)
	assert.Equal(t, "new", result.Keep[0].Name)
}

func TestMatcherKeepsPackageWithOneSurvivingLocation(t *testing.T) {
	p := testPackage("multi-location", pkg.NpmPkg, "/app/vendor/index.js", "sha256:layer-a")
	p.Locations.Add(file.NewLocationFromCoordinates(file.Coordinates{
		RealPath:     "/app/runtime/index.js",
		FileSystemID: "sha256:layer-b",
	}))
	p.SetID()

	matcher := requireMatcher(t, Config{Rules: []RuleConfig{{Path: "**/vendor/**"}}})
	result := matcher.Evaluate([]pkg.Package{p})

	assert.Empty(t, result.RemoveIDs)
	require.Len(t, result.Keep, 1)
}

func TestMatcherMoreSpecificIncludeWins(t *testing.T) {
	runtimePkg := testPackage("runtime", pkg.NpmPkg, "/app/vendor/runtime/index.js", "layer-1")
	devPkg := testPackage("dev", pkg.NpmPkg, "/app/vendor/dev/index.js", "layer-1")

	matcher := requireMatcher(t, Config{Rules: []RuleConfig{
		{Action: ExcludeAction, Path: "**/vendor/**"},
		{Action: IncludeAction, Path: "app/vendor/runtime/**"},
	}})
	result := matcher.Evaluate([]pkg.Package{runtimePkg, devPkg})

	assert.Equal(t, []string{string(devPkg.ID())}, result.RemoveIDs)
	require.Len(t, result.Keep, 1)
	assert.Equal(t, runtimePkg.Name, result.Keep[0].Name)
	assert.Equal(t, 1, result.Audit.IncludedPackageCount)
}

func TestMatcherCombinesDimensions(t *testing.T) {
	matching := testPackage("matching", pkg.NpmPkg, "/app/vendor/index.js", "sha256:layer-a")
	wrongLayer := testPackage("wrong-layer", pkg.NpmPkg, "/app/vendor/index.js", "sha256:layer-b")

	matcher := requireMatcher(t, Config{Rules: []RuleConfig{{
		Path:      "**/vendor/**",
		Ecosystem: "npm",
		Layer:     "sha256:layer-a",
	}}})
	result := matcher.Evaluate([]pkg.Package{matching, wrongLayer})

	assert.Equal(t, []string{string(matching.ID())}, result.RemoveIDs)
	require.Len(t, result.Keep, 1)
	assert.Equal(t, wrongLayer.Name, result.Keep[0].Name)
}

func TestMatcherIncludeWinsAtSameSpecificity(t *testing.T) {
	p := testPackage("kept", pkg.NpmPkg, "/app/vendor/index.js", "layer-1")
	matcher := requireMatcher(t, Config{Rules: []RuleConfig{
		{Action: ExcludeAction, Path: "app/vendor/**"},
		{Action: IncludeAction, Path: "app/vendor/**"},
	}})

	result := matcher.Evaluate([]pkg.Package{p})
	assert.Empty(t, result.RemoveIDs)
	assert.Equal(t, 1, result.Audit.IncludedPackageCount)
}

func TestMatcherCombinedRuleBeatsSingleDimensionInclude(t *testing.T) {
	p := testPackage("removed", pkg.NpmPkg, "/app/vendor/index.js", "sha256:layer-a")
	matcher := requireMatcher(t, Config{Rules: []RuleConfig{
		{Action: IncludeAction, Path: "app/vendor/**"},
		{Action: ExcludeAction, Path: "app/vendor/**", Layer: "sha256:layer-a"},
	}})

	result := matcher.Evaluate([]pkg.Package{p})
	assert.Equal(t, []string{string(p.ID())}, result.RemoveIDs)
}

func TestMatcherInvalidGlobReportsRuleAndReason(t *testing.T) {
	_, err := NewMatcher(Config{Rules: []RuleConfig{
		{Path: "**/ok/**"},
		{Path: "**/[broken/**"},
	}})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "exclusion rule 2")
	assert.Contains(t, err.Error(), "invalid path wildcard")
	assert.Contains(t, err.Error(), "bracket")
}

func TestMatcherEmptyResultRetainsStatistics(t *testing.T) {
	p := testPackage("only", pkg.NpmPkg, "/app/vendor/index.js", "layer-1")
	matcher := requireMatcher(t, Config{Rules: []RuleConfig{{Ecosystem: "npm"}}})

	result := matcher.Evaluate([]pkg.Package{p})
	assert.Empty(t, result.Keep)
	assert.Equal(t, 1, result.Audit.EvaluatedPackageCount)
	assert.Equal(t, 1, result.Audit.ExcludedPackageCount)
	assert.Zero(t, result.Audit.RemainingPackageCount)
	assert.True(t, result.Audit.IsOverlyBroad())
}

func TestSourcePathExclusions(t *testing.T) {
	matcher := requireMatcher(t, Config{Rules: []RuleConfig{
		{Path: "node_modules"},
		{Path: "**/vendor/**"},
	}})

	assert.Equal(t, []string{"./node_modules", "**/vendor/**"}, matcher.SourcePathExclusions())

	withInclude := requireMatcher(t, Config{Rules: []RuleConfig{
		{Path: "node_modules"},
		{Action: IncludeAction, Path: "node_modules/runtime/**"},
	}})
	assert.Empty(t, withInclude.SourcePathExclusions())
}

func TestTaskExcluded(t *testing.T) {
	matcher := requireMatcher(t, Config{Rules: []RuleConfig{{Ecosystem: "npm"}}})
	skip, ok := matcher.TaskExcluded([]string{"javascript-package-cataloger", "javascript", "node"})
	require.True(t, ok)
	assert.Equal(t, 1, skip.RuleIndex)

	withInclude := requireMatcher(t, Config{Rules: []RuleConfig{
		{Ecosystem: "npm"},
		{Action: IncludeAction, Ecosystem: "npm", Path: "app/runtime/**"},
	}})
	_, ok = withInclude.TaskExcluded([]string{"javascript", "node"})
	assert.False(t, ok)
}

func TestWriterPersistsInterruptedAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "exclusions.json")
	audit := Audit{
		SchemaVersion:         AuditSchemaVersion,
		Interrupted:           true,
		EvaluatedPackageCount: 3,
		ExcludedPackageCount:  2,
		RemainingPackageCount: 1,
		Matches: []Match{{
			Package:   PackageRef{ID: "pkg-id", Name: "pkg"},
			Action:    ExcludeAction,
			RuleIndex: 1,
			Reason:    "excluded by exclusion rule 1",
		}},
	}

	require.NoError(t, NewWriter(path).Write(audit))
	contents, err := os.ReadFile(path)
	require.NoError(t, err)

	var got Audit
	require.NoError(t, json.Unmarshal(contents, &got))
	assert.True(t, got.Interrupted)
	assert.Equal(t, 2, got.ExcludedPackageCount)
	require.Len(t, got.Matches, 1)
	assert.Equal(t, "pkg-id", got.Matches[0].Package.ID)
}

func TestParseRuleExpression(t *testing.T) {
	rule, err := ParseRuleExpression("action=include,path=app/vendor/runtime/**,ecosystem=npm,layer=sha256:abc")
	require.NoError(t, err)
	assert.Equal(t, RuleConfig{
		Action:    IncludeAction,
		Path:      "app/vendor/runtime/**",
		Ecosystem: "npm",
		Layer:     "sha256:abc",
	}, rule)

	_, err = ParseRuleExpression("path=**/vendor/**,unknown=value")
	require.ErrorContains(t, err, `unknown field "unknown"`)
}

func TestPathRecorderDeduplicatesOverlappingRules(t *testing.T) {
	recorder := NewPathRecorder()
	recorder.Record(1, "**/vendor/**", "app/vendor/a.js")
	recorder.Record(2, "app/vendor/**", "app/vendor/a.js")
	recorder.Record(1, "**/vendor/**", "app/vendor/b.js")

	audit := Audit{Rules: []RuleAudit{{Index: 1}, {Index: 2}}}
	recorder.Apply(&audit)

	assert.Equal(t, 2, audit.ExcludedPathCount)
	assert.Equal(t, 2, audit.Rules[0].MatchedPathCount)
	assert.Zero(t, audit.Rules[1].MatchedPathCount)
	require.Len(t, audit.PathMatches, 2)
	assert.Equal(t, 1, audit.PathMatches[0].RuleIndex)
}

func requireMatcher(t *testing.T, cfg Config) *Matcher {
	t.Helper()
	matcher, err := NewMatcher(cfg)
	require.NoError(t, err)
	return matcher
}

func testPackage(name string, packageType pkg.Type, path, layer string) pkg.Package {
	p := pkg.Package{
		Name: name,
		Type: packageType,
		Locations: file.NewLocationSet(file.NewLocationFromCoordinates(file.Coordinates{
			RealPath:     path,
			FileSystemID: layer,
		})),
	}
	p.SetID()
	return p
}
