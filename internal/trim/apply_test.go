package trim

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

type testCategoryMetadata struct {
	Dev   bool
	Test  bool
	Build bool
}

func TestApplyCategoryTrimmingIsIndependent(t *testing.T) {
	tests := []struct {
		name       string
		categories map[string]bool
		want       []string
	}{
		{
			name:       "dev only",
			categories: map[string]bool{CategoryDev: true},
			want:       []string{"build-pkg", "test-pkg"},
		},
		{
			name:       "test only",
			categories: map[string]bool{CategoryTest: true},
			want:       []string{"build-pkg", "dev-pkg"},
		},
		{
			name:       "build only",
			categories: map[string]bool{CategoryBuild: true},
			want:       []string{"dev-pkg", "test-pkg"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := testSBOM(
				newTestPackage("dev-pkg", testCategoryMetadata{Dev: true}),
				newTestPackage("test-pkg", pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{Scope: "test"},
				}),
				newTestPackage("build-pkg", pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{Scope: "provided"},
				}),
			)

			config := enabledConfig(Policy{
				Categories:   test.categories,
				ExcludePaths: []string{},
			})

			out, report, err := Apply(input, config)
			require.NoError(t, err)
			assert.Equal(t, test.want, packageNames(out))
			assert.Equal(t, 3, input.Artifacts.Packages.PackageCount(), "input SBOM must not be mutated")
			assert.Equal(t, 3, report.BeforeCount)
			assert.Equal(t, len(test.want), report.AfterCount)
			assert.Equal(t, 1, report.RemovedCount)
			assert.Equal(t, 1, report.AttemptedRemoved)
		})
	}
}

func TestApplyDisabledLeavesSBOMUnchanged(t *testing.T) {
	input := testSBOM(newTestPackage("runtime", testCategoryMetadata{}))
	out, report, err := Apply(input, &Config{})
	require.NoError(t, err)
	assert.Equal(t, input, out)
	assert.False(t, report.Enabled)
}

func TestApplyAcceptsTopLevelDefaultPolicyShorthand(t *testing.T) {
	input := testSBOM(
		newTestPackage("dev", testCategoryMetadata{Dev: true}),
		newTestPackage("runtime", testCategoryMetadata{}),
	)
	config := &Config{
		Enabled: true,
		Policy: Policy{
			Categories:   map[string]bool{CategoryDev: true},
			ExcludePaths: []string{},
		},
	}

	out, report, err := Apply(input, config)
	require.NoError(t, err)
	assert.Equal(t, []string{"runtime"}, packageNames(out))
	assert.Equal(t, 1, report.RemovedCount)
}

func TestApplyTrimsDefaultTestAndExamplePaths(t *testing.T) {
	input := testSBOM(
		newTestPackage("runtime", testCategoryMetadata{}, file.NewLocation("/opt/app/server.js")),
		newTestPackage("test-fixture", testCategoryMetadata{}, file.NewLocation("/opt/app/tests/cases/data.json")),
		newTestPackage("example", testCategoryMetadata{}, file.NewLocation("/opt/app/examples/demo.js")),
		newTestPackage("no-location", testCategoryMetadata{}),
	)
	config := enabledConfig(Policy{})

	out, report, err := Apply(input, config)
	require.NoError(t, err)
	assert.Equal(t, []string{"no-location", "runtime"}, packageNames(out))
	assert.Equal(t, 2, report.RemovedCount)
	assert.Equal(t, 2, report.ByRule["location:excluded-path"])
}

func TestApplyDirectOnlyTrimsTransitiveAndRetainsUnknownDepth(t *testing.T) {
	root := newTestPackage("app", testCategoryMetadata{})
	direct := newTestPackage("direct", pkg.DotnetPackagesLockEntry{Type: "Direct"})
	transitive := newTestPackage("transitive", pkg.DotnetPackagesLockEntry{Type: "Transitive"})
	cycleA := newTestPackage("cycle-a", testCategoryMetadata{})
	cycleB := newTestPackage("cycle-b", testCategoryMetadata{})

	input := testSBOM(root, direct, transitive, cycleA, cycleB)
	input.Relationships = []artifact.Relationship{
		{From: direct, To: root, Type: artifact.DependencyOfRelationship},
		{From: transitive, To: direct, Type: artifact.DependencyOfRelationship},
		{From: cycleA, To: cycleB, Type: artifact.DependencyOfRelationship},
		{From: cycleB, To: cycleA, Type: artifact.DependencyOfRelationship},
	}

	config := enabledConfig(Policy{
		DirectOnly:   true,
		ExcludePaths: []string{},
	})

	out, report, err := Apply(input, config)
	require.NoError(t, err)
	assert.Equal(t, []string{"app", "cycle-a", "cycle-b", "direct"}, packageNames(out))
	assert.Equal(t, 1, report.ByRule["depth:transitive"])
	assert.Equal(t, 2, report.Unknown.Depth)
}

func TestApplyDirectOnlyRetainsIsolatedComponentsAsUnknown(t *testing.T) {
	input := testSBOM(newTestPackage("isolated", testCategoryMetadata{}))
	config := enabledConfig(Policy{
		DirectOnly:   true,
		ExcludePaths: []string{},
	})

	out, report, err := Apply(input, config)
	require.NoError(t, err)
	assert.Equal(t, []string{"isolated"}, packageNames(out))
	assert.Equal(t, 1, report.Unknown.Depth)
	assert.Zero(t, report.RemovedCount)
}

func TestApplyCombinedRulesCountEachComponentOnce(t *testing.T) {
	root := newTestPackage("app", testCategoryMetadata{})
	multiHit := newTestPackage("multi-hit", testCategoryMetadata{Dev: true}, file.NewLocation("/opt/app/tests/multi.js"))

	input := testSBOM(root, multiHit)
	input.Relationships = []artifact.Relationship{
		{From: multiHit, To: root, Type: artifact.DependencyOfRelationship},
	}

	config := enabledConfig(Policy{
		Categories: map[string]bool{CategoryDev: true},
		DirectOnly: true,
	})

	out, report, err := Apply(input, config)
	require.NoError(t, err)
	assert.Equal(t, []string{"app"}, packageNames(out))
	assert.Equal(t, 1, report.RemovedCount)
	assert.Equal(t, 1, report.AttemptedRemoved)
	assert.Equal(t, 1, report.ByCategory[CategoryDev])
	assert.Equal(t, 1, report.ByRule["category:dev"])
	assert.Zero(t, report.ByRule["location:excluded-path"])
	assert.Zero(t, report.ByRule["depth:transitive"])
}

func TestApplyAllTrimmedFallsBackWithWarning(t *testing.T) {
	input := testSBOM(newTestPackage("only-test", testCategoryMetadata{Test: true}))
	config := enabledConfig(Policy{
		Categories:   map[string]bool{CategoryTest: true},
		ExcludePaths: []string{},
	})

	out, report, err := Apply(input, config)
	require.NoError(t, err)
	assert.Equal(t, 1, out.Artifacts.Packages.PackageCount())
	assert.Equal(t, []string{"only-test"}, packageNames(out))
	assert.True(t, report.Fallback)
	assert.Zero(t, report.RemovedCount)
	assert.Equal(t, 1, report.WouldRemoveCount)
	require.Len(t, report.Warnings, 1)
	assert.Contains(t, report.Warnings[0], "retaining the original component list")

	configuration := configurationMap(t, out)
	trimReport, ok := configuration["trim"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, trimReport["fallback"])
	assert.Equal(t, true, trimReport["complete"])
}

func TestApplyRetainsUnknownCategoryAndCountsIt(t *testing.T) {
	input := testSBOM(newTestPackage("unknown", struct{ Something string }{Something: "value"}))
	config := enabledConfig(Policy{
		Categories:   map[string]bool{CategoryDev: true},
		ExcludePaths: []string{},
	})

	out, report, err := Apply(input, config)
	require.NoError(t, err)
	assert.Equal(t, []string{"unknown"}, packageNames(out))
	assert.Zero(t, report.RemovedCount)
	assert.Equal(t, 1, report.Unknown.Total)
	assert.Equal(t, 1, report.Unknown.Category)
}

func TestApplySelectsBusinessLineAndMarksDefaultFallback(t *testing.T) {
	input := testSBOM(newTestPackage("runtime", testCategoryMetadata{}))
	input.Source = source.Description{
		Name:    "registry.example.com/payments/api",
		Version: "1.2.3",
	}

	config := enabledConfig(Policy{ExcludePaths: []string{}})
	config.BusinessLines = []BusinessLineRule{
		{
			Name:   "payments",
			Images: []string{"registry.example.com/payments/*"},
			Policy: Policy{
				Categories:   map[string]bool{CategoryDev: true},
				ExcludePaths: []string{},
			},
		},
	}

	_, report, err := Apply(input, config)
	require.NoError(t, err)
	assert.Equal(t, "payments", report.BusinessLine)
	assert.Equal(t, "business-line-image-match", report.RuleSource)
	assert.Equal(t, "sha256:", prefix(report.RulesDigest, len("sha256:")))

	input.Source = source.Description{Name: "registry.example.com/unowned/api", Version: "1.0.0"}
	_, report, err = Apply(input, config)
	require.NoError(t, err)
	assert.Equal(t, "default", report.BusinessLine)
	assert.Equal(t, "default-no-business-line-match", report.RuleSource)
	require.Len(t, report.Warnings, 1)
	assert.Contains(t, report.Warnings[0], "using default rules")
}

func TestApplyExplicitBusinessLineSupportsSharedBaseImages(t *testing.T) {
	config := enabledConfig(Policy{ExcludePaths: []string{}})
	config.BusinessLine = "risk"
	config.BusinessLines = []BusinessLineRule{
		{Name: "payments", Images: []string{"shared/base"}, Policy: Policy{ExcludePaths: []string{}}},
		{Name: "risk", Images: []string{"shared/base"}, Policy: Policy{ExcludePaths: []string{}}},
	}

	input := testSBOM(newTestPackage("runtime", testCategoryMetadata{}))
	input.Source = source.Description{Name: "shared/base", Version: "latest"}

	_, report, err := Apply(input, config)
	require.NoError(t, err)
	assert.Equal(t, "risk", report.BusinessLine)
	assert.Equal(t, "explicit-business-line", report.RuleSource)
}

func TestConfigRejectsUnknownCategoryWithOptions(t *testing.T) {
	config := enabledConfig(Policy{
		Categories: map[string]bool{"development": true},
	})
	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown trim category "development"`)
	assert.Contains(t, err.Error(), "build, dev, test")
}

func TestApplyReloadsChangedRuleFileWithoutRestart(t *testing.T) {
	rulePath := filepath.Join(t.TempDir(), "trim-rules.yaml")
	writeRules := func(category string) {
		contents := "default:\n  exclude-paths: []\n  categories:\n    " + category + ": true\n"
		require.NoError(t, os.WriteFile(rulePath, []byte(contents), 0o600))
	}

	writeRules(CategoryDev)
	config := &Config{Enabled: true, RuleFile: rulePath}
	require.NoError(t, config.ReloadRules())

	input := testSBOM(
		newTestPackage("dev", testCategoryMetadata{Dev: true}),
		newTestPackage("test", testCategoryMetadata{Test: true}),
	)

	out, report, err := Apply(input, config)
	require.NoError(t, err)
	assert.Equal(t, []string{"test"}, packageNames(out))
	assert.Equal(t, "file:"+rulePath, report.RulesSource)
	assert.False(t, report.RulesReloadedAtApply)
	firstDigest := report.RulesDigest

	writeRules(CategoryTest)
	out, report, err = Apply(input, config)
	require.NoError(t, err)
	assert.Equal(t, []string{"dev"}, packageNames(out))
	assert.True(t, report.RulesReloadedAtApply)
	assert.NotEqual(t, firstDigest, report.RulesDigest)
}

func TestRuleFileCanDefineBusinessLines(t *testing.T) {
	rulePath := filepath.Join(t.TempDir(), "trim-rules.yaml")
	require.NoError(t, os.WriteFile(rulePath, []byte(`
default:
  exclude-paths: []
business-lines:
  - name: payments
    images:
      - "registry.example.com/payments/*"
    categories:
      dev: true
    exclude-paths: []
`), 0o600))

	config := &Config{Enabled: true, RuleFile: rulePath}
	require.NoError(t, config.ReloadRules())

	input := testSBOM(
		newTestPackage("dev", testCategoryMetadata{Dev: true}),
		newTestPackage("runtime", testCategoryMetadata{}),
	)
	input.Source = source.Description{Name: "registry.example.com/payments/api", Version: "1"}

	out, report, err := Apply(input, config)
	require.NoError(t, err)
	assert.Equal(t, []string{"runtime"}, packageNames(out))
	assert.Equal(t, "payments", report.BusinessLine)
	assert.Equal(t, "business-line-image-match", report.RuleSource)
}

func TestAggregateRemovedByBusinessLine(t *testing.T) {
	reports := []Report{
		{
			Enabled:      true,
			BusinessLine: "payments",
			BeforeCount:  10,
			AfterCount:   7,
			RemovedCount: 3,
			Unknown:      UnknownStats{Total: 1, Category: 1},
			ByCategory:   map[string]int{CategoryDev: 2},
			ByRule:       map[string]int{"category:dev": 2, "depth:transitive": 1},
		},
		{
			Enabled:      true,
			BusinessLine: "payments",
			BeforeCount:  4,
			AfterCount:   3,
			RemovedCount: 1,
			ByCategory:   map[string]int{CategoryTest: 1},
			ByRule:       map[string]int{"category:test": 1},
		},
	}

	aggregates := AggregateRemovedByBusinessLine(reports)
	require.Len(t, aggregates, 1)
	assert.Equal(t, "payments", aggregates[0].BusinessLine)
	assert.Equal(t, 2, aggregates[0].Reports)
	assert.Equal(t, 14, aggregates[0].BeforeCount)
	assert.Equal(t, 10, aggregates[0].AfterCount)
	assert.Equal(t, 4, aggregates[0].RemovedCount)
	assert.Equal(t, map[string]int{CategoryDev: 2, CategoryTest: 1}, aggregates[0].ByCategory)
	assert.Equal(t, map[string]int{"category:dev": 2, "category:test": 1, "depth:transitive": 1}, aggregates[0].ByRule)
}

func enabledConfig(policy Policy) *Config {
	return &Config{
		Enabled: true,
		Default: policy,
	}
}

func testSBOM(packages ...pkg.Package) sbom.SBOM {
	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(packages...),
		},
		Source: source.Description{Name: "test-image", Version: "latest"},
		Descriptor: sbom.Descriptor{
			Name:          "syft",
			Version:       "test",
			Configuration: map[string]any{"existing": true},
		},
	}
}

func newTestPackage(name string, metadata any, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   "1.0.0",
		Type:      pkg.NpmPkg,
		PURL:      "pkg:npm/" + name + "@1.0.0",
		FoundBy:   "test-cataloger",
		Locations: file.NewLocationSet(locations...),
		Metadata:  metadata,
	}
	p.SetID()
	return p
}

func packageNames(s sbom.SBOM) []string {
	var names []string
	for _, p := range s.Artifacts.Packages.Sorted() {
		names = append(names, p.Name)
	}
	return names
}

func configurationMap(t *testing.T, s sbom.SBOM) map[string]any {
	t.Helper()
	payload, err := json.Marshal(s.Descriptor.Configuration)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(payload, &out))
	return out
}

func prefix(value string, length int) string {
	if len(value) < length {
		return value
	}
	return value[:length]
}
