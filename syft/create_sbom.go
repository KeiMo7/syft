package syft

import (
	"context"
	"crypto"
	"fmt"
	"runtime"
	"sort"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/go-sync"
	"github.com/anchore/syft/internal/archive"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/incremental"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// CreateSBOM creates a software bill-of-materials from the given source. If the CreateSBOMConfig is nil, then
// default options will be used.
func CreateSBOM(ctx context.Context, src source.Source, cfg *CreateSBOMConfig) (*sbom.SBOM, error) {
	if cfg == nil {
		cfg = DefaultCreateSBOMConfig()
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	if cfg.Incremental != nil && cfg.Incremental.Enabled {
		result, err := CreateSBOMWithIncremental(ctx, src, cfg)
		if err != nil {
			return nil, err
		}
		return result.SBOM, nil
	}
	return createSBOM(ctx, src, cfg)
}

// CreateSBOMIncrementalResult contains the SBOM and diagnostics from an
// incremental cataloging run.
type CreateSBOMIncrementalResult struct {
	SBOM           *sbom.SBOM
	Stats          incremental.MergeStats
	Plan           incremental.Plan
	BaselineStatus string
	Duration       time.Duration
}

// CreateSBOMWithIncremental creates an SBOM using the incremental configuration
// on cfg. It exists separately from CreateSBOM so callers can collect timing,
// package counts, and reuse ratios for auditing.
func CreateSBOMWithIncremental(ctx context.Context, src source.Source, cfg *CreateSBOMConfig) (*CreateSBOMIncrementalResult, error) {
	if cfg == nil {
		cfg = DefaultCreateSBOMConfig()
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	if cfg.Incremental == nil || !cfg.Incremental.Enabled {
		start := time.Now()
		document, err := createSBOM(ctx, src, cfg)
		if err != nil {
			return nil, err
		}
		merged := incremental.Merge(nil, document, incremental.Plan{Mode: incremental.ModeFull})
		return &CreateSBOMIncrementalResult{
			SBOM:           merged.SBOM,
			Stats:          merged.Stats,
			BaselineStatus: "incremental cataloging is disabled",
			Duration:       time.Since(start),
		}, nil
	}

	return createSBOMIncremental(ctx, src, cfg)
}

func createSBOMIncremental(ctx context.Context, src source.Source, cfg *CreateSBOMConfig) (*CreateSBOMIncrementalResult, error) {
	start := time.Now()
	var checkpointWriter *incremental.CheckpointWriter
	if cfg.Incremental.CheckpointPath != "" {
		checkpointWriter = incremental.NewCheckpointWriter(cfg.Incremental.CheckpointPath)
	}
	scanConfig := incrementalCatalogConfig(cfg, checkpointWriter)

	baseline, baselineStatus, loadErr := loadIncrementalBaseline(cfg.Incremental)
	if loadErr != nil {
		log.WithFields("error", loadErr).Warn("incremental reference SBOM is unusable; falling back to a full catalog")
		return fullIncrementalResult(ctx, src, scanConfig, baselineStatus, start, checkpointWriter)
	}

	resolver, err := src.FileResolver(scanConfig.Search.Scope)
	if err != nil {
		return nil, fmt.Errorf("unable to get file resolver for incremental analysis: %w", err)
	}

	plan, err := incremental.Analyze(ctx, baseline, src.Describe(), resolver, cfg.Incremental.Options())
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		baselineStatus = fmt.Sprintf("change detection failed: %v", err)
		log.WithFields("error", err).Warn("incremental change detection failed; falling back to a full catalog")
		return fullIncrementalResult(ctx, src, scanConfig, baselineStatus, start, checkpointWriter)
	}

	if plan.Mode == incremental.ModeFull {
		baselineStatus = plan.Reason
		log.WithFields("reason", plan.Reason).Warn("incremental cataloging requested a full catalog")
		return fullIncrementalResult(ctx, src, scanConfig, baselineStatus, start, checkpointWriter)
	}

	changed := plan.ChangedPathSet()
	filteredResolver := incremental.Resolver(resolver, changed)
	filteredSource := incremental.Source(src, filteredResolver)
	current, err := createSBOM(ctx, filteredSource, scanConfig)
	if err != nil {
		return nil, err
	}

	merged := incremental.Merge(baseline, current, plan)
	if merged.Stats.FallbackRequired {
		baselineStatus = merged.Reason
		log.WithFields("reason", merged.Reason).Warn("incremental merge could not account for every reference package; falling back to a full catalog")
		return fullIncrementalResult(ctx, src, scanConfig, baselineStatus, start, checkpointWriter)
	}

	log.WithFields(
		"changed-paths", merged.Stats.ChangedPaths,
		"reused-paths", merged.Stats.ReusedPaths,
		"packages", merged.Stats.TotalPackages,
		"reused-packages", merged.Stats.ReusedPackages,
		"reuse-ratio", merged.Stats.ReuseRatio,
	).Info("incremental cataloging completed")
	if checkpointWriter != nil {
		checkpointWriter.MarkProcessed(plan.ChangedPaths)
		if err := checkpointWriter.SaveComplete(merged.SBOM); err != nil {
			log.WithFields("error", err).Warn("unable to publish complete incremental checkpoint")
		}
	}

	return &CreateSBOMIncrementalResult{
		SBOM:           merged.SBOM,
		Stats:          merged.Stats,
		Plan:           plan,
		BaselineStatus: baselineStatus,
		Duration:       time.Since(start),
	}, nil
}

func fullIncrementalResult(
	ctx context.Context,
	src source.Source,
	cfg *CreateSBOMConfig,
	status string,
	start time.Time,
	checkpointWriter *incremental.CheckpointWriter,
) (*CreateSBOMIncrementalResult, error) {
	document, err := createSBOM(ctx, src, cfg)
	if err != nil {
		return nil, err
	}
	merged := incremental.Merge(nil, document, incremental.Plan{Mode: incremental.ModeFull})
	if checkpointWriter != nil {
		if err := checkpointWriter.SaveComplete(merged.SBOM); err != nil {
			log.WithFields("error", err).Warn("unable to publish complete incremental checkpoint")
		}
	}
	return &CreateSBOMIncrementalResult{
		SBOM:           merged.SBOM,
		Stats:          merged.Stats,
		BaselineStatus: status,
		Duration:       time.Since(start),
	}, nil
}

func loadIncrementalBaseline(cfg *incremental.Config) (*sbom.SBOM, string, error) {
	if cfg == nil {
		return nil, "incremental configuration is missing", fmt.Errorf("incremental configuration is missing")
	}
	if cfg.Baseline != nil {
		return cfg.Baseline, "using caller-provided reference SBOM", nil
	}
	if cfg.BaselinePath == "" {
		if checkpoint, ok := loadCheckpointBaseline(cfg.CheckpointPath); ok {
			return checkpoint.SBOM, checkpointStatus(cfg.CheckpointPath, checkpoint), nil
		}
		return nil, "no reference SBOM path was configured", incremental.ErrBaselineMissing
	}

	loaded, err := incremental.LoadBaseline(cfg.BaselinePath)
	if err == nil {
		return loaded.SBOM, fmt.Sprintf("loaded reference SBOM %s (%s@%s)", cfg.BaselinePath, loaded.FormatID, loaded.FormatVersion), nil
	}

	status := fmt.Sprintf("reference SBOM %s is unusable: %v", cfg.BaselinePath, err)
	if checkpoint, ok := loadCheckpointBaseline(cfg.CheckpointPath); ok {
		return checkpoint.SBOM, checkpointStatus(cfg.CheckpointPath, checkpoint), nil
	}
	return nil, status, err
}

func loadCheckpointBaseline(path string) (*incremental.Baseline, bool) {
	if path == "" {
		return nil, false
	}
	checkpoint, err := incremental.LoadCheckpoint(path)
	if err != nil {
		return nil, false
	}
	return checkpoint, true
}

func checkpointStatus(path string, checkpoint *incremental.Baseline) string {
	if checkpoint.Complete {
		return fmt.Sprintf("loaded complete checkpoint %s", path)
	}
	return fmt.Sprintf("resuming from partial checkpoint %s", path)
}

func incrementalCatalogConfig(cfg *CreateSBOMConfig, checkpointWriter *incremental.CheckpointWriter) *CreateSBOMConfig {
	out := *cfg
	out.Incremental = nil
	out.onSBOMWrite = nil
	if checkpointWriter != nil {
		out.onSBOMWrite = checkpointWriter.Save
	}
	out.Files = out.Files.
		WithSelection(file.AllFilesSelection).
		WithHashers(append(out.Files.Hashers, crypto.SHA256)...)
	return &out
}

// createSBOM runs the normal catalog pipeline.
//
//nolint:funlen
func createSBOM(ctx context.Context, src source.Source, cfg *CreateSBOMConfig) (*sbom.SBOM, error) {
	if cfg == nil {
		cfg = DefaultCreateSBOMConfig()
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	srcMetadata := src.Describe()

	taskGroups, audit, err := cfg.makeTaskGroups(srcMetadata, sourceExclusions(src))
	if err != nil {
		return nil, err
	}

	resolver, err := src.FileResolver(cfg.Search.Scope)
	if err != nil {
		return nil, fmt.Errorf("unable to get file resolver: %w", err)
	}

	s := sbom.SBOM{
		Source: srcMetadata,
		Descriptor: sbom.Descriptor{
			Name:    cfg.ToolName,
			Version: cfg.ToolVersion,
			Configuration: configurationAuditTrail{
				Search:         cfg.Search,
				Relationships:  cfg.Relationships,
				DataGeneration: cfg.DataGeneration,
				Packages:       cfg.packagesWithArchiveSearch(),
				Files:          cfg.Files,
				Archive:        cfg.Archive,
				Licenses:       cfg.Licenses,
				Catalogers:     *audit,
				ExtraConfigs:   cfg.ToolConfiguration,
			},
		},
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(),
		},
	}

	// check if the caller already provided a TempDir; if so, don't clean it up (the caller owns it)
	callerOwnsTempDir := tmpdir.FromContext(ctx) != nil

	// setup everything we need in context: license scanner, executors, temp storage, etc.
	ctx, err = setupContext(ctx, cfg)
	if err != nil {
		return nil, err
	}

	if !callerOwnsTempDir {
		if td := tmpdir.FromContext(ctx); td != nil {
			defer func() {
				if err := td.Cleanup(); err != nil {
					log.Warnf("failed to clean up temp dir: %v", err)
				}
			}()
		}
	}

	catalogingProgress := monitorCatalogingTask(ctx, src.ID(), taskGroups)
	packageCatalogingProgress := monitorPackageCatalogingTask(ctx)

	callbacks := []func(*sbom.SBOM){monitorPackageCount(packageCatalogingProgress)}
	if cfg.onSBOMWrite != nil {
		callbacks = append(callbacks, cfg.onSBOMWrite)
	}
	builder := sbomsync.NewBuilder(&s, callbacks...)
	for i := range taskGroups {
		err = sync.Collect(&ctx, cataloging.ExecutorFile, sync.ToSeq(taskGroups[i]), func(t task.Task) (any, error) {
			return nil, task.RunTask(ctx, t, resolver, builder, catalogingProgress)
		}, nil)
		if err != nil {
			// TODO: tie this to the open progress monitors...
			return nil, fmt.Errorf("failed to run tasks: %w", err)
		}
	}

	packageCatalogingProgress.SetCompleted()
	catalogingProgress.SetCompleted()

	return &s, nil
}

func setupContext(ctx context.Context, cfg *CreateSBOMConfig) (context.Context, error) {
	// configure parallel executors
	ctx = setContextExecutors(ctx, cfg)

	// one progress row per cataloger for the whole scan, however many archives it is run against
	ctx = bus.WithCatalogerTaskRegistry(ctx)

	// the archive cataloger task recurses into jars too, so the java cataloger must not unarchive them itself
	if cfg.Archive.MaxDepth != 0 {
		ctx = archive.WithNestedCataloging(ctx)
	}

	// configure temp dir factory for catalogers (if not already set)
	if tmpdir.FromContext(ctx) == nil {
		ctx, _ = tmpdir.Root(ctx, "syft-cataloger")
	}

	// configure license scanner
	// skip injecting a license scanner if one already set on context
	if licenses.IsContextLicenseScannerSet(ctx) {
		return ctx, nil
	}

	return SetContextLicenseScanner(ctx, cfg.Licenses)
}

// SetContextLicenseScanner creates and sets a license scanner
// on the provided context using the provided license config.
func SetContextLicenseScanner(ctx context.Context, cfg cataloging.LicenseConfig) (context.Context, error) {
	// inject a single license scanner and content config for all package cataloging tasks into context
	licenseScanner, err := licenses.NewDefaultScanner(
		licenses.WithCoverage(cfg.Coverage),
	)
	if err != nil {
		return nil, fmt.Errorf("could not build licenseScanner for cataloging: %w", err)
	}
	ctx = licenses.SetContextLicenseScanner(ctx, licenseScanner)
	return ctx, nil
}

func setContextExecutors(ctx context.Context, cfg *CreateSBOMConfig) context.Context {
	parallelism := 0
	if cfg != nil {
		parallelism = cfg.Parallelism
	}
	// executor parallelism is: 0 == serial, no goroutines, 1 == max 1 goroutine
	// so if they set 1, we just run in serial to avoid overhead, and treat 0 as default, reasonable max for the system
	// negative is unbounded, so no need for any other special handling
	switch parallelism {
	case 0:
		parallelism = runtime.NumCPU() * 4
	case 1:
		parallelism = 0 // run in serial, don't spawn goroutines
	case -99:
		parallelism = 1 // special case to catch incorrect executor usage during testing
	}
	// set up executors for each dimension we want to coordinate bounds for
	if !sync.HasContextExecutor(ctx, cataloging.ExecutorCPU) {
		ctx = sync.SetContextExecutor(ctx, cataloging.ExecutorCPU, sync.NewExecutor(parallelism))
	}
	if !sync.HasContextExecutor(ctx, cataloging.ExecutorFile) {
		ctx = sync.SetContextExecutor(ctx, cataloging.ExecutorFile, sync.NewExecutor(parallelism))
	}
	return ctx
}

func monitorPackageCount(prog *monitor.TaskProgress) func(s *sbom.SBOM) {
	return func(s *sbom.SBOM) {
		count := humanize.Comma(int64(s.Artifacts.Packages.PackageCount()))
		prog.AtomicStage.Set(fmt.Sprintf("%s packages", count))
	}
}

func monitorPackageCatalogingTask(ctx context.Context) *monitor.TaskProgress {
	info := monitor.GenericTask{
		Title: monitor.Title{
			Default: "Packages",
		},
		ID:            monitor.PackageCatalogingTaskID,
		HideOnSuccess: false,
		ParentID:      monitor.TopLevelCatalogingTaskID,
	}

	return bus.StartCatalogerTask(ctx, info, -1, "")
}

func monitorCatalogingTask(ctx context.Context, srcID artifact.ID, tasks [][]task.Task) *monitor.TaskProgress {
	info := monitor.GenericTask{
		Title: monitor.Title{
			Default:      "Catalog contents",
			WhileRunning: "Cataloging contents",
			OnSuccess:    "Cataloged contents",
		},
		ID:            monitor.TopLevelCatalogingTaskID,
		Context:       string(srcID),
		HideOnSuccess: false,
	}

	var length int64
	for _, tg := range tasks {
		length += int64(len(tg))
	}

	return bus.StartCatalogerTask(ctx, info, length, "")
}

func formatTaskNames(tasks []task.Task) []string {
	set := strset.New()
	for _, td := range tasks {
		if td == nil {
			continue
		}
		set.Add(td.Name())
	}
	list := set.List()
	sort.Strings(list)
	return list
}

// sourceExclusions returns the exclusion patterns the source was configured with, so the same
// exclusions apply inside the archives found in it.
func sourceExclusions(src source.Source) []string {
	if excluder, ok := src.(source.PathExcluder); ok {
		return excluder.ExcludedPaths()
	}
	return nil
}
