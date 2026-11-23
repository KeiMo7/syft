package task

import (
	"context"
	"fmt"

	"github.com/anchore/syft/internal/identitymerge"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg/identity"
	"github.com/anchore/syft/syft/sbom"
)

const identityMergeTaskName = "identity-merge"

// NewIdentityMergeTask returns a task that folds duplicate package records by component identity.
// It must run after every node and every relationship has been cataloged, since it rewrites both.
// It returns nil when the feature is disabled, which keeps the default task set unchanged.
func NewIdentityMergeTask(cfg cataloging.IdentityMergeConfig) Task {
	if !cfg.Enabled {
		return nil
	}

	fn := func(_ context.Context, _ file.Resolver, builder sbomsync.Builder) error {
		accessor := builder.(sbomsync.Accessor)

		var result identity.Result
		accessor.WriteToSBOM(func(s *sbom.SBOM) {
			result = identitymerge.MergeSBOM(s, cfg.Options())
		})
		warning := result.Report.Warning

		if warning != "" {
			log.Warn(warning)
		}

		if cfg.FailOnConflict && result.Report.ThresholdExceeded {
			return fmt.Errorf(
				"identity merge found %d conflicts, above the configured threshold of %d",
				result.Report.ConflictCount, cfg.ConflictThreshold,
			)
		}
		return nil
	}

	return NewTask(identityMergeTaskName, fn)
}
