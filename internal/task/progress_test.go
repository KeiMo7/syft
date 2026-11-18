package task

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goprogress "github.com/wagoodman/go-progress"

	"github.com/anchore/syft/internal/progress"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
)

func TestRunTask_reportsParserFailureAndLayer(t *testing.T) {
	reporter := progress.New(progress.Config{Interval: time.Hour})
	ctx := reporter.Start(context.Background())
	defer reporter.Finish()

	wantErr := errors.New("parser failed")
	tsk := NewTask("java-archive-cataloger", func(context.Context, file.Resolver, sbomsync.Builder) error {
		return wantErr
	})

	ctx = progress.WithLayerContext(ctx, 3)
	runProgress := &monitor.TaskProgress{
		AtomicStage: goprogress.NewAtomicStage(""),
		Manual:      goprogress.NewManual(-1),
	}
	err := RunTask(ctx, tsk, nil, nil, runProgress)
	require.ErrorIs(t, err, wantErr)

	snapshot := reporter.Snapshot(false)
	require.Len(t, snapshot.Details, 1)
	detail := snapshot.Details[0]
	assert.Equal(t, "java-archive-cataloger", detail.Stage)
	assert.Equal(t, "java-archive-cataloger", detail.Parser)
	assert.Equal(t, 3, detail.Layer)
	assert.True(t, detail.Failed)
	assert.Equal(t, "failed", detail.State)
}
