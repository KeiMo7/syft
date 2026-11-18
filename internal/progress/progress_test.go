package progress

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/monitor"
)

type recordingPublisher struct {
	mu     sync.Mutex
	events []partybus.Event
}

func (p *recordingPublisher) Publish(e partybus.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, e)
}

func (p *recordingPublisher) snapshots() []monitor.CatalogingProgress {
	p.mu.Lock()
	defer p.mu.Unlock()

	var snapshots []monitor.CatalogingProgress
	for _, e := range p.events {
		if e.Type != event.CatalogingProgress {
			continue
		}
		snapshot, ok := e.Value.(monitor.CatalogingProgress)
		if ok {
			snapshots = append(snapshots, snapshot)
		}
	}
	return snapshots
}

func TestSnapshot_accumulatesRepeatedStagesAndKeepsDetails(t *testing.T) {
	reporter := New(Config{Interval: time.Hour})
	ctx := reporter.Start(context.Background())
	t.Cleanup(reporter.Finish)
	reporter.Expect(4)

	// the same parser entered at two layers: entries and elapsed time must add, not replace
	for _, layer := range []int{1, 2} {
		_, stage := Begin(ctx, "python-package-cataloger", WithLayer(layer), WithParser("python"))
		stage.SetCount(3)
		time.Sleep(time.Millisecond)
		stage.End(nil)
	}

	_, failedStage := Begin(ctx, "python-package-cataloger", WithLayer(3), WithParser("python"))
	failedStage.SetCount(2)
	failedStage.End(errors.New("bad metadata"))

	snapshot := reporter.Snapshot(false)
	require.Len(t, snapshot.Stages, 1)
	require.Len(t, snapshot.Details, 3)

	stage := snapshot.Stages[0]
	assert.Equal(t, "python-package-cataloger", stage.Stage)
	assert.Equal(t, int64(8), stage.Count, "3 + 3 + 2 entries across repeated stage entries")
	assert.True(t, stage.Failed)
	assert.Equal(t, int64(1), snapshot.Remaining)
	assert.Equal(t, int64(0), snapshot.InFlight)

	assert.Equal(t, []int{1, 2, 3}, []int{
		snapshot.Details[0].Layer,
		snapshot.Details[1].Layer,
		snapshot.Details[2].Layer,
	})
	assert.Equal(t, []int64{3, 3, 2}, []int64{
		snapshot.Details[0].Count,
		snapshot.Details[1].Count,
		snapshot.Details[2].Count,
	})
	assert.Equal(t, []bool{false, false, true}, []bool{
		snapshot.Details[0].Failed,
		snapshot.Details[1].Failed,
		snapshot.Details[2].Failed,
	})
}

func TestReporter_publishesWhileAParserIsStuck(t *testing.T) {
	publisher := &recordingPublisher{}
	bus.Set(publisher)
	t.Cleanup(func() { bus.Set(nil) })

	reporter := New(Config{Interval: 10 * time.Millisecond})
	ctx := reporter.Start(context.Background())
	t.Cleanup(reporter.Finish)
	reporter.Expect(1)

	_, stage := Begin(ctx, "javascript-lock-cataloger", WithLayer(2), WithParser("javascript"))
	defer stage.End(nil)

	require.Eventually(t, func() bool {
		for _, snapshot := range publisher.snapshots() {
			if snapshot.InFlight != 1 || len(snapshot.Stages) != 1 {
				continue
			}
			if snapshot.Stages[0].State == stateRunning &&
				snapshot.Stages[0].Parser == "javascript" &&
				snapshot.Stages[0].Layer == 2 {
				return true
			}
		}
		return false
	}, time.Second, 10*time.Millisecond)

	snapshot := reporter.Snapshot(false)
	assert.Equal(t, stateRunning, snapshot.Stages[0].State)
	assert.GreaterOrEqual(t, snapshot.Stages[0].ElapsedMS, int64(0))
	assert.Equal(t, "javascript", snapshot.Stages[0].Parser)
	assert.Equal(t, 2, snapshot.Stages[0].Layer)
}

func TestReporter_interruptPublishesOneFinalSnapshotPromptly(t *testing.T) {
	publisher := &recordingPublisher{}
	bus.Set(publisher)
	t.Cleanup(func() { bus.Set(nil) })

	reporter := New(Config{Interval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	ctx = reporter.Start(ctx)
	reporter.Expect(2)

	_, completed := Begin(ctx, "go-module-cataloger", WithLayer(0), WithParser("go"))
	completed.SetCount(7)
	completed.End(nil)

	_, stuck := Begin(ctx, "java-archive-cataloger", WithLayer(1), WithParser("java"))
	defer stuck.End(nil)

	start := time.Now()
	cancel()
	reporter.Finish()
	assert.Less(t, time.Since(start), time.Second)

	reporter.Finish()

	var interrupted int
	for _, snapshot := range publisher.snapshots() {
		if snapshot.Interrupted {
			interrupted++
			assert.Equal(t, int64(1), snapshot.Remaining)
			assert.Equal(t, int64(1), snapshot.InFlight)
			require.Len(t, snapshot.Stages, 2)
			assert.Contains(t, []string{stateCompleted, stateInterrupted}, snapshot.Stages[0].State)
			assert.Contains(t, []string{stateCompleted, stateInterrupted}, snapshot.Stages[1].State)
		}
	}
	assert.Equal(t, 1, interrupted, "interrupt must converge to exactly one final snapshot")
}

func TestReporter_resumeKeepsAccumulatedCounts(t *testing.T) {
	reporter := New(Config{Interval: time.Hour})
	firstCtx := reporter.Start(context.Background())
	reporter.Expect(2)

	_, first := Begin(firstCtx, "ruby-cataloger", WithLayer(0))
	first.SetCount(4)
	first.End(nil)
	reporter.Finish()

	before := reporter.Snapshot(false)
	require.Len(t, before.Stages, 1)
	assert.Equal(t, int64(4), before.Stages[0].Count)

	secondCtx := reporter.Start(context.Background())
	_, second := Begin(secondCtx, "ruby-cataloger", WithLayer(1))
	second.SetCount(6)
	second.End(nil)
	reporter.Finish()

	after := reporter.Snapshot(false)
	require.Len(t, after.Stages, 1)
	assert.Equal(t, int64(10), after.Stages[0].Count, "resume must continue at the previous total")
	assert.Len(t, after.Details, 2)
}

func TestReporter_sinkReceivesFinalInterruptSnapshotWithoutTheEventLoop(t *testing.T) {
	var mu sync.Mutex
	var snapshots []monitor.CatalogingProgress

	reporter := New(Config{
		Interval: time.Hour,
		Sink: func(snapshot monitor.CatalogingProgress) error {
			mu.Lock()
			defer mu.Unlock()
			snapshots = append(snapshots, snapshot)
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	ctx = reporter.Start(ctx)
	reporter.Expect(1)
	_, stage := Begin(ctx, "python-package-cataloger", WithLayer(2), WithParser("python"))
	defer stage.End(nil)

	cancel()
	reporter.Finish()

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, snapshots)
	final := snapshots[len(snapshots)-1]
	assert.True(t, final.Interrupted)
	assert.Equal(t, int64(1), final.InFlight)
	assert.Equal(t, "python", final.Stages[0].Parser)
	assert.Equal(t, 2, final.Stages[0].Layer)
}

func TestReporter_panickingSinkDoesNotBreakTheRun(t *testing.T) {
	reporter := New(Config{
		Interval: time.Hour,
		Sink: func(monitor.CatalogingProgress) error {
			panic("broken reporter")
		},
	})
	ctx := reporter.Start(context.Background())
	reporter.Expect(1)
	_, stage := Begin(ctx, "python-package-cataloger")
	stage.End(nil)

	assert.NotPanics(t, reporter.Finish)
	assert.Equal(t, int64(0), reporter.Snapshot(false).Remaining)
}

func TestReporter_concurrentAggregationIsCorrect(t *testing.T) {
	const workers = 64

	reporter := New(Config{Interval: time.Hour})
	ctx := reporter.Start(context.Background())
	reporter.Expect(workers)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(layer int) {
			defer wg.Done()
			_, stage := Begin(ctx, "shared-parser", WithLayer(layer))
			stage.SetCount(int64(layer + 1))
			time.Sleep(time.Duration(layer%3) * time.Millisecond)
			stage.End(nil)
		}(i)
	}
	wg.Wait()
	reporter.Finish()

	snapshot := reporter.Snapshot(false)
	require.Len(t, snapshot.Stages, 1)
	assert.Len(t, snapshot.Details, workers)
	assert.Equal(t, int64(workers*(workers+1)/2), snapshot.Stages[0].Count)
	assert.Equal(t, int64(0), snapshot.Remaining)
	assert.Equal(t, int64(0), snapshot.InFlight)
}
