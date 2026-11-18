package progress

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/wagoodman/go-partybus"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/monitor"
)

const DefaultInterval = 30 * time.Second

const (
	stateRunning     = "running"
	stateCompleted   = "completed"
	stateFailed      = "failed"
	stateInterrupted = "interrupted"
)

type Config struct {
	Interval time.Duration
	Sink     func(monitor.CatalogingProgress) error
}

func DefaultConfig() Config {
	return Config{Interval: DefaultInterval}
}

// Reporter accumulates stage statistics and publishes snapshots on the existing partybus event
// channel. Its lifecycle methods are safe to call more than once; counters are never reset by Finish,
// so a reporter can be attached to another run and continue from the accumulated totals.
type Reporter struct {
	interval time.Duration
	sink     func(monitor.CatalogingProgress) error
	warnOnce sync.Once

	mu        sync.Mutex
	expected  int64
	completed int64
	inFlight  int64
	sequence  uint64
	stages    map[string]*aggregate
	details   []*invocation

	runMu    sync.Mutex
	running  bool
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

type aggregate struct {
	count   int64
	elapsed time.Duration
	failed  bool
	layer   int
	parser  string
}

type invocation struct {
	stage   string
	layer   int
	parser  string
	count   int64
	started time.Time
	ended   bool
	elapsed time.Duration
	err     error
}

// Stage is one entry into a stage. Call End exactly once when the work finishes; End is idempotent.
type Stage struct {
	reporter *Reporter
	entry    *invocation
	endOnce  sync.Once
}

type Option func(*invocation)

func WithCount(count int64) Option {
	return func(i *invocation) {
		i.count = count
	}
}

func WithLayer(layer int) Option {
	return func(i *invocation) {
		i.layer = layer
	}
}

func WithParser(parser string) Option {
	return func(i *invocation) {
		i.parser = parser
	}
}

func New(cfg Config) *Reporter {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	return &Reporter{
		interval: cfg.Interval,
		sink:     cfg.Sink,
		stages:   make(map[string]*aggregate),
	}
}

// Start creates a reporter and installs it on the returned context.
func Start(ctx context.Context, cfg Config) (context.Context, *Reporter) {
	reporter := New(cfg)
	return reporter.Start(ctx), reporter
}

// Start installs this reporter on the context and starts its periodic snapshot loop. Calling Start
// again after Finish resumes reporting with the existing counters instead of clearing them.
func (r *Reporter) Start(ctx context.Context) context.Context {
	if r == nil {
		return ctx
	}

	ctx = withReporter(ctx, r)

	r.runMu.Lock()
	defer r.runMu.Unlock()
	if r.running {
		return ctx
	}

	r.stop = make(chan struct{})
	r.done = make(chan struct{})
	r.stopOnce = sync.Once{}
	r.running = true
	go r.run(ctx, r.stop, r.done)

	return ctx
}

// Finish publishes one final snapshot and waits for the reporting goroutine to stop. It is safe to
// call after an interrupt; in that case the interrupt snapshot is the final one and is not repeated.
func (r *Reporter) Finish() {
	if r == nil {
		return
	}

	r.runMu.Lock()
	if !r.running {
		r.runMu.Unlock()
		return
	}
	done := r.done
	r.stopOnce.Do(func() { close(r.stop) })
	r.running = false
	r.runMu.Unlock()

	<-done
}

func (r *Reporter) run(ctx context.Context, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.publish(true)
			return
		case <-stop:
			r.publish(ctx.Err() != nil)
			return
		case <-ticker.C:
			r.publish(false)
		}
	}
}

func (r *Reporter) publish(interrupted bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			r.warnOnce.Do(func() {
				log.WithFields("panic", recovered).Warn("cataloging progress reporting panicked; further progress output will be suppressed")
			})
		}
	}()

	snapshot := r.Snapshot(interrupted)
	if r.sink != nil {
		if err := r.sink(snapshot); err != nil {
			r.warnOnce.Do(func() {
				log.WithFields("error", err).Warn("unable to report cataloging progress; further progress output will be suppressed")
			})
		}
		return
	}
	bus.Publish(partybus.Event{
		Type:  event.CatalogingProgress,
		Value: snapshot,
	})
}

// Expect adds work that is planned but not yet completed. It may be called as nested work is
// discovered, such as when another archive is opened.
func (r *Reporter) Expect(count int64) {
	if r == nil || count == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expected += count
}

// Expect adds planned work to the reporter carried by ctx.
func Expect(ctx context.Context, count int64) {
	if reporter := fromContext(ctx); reporter != nil {
		reporter.Expect(count)
	}
}

// Snapshot returns the current aggregate and per-entry detail without clearing either.
func (r *Reporter) Snapshot(interrupted bool) monitor.CatalogingProgress {
	if r == nil {
		return monitor.CatalogingProgress{Event: monitor.CatalogingProgressEvent}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.sequence++

	now := time.Now()
	aggregates := make(map[string]*aggregate, len(r.stages))
	for name, item := range r.stages {
		copied := *item
		aggregates[name] = &copied
	}

	details := make([]monitor.CatalogingStage, 0, len(r.details))
	for _, item := range r.details {
		elapsed := item.elapsed
		state := detailState(item, interrupted)
		if !item.ended {
			elapsed = now.Sub(item.started)
		}

		detail := monitor.CatalogingStage{
			Stage:     item.stage,
			Count:     item.count,
			ElapsedMS: elapsed.Milliseconds(),
			Elapsed:   elapsed.Round(time.Millisecond).String(),
			Failed:    item.err != nil && !errors.Is(item.err, context.Canceled),
			State:     state,
			Layer:     item.layer,
			Parser:    item.parser,
		}
		details = append(details, detail)

		agg, ok := aggregates[item.stage]
		if !ok {
			agg = &aggregate{}
			aggregates[item.stage] = agg
		}
		if !item.ended {
			agg.count += item.count
			agg.elapsed += elapsed
		}
		if detail.Failed {
			agg.failed = true
		}
		if item.layer >= agg.layer {
			agg.layer = item.layer
			agg.parser = item.parser
		}
	}

	stages := make([]monitor.CatalogingStage, 0, len(aggregates))
	for name, item := range aggregates {
		state := stateCompleted
		if interrupted && hasRunningDetail(r.details, name) {
			state = stateInterrupted
		} else if hasRunningDetail(r.details, name) {
			state = stateRunning
		} else if item.failed {
			state = stateFailed
		}

		stages = append(stages, monitor.CatalogingStage{
			Stage:     name,
			Count:     item.count,
			ElapsedMS: item.elapsed.Milliseconds(),
			Elapsed:   item.elapsed.Round(time.Millisecond).String(),
			Failed:    item.failed,
			State:     state,
			Layer:     item.layer,
			Parser:    item.parser,
		})
	}
	sort.Slice(stages, func(i, j int) bool { return stages[i].Stage < stages[j].Stage })
	sort.Slice(details, func(i, j int) bool {
		if details[i].Stage == details[j].Stage {
			return details[i].Layer < details[j].Layer
		}
		return details[i].Stage < details[j].Stage
	})

	remaining := r.expected - r.completed
	if remaining < 0 {
		remaining = 0
	}

	failed := false
	for _, item := range stages {
		failed = failed || item.Failed
	}

	return monitor.CatalogingProgress{
		Event:       monitor.CatalogingProgressEvent,
		Sequence:    r.sequence,
		Expected:    r.expected,
		Remaining:   remaining,
		InFlight:    r.inFlight,
		Failed:      failed,
		Interrupted: interrupted,
		Stages:      stages,
		Details:     details,
	}
}

func detailState(item *invocation, interrupted bool) string {
	switch {
	case !item.ended && interrupted:
		return stateInterrupted
	case !item.ended:
		return stateRunning
	case item.err != nil && !errors.Is(item.err, context.Canceled):
		return stateFailed
	case errors.Is(item.err, context.Canceled):
		return stateInterrupted
	default:
		return stateCompleted
	}
}

func hasRunningDetail(items []*invocation, stage string) bool {
	for _, item := range items {
		if item.stage == stage && !item.ended {
			return true
		}
	}
	return false
}

func (r *Reporter) begin(ctx context.Context, stage string, opts ...Option) *invocation {
	item := &invocation{
		stage:   stage,
		count:   1,
		started: time.Now(),
		layer:   layerFromContext(ctx),
		parser:  stage,
	}
	for _, opt := range opts {
		opt(item)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.details = append(r.details, item)
	r.inFlight++
	if _, ok := r.stages[stage]; !ok {
		r.stages[stage] = &aggregate{layer: item.layer, parser: item.parser}
	}
	return item
}

func (r *Reporter) end(item *invocation, err error, elapsed time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if item.ended {
		return
	}
	item.ended = true
	item.elapsed = elapsed
	item.err = err
	r.inFlight--
	r.completed++

	agg := r.stages[item.stage]
	if agg == nil {
		agg = &aggregate{}
		r.stages[item.stage] = agg
	}
	agg.count += item.count
	agg.elapsed += elapsed
	agg.failed = agg.failed || (err != nil && !errors.Is(err, context.Canceled))
	if item.layer >= agg.layer {
		agg.layer = item.layer
		agg.parser = item.parser
	}
}

func (s *Stage) Annotate(opts ...Option) {
	if s == nil || s.reporter == nil || s.entry == nil {
		return
	}
	s.reporter.mu.Lock()
	defer s.reporter.mu.Unlock()
	for _, opt := range opts {
		opt(s.entry)
	}
}

func (s *Stage) End(err error) {
	if s == nil || s.reporter == nil || s.entry == nil {
		return
	}
	s.endOnce.Do(func() {
		s.reporter.end(s.entry, err, time.Since(s.entry.started))
	})
}

func (s *Stage) SetCount(count int64) {
	s.Annotate(WithCount(count))
}

func (s *Stage) SetParser(parser string) {
	s.Annotate(WithParser(parser))
}

// Begin starts a stage using the reporter installed on the context. With no reporter this is a no-op.
func Begin(ctx context.Context, stage string, opts ...Option) (context.Context, *Stage) {
	reporter := fromContext(ctx)
	if reporter == nil {
		return ctx, &Stage{}
	}
	handle := &Stage{
		reporter: reporter,
		entry:    reporter.begin(ctx, stage, opts...),
	}
	return withStage(ctx, handle), handle
}

// Annotate updates the stage currently carried by the context.
func Annotate(ctx context.Context, opts ...Option) {
	if handle := stageFromContext(ctx); handle != nil {
		handle.Annotate(opts...)
	}
}

func SetCount(ctx context.Context, count int64) {
	Annotate(ctx, WithCount(count))
}

type reporterContextKey struct{}
type stageContextKey struct{}
type layerContextKey struct{}

func withReporter(ctx context.Context, reporter *Reporter) context.Context {
	return context.WithValue(ctx, reporterContextKey{}, reporter)
}

func fromContext(ctx context.Context) *Reporter {
	reporter, _ := ctx.Value(reporterContextKey{}).(*Reporter)
	return reporter
}

func withStage(ctx context.Context, stage *Stage) context.Context {
	return context.WithValue(ctx, stageContextKey{}, stage)
}

func stageFromContext(ctx context.Context) *Stage {
	stage, _ := ctx.Value(stageContextKey{}).(*Stage)
	return stage
}

// WithLayer records the nesting level (or layer) a stage is running in.
func WithLayerContext(ctx context.Context, layer int) context.Context {
	return context.WithValue(ctx, layerContextKey{}, layer)
}

func layerFromContext(ctx context.Context) int {
	layer, _ := ctx.Value(layerContextKey{}).(int)
	return layer
}
