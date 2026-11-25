package sbomartifact

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/anchore/syft/syft/sbom"
)

// Request is one resolved output: a destination path plus the formats that should land in it.
// Empty paths are not valid here; terminal (path-less) outputs stay on the report bus and are
// handled by the caller alongside the batch.
type Request struct {
	Path     string
	Encoders []sbom.FormatEncoder
}

// resolvedTarget pairs a target with the encoder identities it requested, before member names are
// derived.
type resolvedTarget struct {
	path     string
	kind     TargetKind
	encoders []sbom.FormatEncoder
	target   target
}

// Batch is a set of output destinations that are staged together and commit or roll back together.
// It implements sbom.Writer so scan and convert share one persistence path.
type Batch struct {
	targets  []target
	resolved []*resolvedTarget
	lockers  []Locker
}

var _ sbom.Writer = (*Batch)(nil)

// NewBatch validates and groups requests into concrete targets. All path and format validation
// happens before any visible destination is touched, so an illegal request fails cleanly with no
// on-disk side effects.
func NewBatch(ctx context.Context, requests ...Request) (*Batch, error) {
	grouped, err := groupRequests(requests)
	if err != nil {
		return nil, err
	}

	paths := make([]string, 0, len(grouped))
	for p := range grouped {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var resolved []*resolvedTarget
	for _, p := range paths {
		encoders := grouped[p]
		kind, err := classifyForEncoders(p, encoders)
		if err != nil {
			return nil, err
		}

		names := make([]string, 0, len(encoders))
		for _, enc := range encoders {
			names = append(names, MemberName(enc))
		}

		var t target
		switch kind {
		case KindFile:
			// groupRequests guarantees exactly one encoder for a file destination
			t = newFileTarget(p, names[0])
		case KindDirectory:
			t = newDirectoryTarget(p, names)
		case KindArchive:
			t = newArchiveTarget(p, names)
		default:
			return nil, fmt.Errorf("internal error: unhandled target kind for %q", p)
		}
		resolved = append(resolved, &resolvedTarget{path: p, kind: kind, encoders: encoders, target: t})
	}

	b := &Batch{}
	// acquire locks only after everything validated, in path order, so acquisition cannot deadlock
	for _, r := range resolved {
		locker, err := lockTarget(r.path)
		if err != nil {
			_ = b.releaseLocks()
			return nil, err
		}
		if err := locker.Lock(ctx); err != nil {
			_ = locker.Unlock()
			_ = b.releaseLocks()
			return nil, fmt.Errorf("output target %q is busy: %w", r.path, err)
		}
		b.lockers = append(b.lockers, locker)
		b.targets = append(b.targets, r.target)
	}

	// stash encoder sets on the batch for Write
	b.resolved = resolved
	return b, nil
}

// Write encodes every distinct format once, stages every target from those shared members, then
// swaps them all in. A failure at any point rolls every target — including ones already swapped —
// back to the pre-call state and removes all staging artifacts.
func (b *Batch) Write(s sbom.SBOM) error {
	root, err := b.stagingRoot()
	if err != nil {
		return b.fail(err)
	}
	stage, err := stageDir(root)
	if err != nil {
		return b.fail(err)
	}
	defer cleanupStage(stage)

	// 1. one encode per distinct format for the whole batch; directory and archive consume the
	// same bytes, so their members are byte-identical by construction
	allEncoders := b.distinctEncoders()
	members, err := encodeAllMembers(allEncoders, s, stage)
	if err != nil {
		// attach the concrete targets that requested the failing format so the error pinpoints
		// both the format and a destination rather than an anonymous batch
		var encErr *EncodeError
		if errors.As(err, &encErr) {
			for _, r := range b.resolved {
				for _, e := range r.encoders {
					if sameEncoder(e, allEncoderByID(allEncoders, encErr)) {
						encErr.Path = r.path
						break
					}
				}
			}
		}
		return b.fail(err)
	}

	// 2. every target builds its own index over exactly the members it carries, so a target that
	// requests a format subset never advertises members it does not contain
	// 3. every target stages privately from the shared members
	for _, t := range b.targets {
		indexBytes, err := b.indexForTarget(t, members)
		if err != nil {
			return b.fail(err)
		}
		if err := t.Stage(members, indexBytes); err != nil {
			return b.fail(err)
		}
	}

	// 4. swap in all targets; a failure rolls back the ones already committed
	committed := make([]target, 0, len(b.targets))
	for _, t := range b.targets {
		if err := t.Commit(); err != nil {
			for i := len(committed) - 1; i >= 0; i-- {
				_ = committed[i].Rollback()
			}
			_ = t.Rollback()
			return b.fail(err)
		}
		committed = append(committed, t)
	}

	// 5. all targets are visibly in place; only now drop the pre-call backups
	var finalizeErr error
	for _, t := range committed {
		if err := t.Finalize(); err != nil && finalizeErr == nil {
			finalizeErr = err
		}
	}
	if finalizeErr != nil {
		return finalizeErr
	}
	return b.releaseLocks()
}

// Close releases any locks still held when a batch is abandoned before Write, and retries removal
// of lock files that an earlier rollback could not delete.
func (b *Batch) Close() error {
	var errs error
	for _, l := range b.lockers {
		if err := l.RemoveFile(); err != nil {
			errs = joinErr(errs, err)
		}
	}
	b.lockers = nil
	return errs
}

func (b *Batch) fail(err error) error {
	for _, t := range b.targets {
		_ = t.Rollback()
	}
	_ = b.releaseLocks()
	return err
}

// releaseLocks releases every held OS lock. Locks whose lock file could not be removed (for example
// while a parent directory is read-only) are retained so a later Close retries the cleanup once
// the obstruction is gone; successfully cleaned ones are dropped from the batch.
func (b *Batch) releaseLocks() error {
	var errs error
	var retained []Locker
	for _, l := range b.lockers {
		if err := l.Unlock(); err != nil {
			errs = joinErr(errs, err)
			retained = append(retained, l)
		}
	}
	b.lockers = retained
	return errs
}

// stagingRoot chooses one parent directory for the shared staging area that is on the same
// filesystem as every target, so all swap-ins remain atomic renames.
func (b *Batch) stagingRoot() (string, error) {
	if len(b.resolved) == 0 {
		return "", fmt.Errorf("internal error: batch has no targets")
	}
	return filepath.Dir(b.resolved[0].path), nil
}

// indexForTarget builds the index document covering only the members that the given target will
// contain. Bundle targets report their member selection through the indexMemberSelector interface;
// single-file targets carry no index and receive nil.
func (b *Batch) indexForTarget(t target, members []*encodedMember) ([]byte, error) {
	selector, ok := t.(indexMemberSelector)
	if !ok {
		return nil, nil
	}
	wanted := selector.indexMembers()
	if len(wanted) == 0 {
		return nil, nil
	}
	selected := make([]*encodedMember, 0, len(wanted))
	for _, name := range wanted {
		m := findMember(members, name)
		if m == nil {
			return nil, fmt.Errorf("internal error: member %q missing for target %q", name, t.Path())
		}
		selected = append(selected, m)
	}
	records, err := memberRecordsFromEncoded(selected)
	if err != nil {
		return nil, err
	}
	indexBytes, _, err := newIndex(records)
	return indexBytes, err
}

// distinctEncoders returns the union of encoders across targets, de-duplicated by format and
// version, so each format is encoded exactly once for the whole batch.
func (b *Batch) distinctEncoders() []sbom.FormatEncoder {
	seen := make(map[string]struct{})
	var out []sbom.FormatEncoder
	for _, r := range b.resolved {
		for _, enc := range r.encoders {
			label := formatLabel(enc)
			if _, ok := seen[label]; ok {
				continue
			}
			seen[label] = struct{}{}
			out = append(out, enc)
		}
	}
	// stable order keeps member/index ordering reproducible
	sort.Slice(out, func(i, j int) bool { return MemberName(out[i]) < MemberName(out[j]) })
	return out
}

// groupRequests merges requests that resolve to the same destination. It first aggregates the
// complete format set per destination and only then classifies the destination, so two requests
// aimed at one missing path correctly form a directory bundle rather than two conflicting files.
// Two genuinely different documents aimed at one existing file path is an explicit error rather
// than a silent truncation or mixed-content write.
func groupRequests(requests []Request) (map[string][]sbom.FormatEncoder, error) {
	// pass 1: aggregate distinct encoders keyed by absolute path, preserving first-seen order
	encodersByPath := make(map[string][]sbom.FormatEncoder)
	var pathOrder []string
	for _, req := range requests {
		if req.Path == "" {
			return nil, fmt.Errorf("internal error: empty output path in persistence request")
		}
		abs, err := filepath.Abs(req.Path)
		if err != nil {
			return nil, fmt.Errorf("unable to resolve output path %q: %w", req.Path, err)
		}
		if _, seen := encodersByPath[abs]; !seen {
			pathOrder = append(pathOrder, abs)
		}
		if len(req.Encoders) == 0 {
			return nil, &errEmptyTarget{path: abs, kind: KindFile}
		}
		for _, enc := range req.Encoders {
			if !containsEncoder(encodersByPath[abs], enc) {
				encodersByPath[abs] = append(encodersByPath[abs], enc)
			}
		}
	}

	// pass 2: classify each destination from its complete format set and enforce file constraints
	out := make(map[string][]sbom.FormatEncoder, len(encodersByPath))
	for _, abs := range pathOrder {
		encoders := encodersByPath[abs]
		kind, err := classifyForEncoders(abs, encoders)
		if err != nil {
			return nil, err
		}
		if kind == KindFile && len(encoders) > 1 {
			// an existing single-file destination cannot hold multiple distinct documents
			return nil, fmt.Errorf("output path %q is a single file and cannot receive multiple formats (%s and %s); use a directory or archive for multi-format output",
				abs, formatLabel(encoders[0]), formatLabel(encoders[1]))
		}
		out[abs] = encoders
	}
	return out, nil
}

func containsEncoder(list []sbom.FormatEncoder, enc sbom.FormatEncoder) bool {
	for _, e := range list {
		if sameEncoder(e, enc) {
			return true
		}
	}
	return false
}

// allEncoderByID resolves the encoder whose format and version match the one described in an
// EncodeError, used to attribute a shared-encode failure back to the targets that requested it.
func allEncoderByID(all []sbom.FormatEncoder, encErr *EncodeError) sbom.FormatEncoder {
	for _, e := range all {
		if string(e.ID()) == encErr.Format && e.Version() == encErr.Version {
			return e
		}
	}
	return nil
}

func sameEncoder(a, b sbom.FormatEncoder) bool {
	return a.ID() == b.ID() && a.Version() == b.Version()
}

func formatLabel(enc sbom.FormatEncoder) string {
	v := enc.Version()
	if v == "" || v == sbom.AnyVersion {
		return string(enc.ID())
	}
	return fmt.Sprintf("%s@%s", enc.ID(), v)
}

// Targets reports the resolved destinations, mainly useful for tests and diagnostics.
func (b *Batch) Targets() []string {
	paths := make([]string, len(b.targets))
	for i, t := range b.targets {
		paths[i] = t.Path()
	}
	return paths
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
