// Package requal is the host side of local requalification (UPD-5, HLD-3):
// it runs a suite's cases in a sandbox booted from a release and grades
// what comes back, so a candidate release is scored against the installed
// one by the installed one's cases and graders, never its own.
package requal

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ghbmrk/agentos/broker/update"
)

// ErrNoSource is a suite the box has no cases or grader for. Requalify
// takes it as a failure to run, so the release holds (the ship gate).
var ErrNoSource = errors.New("requal: no source for suite")

// Case is one case held by the installed release. Only Input reaches the
// sandbox; ID and Expect stay on the host.
type Case struct {
	ID     string
	Input  []byte
	Expect []byte
}

// Source gives one suite's cases.
type Source interface {
	Cases(ctx context.Context) ([]Case, error)
}

// DroppedSource is a Source whose suite the owner can shrink by passkey
// (HLD-3): it gives the cases and how many the owner dropped, read at once,
// so the security floor counts the drops and no other shrink (update.Score).
type DroppedSource interface {
	Source
	CasesDropped(ctx context.Context) ([]Case, int, error)
}

// Grade is a grader's judgement of one output. Unadmitted counts replayed
// steps the recorded keys would not have admitted (HLD-2).
type Grade struct {
	Pass       bool
	Unadmitted int
}

// Grader judges one case's output on the host.
type Grader func(c Case, out []byte) Grade

// Suite is where one suite's cases come from and how they are graded.
type Suite struct {
	Source Source
	Grade  Grader
}

// Sandbox boots a release with no live effects. A nil release is the
// installed one, the baseline.
type Sandbox interface {
	Start(ctx context.Context, rel *update.Verified) (Session, error)
}

// Session is one booted release that answers case inputs.
type Session interface {
	Run(ctx context.Context, input []byte) ([]byte, error)
	Close() error
}

// Config configures New. CaseTimeout bounds one case and Budget a whole
// run (HLD-2's evaluation budget); both are the installed release's.
type Config struct {
	Sandbox     Sandbox
	Suites      map[string]Suite
	CaseTimeout time.Duration
	Budget      time.Duration
}

// Runner implements update.Runner.
type Runner struct{ cfg Config }

var _ update.Runner = (*Runner)(nil)

// New checks cfg. Suites may be missing: Run then answers ErrNoSource.
func New(cfg Config) (*Runner, error) {
	if cfg.Sandbox == nil || cfg.CaseTimeout <= 0 || cfg.Budget <= 0 {
		return nil, errors.New("requal: runner needs a sandbox, a case timeout and a budget")
	}
	return &Runner{cfg: cfg}, nil
}

// Run scores suite on rel, or on the installed release when rel is nil.
// A candidate that errs or times out on a case fails the case; a baseline
// that does is an error, since a broken baseline would lower the bar. A
// spent budget is an error, never a partial score.
func (r *Runner) Run(ctx context.Context, rel *update.Verified, suite string) (update.Score, error) {
	s, ok := r.cfg.Suites[suite]
	if !ok || s.Source == nil || s.Grade == nil {
		return update.Score{}, fmt.Errorf("%w %s", ErrNoSource, suite)
	}
	if rel != nil && !rel.OK() {
		return update.Score{}, errors.New("requal: release is not checked")
	}
	var (
		cases   []Case
		dropped int
		err     error
	)
	if ds, ok := s.Source.(DroppedSource); ok {
		cases, dropped, err = ds.CasesDropped(ctx)
	} else {
		cases, err = s.Source.Cases(ctx)
	}
	if err == nil && dropped < 0 {
		err = errors.New("negative drop count")
	}
	if err != nil {
		return update.Score{}, fmt.Errorf("requal: %s cases: %w", suite, err)
	}
	digest, err := digestOf(cases)
	if err != nil {
		return update.Score{}, fmt.Errorf("requal: %s: %w", suite, err)
	}
	sc := update.Score{Suite: suite, Digest: digest, Cases: len(cases), Dropped: dropped}
	if len(cases) == 0 {
		return sc, nil
	}
	ctx, cancel := context.WithTimeout(ctx, r.cfg.Budget)
	defer cancel()
	sess, err := r.cfg.Sandbox.Start(ctx, rel)
	if err != nil {
		return update.Score{}, fmt.Errorf("requal: %s start: %w", suite, err)
	}
	if err := r.cases(ctx, sess, rel == nil, suite, s.Grade, cases, &sc); err != nil {
		sess.Close()
		return update.Score{}, err
	}
	if err := sess.Close(); err != nil {
		return update.Score{}, fmt.Errorf("requal: %s close: %w", suite, err)
	}
	return sc, nil
}

func (r *Runner) cases(ctx context.Context, sess Session, baseline bool, suite string, grade Grader, cases []Case, sc *update.Score) error {
	for _, c := range cases {
		cctx, cancel := context.WithTimeout(ctx, r.cfg.CaseTimeout)
		out, err := sess.Run(cctx, append([]byte(nil), c.Input...))
		cancel()
		if ctx.Err() != nil {
			return fmt.Errorf("requal: %s: evaluation budget spent", suite)
		}
		if err != nil {
			if baseline {
				return fmt.Errorf("requal: %s baseline case %s: %w", suite, c.ID, err)
			}
			continue
		}
		g := grade(c, out)
		if g.Pass {
			sc.Passed++
		}
		if suite == update.SuiteReplay {
			sc.Unadmitted += max(g.Unadmitted, 0)
		}
	}
	return nil
}

// digestOf names the cases exactly, length-prefixed so no two case lists
// share one; duplicate IDs are refused.
func digestOf(cases []Case) (string, error) {
	h := sha256.New()
	seen := make(map[string]bool, len(cases))
	field := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	for _, c := range cases {
		if seen[c.ID] {
			return "", fmt.Errorf("duplicate case %q", c.ID)
		}
		seen[c.ID] = true
		field([]byte(c.ID))
		field(c.Input)
		field(c.Expect)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
