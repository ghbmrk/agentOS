package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"

	"github.com/ghbmrk/agentos/broker/durable"
)

// The suites a release is requalified on, in run order (UPD-5, HLD-3).
const (
	SuiteHeldOut  = "held-out" // owner outcomes on real tasks (KRN-9)
	SuiteReplay   = "replay"   // past tasks replayed in shadow (HLD-2)
	SuiteSecurity = "security" // injection tests and regression cases (HLD-5)
)

var suites = []string{SuiteHeldOut, SuiteReplay, SuiteSecurity}

// RequalUnavailable is Verdict.Reason when the box has no Runner: it
// cannot requalify, so an ordinary stable release holds (the ship gate,
// Mark's decision C on #3961).
const RequalUnavailable = "unavailable"

// Score is one suite's run on one release. Digest names the suite's
// contents, so a candidate and its baseline are compared on one suite.
type Score struct {
	Suite  string `json:"suite"`
	Digest string `json:"digest"`
	Cases  int    `json:"cases"`
	Passed int    `json:"passed"`
	// Unadmitted counts replayed steps the recorded keys would not have
	// admitted (HLD-2); only the replay suite has any.
	Unadmitted int `json:"unadmitted,omitempty"`
}

// Runner runs one suite against a release in a sandbox. A nil release is
// the installed one, the baseline (HLD-3).
type Runner interface {
	Run(ctx context.Context, rel *Verified, suite string) (Score, error)
}

// Verdict is one requalification. Reason is "" when Passed; otherwise
// RequalUnavailable or the suite that failed, with Detail for the log.
type Verdict struct {
	Ref    Ref     `json:"ref"`
	Base   Ref     `json:"base"`
	Passed bool    `json:"passed"`
	Reason string  `json:"reason,omitempty"`
	Detail string  `json:"detail,omitempty"`
	Scores []Score `json:"scores,omitempty"`
}

// Requalifier is UPD-5's local requalification: an ordinary release
// installs on a stable box only after it passes the box's held-out
// suite, replays and security suite against the installed release.
type Requalifier struct {
	store  *Store
	runner Runner
	path   string
	mu     sync.Mutex
	// failed holds this process's security failures too, so a mark whose
	// save failed still holds until the process ends.
	failed map[string][]string
}

// requalState is the saved record: the security suite's floor, which only
// grows (HLD-3), and, per candidate, the digests of the security suites it
// failed. No verdict is kept, so a suite that gained a case since a pass is
// run, and held-out or replay noise is retried; but a security failure is
// final on that suite, so a retry never turns one into a pass.
type requalState struct {
	Floor  int                 `json:"security_floor"`
	Failed map[string][]string `json:"security_failed"`
}

// NewRequalifier keeps its record at path. A nil runner is allowed: every
// Requalify then answers RequalUnavailable.
func NewRequalifier(store *Store, runner Runner, path string) (*Requalifier, error) {
	if store == nil || path == "" {
		return nil, errors.New("update: requalifier needs a store and a state path")
	}
	return &Requalifier{store: store, runner: runner, path: path, failed: map[string][]string{}}, nil
}

// Requalify judges v against the installed release, running every suite
// on both. A Runner error saves nothing; otherwise the floor is saved
// before the verdict is returned.
func (q *Requalifier) Requalify(ctx context.Context, v *Verified) (Verdict, error) {
	if !v.ok() {
		return Verdict{}, ErrNotChecked
	}
	in, err := q.store.Installed()
	if err != nil {
		return Verdict{}, err
	}
	out := Verdict{Ref: v.Ref(), Base: Ref{Version: in.Version, UsrRootHash: in.UsrRootHash, ManifestSHA256: in.ManifestSHA256}}
	if q.runner == nil {
		out.Reason = RequalUnavailable
		return out, nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	st, err := q.load()
	if err != nil {
		return Verdict{}, err
	}
	key := refKey(out.Ref)
	for _, s := range suites {
		cand, err := q.run(ctx, v, s)
		if err != nil {
			return Verdict{}, err
		}
		// A failing security case is marked and saved before anything
		// else can fail, so no later error lets a retry pass it.
		if s == SuiteSecurity && cand.Passed < cand.Cases {
			if err := q.mark(&st, key, cand.Digest); err != nil {
				return Verdict{}, err
			}
		}
		base, err := q.run(ctx, nil, s)
		if err != nil {
			return Verdict{}, err
		}
		out.Scores = append(out.Scores, cand)
		if s == SuiteSecurity {
			st.Floor = max(st.Floor, base.Cases)
		}
		detail := judge(cand, base, st.Floor)
		if s == SuiteSecurity {
			if detail != "" {
				addDigest(st.Failed, key, cand.Digest)
				addDigest(q.failed, key, cand.Digest)
			} else if slices.Contains(st.Failed[key], cand.Digest) || slices.Contains(q.failed[key], cand.Digest) {
				detail = "failed this security suite before"
			}
		}
		if detail != "" {
			out.Reason, out.Detail = s, detail
			break
		}
	}
	out.Passed = out.Reason == ""
	if err := q.save(st); err != nil {
		return Verdict{}, err
	}
	return out, nil
}

func refKey(r Ref) string {
	return fmt.Sprintf("%d:%s:%s", r.Version, r.UsrRootHash, r.ManifestSHA256)
}

// addDigest adds digest to key's set in m.
func addDigest(m map[string][]string, key, digest string) {
	if !slices.Contains(m[key], digest) {
		m[key] = append(m[key], digest)
	}
}

// mark records that the candidate failed the security suite digest, in
// memory first, then in the saved record.
func (q *Requalifier) mark(st *requalState, key, digest string) error {
	addDigest(q.failed, key, digest)
	addDigest(st.Failed, key, digest)
	return q.save(*st)
}

// run is one Runner call whose score must be for the suite it asked for
// and internally consistent; anything else is an error (fail closed).
func (q *Requalifier) run(ctx context.Context, rel *Verified, suite string) (Score, error) {
	sc, err := q.runner.Run(ctx, rel, suite)
	if err != nil {
		return Score{}, fmt.Errorf("update: requalify %s: %w", suite, err)
	}
	if sc.Suite != suite || sc.Digest == "" || sc.Cases < 0 || sc.Passed < 0 || sc.Passed > sc.Cases || sc.Unadmitted < 0 {
		return Score{}, fmt.Errorf("update: requalify %s: malformed score %+v", suite, sc)
	}
	return sc, nil
}

// judge is HLD-2 and HLD-3's rule for one suite: "" passes, otherwise the
// reason. floor is the most security cases ever run on this box.
func judge(cand, base Score, floor int) string {
	if cand.Digest != base.Digest || cand.Cases != base.Cases {
		return "candidate and baseline ran different suites"
	}
	switch cand.Suite {
	case SuiteReplay:
		if cand.Unadmitted > 0 {
			return fmt.Sprintf("%d replayed steps the recorded keys would not admit", cand.Unadmitted)
		}
	case SuiteSecurity:
		if cand.Cases == 0 || cand.Cases < floor {
			return fmt.Sprintf("security suite has %d cases, fewer than %d", cand.Cases, max(floor, 1))
		}
		if cand.Passed < cand.Cases {
			return fmt.Sprintf("%d security cases fail", cand.Cases-cand.Passed)
		}
		return ""
	}
	if cand.Passed < base.Passed {
		return fmt.Sprintf("%d of %d pass, below the installed release's %d", cand.Passed, cand.Cases, base.Passed)
	}
	return ""
}

func (q *Requalifier) load() (requalState, error) {
	st := requalState{Failed: map[string][]string{}}
	b, err := readFile(q.path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return requalState{}, fmt.Errorf("update: requalification record: %w", err)
	}
	if st.Failed == nil {
		st.Failed = map[string][]string{}
	}
	return st, nil
}

func (q *Requalifier) save(st requalState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return durable.WriteFile(q.path, b, 0o600)
}
