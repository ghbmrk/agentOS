package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
}

// requalState is the saved record: the security suite's floor (it only
// grows, HLD-3) and the verdict for each candidate against Base, the
// installed release.
type requalState struct {
	Floor    int                `json:"security_floor"`
	Base     Ref                `json:"base"`
	Verdicts map[string]Verdict `json:"verdicts"`
}

// NewRequalifier keeps its record at path. A nil runner is allowed: every
// Requalify then answers RequalUnavailable.
func NewRequalifier(store *Store, runner Runner, path string) (*Requalifier, error) {
	if store == nil || path == "" {
		return nil, errors.New("update: requalifier needs a store and a state path")
	}
	return &Requalifier{store: store, runner: runner, path: path}, nil
}

func refKey(r Ref) string {
	return fmt.Sprintf("%d:%s:%s", r.Version, r.UsrRootHash, r.ManifestSHA256)
}

// Requalify judges v against the installed release. A verdict is kept per
// candidate and reused while the installed release is the same one; a
// Runner error keeps nothing, so the next call runs again. The record is
// saved before a verdict is returned.
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
	if st.Base != out.Base {
		// Verdicts against another installed release are stale.
		st = requalState{Floor: st.Floor, Base: out.Base, Verdicts: map[string]Verdict{}}
	}
	key := refKey(out.Ref)
	if old, ok := st.Verdicts[key]; ok {
		return old, nil
	}
	for _, s := range suites {
		cand, err := q.run(ctx, v, s)
		if err != nil {
			return Verdict{}, err
		}
		base, err := q.run(ctx, nil, s)
		if err != nil {
			return Verdict{}, err
		}
		out.Scores = append(out.Scores, cand)
		if s == SuiteSecurity {
			st.Floor = max(st.Floor, base.Cases)
		}
		if detail := judge(cand, base, st.Floor); detail != "" {
			out.Reason, out.Detail = s, detail
			break
		}
	}
	out.Passed = out.Reason == ""
	st.Verdicts[key] = out
	if err := q.save(st); err != nil {
		return Verdict{}, err
	}
	return out, nil
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
	st := requalState{Verdicts: map[string]Verdict{}}
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
	return st, nil
}

func (q *Requalifier) save(st requalState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return durable.WriteFile(q.path, b, 0o600)
}
