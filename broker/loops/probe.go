package loops

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"
)

// LOOP-7 probes (P3-4b-4a): off-the-shelf active tests that run in Loop
// 2's slot after the passive checks and hand what they find to Report.
// The scheduler takes one source per loop, so Guard runs them. A probe
// never writes or generates an attack: it replays published corpora or
// fixed scripts (D-067).

// Checks a probe reports. Their findings carry no tree rule: the probe
// that found one is its regression, and the probe's next clean run of the
// same subject closes it.
const (
	CheckCanary Check = "canary" // a canary round found a planted test secret where the adversary could reach it (A5)
	CheckCorpus Check = "corpus" // a published injection item got past a closed check
)

// probeChecks are the checks Report takes without a tree rule.
var probeChecks = map[Check]bool{CheckCanary: true, CheckCorpus: true, CheckTamper: true, CheckExhaust: true}

// Probe is one LOOP-7 source. Run makes no model calls. It returns what it
// found and the subjects it checked; an error with a result means part of
// the run failed, so its findings are reported but nothing is closed.
type Probe interface {
	Check() Check
	// Every is how often the probe runs.
	Every() time.Duration
	Run(ctx context.Context) (ProbeResult, error)
}

// ProbeResult is one run's outcome.
type ProbeResult struct {
	Found []Finding
	// Checked are the subjects the run tested, found or not.
	Checked []string
}

// dueProbe is the first configured probe whose interval has passed.
func (s *Guard) dueProbe() (Probe, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	for _, p := range s.cfg.Probes {
		if now.Sub(s.st.ProbeLast[p.Check()]) >= p.Every() {
			return p, true
		}
	}
	return nil, false
}

// runProbe runs p once: it reports each finding through Report, then
// closes the open findings of p's check whose subject the run checked and
// did not find. A preempted run changes nothing and is offered again; a
// failed one is said in STATUS and the digest until a run succeeds.
func (s *Guard) runProbe(ctx context.Context, p Probe) Result {
	c := p.Check()
	res, err := p.Run(ctx)
	if ctx.Err() != nil {
		return Result{Err: ctx.Err()}
	}
	var errs []error
	if err != nil {
		errs = append(errs, fmt.Errorf("probe %s: %w", c, err))
	}
	found := map[string]bool{}
	n := 0
	for _, f := range res.Found {
		if f.Check != c {
			errs = append(errs, fmt.Errorf("%w: probe %s reported a %q finding", ErrFinding, c, f.Check))
			continue
		}
		s.mu.Lock()
		_, before := s.st.Open[reportID(f)]
		s.mu.Unlock()
		rec, rerr := s.Report(ctx, f)
		if rerr != nil {
			errs = append(errs, rerr)
			continue
		}
		found[rec.Finding.ID] = true
		if !before {
			n++
		}
	}
	if ctx.Err() != nil {
		return Result{Value: float64(n), Err: errors.Join(append(errs, ctx.Err())...)}
	}
	failed := len(errs) > 0
	s.reportMu.Lock()
	s.mu.Lock()
	now := s.cfg.Now()
	var closed []Record
	if !failed {
		for _, id := range sortedKeys(s.st.Open) {
			rec := s.st.Open[id]
			if rec.Finding.Check != c || !rec.Reported || rec.Finding.Rule != nil || found[id] || !slices.Contains(res.Checked, rec.Finding.Subject) {
				continue
			}
			delete(s.st.Open, id)
			s.st.Cleared[id] = now
			closed = append(closed, rec)
		}
	}
	lines := s.clearedLinesLocked(closed)
	if s.st.ProbeLast == nil {
		s.st.ProbeLast = map[Check]time.Time{}
	}
	s.st.ProbeLast[c] = now
	s.st.ProbeFailed = slices.DeleteFunc(s.st.ProbeFailed, func(x string) bool { return x == string(c) })
	if failed {
		s.st.ProbeFailed = append(s.st.ProbeFailed, string(c))
		sort.Strings(s.st.ProbeFailed)
	}
	serr := s.saveLocked()
	s.mu.Unlock()
	s.reportMu.Unlock()
	if text := s.batch(lines); text != "" {
		s.cfg.Notify(text, false)
	}
	return Result{Value: float64(n), Err: errors.Join(append(errs, serr)...)}
}

// reportID is the ID Report gives f.
func reportID(f Finding) string {
	if f.ID != "" || f.Rule != nil {
		return f.ID
	}
	return findingID(f.Check, f.Subject, f.Detail)
}

// countPauseLocked counts an automatic pause by a probe for today's
// repeat line (A-6, P3-4b).
func (s *Guard) countPauseLocked(c Check) {
	if !probeChecks[c] {
		return
	}
	if s.st.SourcePauses == nil {
		s.st.SourcePauses = map[Check]int{}
	}
	s.st.SourcePauses[c]++
}

// rollDayLocked starts a new UTC day's pause counts.
func (s *Guard) rollDayLocked(now time.Time) {
	if day := now.UTC().Format(time.DateOnly); s.st.PauseDay != day {
		s.st.PauseDay, s.st.Pauses, s.st.SourcePauses = day, 0, nil
	}
}

// repeatLinesLocked names each probe that paused more than once today
// (A-6, P3-4b), so the owner sees a probe that keeps pausing.
func (s *Guard) repeatLinesLocked() []string {
	if s.st.PauseDay != s.cfg.Now().UTC().Format(time.DateOnly) {
		return nil
	}
	var out []string
	for _, c := range []Check{CheckCanary, CheckCorpus, CheckTamper, CheckExhaust} {
		if n := s.st.SourcePauses[c]; n > 1 {
			out = append(out, fmt.Sprintf("Loop 2: %s paused access %d times today.", plainCheck[c], n))
		}
	}
	return out
}
