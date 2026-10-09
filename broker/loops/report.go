package loops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// Findings handed in from outside the passive checks (P3-4b-1). Report
// takes one that arrives as a failing security test, such as a seed the
// A11 harness plants, and runs the same chain a passive finding gets
// (LOOP-9). It is called in process only; no socket reaches it.

// CheckSeeded names a finding handed in as a failing tree-rule test.
const CheckSeeded Check = "seeded"

// CheckFuzz and CheckProbe name findings from Loop 7's off-the-shelf
// checks (P3-4b-3): a fuzz target's crash and an in-guest socket probe's
// failure. They have no tree rule, so nothing in the suite can grade a
// Loop 2 fix: the fix comes with an update, and the caller's own
// regression (the crash input, the probe frame) replays it, calling
// Resolve once it passes. Detail names the evidence (an input digest).
const (
	CheckFuzz  Check = "fuzz"
	CheckProbe Check = "probe"
)

// ruleLess reports a check Report takes without a tree rule.
func ruleLess(c Check) bool { return c == CheckFuzz || c == CheckProbe }

// OriginalSuffix ends the ID of a reported finding's original,
// unminimized test, linked beside its regression `loop2/<id>`.
const OriginalSuffix = "/original"

// ErrFinding: Report refused a finding it cannot act on. Nothing was
// paused, saved or added for it.
var ErrFinding = errors.New("loops: finding refused")

// Report contains f, saves its evidence, adds its minimized test to the
// security suite linked to it, records an open fix request and texts the
// owner when the finding calls for it, in that order. It never calls the
// fixer: the next Pass proposes the fix, so a case linked to the finding
// in between grades it (LOOP-10, 6(g)). The same finding again returns
// its open record.
func (s *Guard) Report(ctx context.Context, f Finding) (Record, error) {
	s.reportMu.Lock()
	defer s.reportMu.Unlock()
	rule, err := s.reportable(f)
	if err != nil {
		return Record{}, err
	}
	if f.ID == "" && ruleLess(f.Check) {
		h := sha256.Sum256([]byte(f.Detail))
		f.ID = findingID(f.Check, f.Subject, hex.EncodeToString(h[:]))
	} else if f.ID == "" && f.Rule == nil {
		f.ID = reportID(f)
	} else if f.ID == "" {
		h := sha256.Sum256(rule.Encode())
		f.ID = findingID(f.Check, f.Subject, hex.EncodeToString(h[:]))
	}
	now := s.cfg.Now()
	s.mu.Lock()
	if rec, open := s.st.Open[f.ID]; open {
		s.mu.Unlock()
		if !rec.Reported || !unfinished(rec) {
			return rec, nil
		}
		// Left part done by a crash or a store error (P3-4b-1b item 3).
		return s.resumeLocked(ctx, f.ID)
	}
	s.rollDayLocked(now)
	pause := f.Contain != nil && s.st.Pauses < s.cfg.MaxPausesPerDay
	if pause {
		s.st.Pauses++
		s.countPauseLocked(f.Check)
	}
	s.mu.Unlock()
	rec, err := s.handle(ctx, f, pause, true)
	rec = s.tell(rec)
	return rec, errors.Join(err, s.save())
}

// reportable checks f before anything acts on it: a check Report takes, a
// severity, a valid tree rule that fails on the active tree, a
// containment target of a known kind, and an ID that is not another
// finding's original-test slot: one ending in OriginalSuffix would take
// that slot, so the other finding could never link (#493 intake). A
// probe finding (LOOP-7) may carry no rule, and then needs a subject,
// which its probe closes it by.
func (s *Guard) reportable(f Finding) (change.TreeRule, error) {
	if strings.HasSuffix(f.ID, OriginalSuffix) {
		return change.TreeRule{}, fmt.Errorf("%w: ID %q ends in %s", ErrFinding, f.ID, OriginalSuffix)
	}
	if f.Check != CheckSeeded && !probeChecks[f.Check] && !ruleLess(f.Check) {
		return change.TreeRule{}, fmt.Errorf("%w: check %q is not reported", ErrFinding, f.Check)
	}
	if probeChecks[f.Check] && f.Subject == "" {
		return change.TreeRule{}, fmt.Errorf("%w: a probe finding needs a subject", ErrFinding)
	}
	if f.Severity != Low && f.Severity != High {
		return change.TreeRule{}, fmt.Errorf("%w: severity %q", ErrFinding, f.Severity)
	}
	if f.Contain != nil && f.Contain.Kind != "grant" && f.Contain.Kind != "executor" {
		return change.TreeRule{}, fmt.Errorf("%w: containment kind %q", ErrFinding, f.Contain.Kind)
	}
	if ruleLess(f.Check) {
		switch {
		case f.Rule != nil:
			return change.TreeRule{}, fmt.Errorf("%w: a %s finding carries no tree rule", ErrFinding, f.Check)
		case f.Detail == "" || f.Subject == "":
			return change.TreeRule{}, fmt.Errorf("%w: a %s finding needs a subject and its evidence", ErrFinding, f.Check)
		}
		return change.TreeRule{}, nil
	}
	if f.Rule == nil && probeChecks[f.Check] {
		return change.TreeRule{}, nil
	}
	rule, ok, err := change.ParseTreeRule(f.Rule)
	if !ok || err != nil {
		return change.TreeRule{}, fmt.Errorf("%w: no valid tree rule (%v)", ErrFinding, err)
	}
	if rule.Holds(s.activeTree(rule)) {
		return change.TreeRule{}, fmt.Errorf("%w: the test already passes", ErrFinding)
	}
	return rule, nil
}

// activeTree is the adopted tree of every namespace r reads.
func (s *Guard) activeTree(r change.TreeRule) change.Tree {
	t := change.Tree{}
	for _, ns := range r.Namespaces() {
		for p, b := range s.cfg.Pipeline.Files(ns) {
			t[p] = b
		}
	}
	return t
}

// regression is the reported finding's test reduced to a 1-minimal
// clause set against the active tree, as the suite stores it.
func (s *Guard) regression(f Finding) []byte {
	rule, ok, err := change.ParseTreeRule(f.Rule)
	if !ok || err != nil {
		return f.Rule
	}
	return rule.Minimize(s.activeTree(rule)).Encode()
}

// Measured reports whether Loop 2 has carried a finding to containment
// since start, so its share is measured (LOOP-3); until then the
// scheduler treats its return as unmeasured.
func (s *Guard) Measured() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.contained
}

// Why a reported finding still waits for its fix, for STATUS and the
// digest.
const (
	waitNoFixer   = "I cannot build one yet"
	waitBuilding  = "one is being prepared"
	waitFailed    = "building one failed; I try again at the next check"
	waitRejected  = "the last one did not qualify; I try again at the next check"
	waitForAFixOf = "waits for a fix: "
	waitNoTest    = "its test could not be added to my security checks, so no fix can qualify yet"
	waitUpdate    = "one comes with an update; I check it again at least twice a day"
	waitLater     = "building the last ones failed; I try again in a day"
	waitUnchanged = "the last ones did not qualify; I try again once my security checks or settings change"
	waitStopped   = "none of the last ones worked, so I stopped trying; one may come with an update"
)

// waitingLocked is why an open reported record waits, "" if it does not.
func (s *Guard) waitingLocked(r Record) string {
	if r.Reported && r.Fix == "" && ruleLess(r.Finding.Check) {
		return waitUpdate
	}
	if r.Reported && r.Finding.Rule == nil && probeChecks[r.Finding.Check] {
		return "" // its probe closes it (P3-4b-4a)
	}
	if r.Reported && r.Fix == "" {
		return waitNoTest
	}
	if !r.Reported || r.Fix == string(change.StateAdopted) {
		return ""
	}
	u, _ := s.cfg.Fixer.(Unready)
	switch {
	case s.cfg.Fixer == nil:
		return waitNoFixer
	case u != nil && u.Unready() != "":
		return waitNoFixer + ": " + u.Unready()
	case r.FixHold == holdStopped:
		return waitStopped
	case r.FixHold == holdUnchanged:
		return waitUnchanged
	case r.FixHold == holdLater:
		return waitLater
	case r.Fix == FixFailed:
		return waitFailed
	case r.Fix == string(change.StateRejected):
		return waitRejected
	}
	return waitBuilding
}

// waitStatusLocked is the STATUS line for reported findings waiting for a
// fix, one sentence per reason.
func (s *Guard) waitStatusLocked() string {
	count := map[string]int{}
	var order []string
	for _, id := range sortedKeys(s.st.Open) {
		if why := s.waitingLocked(s.st.Open[id]); why != "" {
			if count[why] == 0 {
				order = append(order, why)
			}
			count[why]++
		}
	}
	var out []string
	for _, why := range order {
		if n := count[why]; n == 1 {
			out = append(out, "Loop 2: 1 finding "+waitForAFixOf+why+".")
		} else {
			out = append(out, fmt.Sprintf("Loop 2: %d findings wait for a fix: %s.", n, why))
		}
	}
	return strings.Join(out, " ")
}

// Replay is a source's record of re-running a fuzz or probe finding's
// stored input: Evidence names the input (the finding's Detail, an input
// digest) and Passed says the replay of that input passed.
type Replay struct {
	Evidence string    `json:"evidence"`
	Passed   bool      `json:"passed"`
	At       time.Time `json:"at"`
}

// Resolve closes open reported fuzz or probe finding id as cleared, only
// on a replay that passed on the finding's own stored input; nothing else
// clears one. The replay is saved on the finding's evidence. A pause it
// caused stays until the owner resumes the target, and the owner hears it
// cleared where they heard of it. A finding with a tree rule clears only
// when its linked cases hold (passedReported), never on a caller's word.
func (s *Guard) Resolve(id string, r Replay) error {
	s.reportMu.Lock()
	defer s.reportMu.Unlock()
	s.mu.Lock()
	rec, ok := s.st.Open[id]
	if !ok || !rec.Reported || !ruleLess(rec.Finding.Check) {
		s.mu.Unlock()
		return fmt.Errorf("%w: %q is not an open fuzz or probe finding", ErrFinding, id)
	}
	if !r.Passed || r.Evidence != rec.Finding.Detail {
		s.mu.Unlock()
		return fmt.Errorf("%w: no passing replay of %q's stored input", ErrFinding, id)
	}
	for i := range s.st.Evidence {
		if e := &s.st.Evidence[i]; e.Digest == rec.Digest {
			e.Replay = &r
		}
	}
	delete(s.st.Open, id)
	delete(s.held, id)
	s.st.Cleared[id] = s.cfg.Now()
	err := s.saveLocked()
	lines := s.clearedLinesLocked([]Record{rec})
	s.mu.Unlock()
	if text := s.batch(lines); text != "" {
		s.cfg.Notify(text, false)
	}
	return err
}

// clearedLinesLocked is the cleared text for the texted records just
// closed: one line per check and plain subject, and none while another
// open texted finding shares that name, so "Cleared: X" is never said
// while an X the owner heard of is still open (L3 #558 point 1).
func (s *Guard) clearedLinesLocked(closed []Record) []string {
	key := func(r Record) string { return string(r.Finding.Check) + "\x00" + plainSubject(r.Finding) }
	open := map[string]bool{}
	for _, r := range s.st.Open {
		if r.Texted {
			open[key(r)] = true
		}
	}
	said := map[string]bool{}
	var lines []string
	for _, r := range closed {
		if k := key(r); r.Texted && !open[k] && !said[k] {
			said[k] = true
			lines = append(lines, clearedLine(r))
		}
	}
	return lines
}

// OpenReported is the open reported findings of check c, so a LOOP-7
// source can resolve the ones its regression now passes.
func (s *Guard) OpenReported(c Check) []Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Finding
	for _, id := range sortedKeys(s.st.Open) {
		if r := s.st.Open[id]; r.Reported && r.Finding.Check == c {
			out = append(out, r.Finding)
		}
	}
	return out
}
