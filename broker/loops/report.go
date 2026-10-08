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
	if f.ID == "" {
		h := sha256.Sum256(rule.Encode())
		f.ID = findingID(f.Check, f.Subject, hex.EncodeToString(h[:]))
	}
	now := s.cfg.Now()
	s.mu.Lock()
	if rec, open := s.st.Open[f.ID]; open {
		s.mu.Unlock()
		return rec, nil
	}
	if day := now.UTC().Format(time.DateOnly); s.st.PauseDay != day {
		s.st.PauseDay, s.st.Pauses = day, 0
	}
	pause := f.Contain != nil && s.st.Pauses < s.cfg.MaxPausesPerDay
	if pause {
		s.st.Pauses++
	}
	s.mu.Unlock()
	rec, err := s.handle(ctx, f, pause, true)
	if rec.Texted {
		// Sent on its own, not through batch, so lines held for MORE stay.
		s.cfg.Notify("Security checks: "+ownerLine(rec), f.Check != CheckExpiry)
	}
	s.mu.Lock()
	err2 := s.saveLocked()
	s.mu.Unlock()
	return rec, errors.Join(err, err2)
}

// reportable checks f before anything acts on it: a check Report takes, a
// severity, a valid tree rule that fails on the active tree, and a
// containment target of a known kind.
func (s *Guard) reportable(f Finding) (change.TreeRule, error) {
	if f.Check != CheckSeeded {
		return change.TreeRule{}, fmt.Errorf("%w: check %q is not reported", ErrFinding, f.Check)
	}
	if f.Severity != Low && f.Severity != High {
		return change.TreeRule{}, fmt.Errorf("%w: severity %q", ErrFinding, f.Severity)
	}
	if f.Contain != nil && f.Contain.Kind != "grant" && f.Contain.Kind != "executor" {
		return change.TreeRule{}, fmt.Errorf("%w: containment kind %q", ErrFinding, f.Contain.Kind)
	}
	rule, ok, err := change.ParseTreeRule(f.Rule)
	if !ok || err != nil {
		return change.TreeRule{}, fmt.Errorf("%w: no valid tree rule (%v)", ErrFinding, err)
	}
	if rule.Holds(s.activeTree(rule)) {
		return change.TreeRule{}, fmt.Errorf("%w: the test passes on this box", ErrFinding)
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
	waitNoFixer   = "nothing on this box can build one yet"
	waitBuilding  = "one is being prepared"
	waitFailed    = "building one failed; I try again at the next check"
	waitRejected  = "the last one did not qualify; I try again at the next check"
	waitForAFixOf = "waits for a fix: "
)

// waitingLocked is why an open reported record waits, "" if it does not.
func (s *Guard) waitingLocked(r Record) string {
	if !r.Reported || r.Fix == "" || r.Fix == string(change.StateAdopted) {
		return ""
	}
	switch {
	case s.cfg.Fixer == nil:
		return waitNoFixer
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
