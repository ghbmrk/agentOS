package loops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// Loop 2, self-securing (LOOP-8 to LOOP-10). This file holds the passive
// checks and what happens to a finding. LOOP-7's off-the-shelf probes
// (canary rounds, published corpora) are in probe.go and corpus.go,
// with the command runner in ../probecmd; the tamper and exhaustion
// probes are P3-4b-4b.

// Severity decides how the owner hears about a finding (LOOP-9).
type Severity string

const (
	// Low findings go in the digest.
	Low Severity = "low"
	// High findings are texted at once.
	High Severity = "high"
)

// Check names a passive check (LOOP-8).
type Check string

const (
	CheckHash     Check = "hash"     // image or dependency digest vs the signed release
	CheckAdvisory Check = "advisory" // known vulnerability in an installed package
	CheckDrift    Check = "drift"    // configuration differs from the adopted state
	CheckExpiry   Check = "expiry"   // a credential or certificate expires
)

// Target is what containment pauses: a grant or an executor (LOOP-9).
type Target struct {
	Kind string `json:"kind"` // "grant" or "executor"
	Name string `json:"name"` // the grant ID or executor name
	// Label is what the owner calls it ("pre-allowance P4", "the mail
	// tool"), from the wiring; owner text never says grant or executor.
	Label string `json:"label,omitempty"`
}

// Artifact is one hashed thing the signed release names: an image or a
// dependency. Contain is what runs it.
type Artifact struct {
	Name    string
	Contain *Target
}

// Package is an installed package, matched against advisories.
type Package struct {
	Name    string
	Version string
	// Scheme is how versions order: SchemeDeb (default) or SchemeSemver.
	Scheme  string
	Contain *Target
}

// Advisory is one known vulnerability: versions of Package below Fixed are
// affected. Severity is the feed's word; "high" and "critical" are High.
type Advisory struct {
	ID       string `json:"id"`
	Package  string `json:"package"`
	Fixed    string `json:"fixed"`
	Severity string `json:"severity"`
}

// Snapshot is the last advisory feed fetched (like updates, DEP-4) and
// when. Checks run on it offline.
type Snapshot struct {
	Fetched    time.Time
	Advisories []Advisory
}

// Expiry is a credential or certificate held in the vault, by name only.
type Expiry struct {
	Name     string
	NotAfter time.Time
}

// Box is what the passive checks read. Every field may be nil: that check
// is then not run, and the digest says so.
type Box struct {
	// Signed returns the digests the signed release names (UPD-8).
	Signed func() (map[string]string, error)
	// Artifacts lists what to measure; Measure returns its digest now.
	Artifacts []Artifact
	Measure   func(name string) (string, error)
	// Installed lists installed packages; Advisories returns the last
	// snapshot.
	Installed  func() ([]Package, error)
	Advisories func() (Snapshot, error)
	// Adopted and Live return config file digests: what the change
	// pipeline's active tree says, and what is in force.
	Adopted func() (map[string]string, error)
	Live    func() (map[string]string, error)
	// Expiries lists vault items with an expiry.
	Expiries func() ([]Expiry, error)
}

// Finding is one thing a passive check found. ID is stable while the same
// problem persists, so it is handled once.
type Finding struct {
	ID       string   `json:"id"`
	Check    Check    `json:"check"`
	Subject  string   `json:"subject"`
	Detail   string   `json:"detail"`
	Severity Severity `json:"severity"`
	Contain  *Target  `json:"contain,omitempty"`
	// Fixed is the first fixed version, for an advisory.
	Fixed string `json:"fixed,omitempty"`
	// Rule is the regression fixture's input, empty when the finding is
	// not something a change could reintroduce (expiry, drift).
	Rule []byte `json:"rule,omitempty"`
}

// Containment pauses a grant or executor. Pausing only narrows authority
// (journal A9), so it works during STOP. finding is "<check>:<finding
// ID>", for the pause's record (security L2 on W5a).
type Containment interface {
	Contain(ctx context.Context, t Target, finding string) error
}

// Fixer drafts a fix for a finding. Whatever it returns goes through the
// change pipeline like any candidate (§11); it decides nothing.
type Fixer interface {
	Fix(ctx context.Context, f Finding) (change.Candidate, error)
}

// ErrNotFixable is what a fixer's error wraps when it can never build a fix
// for the finding (no namespace it may write, LOOP-10): Loop 2 then holds
// the request without counting a failed build, and STATUS says so.
var ErrNotFixable = errors.New("loops: no fix this fixer can build")

// Unready is a Fixer that can tell, without building, that it cannot
// build now (no builder machines, no model access). Loop 2 then asks it
// nothing, the request stays open, and STATUS says why: the answer is
// owner text, in the box's words.
type Unready interface {
	Unready() string
}

// SuitePipeline is the part of the change pipeline Loop 2 uses: it adds
// fixtures, proposes fixes and reads the active tree they change. It has
// no way to remove a fixture (LOOP-10): that is an owner-approved intent.
type SuitePipeline interface {
	AddSecurityCase(c change.Case) error
	Propose(ctx context.Context, c change.Candidate) (change.Report, error)
	Files(ns string) change.Tree
	// LinkedHold answers a finding's linked cases from the active tree
	// (P3-4b-1b item 1).
	LinkedHold(finding string) (linked int, hold bool)
	// Digests are the active tree's and the whole suite's digests: what a
	// rejection was graded against (fixKey, P3-4b-5).
	Digests() (tree, suite string)
}

// GuardConfig configures NewSecure.
type GuardConfig struct {
	Box      Box
	Pipeline SuitePipeline
	Store    change.Store
	// Contain may be nil only in tests; without it nothing is paused and
	// every finding says so.
	Contain Containment
	// Fixer may be nil: findings then wait for a fix from an update.
	Fixer Fixer
	// Notify texts the owner one message per pass with that pass's High
	// findings, in fixed wording. Urgent marks what may break quiet hours
	// (CH-15): a tampered file or a vulnerability, not an expiring
	// credential.
	Notify func(text string, urgent bool)
	// FixturesLive turns on adding regression fixtures to the security
	// suite. Leave it off until replay answers them (K-S1) and the pipeline
	// grades open findings as no-regression (PS1): every fixture must pass
	// for every adoption and update, so an unanswerable fixture would stop
	// both. Off, each fixture is recorded as "deferred"; detection,
	// containment, evidence, and notice still run.
	FixturesLive bool
	// FixturesLiveFor turns fixtures on for single checks whose fixtures
	// replay answers already, such as CheckSeeded's tree rules (P3-4b).
	FixturesLiveFor map[Check]bool
	// UncomparedAlert is how long a version may stay uncomparable before
	// the owner is texted once. Default 7 days.
	UncomparedAlert time.Duration
	// MaxPauses caps automatic containment per pass, so a bad advisory
	// feed cannot pause everything; the owner is texted about the rest.
	// Default 3.
	MaxPauses int
	// MaxPausesPerDay caps them per UTC day (security L2 on W5a); past
	// either cap the owner is texted how to pause instead. Default 10.
	MaxPausesPerDay int
	// NotRun is why each check the box cannot run yet does not run
	// ("needs the updater"), for STATUS and the digest.
	NotRun map[Check]string
	// ReText is how long a finding must stay clear to be texted again when
	// it comes back; sooner, it is in the digest as "again". Default 24
	// hours.
	ReText time.Duration
	// Every is how often the passive checks run. Default 6 hours.
	Every time.Duration
	// Warn is how far ahead an expiry is reported. Default 14 days.
	Warn time.Duration
	// Stale is the advisory snapshot age past which the digest says the
	// checks are not current. Default 7 days.
	Stale time.Duration
	Now   func() time.Time
	// ResumeFor is how long a preempted fix is kept: change.ResumeFor
	// unless set (PE7).
	ResumeFor time.Duration
	// Probes are the LOOP-7 probes, run after the passive checks, one per
	// check (P3-4b-4a).
	Probes []Probe
}

// Guard is Loop 2's Source.
type Guard struct {
	cfg GuardConfig

	mu    sync.Mutex
	st    secureState
	force bool
	stale string
	more  []string // lines held back from the last text, for MORE
	// held are fix candidates whose evaluation was preempted, by finding
	// ID, offered again without another fixer call (PE4); memory only.
	held map[string]heldFix
	// contained is set once a finding is paused since start: Loop 2's
	// return is measured from then on (LOOP-3); memory only.
	contained bool
	// reportMu serializes Report.
	reportMu sync.Mutex
}

// heldFix is a checked fix candidate kept after a preempted evaluation,
// with the hash of each namespace it touches as the fixer saw it.
type heldFix struct {
	cand change.Candidate
	base map[string]string
	at   time.Time
}

// A Record's Fix before the pipeline settles it (PE4): FixPending until
// Pass first proposes it, FixPreempted while it waits to be proposed again
// after the fixer or the evaluation was preempted, and FixFailed, final,
// when the fixer failed.
const (
	FixPending   = "pending"
	FixPreempted = "preempted"
	FixFailed    = "failed"
)

// maxHeldFixes bounds the kept candidates, oldest dropped first.
const maxHeldFixes = 16

// The retry bound for a fix request (Potency 1 on #464, #493). Each
// failed or rejected attempt is a builder job with a model fixer. Two
// rejections in a row for the same reason, with the suite and tree as the
// last one found them, mean the verdict is deterministic (S22), so the
// fixer is not asked again until the suite or the tree changes; after fixBurst failures to build
// one, the next waits fixBackoff; after maxFixTries the box stops asking
// and STATUS says so. A rejection for a new reason is asked again at the
// next pass, as the A11 harness's scripted set needs.
const (
	fixBurst    = 2
	maxFixTries = 8
	fixBackoff  = 24 * time.Hour
)

// Why a fix request is held back (Record.FixHold).
const (
	holdUnchanged = "unchanged"
	holdLater     = "later"
	holdStopped   = "stopped"
	holdUnfixable = "unfixable"
)

type secureState struct {
	Last time.Time `json:"last"`
	// Open are findings still observed, by ID.
	Open map[string]Record `json:"open"`
	// Evidence is every distinct finding ever recorded, one record per
	// finding digest; it only grows.
	Evidence []Record `json:"evidence"`
	// Paused are containments still in force, by target, kept after their
	// finding clears until the owner resumes the target.
	Paused map[string]Record `json:"paused,omitempty"`
	// Cleared is when each finding last cleared, so a flapping finding is
	// not texted again unless it stayed clear for ReText.
	Cleared map[string]time.Time `json:"cleared,omitempty"`
	// ToldCleared are the findings whose last close in Pass texted the
	// owner "Cleared", so a return within ReText is texted, not left as a
	// false all-clear (L3 #585 point 1).
	ToldCleared map[string]bool `json:"told_cleared,omitempty"`
	// NotRun are the checks the last pass had no input for, Failed those
	// whose input errored, and NotRunSaid the set the digest last named
	// (Digest).
	NotRun     []string `json:"not_run,omitempty"`
	Failed     []string `json:"failed,omitempty"`
	NotRunSaid string   `json:"not_run_said,omitempty"`
	// PauseDay and Pauses count the automatic pauses on one UTC day
	// (MaxPausesPerDay).
	PauseDay string `json:"pause_day,omitempty"`
	Pauses   int    `json:"pauses,omitempty"`
	// SourcePauses counts PauseDay's automatic pauses per probe (A-6,
	// P3-4b).
	SourcePauses map[Check]int `json:"source_pauses,omitempty"`
	// ProbeLast is when each probe last ran to the end; ProbeFailed are
	// the probes whose last run failed (P3-4b-4a).
	ProbeLast   map[Check]time.Time `json:"probe_last,omitempty"`
	ProbeFailed []string            `json:"probe_failed,omitempty"`
}

// Record is a finding's preserved evidence (LOOP-9).
type Record struct {
	Finding   Finding   `json:"finding"`
	At        time.Time `json:"at"`
	Contained string    `json:"contained"` // "paused", "failed", "capped", "none"
	Fixture   string    `json:"fixture,omitempty"`
	Fix       string    `json:"fix,omitempty"` // pipeline state of the fix, if any
	FixReason string    `json:"fix_reason,omitempty"`
	Digest    string    `json:"digest"` // sha256 of the finding, for tamper evidence
	// Texted marks a finding the owner was texted about; Again one that
	// came back too soon after clearing to be texted.
	Texted bool `json:"texted,omitempty"`
	Again  bool `json:"again,omitempty"`
	// Seen counts the times the finding appeared; Last is the latest.
	Seen int       `json:"seen"`
	Last time.Time `json:"last"`
	// Reported marks a finding handed in through Report: it stays open
	// until a fix for it is adopted, not until a pass stops seeing it.
	Reported bool `json:"reported,omitempty"`
	// Regression is the minimized test added to the suite for a reported
	// finding.
	Regression []byte `json:"regression,omitempty"`
	// Replay is the passing replay that closed a fuzz or probe finding
	// (Resolve).
	Replay *Replay `json:"replay,omitempty"`
	// Closure is the good fuzz step that closed a hang finding
	// (CloseTarget), which replayed no stored input.
	Closure *Closure `json:"closure,omitempty"`
	// Told marks a reported finding's owner text as sent, so a resume
	// after a crash sends a text not yet sent, and only that (P3-4b-1b
	// item 3).
	Told bool `json:"told,omitempty"`
	// FixTries counts the fix attempts that failed or did not qualify,
	// FixLast is the latest, FixKey what its rejection was graded against
	// (fixKey), FixAgain marks a rejection for the same reason as the one
	// before, FixSeen the rejected candidates' hashes, and FixHold why the
	// request is held back (holdUnchanged, holdLater, holdStopped): they
	// bound the retries (Potency 1 on #464, #493; LOOP-2).
	FixTries int       `json:"fix_tries,omitempty"`
	FixLast  time.Time `json:"fix_last,omitempty"`
	FixKey   string    `json:"fix_key,omitempty"`
	FixAgain bool      `json:"fix_again,omitempty"`
	FixSeen  []string  `json:"fix_seen,omitempty"`
	FixHold  string    `json:"fix_hold,omitempty"`
}

// NewGuard loads Loop 2's state.
func NewGuard(cfg GuardConfig) (*Guard, error) {
	if cfg.Pipeline == nil || cfg.Store == nil {
		return nil, errors.New("loops: Pipeline and Store are required")
	}
	if cfg.UncomparedAlert <= 0 {
		cfg.UncomparedAlert = 7 * 24 * time.Hour
	}
	if cfg.MaxPausesPerDay <= 0 {
		cfg.MaxPausesPerDay = 10
	}
	if cfg.MaxPauses <= 0 {
		cfg.MaxPauses = 3
	}
	if cfg.ReText <= 0 {
		cfg.ReText = 24 * time.Hour
	}
	if cfg.Every <= 0 {
		cfg.Every = 6 * time.Hour
	}
	if cfg.Warn <= 0 {
		cfg.Warn = 14 * 24 * time.Hour
	}
	if cfg.Stale <= 0 {
		cfg.Stale = 7 * 24 * time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Notify == nil {
		cfg.Notify = func(string, bool) {}
	}
	seen := map[Check]bool{}
	for _, p := range cfg.Probes {
		if !probeChecks[p.Check()] || seen[p.Check()] || p.Every() <= 0 {
			return nil, fmt.Errorf("loops: probe %q: unknown, repeated or without an interval", p.Check())
		}
		seen[p.Check()] = true
	}
	s := &Guard{cfg: cfg, force: true}
	b, err := cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	if b != nil {
		if err := json.Unmarshal(b, &s.st); err != nil {
			return nil, fmt.Errorf("loops: saved loop 2 state: %v", err)
		}
	}
	if s.st.Open == nil {
		s.st.Open = map[string]Record{}
	}
	if s.st.Paused == nil {
		s.st.Paused = map[string]Record{}
	}
	if s.st.Cleared == nil {
		s.st.Cleared = map[string]time.Time{}
	}
	if s.st.ToldCleared == nil {
		s.st.ToldCleared = map[string]bool{}
	}
	return s, nil
}

func (s *Guard) Loop() Loop { return Secure }

// Trigger asks for a pass at the next chance (a new release, a new
// advisory snapshot); pair it with Scheduler.Wake.
func (s *Guard) Trigger() {
	s.mu.Lock()
	s.force = true
	s.mu.Unlock()
}

// Next offers one pass of the passive checks when one is due, else one
// due probe (LOOP-7). Neither makes model calls.
func (s *Guard) Next(_ context.Context, _ bool) (Job, bool) {
	if s.Urgent() {
		return Job{Name: "passive", Run: func(ctx context.Context) Result {
			n, err := s.Pass(ctx)
			return Result{Value: float64(n), Err: err}
		}}, true
	}
	p, ok := s.dueProbe()
	if !ok {
		return Job{}, false
	}
	return Job{Name: "probe:" + string(p.Check()), Run: func(ctx context.Context) Result {
		return s.runProbe(ctx, p)
	}}, true
}

// Urgent reports a pass due: the scheduler then offers Loop 2 work even
// while L5 parks it for dry runs, since a pass makes no model calls and
// costs little, so the 6 h cadence holds (S3; potency on #54).
func (s *Guard) Urgent() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.force || s.cfg.Now().Sub(s.st.Last) >= s.cfg.Every
}

// Pass runs every passive check and handles each new finding. It returns
// how many findings were new: Loop 2's measured value (LOOP-3). Passes
// must not run concurrently; the scheduler runs one job at a time.
func (s *Guard) Pass(ctx context.Context) (int, error) {
	found, notes, failed, stale := s.check()
	resumeErr := s.resumeReported(ctx)
	clear := s.passedReported()
	now := s.cfg.Now()
	s.mu.Lock()
	s.st.NotRun, s.st.Failed, s.stale, s.force = notes, failed, stale, false
	s.st.Last = now
	seen := map[string]bool{}
	var fresh []Finding
	for _, f := range found {
		seen[f.ID] = true
		if _, open := s.st.Open[f.ID]; !open {
			fresh = append(fresh, f)
		}
	}
	// later holds cleared and uncomparable lines, which follow new
	// findings in the text so a new alert is never pushed into MORE.
	var lines, later []string
	urgent := false
	// A check that failed this pass looked at nothing, so none of its
	// open findings closes, seen or not (P3-4b-3r-pass; #558 Security 4a).
	broke := map[Check]bool{}
	for _, c := range failed {
		broke[Check(c)] = true
	}
	var closed []Record
	for _, id := range sortedKeys(s.st.Open) {
		rec := s.st.Open[id]
		if seen[id] || rec.Reported && !clear[id] || broke[rec.Finding.Check] {
			continue
		}
		// No longer observed; its evidence stays. A pause it caused stays
		// too.
		delete(s.st.Open, id)
		delete(s.held, id)
		s.st.Cleared[id] = now
		// A texted return within ReText (Again) clears in the digest
		// only, so the next return within ReText is not texted. A pause
		// still hears it cleared: that line says it stays paused, so it
		// is no all-clear and a return while paused stays untexted.
		if rec.Texted && (!rec.Again || rec.Contained == "paused") {
			closed = append(closed, rec)
			if rec.Contained != "paused" {
				s.st.ToldCleared[id] = true
			}
		}
	}
	// A version (installed or fixed) that stays uncomparable for
	// UncomparedAlert is texted once
	// (arbitrator ruling 1 on #54).
	for _, id := range sortedKeys(s.st.Open) {
		rec := s.st.Open[id]
		if seen[id] && !rec.Texted && (strings.HasPrefix(rec.Finding.Detail, uncompared) || strings.HasPrefix(rec.Finding.Detail, unreadable)) && now.Sub(rec.At) >= s.cfg.UncomparedAlert {
			rec.Texted = true
			s.st.Open[id] = rec
			later = append(later, findingText(rec.Finding))
		}
	}
	s.mu.Unlock()
	// Most serious first, so the pause cap and the text go to tampering
	// before anything a noisy feed can produce.
	sort.SliceStable(fresh, func(i, j int) bool {
		a, b := fresh[i], fresh[j]
		if (a.Severity == High) != (b.Severity == High) {
			return a.Severity == High
		}
		return checkRank[a.Check] < checkRank[b.Check]
	})
	// Every new finding is contained, its evidence saved and the owner
	// texted before any fix is built or proposed, so a slow or preempted
	// fix never holds containment back (PE4, L3 on #112).
	var errs []error
	var ids []string
	pauses := 0
	s.mu.Lock()
	s.rollDayLocked(now)
	s.mu.Unlock()
	for _, f := range fresh {
		if ctx.Err() != nil {
			break
		}
		s.mu.Lock()
		pause := f.Contain != nil && pauses < s.cfg.MaxPauses && s.st.Pauses < s.cfg.MaxPausesPerDay
		if pause {
			pauses++
			s.st.Pauses++
		}
		s.mu.Unlock()
		rec, err := s.handle(ctx, f, pause, false)
		if err != nil {
			errs = append(errs, err)
		}
		ids = append(ids, f.ID)
		if rec.Texted {
			lines = append(lines, ownerLine(rec))
			urgent = urgent || urgentText(rec)
		}
	}
	// Every texted finding is told it cleared, paused or not, once no
	// open texted finding shares its plain name, new ones included (S39).
	s.mu.Lock()
	later = append(later, s.clearedLinesLocked(closed)...)
	s.mu.Unlock()
	text := s.batch(append(lines, later...))
	s.mu.Lock()
	err := s.saveLocked()
	s.mu.Unlock()
	if text != "" {
		s.cfg.Notify(text, urgent)
	}
	if err := s.fixPending(ctx, ids); err != nil {
		errs = append(errs, err)
	}
	s.mu.Lock()
	err2 := s.saveLocked()
	s.mu.Unlock()
	return len(fresh), errors.Join(append(errs, resumeErr, err, err2)...)
}

// passedReported answers each open reported finding's linked cases from
// the active tree; the ones whose cases all hold close as cleared in this
// pass, whoever repaired the tree (an owner-approved intent, an update),
// so nothing says they wait for a fix (P3-4b-1b item 1). Only a finding
// whose own cases are all in the suite qualifies: with its original test
// missing, the regression passing says nothing about it.
func (s *Guard) passedReported() map[string]bool {
	s.mu.Lock()
	var ids []string
	for _, id := range sortedKeys(s.st.Open) {
		if rec := s.st.Open[id]; rec.Reported && rec.Fixture == change.Loop2Fixture+id {
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()
	clear := map[string]bool{}
	for _, id := range ids {
		if _, hold := s.cfg.Pipeline.LinkedHold(id); hold {
			clear[id] = true
		}
	}
	return clear
}

// resumeReported repairs every open reported finding a crash or a store
// error left part done (P3-4b-1b item 3).
func (s *Guard) resumeReported(ctx context.Context) error {
	s.reportMu.Lock()
	defer s.reportMu.Unlock()
	s.mu.Lock()
	var ids []string
	for _, id := range sortedKeys(s.st.Open) {
		if rec := s.st.Open[id]; rec.Reported && unfinished(rec) {
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()
	var errs []error
	for _, id := range ids {
		if _, err := s.resumeLocked(ctx, id); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// unfinished reports a reported record whose case adds or fix request
// never happened, or whose owner text was never sent.
func unfinished(r Record) bool {
	return r.Fix == "" && r.Finding.Rule != nil || r.Texted && !r.Told
}

// resumeLocked finishes what handle left undone for open reported
// finding id: it adds the cases and opens the request, then sends the
// owner text if it was never sent. s.reportMu is held.
func (s *Guard) resumeLocked(ctx context.Context, id string) (Record, error) {
	s.mu.Lock()
	rec, ok := s.st.Open[id]
	s.mu.Unlock()
	if !ok || !rec.Reported {
		return rec, nil
	}
	var errs []error
	if rec.Fix == "" && rec.Finding.Rule != nil {
		errs = append(errs, s.link(ctx, &rec))
		s.mu.Lock()
		if _, still := s.st.Open[id]; still {
			s.st.Open[id] = rec
			for i := range s.st.Evidence {
				if e := &s.st.Evidence[i]; e.Digest == rec.Digest {
					e.Fixture, e.Fix, e.FixReason, e.Regression = rec.Fixture, rec.Fix, rec.FixReason, rec.Regression
				}
			}
		}
		s.mu.Unlock()
	}
	return s.tell(rec), errors.Join(append(errs, s.save())...)
}

// tell sends a reported finding's owner text once, on its own and not
// through batch, so lines held for MORE stay; Told is saved after it.
// A crash between the two sends it again on the next resume: at least
// once, never lost.
func (s *Guard) tell(rec Record) Record {
	if !rec.Texted || rec.Told {
		return rec
	}
	s.cfg.Notify("Security checks: "+ownerLine(rec), urgentText(rec))
	rec.Told = true
	s.mu.Lock()
	if _, still := s.st.Open[rec.Finding.ID]; still {
		s.st.Open[rec.Finding.ID] = rec
	}
	s.mu.Unlock()
	return rec
}

func (s *Guard) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

// textBudget is three SMS segments (CH-15).
const textBudget = 3 * 153

// batch joins a pass's lines into one text within textBudget, holding the
// rest for MORE.
func (s *Guard) batch(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	const tail = " Reply MORE for the rest."
	text := "Security checks:"
	n := 0
	for ; n < len(lines); n++ {
		budget := textBudget
		if n < len(lines)-1 {
			budget -= len(tail)
		}
		if n > 0 && len(text)+1+len(lines[n]) > budget {
			break
		}
		text += " " + lines[n]
	}
	s.mu.Lock()
	s.more = append([]string(nil), lines[n:]...)
	s.mu.Unlock()
	if n < len(lines) {
		text += tail
	}
	return text
}

// More returns the lines the last text held back (the owner's MORE), once.
func (s *Guard) More() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.more
	s.more = nil
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// handle is LOOP-9: contain, preserve evidence, add the regression
// fixture, and mark a fix pending. It decides whether the owner is texted;
// Pass sends the text, then proposes the fix.
func (s *Guard) handle(ctx context.Context, f Finding, pause, reported bool) (Record, error) {
	rec := Record{Finding: f, At: s.cfg.Now(), Contained: "none", Digest: digestOf(f), Reported: reported}
	if reported && f.Rule != nil {
		// Minimized now and saved with the first save, so a resume adds
		// the same test even if the tree has moved on since.
		rec.Regression = s.regression(f)
	}
	var errs []error
	if f.Contain != nil {
		if !pause {
			rec.Contained = "capped"
		} else if s.cfg.Contain == nil {
			rec.Contained = "failed"
		} else if err := s.cfg.Contain.Contain(ctx, *f.Contain, string(f.Check)+":"+f.ID); err != nil {
			rec.Contained = "failed"
			errs = append(errs, fmt.Errorf("contain %s: %w", f.ID, err))
		} else {
			rec.Contained = "paused"
		}
	}
	s.mu.Lock()
	if rec.Contained == "paused" {
		s.contained = true
	}
	// Back too soon: the digest says so instead, unless the owner's last
	// text about it said it cleared; then it is texted once more, and as
	// Again its own clearing is not (Pass), so a flap ends on "it is back".
	told := false
	if t, ok := s.st.Cleared[f.ID]; ok && rec.At.Sub(t) < s.cfg.ReText {
		rec.Again = true
		told = s.st.ToldCleared[f.ID]
	}
	delete(s.st.ToldCleared, f.ID)
	// Every automatic pause is texted at once (security L2 on W5a),
	// unless the target was still paused from before: a finding back too
	// soon then stays in the digest as "again".
	newPause := false
	if rec.Contained == "paused" {
		_, still := s.st.Paused[targetKey(*f.Contain)]
		newPause = !still
	}
	rec.Texted = newPause || told || !rec.Again && (f.Severity == High || rec.Contained == "capped")
	// Evidence is saved before anything slower runs.
	s.st.Open[f.ID] = rec
	if rec.Contained == "paused" {
		s.st.Paused[targetKey(*f.Contain)] = rec
	}
	ev := s.evidenceLocked(rec)
	err := s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		errs = append(errs, err)
	}
	if err := s.link(ctx, &rec); err != nil {
		errs = append(errs, err)
	}
	s.mu.Lock()
	s.st.Open[f.ID] = rec
	e := &s.st.Evidence[ev]
	e.Fixture, e.Fix, e.FixReason, e.Regression = rec.Fixture, rec.Fix, rec.FixReason, rec.Regression
	s.mu.Unlock()
	return rec, errors.Join(errs...)
}

// link adds rec's fixture, and for a reported finding its linked cases,
// to the suite, then opens the fix request when that can grade a fix.
// handle runs it after the first save; a resume runs it again.
func (s *Guard) link(ctx context.Context, rec *Record) error {
	f, reported := rec.Finding, rec.Reported
	var errs []error
	linked := false // every case for f is in the suite
	if f.Rule == nil && reported && probeChecks[f.Check] {
		// The probe that found it is its regression: it runs on its
		// interval for as long as Loop 2 runs (P3-4b-4a).
		rec.Fixture = "probe:" + string(f.Check)
	} else if f.Rule != nil && !s.cfg.FixturesLive && !s.cfg.FixturesLiveFor[f.Check] {
		rec.Fixture = "deferred"
	} else if f.Rule != nil {
		c := change.Case{ID: change.Loop2Fixture + f.ID, Class: change.ClassConfig, Input: f.Rule, Expect: []byte(FixtureOK)}
		cases := []change.Case{c}
		if reported {
			// The minimized test, linked to its finding: a fix for it must
			// pass every case linked to it (LOOP-10). Minimizing drops
			// failing clauses, so the original test is linked beside it.
			cases[0].Input, cases[0].Expect, cases[0].Finding = rec.Regression, []byte(change.TreeRuleOK), f.ID
			orig := cases[0]
			orig.ID, orig.Input = c.ID+OriginalSuffix, f.Rule
			cases = append(cases, orig)
		}
		linked = true
		for _, c := range cases {
			switch err := s.cfg.Pipeline.AddSecurityCase(c); {
			case err == nil, errors.Is(err, change.ErrDuplicate) && !errors.Is(err, change.ErrConflict):
				// Already there, as this same case: a re-run after a crash.
			default:
				// Another finding's case holds the ID (ErrConflict), or the
				// store failed: f is not linked (P3-4b-1b item 2).
				linked = false
				errs = append(errs, fmt.Errorf("fixture %s: %w", c.ID, err))
			}
		}
		if linked {
			rec.Fixture = c.ID
		}
	}
	switch {
	case reported && f.Rule != nil && !linked:
		// Fail closed: with no linked regression in the suite nothing
		// could grade a fix, so none is requested and the finding stays
		// open and contained (STATUS says why).
	case (s.cfg.Fixer != nil || reported) && f.Rule != nil:
		// Pass proposes it once every finding is contained. A reported
		// finding's request is recorded even with no fixer, so STATUS and
		// the digest can say it waits and why.
		rec.Fix = FixPending
	}
	return errors.Join(errs...)
}

// fix proposes a fix for rec's finding through the pipeline. A candidate
// kept from a preempted evaluation of the same finding is offered again
// without calling the fixer, within change.ResumeFor and only while every
// namespace it touches is as it was when the fixer built it; otherwise the
// fixer builds one, so a kept candidate never reverts a newer adoption
// (CHG-2, Security on #112). If the fixer or the evaluation is preempted,
// the fix stays FixPreempted and a later pass offers it again (PE4, L3 on
// #103). A fixer that fails otherwise leaves FixFailed, which is final, so
// a broken fixer is not called on every pass (OP-8).
func (s *Guard) fix(ctx context.Context, rec *Record) error {
	f := rec.Finding
	prev, rejected := rec.FixReason, rec.Fix == string(change.StateRejected)
	s.mu.Lock()
	h, ok := s.held[f.ID]
	delete(s.held, f.ID)
	s.mu.Unlock()
	cand, base := h.cand, h.base
	if !ok || s.cfg.Now().Sub(h.at) > s.resumeFor() || !maps.Equal(base, s.bases(cand)) {
		// The fixer gets the minimized regression, not the padded test
		// (P3-4b-5): what a fix must pass, and no more of the suite.
		in := f
		if rec.Regression != nil {
			in.Rule = rec.Regression
		}
		var err error
		if cand, err = s.cfg.Fixer.Fix(ctx, in); err != nil {
			if ctx.Err() != nil {
				rec.Fix, rec.FixReason = FixPreempted, ""
				return nil
			}
			rec.Fix, rec.FixReason = FixFailed, ""
			if errors.Is(err, ErrNotFixable) {
				// Not a failed build: no job ran and none ever can.
				rec.FixHold = holdUnfixable
				return nil
			}
			s.tried(rec, "", false)
			return fmt.Errorf("fix %s: %w", f.ID, err)
		}
		// Loop 2 sets these, never the fixer; goals a fixer sets would tie
		// the fix to an owner goal whose forgetting undoes it (Security 4
		// on #464, CHG-2).
		cand.Source, cand.Origin, cand.Public, cand.Finding, cand.Goals, cand.Claim = change.Local, "loop2", false, "", nil, ""
		if rec.Reported {
			// Only a reported finding has linked cases to grade the fix.
			cand.Finding = f.ID
		}
		if slices.Contains(rec.FixSeen, candHash(cand)) {
			// Rejected before: the same verdict, without a second
			// evaluation.
			rec.Fix = string(change.StateRejected)
			s.tried(rec, "", rejected)
			return nil
		}
		base = s.bases(cand)
	}
	rep, err := s.cfg.Pipeline.Propose(ctx, cand)
	if errors.Is(err, change.ErrInterrupted) {
		s.keep(f.ID, heldFix{cand: cand, base: base, at: s.cfg.Now()})
		rec.Fix, rec.FixReason = FixPreempted, ""
		return nil
	}
	rec.Fix, rec.FixReason = string(rep.State), rep.Reason
	if rep.State == change.StateRejected {
		s.tried(rec, candHash(cand), rejected && rep.Reason == prev)
	}
	if err != nil {
		return fmt.Errorf("fix %s: %w", f.ID, err)
	}
	return nil
}

// tried counts a fix attempt that failed or was rejected, with the
// rejected candidate's hash if any; again marks a rejection for the same
// reason as the last.
func (s *Guard) tried(rec *Record, hash string, again bool) {
	rec.FixTries++
	rec.FixLast = s.cfg.Now()
	rec.FixKey, rec.FixAgain = s.fixKey(*rec), again
	if hash != "" && !slices.Contains(rec.FixSeen, hash) {
		rec.FixSeen = append(rec.FixSeen, hash)
	}
}

// fixKey is what rec's rejection was graded against: its reason and the
// digests of the active tree and the whole suite (its linked cases
// included). Equal keys give the same verdict to the same candidate. ""
// for anything but a rejection. It calls the pipeline: never with s.mu
// held.
func (s *Guard) fixKey(rec Record) string {
	if rec.Fix != string(change.StateRejected) {
		return ""
	}
	tree, suite := s.cfg.Pipeline.Digests()
	h := sha256.Sum256(fmt.Appendf(nil, "%q\ntree %s\nsuite %s\n", rec.FixReason, tree, suite))
	return hex.EncodeToString(h[:])
}

// hold is why rec's fix request is held back now, "" when it is due. It
// calls the pipeline: never with s.mu held.
func (s *Guard) hold(rec Record) string {
	switch {
	case rec.FixHold == holdUnfixable:
		return holdUnfixable
	case rec.FixTries >= maxFixTries:
		return holdStopped
	case rec.FixTries < fixBurst:
		return ""
	case rec.Fix == string(change.StateRejected):
		if rec.FixAgain && rec.FixKey == s.fixKey(rec) {
			return holdUnchanged
		}
	case rec.Fix == FixFailed && s.cfg.Now().Before(rec.FixLast.Add(fixBackoff)):
		return holdLater
	}
	return ""
}

// candHash identifies a candidate's changes.
func candHash(c change.Candidate) string {
	h := sha256.New()
	for _, p := range slices.Sorted(maps.Keys(c.Files)) {
		fmt.Fprintf(h, "%q %d\n", p, len(c.Files[p]))
		h.Write(c.Files[p])
	}
	for _, p := range slices.Sorted(slices.Values(c.Delete)) {
		fmt.Fprintf(h, "-%q\n", p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Guard) resumeFor() time.Duration {
	if s.cfg.ResumeFor > 0 {
		return s.cfg.ResumeFor
	}
	return change.ResumeFor
}

// bases hashes the active tree of each namespace a candidate touches.
func (s *Guard) bases(c change.Candidate) map[string]string {
	out := map[string]string{}
	for _, p := range append(slices.Collect(maps.Keys(c.Files)), c.Delete...) {
		ns, _, _ := strings.Cut(p, "/")
		if _, done := out[ns]; !done {
			out[ns] = s.cfg.Pipeline.Files(ns).Hash()
		}
	}
	return out
}

// keep holds a preempted fix candidate, dropping the oldest past
// maxHeldFixes.
func (s *Guard) keep(id string, h heldFix) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.held == nil {
		s.held = map[string]heldFix{}
	}
	s.held[id] = h
	for len(s.held) > maxHeldFixes {
		oldest := ""
		for k, v := range s.held {
			if oldest == "" || v.at.Before(s.held[oldest].at) {
				oldest = k
			}
		}
		delete(s.held, oldest)
	}
}

// fixPending proposes every open finding's pending or preempted fix:
// those left from earlier passes first, oldest finding ID order, then this
// pass's new findings in the order given. A reported finding's request
// stays open until a fix is adopted, so a failed or rejected one is asked
// again, once per pass; an adopted fix closes the finding.
func (s *Guard) fixPending(ctx context.Context, fresh []string) error {
	if s.cfg.Fixer == nil {
		return nil
	}
	if u, ok := s.cfg.Fixer.(Unready); ok && u.Unready() != "" {
		return nil // the requests stay open; STATUS says why
	}
	s.mu.Lock()
	var ids []string
	for _, id := range sortedKeys(s.st.Open) {
		if retry(s.st.Open[id]) && !slices.Contains(fresh, id) {
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()
	var errs []error
	for _, id := range append(ids, fresh...) {
		if ctx.Err() != nil {
			break
		}
		s.mu.Lock()
		rec, ok := s.st.Open[id]
		s.mu.Unlock()
		if !ok || !retry(rec) {
			continue
		}
		if rec.FixHold = s.hold(rec); rec.FixHold == "" {
			if err := s.fix(ctx, &rec); err != nil {
				errs = append(errs, err)
			}
			if rec.FixHold != holdUnfixable {
				rec.FixHold = s.hold(rec)
			}
		}
		s.mu.Lock()
		if _, still := s.st.Open[id]; still {
			s.st.Open[id] = rec
			for i := range s.st.Evidence {
				if e := &s.st.Evidence[i]; e.Digest == rec.Digest {
					e.Fix, e.FixReason = rec.Fix, rec.FixReason
				}
			}
			if rec.Reported && rec.Fix == string(change.StateAdopted) {
				// Fixed: the finding closes; a pause it caused stays until
				// the owner resumes the target, and the digest says so.
				delete(s.st.Open, id)
				delete(s.held, id)
				s.st.Cleared[id] = s.cfg.Now()
			}
		}
		s.mu.Unlock()
	}
	return errors.Join(errs...)
}

// retry reports a fix request still to be proposed.
func retry(r Record) bool {
	switch r.Fix {
	case FixPending, FixPreempted:
		return true
	case FixFailed, string(change.StateRejected):
		return r.Reported
	}
	return false
}

// evidenceLocked records a finding's evidence, once per digest, and
// returns its index.
func (s *Guard) evidenceLocked(rec Record) int {
	for i := range s.st.Evidence {
		if e := &s.st.Evidence[i]; e.Digest == rec.Digest {
			e.Seen++
			e.Last = rec.At
			return i
		}
	}
	rec.Seen, rec.Last = 1, rec.At
	s.st.Evidence = append(s.st.Evidence, rec)
	return len(s.st.Evidence) - 1
}

func targetKey(t Target) string { return t.Kind + "/" + t.Name }

// Resumed tells Loop 2 the owner resumed a paused target, so the digest
// stops listing it. The wiring calls it when the grant or executor resumes.
func (s *Guard) Resumed(t Target) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.st.Paused, targetKey(t))
	return s.saveLocked()
}

// Reconcile drops every listed pause whose target held no longer reports
// paused: one that ended while the guard could not hear it, such as a
// crash between the gate's resume and the guard's save (L3 S1 on #169).
// The wiring calls it at start, once the gate has replayed its journal.
func (s *Guard) Reconcile(held func(Target) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.st.Paused)
	for k, r := range s.st.Paused {
		if r.Finding.Contain == nil || !held(*r.Finding.Contain) {
			delete(s.st.Paused, k)
		}
	}
	if len(s.st.Paused) == n {
		return nil
	}
	return s.saveLocked()
}

func (s *Guard) saveLocked() error {
	b, err := json.Marshal(s.st)
	if err != nil {
		return err
	}
	return s.cfg.Store.Save(b)
}

func digestOf(f Finding) string {
	b, _ := json.Marshal(f)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// FindingID is the ID Report gives a finding of check c about subject with
// detail; a probe outside this package that sets its own IDs uses it, such
// as probecmd with an empty detail (P3-4b-4a).
func FindingID(c Check, subject, detail string) string { return findingID(c, subject, detail) }

func findingID(c Check, subject, detail string) string {
	h := sha256.Sum256([]byte(string(c) + "\x00" + subject + "\x00" + detail))
	return string(c) + "-" + hex.EncodeToString(h[:6])
}

// check runs the passive checks (LOOP-8). Notes name checks that could not
// run; stale is set when the advisory snapshot is old.
func (s *Guard) check() (found []Finding, notes, failed []string, stale string) {
	b, now := s.cfg.Box, s.cfg.Now()
	add := func(c Check, subject, detail string, sev Severity, t *Target, rule []byte) {
		found = append(found, Finding{ID: findingID(c, subject, detail), Check: c, Subject: subject,
			Detail: detail, Severity: sev, Contain: t, Rule: rule})
	}
	note := func(c Check, err error) {
		if err != nil {
			failed = append(failed, string(c))
		}
	}

	// Hashes vs the signed release. An artifact the release does not name,
	// or that cannot be measured, is a finding: fail closed.
	if b.Signed != nil && b.Measure != nil {
		signed, err := b.Signed()
		note(CheckHash, err)
		if err == nil {
			for _, a := range b.Artifacts {
				want, ok := signed[a.Name]
				got, merr := b.Measure(a.Name)
				switch {
				case !ok:
					add(CheckHash, a.Name, "not in the signed release", High, a.Contain, nil)
				case merr != nil:
					add(CheckHash, a.Name, "could not be measured", High, a.Contain, nil)
				case got != want:
					// No fixture: a fixture pinned to today's digest would fail
					// every later release that changes this artifact, and a
					// candidate cannot reintroduce tampering (UPD-8 checks
					// signatures on every release).
					add(CheckHash, a.Name, "differs from the signed release", High, a.Contain, nil)
				}
			}
		}
	} else {
		notes = append(notes, string(CheckHash))
	}

	// Advisories, on the last snapshot even when offline.
	if b.Installed != nil && b.Advisories != nil {
		pkgs, err1 := b.Installed()
		snap, err2 := b.Advisories()
		note(CheckAdvisory, errors.Join(err1, err2))
		if err1 == nil && err2 == nil {
			if snap.Fetched.IsZero() || now.Sub(snap.Fetched) > s.cfg.Stale {
				stale = staleLine(snap.Fetched, now)
			}
			for _, p := range pkgs {
				uncomp := false
				for _, a := range snap.Advisories {
					if a.Package != p.Name {
						continue
					}
					c, ok := compareVersions(p.Scheme, p.Version, a.Fixed)
					if _, vok := compareVersions(p.Scheme, p.Version, p.Version); !ok && vok {
						// The installed version reads; the advisory's fixed
						// version does not. Name the advisory, not the
						// package's version.
						add(CheckAdvisory, p.Name, unreadable+a.ID, Low, nil, nil)
						continue
					}
					if !ok {
						// Neither assumed fixed nor assumed vulnerable: one
						// Low finding per package and version, in the
						// digest, with nothing paused or pinned on a guess.
						if !uncomp {
							uncomp = true
							add(CheckAdvisory, p.Name, uncompared+p.Version, Low, nil, nil)
						}
						continue
					}
					if c >= 0 {
						continue
					}
					sev := Low
					if sw := strings.ToLower(a.Severity); sw == "high" || sw == "critical" {
						sev = High
					}
					add(CheckAdvisory, p.Name, a.ID, sev, p.Contain,
						fixtureInput(FixtureRule{Check: CheckAdvisory, Subject: p.Name, Fixed: a.Fixed, Scheme: p.Scheme}))
					found[len(found)-1].Fixed = a.Fixed
				}
			}
		}
	} else {
		notes = append(notes, string(CheckAdvisory))
	}

	// Configuration drift: any live file whose digest is not the adopted
	// one, and any adopted file missing or extra.
	if b.Adopted != nil && b.Live != nil {
		want, err1 := b.Adopted()
		got, err2 := b.Live()
		note(CheckDrift, errors.Join(err1, err2))
		if err1 == nil && err2 == nil {
			for _, name := range unionKeys(want, got) {
				w, inW := want[name]
				g, inG := got[name]
				switch {
				case !inG:
					add(CheckDrift, name, "missing", High, nil, nil)
				case !inW:
					add(CheckDrift, name, "not adopted", High, nil, nil)
				case w != g:
					add(CheckDrift, name, "changed outside the change pipeline", High, nil, nil)
				}
			}
		}
	} else {
		notes = append(notes, string(CheckDrift))
	}

	// Expiry of vault credentials and certificates.
	if b.Expiries != nil {
		xs, err := b.Expiries()
		note(CheckExpiry, err)
		for _, x := range xs {
			switch {
			case !now.Before(x.NotAfter):
				add(CheckExpiry, x.Name, "expired", High, nil, nil)
			case x.NotAfter.Sub(now) <= s.cfg.Warn:
				add(CheckExpiry, x.Name, "expires "+x.NotAfter.UTC().Format("2006-01-02"), Low, nil, nil)
			}
		}
	} else {
		notes = append(notes, string(CheckExpiry))
	}
	sort.Slice(found, func(i, j int) bool { return found[i].ID < found[j].ID })
	return found, notes, failed, stale
}

func unionKeys(a, b map[string]string) []string {
	m := map[string]bool{}
	for k := range a {
		m[k] = true
	}
	for k := range b {
		m[k] = true
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func staleLine(fetched, now time.Time) string {
	if fetched.IsZero() {
		return "Security advisories have never been fetched, so known-vulnerability checks are not current."
	}
	days := int(now.Sub(fetched).Hours() / 24)
	return fmt.Sprintf("Security advisories were last fetched %d days ago, so known-vulnerability checks are not current.", days)
}

// FixtureRule is a Loop 2 regression fixture's input: the condition a
// change must not break again. It is the minimized case for a passive
// finding: one subject, one condition.
type FixtureRule struct {
	Check   Check  `json:"check"`
	Subject string `json:"subject"`
	Fixed   string `json:"fixed,omitempty"` // CheckAdvisory: the first fixed version
	Scheme  string `json:"scheme,omitempty"`
}

// FixtureOK is what a passing fixture answers.
const FixtureOK = "ok"

func fixtureInput(r FixtureRule) []byte {
	b, _ := json.Marshal(r)
	return b
}

// Facts are what a candidate tree would install: package versions. The
// evaluator builds them for the tree under test.
type Facts struct {
	Versions map[string]string
}

// AnswerFixture is how an evaluator answers a Loop 2 fixture against the
// facts of the tree under test: FixtureOK when the condition holds. An
// input it cannot read, or a subject the facts do not name, fails.
func AnswerFixture(input []byte, f Facts) []byte {
	var r FixtureRule
	if err := json.Unmarshal(input, &r); err != nil {
		return []byte("unreadable")
	}
	if r.Check == CheckAdvisory {
		// A tree without the package is not vulnerable to it.
		if v, ok := f.Versions[r.Subject]; !ok || !versionBelow(r.Scheme, v, r.Fixed) {
			return []byte(FixtureOK)
		}
	}
	return []byte("fails")
}

// checkRank orders findings of one severity: tampering first.
var checkRank = map[Check]int{CheckHash: 0, CheckDrift: 1, CheckAdvisory: 2, CheckExpiry: 3}

// uncompared marks an advisory finding whose versions could not be
// compared.
const uncompared = "uncompared:"

// unreadable marks an advisory whose fixed version does not parse.
const unreadable = "unreadable:"

// plainCheck names a check for the owner.
var plainCheck = map[Check]string{
	CheckHash:     "file hashes",
	CheckAdvisory: "known vulnerabilities",
	CheckDrift:    "settings",
	CheckExpiry:   "credential expiry",
	CheckCanary:   "leak tests",
	CheckCorpus:   "attack-text tests",
	CheckTamper:   "tamper tests",
	CheckExhaust:  "load tests",
}

// safeName keeps owner-facing names to a fixed alphabet.
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./: ", r)) {
			b.WriteRune(r)
		}
		if b.Len() >= 48 {
			break
		}
	}
	return b.String()
}

// safeVersion is safeName for version strings, which also keeps "~" and
// "+": both change dpkg order, so dropping them would name the wrong
// version.
func safeVersion(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:~+", r)) {
			b.WriteRune(r)
		}
		if b.Len() >= 48 {
			break
		}
	}
	return b.String()
}

func label(t *Target) string {
	if t == nil || t.Label == "" {
		return "the affected tool"
	}
	return safeName(t.Label)
}

func capFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// aboveBudget says what an exhaustion round's "above budget" finding lets
// an agent machine do, by resource.
var aboveBudget = map[string]string{
	"memory": "use more memory than its budget",
	// No round reports "processes" now (S35), but an open record
	// still reads this way.
	"processes": "start more processes than its budget",
	// pids.max bounds the sandbox's host threads, not guest processes
	// (RES-2, loops S35).
	sandboxThreads: "run more sandbox threads than its budget",
	"disk":         "use more disk space than its budget",
	"cpu":          "take as large a share of processor time as I get",
}

// findingText is one finding in plain words, with the next step.
func findingText(f Finding) string {
	sub := safeName(f.Subject)
	switch f.Check {
	case CheckHash:
		switch f.Detail {
		case "not in the signed release":
			return "File " + sub + " is not in the signed release."
		case "could not be measured":
			return "File " + sub + " could not be checked."
		}
		return "File " + sub + " does not match the signed release."
	case CheckAdvisory:
		if v, ok := strings.CutPrefix(f.Detail, uncompared); ok {
			return fmt.Sprintf("Could not check %s version %s against known vulnerabilities. Check it on my Wi-Fi page.",
				sub, safeVersion(v))
		}
		if id, ok := strings.CutPrefix(f.Detail, unreadable); ok {
			return fmt.Sprintf("Could not read the fixed version in advisory %s for %s. Check it on my Wi-Fi page.",
				safeName(id), sub)
		}
		return fmt.Sprintf("Known vulnerability in %s (%s), fixed in %s. I take the fix when an update has it.",
			sub, safeName(f.Detail), safeVersion(f.Fixed))
	case CheckDrift:
		switch f.Detail {
		case "missing":
			return "Setting file " + sub + " is missing."
		case "not adopted":
			return "Setting file " + sub + " appeared outside my change process."
		}
		return "Setting file " + sub + " changed outside my change process."
	case CheckExpiry:
		if f.Detail == "expired" {
			return "Credential " + sub + " has expired. Replace it on my Wi-Fi page."
		}
		return "Credential " + sub + " " + safeName(f.Detail) + ". Replace it on my Wi-Fi page."
	case CheckSeeded:
		return "Security test " + sub + " fails on my current setup."
	case CheckFuzz:
		if hangDetail(f.Detail) {
			return "My self-test of " + plainSubject(f) + " stopped responding to a test input. The fix comes with an update."
		}
		if f.Detail == FuzzOversizeDetail {
			return "My self-test of " + plainSubject(f) + " has a stored test input too large to replay, so it is not tested."
		}
		return "My self-test found a crash in " + plainSubject(f) + ". The fix comes with an update."
	case CheckProbe:
		return "My self-test of " + plainSubject(f) + " failed. The fix comes with an update."
	case CheckCanary:
		return "My leak self-test found a planted test secret in " + plainSubject(f) + "."
	case CheckCorpus:
		c, ok := corpusNames[f.Detail]
		if !ok {
			c = corpusFallback
		}
		return "My self-test of " + c.name + " failed: it " + c.missed + ". Nothing real was exposed."
	case CheckTamper:
		return "A tamper test changed my " + sub + " from inside an agent machine."
	case CheckExhaust:
		switch {
		case f.Detail != "slow":
			if over, ok := aboveBudget[f.Subject]; ok {
				return "A load test found an agent machine can " + over + "."
			}
			return "A load test found an agent machine over its budget for " + sub + "."
		case f.Subject == "preemption":
			return "Under a load test I stopped an agent machine slower than my target."
		}
		return "Under a load test I answered slower than my target."
	}
	return "Security finding on " + sub + "."
}

// ownerLine is a finding and what was done about it, in fixed wording.
// A line names a step (a pause that happened, PAUSE or STOP) exactly when
// urgentText holds; any other line says nothing is paused or needed,
// unless its finding names the owner's own step (ownStep).
func ownerLine(r Record) string {
	f := r.Finding
	line := findingText(f)
	switch r.Contained {
	case "paused":
		line += " Paused " + label(f.Contain) + ". It stays paused until you resume it on my Wi-Fi page."
	case "failed":
		line += " Could not pause " + label(f.Contain) + ". STOP pauses everything."
	case "capped":
		line += " Not paused (too many findings at once)."
		if f.Contain.Kind == "grant" {
			line += fmt.Sprintf(" Reply PAUSE %s to pause it, or STOP to pause everything.", safeName(f.Contain.Name))
		} else {
			line += " Reply STOP to pause everything."
		}
	default:
		if !stopChecks[f.Check] && !ownStep(f) {
			line += " " + nothingNeeded
		}
	}
	// A leak or a sign of tampering always offers STOP (P3-4b-3c
	// requirement 3; Security 4a on #558). The failed and capped lines
	// offer it already.
	if stopChecks[f.Check] && r.Contained != "failed" && r.Contained != "capped" {
		line += " Reply STOP to pause everything."
	}
	return line
}

// stopChecks are the checks whose findings always offer STOP, so they
// stay urgent when nothing was paused: a canary leak, and tampering with
// a file, a setting or an evaluator (hash, drift, tamper).
var stopChecks = map[Check]bool{CheckCanary: true, CheckHash: true, CheckDrift: true, CheckTamper: true}

// nothingNeeded ends the line of a finding with no pause and no step.
const nothingNeeded = "Nothing is paused and nothing is needed from you."

// urgentContained reports a containment state whose line names a step:
// a pause that happened, or PAUSE or STOP.
func urgentContained(c string) bool { return c == "paused" || c == "failed" || c == "capped" }

// urgentText is the one urgency rule for a finding's owner text, in tell
// and in Pass's batch: urgent only when the line names a pause that
// happened or a reply that works: a pause, PAUSE or STOP, which every
// stopChecks finding offers. Severity decides whether the owner is texted
// at all, not whether the text interrupts them (P3-4b-3c).
func urgentText(r Record) bool {
	return urgentContained(r.Contained) || stopChecks[r.Finding.Check]
}

// ownStep reports a finding whose text names a step of its own on my
// Wi-Fi page, so its line does not say nothing is needed.
func ownStep(f Finding) bool {
	return f.Check == CheckExpiry ||
		f.Check == CheckAdvisory && (strings.HasPrefix(f.Detail, uncompared) || strings.HasPrefix(f.Detail, unreadable))
}

// clearedLine tells the owner a texted finding cleared: a pause it caused
// stays until they resume it; otherwise nothing more is needed.
func clearedLine(r Record) string {
	what := clearedWhat(r.Finding)
	if r.Contained == "paused" {
		return fmt.Sprintf("Cleared: %s. %s stays paused until you resume it on my Wi-Fi page.",
			what, capFirst(label(r.Finding.Contain)))
	}
	return "Cleared: " + what + ". Nothing more is needed from you."
}

// clearedWhat is what a cleared line says cleared: for a fuzz finding,
// the crash or the hang, so the line is never ambiguous with another
// finding on the same plain name still open (L3 on #586 point 1).
func clearedWhat(f Finding) string {
	switch {
	case f.Check == CheckFuzz && hangDetail(f.Detail):
		return plainSubject(f) + " responds to test inputs again"
	case f.Check == CheckFuzz && f.Detail == FuzzOversizeDetail:
		return plainSubject(f) + " is tested again"
	case f.Check == CheckFuzz:
		return "the crash in " + plainSubject(f)
	}
	return plainSubject(f)
}

// FuzzOversizeDetail is the target finding for a stored input loop7
// refuses to read, being past its cap (P3-4b-3r-confine-r5). The target
// is not fuzzed while it stands; a whole replay that reads every input it
// names resolves it.
const FuzzOversizeDetail = "a stored test input is too large to replay"

// digestCap is how many open-finding lines the digest shows.
const digestCap = 3

// Digest is Loop 2's lines for the owner's digest: open findings (High
// first, advisories grouped per package, at most digestCap lines), pauses
// whose finding cleared, checks that could not run, and stale advisories.
// A Low finding is reported only here.
func (s *Guard) Digest() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	type item struct {
		high bool
		line string
	}
	var items []item
	pkgs := map[string][]Record{}
	for _, id := range sortedKeys(s.st.Open) {
		r := s.st.Open[id]
		if r.Finding.Check == CheckAdvisory && !strings.HasPrefix(r.Finding.Detail, uncompared) && !strings.HasPrefix(r.Finding.Detail, unreadable) {
			pkgs[r.Finding.Subject] = append(pkgs[r.Finding.Subject], r)
			continue
		}
		line := ownerLine(r)
		if r.Again {
			line = "Again: " + line
		}
		if why := s.waitingLocked(r); why != "" {
			line += " It " + waitForAFixOf + why + "."
		}
		items = append(items, item{r.Finding.Severity == High, line})
	}
	for _, name := range sortedKeys(pkgs) {
		rs := pkgs[name]
		if len(rs) == 1 {
			line := ownerLine(rs[0])
			if rs[0].Again {
				line = "Again: " + line
			}
			items = append(items, item{rs[0].Finding.Severity == High, line})
			continue
		}
		high, fixed := false, ""
		var ids []string
		for _, r := range rs {
			high = high || r.Finding.Severity == High
			ids = append(ids, safeName(r.Finding.Detail))
			var fr FixtureRule
			_ = json.Unmarshal(r.Finding.Rule, &fr)
			if fixed == "" || versionBelow(fr.Scheme, fixed, r.Finding.Fixed) {
				fixed = r.Finding.Fixed
			}
		}
		items = append(items, item{high, fmt.Sprintf("Known vulnerabilities in %s (%s), all fixed in %s. I take the fix when an update has it.",
			safeName(name), strings.Join(ids, ", "), safeVersion(fixed))})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].high && !items[j].high })
	var out []string
	for i, it := range items {
		if i == digestCap {
			out = append(out, fmt.Sprintf("And %d more security findings: ask your agent for the list.", len(items)-digestCap))
			break
		}
		out = append(out, "Security check: "+it.line)
	}
	for _, k := range sortedKeys(s.st.Paused) {
		r := s.st.Paused[k]
		if _, open := s.st.Open[r.Finding.ID]; !open {
			out = append(out, clearedLine(r))
		}
	}
	// Checks not run: named with their cause once, then again only when
	// the set changes; a failed check or a pass overdue is said every
	// time (potency C2,
	// UX W2 on W5a). Nothing here ever reads as passed (L5).
	now := s.cfg.Now()
	if s.overdueLocked(now) {
		out = append(out, "Loop 2: checks haven't run since "+s.st.Last.Format("Mon 2 Jan")+".")
	} else if said := strings.Join(s.st.NotRun, ",") + "/" + strings.Join(s.st.Failed, ","); said != s.st.NotRunSaid || len(s.st.Failed)+len(s.st.ProbeFailed) > 0 {
		// A check that failed is said every time, like an overdue pass.
		if len(s.st.NotRun)+len(s.st.Failed)+len(s.st.ProbeFailed) > 0 {
			out = append(out, s.partialLocked())
		}
		s.st.NotRunSaid = said
		_ = s.saveLocked() // a lost save only says it again
	}
	if s.stale != "" {
		out = append(out, s.stale)
	}
	return append(out, s.repeatLinesLocked()...)
}

// overdueLocked reports no pass for twice the cadence since the last one.
func (s *Guard) overdueLocked(now time.Time) bool {
	return !s.st.Last.IsZero() && now.Sub(s.st.Last) >= 2*s.cfg.Every
}

// partialLocked names the checks the last pass could not run, with the
// cause the wiring gave for each, then those whose input failed.
func (s *Guard) partialLocked() string {
	var parts []string
	for _, n := range s.st.NotRun {
		part := plainCheck[Check(n)]
		if why := s.cfg.NotRun[Check(n)]; why != "" {
			part += ", " + why
		}
		parts = append(parts, part)
	}
	for _, n := range append(append([]string(nil), s.st.Failed...), s.st.ProbeFailed...) {
		parts = append(parts, plainCheck[Check(n)]+", failed")
	}
	return "Loop 2: partial (not run: " + strings.Join(parts, "; ") + ")."
}

// Status is Loop 2's STATUS line: never run yet, overdue, or partial with
// what was not run and why. It is empty only when every check ran on the
// last pass; it never says the checks passed (security L5 on W5a).
func (s *Guard) Status() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var line string
	switch now := s.cfg.Now(); {
	case s.st.Last.IsZero():
		line = "Loop 2: not run yet."
	case s.overdueLocked(now):
		line = "Loop 2: checks haven't run since " + s.st.Last.Format("Mon 2 Jan") + "."
	case len(s.st.NotRun)+len(s.st.Failed)+len(s.st.ProbeFailed) > 0:
		line = s.partialLocked()
	}
	if wait := s.waitStatusLocked(); wait != "" {
		return strings.TrimSpace(line + " " + wait)
	}
	return line
}

// Evidence returns every recorded finding, oldest first.
func (s *Guard) Evidence() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Record(nil), s.st.Evidence...)
}
