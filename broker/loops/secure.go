package loops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// Loop 2, self-securing (LOOP-8 to LOOP-10). This file holds the passive
// checks and what happens to a finding. Active testing from inside the
// sandbox (LOOP-7) is not built here (S1).

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
// (journal A9), so it works during STOP.
type Containment interface {
	Contain(ctx context.Context, t Target, finding string) error
}

// Fixer drafts a fix for a finding. Whatever it returns goes through the
// change pipeline like any candidate (§11); it decides nothing.
type Fixer interface {
	Fix(ctx context.Context, f Finding) (change.Candidate, error)
}

// SuitePipeline is the part of the change pipeline Loop 2 uses: it adds
// fixtures and proposes fixes. It has no way to remove a fixture
// (LOOP-10): that is an owner-approved intent.
type SuitePipeline interface {
	AddSecurityCase(c change.Case) error
	Propose(ctx context.Context, c change.Candidate) (change.Report, error)
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
	// UncomparedAlert is how long a version may stay uncomparable before
	// the owner is texted once. Default 7 days.
	UncomparedAlert time.Duration
	// MaxPauses caps automatic containment per pass, so a bad advisory
	// feed cannot pause everything; the owner is texted about the rest.
	// Default 3.
	MaxPauses int
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
}

// Guard is Loop 2's Source.
type Guard struct {
	cfg GuardConfig

	mu    sync.Mutex
	st    secureState
	force bool
	notes []string // checks that could not run on the last pass
	stale string
	more  []string // lines held back from the last text, for MORE
	// fixes are fix candidates whose evaluation was cut short, by finding
	// ID, in memory only (PE4).
	fixes map[string]keptFix
}

// FixPending is a Record's Fix while its fix's evaluation was cut short
// (PE4): the next pass offers the fix again.
const FixPending = "pending"

// maxKeptFixes bounds the kept fix candidates, oldest dropped first.
const maxKeptFixes = 16

// keptFix is a fixer's candidate, marked by Loop 2, kept for the exact
// finding it was drafted for.
type keptFix struct {
	cand   change.Candidate
	digest string
	at     time.Time
}

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
}

// NewGuard loads Loop 2's state.
func NewGuard(cfg GuardConfig) (*Guard, error) {
	if cfg.Pipeline == nil || cfg.Store == nil {
		return nil, errors.New("loops: Pipeline and Store are required")
	}
	if cfg.UncomparedAlert <= 0 {
		cfg.UncomparedAlert = 7 * 24 * time.Hour
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

// Next offers one pass of the passive checks when one is due. It makes no
// model calls.
func (s *Guard) Next(_ context.Context, _ bool) (Job, bool) {
	s.mu.Lock()
	due := s.force || s.cfg.Now().Sub(s.st.Last) >= s.cfg.Every
	s.mu.Unlock()
	if !due {
		return Job{}, false
	}
	return Job{Name: "passive", Run: func(ctx context.Context) Result {
		n, err := s.Pass(ctx)
		return Result{Value: float64(n), Err: err}
	}}, true
}

// Pass runs every passive check and handles each new finding. It returns
// how many findings were new: Loop 2's measured value (LOOP-3). Passes
// must not run concurrently; the scheduler runs one job at a time.
func (s *Guard) Pass(ctx context.Context) (int, error) {
	found, notes, stale := s.check()
	now := s.cfg.Now()
	s.mu.Lock()
	s.notes, s.stale, s.force = notes, stale, false
	s.st.Last = now
	seen := map[string]bool{}
	var fresh, pending []Finding
	for _, f := range found {
		seen[f.ID] = true
		if rec, open := s.st.Open[f.ID]; !open {
			fresh = append(fresh, f)
		} else if rec.Fix == FixPending {
			pending = append(pending, rec.Finding)
		}
	}
	// later holds cleared and uncomparable lines, which follow new
	// findings in the text so a new alert is never pushed into MORE.
	var lines, later []string
	urgent := false
	for _, id := range sortedKeys(s.st.Open) {
		rec := s.st.Open[id]
		if seen[id] {
			continue
		}
		// No longer observed; its evidence stays. A pause it caused stays
		// too, and the owner hears it cleared where they heard of it.
		delete(s.st.Open, id)
		delete(s.fixes, id)
		s.st.Cleared[id] = now
		if rec.Contained == "paused" && rec.Texted {
			later = append(later, clearedLine(rec))
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
	var errs []error
	pauses := 0
	for _, f := range fresh {
		if ctx.Err() != nil {
			break
		}
		pause := f.Contain != nil && pauses < s.cfg.MaxPauses
		if pause {
			pauses++
		}
		rec, err := s.handle(ctx, f, pause)
		if err != nil {
			errs = append(errs, err)
		}
		if rec.Texted {
			lines = append(lines, ownerLine(rec))
			urgent = urgent || rec.Finding.Check != CheckExpiry
		}
	}
	// Fixes cut short on an earlier pass are offered again (PE4).
	for _, f := range pending {
		if ctx.Err() != nil || s.cfg.Fixer == nil || f.Rule == nil {
			break
		}
		fix, reason, err := s.proposeFix(ctx, f)
		if err != nil {
			errs = append(errs, err)
		}
		s.mu.Lock()
		s.setFixLocked(f, fix, reason)
		s.mu.Unlock()
	}
	text := s.batch(append(lines, later...))
	s.mu.Lock()
	// A fix still pending makes the next pass due; after an interrupted
	// pass the scheduler waits Retry first (loops L20).
	for _, rec := range s.st.Open {
		if rec.Fix == FixPending {
			s.force = true
		}
	}
	err := s.saveLocked()
	s.mu.Unlock()
	if text != "" {
		s.cfg.Notify(text, urgent)
	}
	return len(fresh), errors.Join(append(errs, err)...)
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
// fixture, propose a fix. It decides whether the owner is texted; Pass
// sends the text.
func (s *Guard) handle(ctx context.Context, f Finding, pause bool) (Record, error) {
	rec := Record{Finding: f, At: s.cfg.Now(), Contained: "none", Digest: digestOf(f)}
	var errs []error
	if f.Contain != nil {
		if !pause {
			rec.Contained = "capped"
		} else if s.cfg.Contain == nil {
			rec.Contained = "failed"
		} else if err := s.cfg.Contain.Contain(ctx, *f.Contain, f.ID); err != nil {
			rec.Contained = "failed"
			errs = append(errs, fmt.Errorf("contain %s: %w", f.ID, err))
		} else {
			rec.Contained = "paused"
		}
	}
	s.mu.Lock()
	if t, ok := s.st.Cleared[f.ID]; ok && rec.At.Sub(t) < s.cfg.ReText {
		rec.Again = true // back too soon: the digest says so instead
	}
	rec.Texted = !rec.Again && (f.Severity == High || rec.Contained == "capped")
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
	if f.Rule != nil && !s.cfg.FixturesLive {
		rec.Fixture = "deferred"
	} else if f.Rule != nil {
		c := change.Case{ID: "loop2/" + f.ID, Class: change.ClassConfig, Input: f.Rule, Expect: []byte(FixtureOK)}
		switch err := s.cfg.Pipeline.AddSecurityCase(c); {
		case err == nil, errors.Is(err, change.ErrDuplicate):
			rec.Fixture = c.ID
		default:
			errs = append(errs, fmt.Errorf("fixture %s: %w", f.ID, err))
		}
	}
	if s.cfg.Fixer != nil && f.Rule != nil {
		var err error
		rec.Fix, rec.FixReason, err = s.proposeFix(ctx, f)
		if err != nil {
			errs = append(errs, err)
		}
	}
	s.mu.Lock()
	s.st.Open[f.ID] = rec
	e := &s.st.Evidence[ev]
	e.Fixture, e.Fix, e.FixReason = rec.Fixture, rec.Fix, rec.FixReason
	s.mu.Unlock()
	return rec, errors.Join(errs...)
}

// proposeFix drafts a fix for f and proposes it, returning the fix's
// state and reason. A fix whose drafting or evaluation is cut short is
// FixPending, and its error wraps change.ErrInterrupted, so the scheduler
// counts the pass as preempted (loops L20). The candidate, once drafted,
// is kept for the same finding (by digest) for change.ResumeFor, so the
// next offer costs no second draft and the pipeline resumes from the
// pairs that finished (change C15).
func (s *Guard) proposeFix(ctx context.Context, f Finding) (fix, reason string, err error) {
	digest, now := digestOf(f), s.cfg.Now()
	s.mu.Lock()
	k, ok := s.fixes[f.ID]
	s.mu.Unlock()
	if !ok || k.digest != digest || now.Sub(k.at) > change.ResumeFor {
		cand, err := s.cfg.Fixer.Fix(ctx, f)
		if err != nil {
			if ctx.Err() != nil && !errors.Is(err, change.ErrInterrupted) {
				err = fmt.Errorf("%w: %w", change.ErrInterrupted, err)
			}
			if errors.Is(err, change.ErrInterrupted) {
				return FixPending, "", fmt.Errorf("fix %s: %w", f.ID, err)
			}
			return "", "", fmt.Errorf("fix %s: %w", f.ID, err)
		}
		// Loop 2 sets these, never the fixer.
		cand.Source, cand.Origin, cand.Public = change.Local, "loop2", false
		k = keptFix{cand: cand, digest: digest, at: now}
	}
	rep, err := s.cfg.Pipeline.Propose(ctx, k.cand)
	if err != nil && ctx.Err() != nil && !errors.Is(err, change.ErrInterrupted) {
		err = fmt.Errorf("%w: %w", change.ErrInterrupted, err)
	}
	if errors.Is(err, change.ErrInterrupted) {
		s.keepFix(f, k.cand, k.at)
		return FixPending, "", fmt.Errorf("fix %s: %w", f.ID, err)
	}
	s.dropFix(f.ID)
	if err != nil {
		err = fmt.Errorf("fix %s: %w", f.ID, err)
	}
	return string(rep.State), rep.Reason, err
}

// keepFix keeps a cut-short fix candidate for f, drafted at at, dropping
// the oldest while over maxKeptFixes.
func (s *Guard) keepFix(f Finding, cand change.Candidate, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fixes == nil {
		s.fixes = map[string]keptFix{}
	}
	s.fixes[f.ID] = keptFix{cand: cand, digest: digestOf(f), at: at}
	for len(s.fixes) > maxKeptFixes {
		oldest := ""
		for id, k := range s.fixes {
			if oldest == "" || k.at.Before(s.fixes[oldest].at) {
				oldest = id
			}
		}
		delete(s.fixes, oldest)
	}
}

func (s *Guard) dropFix(id string) {
	s.mu.Lock()
	delete(s.fixes, id)
	s.mu.Unlock()
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

// setFixLocked records a fix's state on the open finding and its
// evidence.
func (s *Guard) setFixLocked(f Finding, fix, reason string) {
	if rec, ok := s.st.Open[f.ID]; ok {
		rec.Fix, rec.FixReason = fix, reason
		s.st.Open[f.ID] = rec
	}
	d := digestOf(f)
	for i := range s.st.Evidence {
		if e := &s.st.Evidence[i]; e.Digest == d {
			e.Fix, e.FixReason = fix, reason
		}
	}
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

func findingID(c Check, subject, detail string) string {
	h := sha256.Sum256([]byte(string(c) + "\x00" + subject + "\x00" + detail))
	return string(c) + "-" + hex.EncodeToString(h[:6])
}

// check runs the passive checks (LOOP-8). Notes name checks that could not
// run; stale is set when the advisory snapshot is old.
func (s *Guard) check() (found []Finding, notes []string, stale string) {
	b, now := s.cfg.Box, s.cfg.Now()
	add := func(c Check, subject, detail string, sev Severity, t *Target, rule []byte) {
		found = append(found, Finding{ID: findingID(c, subject, detail), Check: c, Subject: subject,
			Detail: detail, Severity: sev, Contain: t, Rule: rule})
	}
	note := func(c Check, err error) {
		if err != nil {
			notes = append(notes, string(c))
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
	return found, notes, stale
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
			return fmt.Sprintf("Could not check %s version %s against known vulnerabilities. Check it on the box page.",
				sub, safeVersion(v))
		}
		if id, ok := strings.CutPrefix(f.Detail, unreadable); ok {
			return fmt.Sprintf("Could not read the fixed version in advisory %s for %s. Check it on the box page.",
				safeName(id), sub)
		}
		return fmt.Sprintf("Known vulnerability in %s (%s), fixed in %s. The box takes the fix when an update has it.",
			sub, safeName(f.Detail), safeVersion(f.Fixed))
	case CheckDrift:
		switch f.Detail {
		case "missing":
			return "Setting file " + sub + " is missing."
		case "not adopted":
			return "Setting file " + sub + " appeared outside the box's change process."
		}
		return "Setting file " + sub + " changed outside the box's change process."
	case CheckExpiry:
		if f.Detail == "expired" {
			return "Credential " + sub + " has expired. Replace it on the box page."
		}
		return "Credential " + sub + " " + safeName(f.Detail) + ". Replace it on the box page."
	}
	return "Security finding on " + sub + "."
}

// ownerLine is a finding and what was done about it, in fixed wording.
func ownerLine(r Record) string {
	f := r.Finding
	line := findingText(f)
	switch r.Contained {
	case "paused":
		line += " Paused " + label(f.Contain) + ". It stays paused until you turn it back on."
	case "failed":
		line += " Could not pause " + label(f.Contain) + ". STOP pauses everything."
	case "capped":
		line += " Not paused (too many findings at once)."
		if f.Contain.Kind == "grant" {
			line += fmt.Sprintf(" Reply PAUSE %s to pause it, or STOP to pause everything.", safeName(f.Contain.Name))
		} else {
			line += " Reply STOP to pause everything."
		}
	}
	return line
}

func clearedLine(r Record) string {
	return fmt.Sprintf("Cleared: %s. %s is still paused; ask your agent to turn it back on.",
		safeName(r.Finding.Subject), capFirst(label(r.Finding.Contain)))
}

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
		items = append(items, item{high, fmt.Sprintf("Known vulnerabilities in %s (%s), all fixed in %s. The box takes the fix when an update has it.",
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
	if len(s.notes) > 0 {
		var names []string
		for _, n := range s.notes {
			names = append(names, plainCheck[Check(n)])
		}
		out = append(out, "Security checks not run: "+strings.Join(names, ", ")+".")
	}
	if s.stale != "" {
		out = append(out, s.stale)
	}
	return out
}

// Evidence returns every recorded finding, oldest first.
func (s *Guard) Evidence() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Record(nil), s.st.Evidence...)
}
