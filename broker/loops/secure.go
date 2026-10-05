package loops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
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
	Name string `json:"name"`
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
	// Notify texts the owner a High finding at once, in fixed wording.
	Notify func(line string)
	// MaxPauses caps automatic containment per pass, so a bad advisory
	// feed cannot pause everything; the owner is texted about the rest.
	// Default 3.
	MaxPauses int
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
}

type secureState struct {
	Last time.Time `json:"last"`
	// Open are findings still observed, by ID.
	Open map[string]Record `json:"open"`
	// Evidence is every finding ever recorded; it only grows.
	Evidence []Record `json:"evidence"`
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
}

// NewGuard loads Loop 2's state.
func NewGuard(cfg GuardConfig) (*Guard, error) {
	if cfg.Pipeline == nil || cfg.Store == nil {
		return nil, errors.New("loops: Pipeline and Store are required")
	}
	if cfg.MaxPauses <= 0 {
		cfg.MaxPauses = 3
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
		cfg.Notify = func(string) {}
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
// how many findings were new: Loop 2's measured value (LOOP-3).
func (s *Guard) Pass(ctx context.Context) (int, error) {
	found, notes, stale := s.check()
	s.mu.Lock()
	s.notes, s.stale, s.force = notes, stale, false
	s.st.Last = s.cfg.Now()
	seen := map[string]bool{}
	var fresh []Finding
	for _, f := range found {
		seen[f.ID] = true
		if _, open := s.st.Open[f.ID]; !open {
			fresh = append(fresh, f)
		}
	}
	for id := range s.st.Open {
		if !seen[id] {
			delete(s.st.Open, id) // no longer observed; its evidence stays
		}
	}
	s.mu.Unlock()
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
		if err := s.handle(ctx, f, pause); err != nil {
			errs = append(errs, err)
		}
	}
	s.mu.Lock()
	err := s.saveLocked()
	s.mu.Unlock()
	return len(fresh), errors.Join(append(errs, err)...)
}

// handle is LOOP-9: contain, preserve evidence, add the regression
// fixture, propose a fix, notify.
func (s *Guard) handle(ctx context.Context, f Finding, pause bool) error {
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
	// Evidence is saved before anything slower runs.
	s.mu.Lock()
	s.st.Open[f.ID] = rec
	s.st.Evidence = append(s.st.Evidence, rec)
	err := s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		errs = append(errs, err)
	}
	if f.Rule != nil {
		c := change.Case{ID: "loop2/" + f.ID, Class: change.ClassConfig, Input: f.Rule, Expect: []byte(FixtureOK)}
		switch err := s.cfg.Pipeline.AddSecurityCase(c); {
		case err == nil, errors.Is(err, change.ErrDuplicate):
			rec.Fixture = c.ID
		default:
			errs = append(errs, fmt.Errorf("fixture %s: %w", f.ID, err))
		}
	}
	if s.cfg.Fixer != nil && f.Rule != nil {
		cand, err := s.cfg.Fixer.Fix(ctx, f)
		if err == nil {
			// Loop 2 sets these, never the fixer.
			cand.Source, cand.Origin, cand.Public = change.Local, "loop2", false
			var rep change.Report
			rep, err = s.cfg.Pipeline.Propose(ctx, cand)
			rec.Fix, rec.FixReason = string(rep.State), rep.Reason
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("fix %s: %w", f.ID, err))
		}
	}
	s.mu.Lock()
	s.st.Open[f.ID] = rec
	s.st.Evidence[len(s.st.Evidence)-1] = rec
	s.mu.Unlock()
	if f.Severity == High || rec.Contained == "capped" {
		s.cfg.Notify(ownerLine(rec))
	}
	return errors.Join(errs...)
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
					add(CheckHash, a.Name, "differs from the signed release", High, a.Contain,
						fixtureInput(FixtureRule{Check: CheckHash, Subject: a.Name, Digest: want}))
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
				for _, a := range snap.Advisories {
					if a.Package != p.Name || !versionBelow(p.Version, a.Fixed) {
						continue
					}
					sev := Low
					if sw := strings.ToLower(a.Severity); sw == "high" || sw == "critical" {
						sev = High
					}
					add(CheckAdvisory, p.Name, a.ID, sev, p.Contain,
						fixtureInput(FixtureRule{Check: CheckAdvisory, Subject: p.Name, Fixed: a.Fixed}))
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

// versionBelow reports v < fixed, comparing dot-separated numbers. A
// version either side that does not parse counts as below: fail closed.
func versionBelow(v, fixed string) bool {
	a, ok1 := parseVersion(v)
	b, ok2 := parseVersion(fixed)
	if !ok1 || !ok2 {
		return true
	}
	for i := 0; i < max(len(a), len(b)); i++ {
		x, y := 0, 0
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func parseVersion(v string) ([]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" {
		return nil, false
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// FixtureRule is a Loop 2 regression fixture's input: the condition a
// change must not break again. It is the minimized case for a passive
// finding: one subject, one condition.
type FixtureRule struct {
	Check   Check  `json:"check"`
	Subject string `json:"subject"`
	Digest  string `json:"digest,omitempty"` // CheckHash: the signed digest
	Fixed   string `json:"fixed,omitempty"`  // CheckAdvisory: the first fixed version
}

// FixtureOK is what a passing fixture answers.
const FixtureOK = "ok"

func fixtureInput(r FixtureRule) []byte {
	b, _ := json.Marshal(r)
	return b
}

// Facts are what a candidate tree would install: digests and package
// versions. The evaluator builds them for the tree under test.
type Facts struct {
	Digests  map[string]string
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
	switch r.Check {
	case CheckHash:
		if d, ok := f.Digests[r.Subject]; ok && d == r.Digest {
			return []byte(FixtureOK)
		}
	case CheckAdvisory:
		if v, ok := f.Versions[r.Subject]; ok && !versionBelow(v, r.Fixed) {
			return []byte(FixtureOK)
		}
	}
	return []byte("fails")
}

var checkWords = map[Check]string{
	CheckHash:     "a file that does not match the signed release",
	CheckAdvisory: "a known vulnerability",
	CheckDrift:    "a setting changed outside the box's change process",
	CheckExpiry:   "a credential that expires",
}

// safe keeps owner-facing names to a fixed alphabet.
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:", r)) {
			b.WriteRune(r)
		}
		if b.Len() >= 48 {
			break
		}
	}
	return b.String()
}

func ownerLine(r Record) string {
	f := r.Finding
	line := fmt.Sprintf("Security check found %s: %s (%s).", checkWords[f.Check], safeName(f.Subject), safeName(f.Detail))
	switch r.Contained {
	case "paused":
		line += fmt.Sprintf(" Paused %s %s until it is fixed.", f.Contain.Kind, safeName(f.Contain.Name))
	case "failed":
		line += " Could not pause it. STOP pauses everything."
	case "capped":
		line += " Not paused: too many findings at once."
		if f.Contain.Kind == "grant" {
			line += fmt.Sprintf(" Reply PAUSE %s to pause it, or STOP to pause everything.", safeName(f.Contain.Name))
		} else {
			line += " Reply STOP to pause everything."
		}
	}
	return line
}

// Digest is Loop 2's lines for the owner's digest: open findings, checks
// that could not run, and stale advisories. A Low finding is reported only
// here.
func (s *Guard) Digest() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	ids := make([]string, 0, len(s.st.Open))
	for id := range s.st.Open {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		out = append(out, ownerLine(s.st.Open[id]))
	}
	if len(s.notes) > 0 {
		out = append(out, "Security checks not run: "+strings.Join(s.notes, ", ")+".")
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
