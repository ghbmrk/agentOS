package loops

// REQ: LOOP-8, LOOP-9, LOOP-10

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
)

// box is a fake box for the passive checks.
type box struct {
	signed   map[string]string
	measured map[string]string
	pkgs     []Package
	snap     Snapshot
	adopted  map[string]string
	live     map[string]string
	expiries []Expiry
	// signedErr and liveErr make the hash and drift checks fail to run.
	signedErr, liveErr error
}

func (b *box) Box() Box {
	return Box{
		Signed: func() (map[string]string, error) { return b.signed, b.signedErr },
		Artifacts: []Artifact{
			{Name: "guest-image/openclaw", Contain: &Target{Kind: "executor", Name: "openclaw", Label: "the agent machine"}},
			{Name: "dep/libfoo"},
		},
		Measure: func(n string) (string, error) {
			d, ok := b.measured[n]
			if !ok {
				return "", errors.New("gone")
			}
			return d, nil
		},
		Installed:  func() ([]Package, error) { return b.pkgs, nil },
		Advisories: func() (Snapshot, error) { return b.snap, nil },
		Adopted:    func() (map[string]string, error) { return b.adopted, nil },
		Live:       func() (map[string]string, error) { return b.live, b.liveErr },
		Expiries:   func() ([]Expiry, error) { return b.expiries, nil },
	}
}

var t0 = time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)

func cleanBox() *box {
	return &box{
		signed:   map[string]string{"guest-image/openclaw": "aa", "dep/libfoo": "bb"},
		measured: map[string]string{"guest-image/openclaw": "aa", "dep/libfoo": "bb"},
		pkgs:     []Package{{Name: "openssl", Version: "3.0.15", Contain: &Target{Kind: "executor", Name: "egress", Label: "the network gateway"}}},
		snap: Snapshot{Fetched: t0.Add(-time.Hour), Advisories: []Advisory{
			{ID: "ADV-1", Package: "openssl", Fixed: "3.0.14", Severity: "high"},
		}},
		adopted:  map[string]string{"config/quiet.json": "c1"},
		live:     map[string]string{"config/quiet.json": "c1"},
		expiries: []Expiry{{Name: "mail-oauth", NotAfter: t0.Add(90 * 24 * time.Hour)}},
	}
}

// fixtureEval answers Loop 2 fixtures from the facts file of the tree
// under test, and other probes with the tree file they name.
type fixtureEval struct{}

func (fixtureEval) Run(_ context.Context, t change.Tree, p change.Probe) ([]byte, error) {
	if strings.HasPrefix(string(p.Input), `{"check"`) {
		var f Facts
		if b, ok := t["config/facts.json"]; ok {
			if err := json.Unmarshal(b, &f); err != nil {
				return nil, err
			}
		}
		return AnswerFixture(p.Input, f), nil
	}
	b, ok := t[string(p.Input)]
	if !ok {
		return nil, errors.New("no file")
	}
	return b, nil
}

func facts(openssl string) []byte {
	b, _ := json.Marshal(Facts{Versions: map[string]string{"openssl": openssl}})
	return b
}

func newPipe(t *testing.T) *change.Pipeline {
	t.Helper()
	p, err := change.New(change.Config{
		Store:     &change.MemStore{},
		Evaluator: fixtureEval{},
		Initial:   change.Tree{"config/facts.json": facts("3.0.13"), "skills/greet": []byte("hi")},
		Now:       func() time.Time { return t0 },
		Rand:      fixed{},
	})
	if err != nil {
		t.Fatal(err)
	}
	eng, err := journal.Open(&journal.MemStore{}, &policy{p: p, approve: true}, map[string]journal.Executor{change.Executor: p},
		func(s string) string { return s }, journal.WithClock(func() time.Time { return t0 }))
	if err != nil {
		t.Fatal(err)
	}
	p.Attach(eng)
	return p
}

type contain struct {
	mu   sync.Mutex
	got  []Target
	fail bool
}

func (c *contain) Contain(_ context.Context, t Target, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return errors.New("gate refused")
	}
	c.got = append(c.got, t)
	return nil
}

type fixer struct {
	cand  change.Candidate
	calls int
}

func (f *fixer) Fix(context.Context, Finding) (change.Candidate, error) {
	f.calls++
	c := f.cand
	c.Origin, c.Public = "fixer-claims-this", true // must be overwritten
	return c, nil
}

type guardRig struct {
	b             *box
	p             *change.Pipeline
	c             *contain
	fx            *fixer
	store         *change.MemStore
	now           time.Time
	texts         []string
	urgent        []bool
	deferFixtures bool
	g             *Guard
}

func newGuardRig(t *testing.T, b *box) *guardRig {
	t.Helper()
	r := &guardRig{b: b, p: newPipe(t), c: &contain{}, store: &change.MemStore{}, now: t0}
	r.reopen(t)
	return r
}

func (r *guardRig) reopen(t *testing.T) {
	t.Helper()
	cfg := GuardConfig{Box: r.b.Box(), Pipeline: r.p, Store: r.store, Contain: r.c, FixturesLive: !r.deferFixtures,
		Notify: func(s string, u bool) { r.texts, r.urgent = append(r.texts, s), append(r.urgent, u) }, Now: func() time.Time { return r.now }}
	if r.fx != nil {
		cfg.Fixer = r.fx
	}
	g, err := NewGuard(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.g = g
}

func (r *guardRig) pass(t *testing.T) int {
	t.Helper()
	n, err := r.g.Pass(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func checks(fs []Record) map[Check]int {
	out := map[Check]int{}
	for _, f := range fs {
		out[f.Finding.Check]++
	}
	return out
}

// LOOP-8: a clean box has no findings; each passive check finds its own
// kind of problem, the advisory check runs offline on the last snapshot,
// and an old snapshot is never reported as current.
func TestPassiveChecks(t *testing.T) {
	r := newGuardRig(t, cleanBox())
	if n := r.pass(t); n != 0 {
		t.Fatalf("clean box: %d findings: %+v", n, r.g.Evidence())
	}
	if d := r.g.Digest(); len(d) != 0 {
		t.Fatalf("clean digest: %q", d)
	}

	b := cleanBox()
	b.measured["guest-image/openclaw"] = "tampered" // hash mismatch
	delete(b.measured, "dep/libfoo")                // cannot be measured: fail closed
	b.pkgs[0].Version = "3.0.9"                     // below the fixed version
	b.snap.Fetched = t0.Add(-30 * 24 * time.Hour)   // offline for a month
	b.live["config/quiet.json"] = "edited"          // drift
	b.live["config/extra.json"] = "x"               // not adopted
	b.expiries = append(b.expiries,
		Expiry{Name: "cal-cert", NotAfter: t0.Add(3 * 24 * time.Hour)}, // soon
		Expiry{Name: "old-token", NotAfter: t0.Add(-time.Hour)})        // expired
	r = newGuardRig(t, b)
	if n := r.pass(t); n != 7 {
		t.Fatalf("findings = %d, want 7: %+v", n, r.g.Evidence())
	}
	got := checks(r.g.Evidence())
	want := map[Check]int{CheckHash: 2, CheckAdvisory: 1, CheckDrift: 2, CheckExpiry: 2}
	for c, n := range want {
		if got[c] != n {
			t.Errorf("%s: %d findings, want %d", c, got[c], n)
		}
	}
	d := strings.Join(r.g.Digest(), "\n")
	if !strings.Contains(d, "last fetched 30 days ago") || !strings.Contains(d, "not current") {
		t.Errorf("stale snapshot not reported: %s", d)
	}

	// Version ordering: dpkg for Debian (epoch, revision, ~), semver
	// where named; anything unparseable is below (fail closed).
	for _, c := range []struct {
		scheme, v, fixed string
		below            bool
	}{
		{"", "1.2.3", "1.2.4", true}, {"", "1.10", "1.9", false}, {"", "1.2", "1.2.1", true},
		{"", "3.0.15-1~deb12u1", "3.0.15-1", true}, {"", "3.0.15-1+deb12u1", "3.0.15-1", false},
		{"", "1:1.0", "2.0", false}, {"", "1.0~rc1", "1.0", true}, {"", "1.0a", "1.0", false},
		{"", "2.36-9+deb12u7", "2.36-9+deb12u8", true},
		{SchemeSemver, "1.2.0-rc.1", "1.2.0", true}, {SchemeSemver, "v1.2.0", "1.2.0", false},
		{SchemeSemver, "1.2.0-alpha", "1.2.0-alpha.1", true}, {SchemeSemver, "1.2.0-2", "1.2.0-10", true},
		{SchemeSemver, "1.10.0", "1.9.9", false}, {SchemeSemver, "1.x", "1.0", true},
	} {
		if versionBelow(c.scheme, c.v, c.fixed) != c.below {
			t.Errorf("versionBelow(%q, %s, %s) != %v", c.scheme, c.v, c.fixed, c.below)
		}
	}

	// A check with nothing wired is named as not run, never as passed.
	g, _ := NewGuard(GuardConfig{Pipeline: newPipe(t), Store: &change.MemStore{}, Now: func() time.Time { return t0 }})
	if _, err := g.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := strings.Join(g.Digest(), " "); !strings.Contains(d, "Loop 2: partial (not run: file hashes; known vulnerabilities; settings; credential expiry).") {
		t.Errorf("unwired checks: %s", d)
	}
}

// Security L5, UX W2 and potency C2 on W5a: STATUS always says what did
// not run and why; the digest says it once, again when the set changes,
// and whenever a pass is overdue. Nothing ever reads as clean or passed.
func TestNotRunIsSaidAndNothingReadsPassed(t *testing.T) {
	now := t0
	b := cleanBox()
	box := b.Box()
	box.Expiries = nil
	g, err := NewGuard(GuardConfig{Box: box, Pipeline: newPipe(t), Store: &change.MemStore{}, Now: func() time.Time { return now },
		NotRun: map[Check]string{CheckExpiry: "needs the vault's expiry list"}})
	if err != nil {
		t.Fatal(err)
	}
	var said []string
	look := func() (status, digest string) {
		status, digest = g.Status(), strings.Join(g.Digest(), " ")
		said = append(said, status, digest)
		return
	}
	if st, _ := look(); st != "Loop 2: not run yet." {
		t.Fatalf("before a pass: %q", st)
	}
	g.Pass(context.Background())
	want := "Loop 2: partial (not run: credential expiry, needs the vault's expiry list)."
	if st, d := look(); st != want || d != want {
		t.Fatalf("first pass: STATUS %q, digest %q", st, d)
	}
	if st, d := look(); st != want || strings.Contains(d, "Loop 2") {
		t.Fatalf("second look: STATUS %q, digest %q", st, d)
	}
	// Every check wired: STATUS has nothing to say, and says nothing.
	g.cfg.Box.Expiries = b.Box().Expiries
	now = now.Add(6 * time.Hour)
	g.Pass(context.Background())
	if st, d := look(); st != "" || strings.Contains(d, "Loop 2") {
		t.Fatalf("all wired: STATUS %q, digest %q", st, d)
	}
	// Overdue: said in both, every time.
	now = now.Add(12 * time.Hour)
	for range 2 {
		if st, d := look(); !strings.HasPrefix(st, "Loop 2: checks haven't run since") || !strings.Contains(d, st) {
			t.Fatalf("overdue: STATUS %q, digest %q", st, d)
		}
	}
	for _, s := range said {
		l := strings.ToLower(s)
		for _, w := range []string{"passed", "clean", "all checks", "no problems", "ok"} {
			if strings.Contains(l, w) {
				t.Fatalf("%q reads as passed (%q)", s, w)
			}
		}
	}
}

// REQ: LOOP-8. Potency C2 on W5a: a check whose input exists but errored
// is said as failed, in STATUS and in every digest while it fails, not
// only once like a check that is not wired yet.
func TestAFailedCheckIsSaidEveryDigest(t *testing.T) {
	now := t0
	box := cleanBox().Box()
	box.Expiries = func() ([]Expiry, error) { return nil, errors.New("vault unreachable") }
	g, err := NewGuard(GuardConfig{Box: box, Pipeline: newPipe(t), Store: &change.MemStore{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	g.Pass(context.Background())
	want := "Loop 2: partial (not run: credential expiry, failed)."
	for i := range 2 {
		if st, d := g.Status(), strings.Join(g.Digest(), " "); st != want || d != want {
			t.Fatalf("digest %d: STATUS %q, digest %q", i, st, d)
		}
	}
	// Fixed: nothing to say, and nothing reads as passed.
	box.Expiries = func() ([]Expiry, error) { return nil, nil }
	g.cfg.Box = box
	now = now.Add(6 * time.Hour)
	g.Pass(context.Background())
	if st, d := g.Status(), strings.Join(g.Digest(), " "); st != "" || d != "" {
		t.Fatalf("recovered: STATUS %q, digest %q", st, d)
	}
}

// LOOP-9: a finding is contained, its evidence preserved, a regression
// fixture added to the security suite, a fix proposed through the change
// pipeline, and the owner told by severity. It is handled once while it
// persists, and again if it comes back.
func TestFindingHandling(t *testing.T) {
	b := cleanBox()
	b.pkgs[0].Version = "3.0.13"
	b.expiries = []Expiry{{Name: "cal-cert", NotAfter: t0.Add(3 * 24 * time.Hour)}}
	r := newGuardRig(t, b)
	r.fx = &fixer{cand: change.Candidate{Files: change.Tree{"config/facts.json": facts("3.0.14")}}}
	r.reopen(t)
	if n := r.pass(t); n != 2 {
		t.Fatalf("findings = %d, want 2", n)
	}
	if len(r.c.got) != 1 || r.c.got[0] != (Target{Kind: "executor", Name: "egress", Label: "the network gateway"}) {
		t.Fatalf("contained %+v", r.c.got)
	}
	ev := r.g.Evidence()
	var adv Record
	for _, e := range ev {
		if e.Finding.Check == CheckAdvisory {
			adv = e
		}
		if e.Digest != digestOf(e.Finding) {
			t.Errorf("evidence digest does not match its finding")
		}
	}
	if adv.Contained != "paused" || adv.Fixture == "" {
		t.Fatalf("advisory record %+v", adv)
	}
	// The fix went through the pipeline and passed the new fixture; it is
	// a config change, so it adopts only on the owner's approval (given here).
	if r.fx.calls != 1 || adv.Fix != string(change.StateAdopted) {
		t.Fatalf("fix calls %d, state %q (%s)", r.fx.calls, adv.Fix, adv.FixReason)
	}
	// Only the High finding is texted; the Low one is in the digest.
	if len(r.texts) != 1 || !r.urgent[0] ||
		!strings.Contains(r.texts[0], "Known vulnerability in openssl (ADV-1), fixed in 3.0.14.") ||
		!strings.Contains(r.texts[0], "Paused the network gateway. It stays paused until you resume it on my Wi-Fi page.") ||
		strings.Contains(r.texts[0], "executor") || strings.Contains(r.texts[0], "grant") {
		t.Fatalf("texts %q", r.texts)
	}
	if d := strings.Join(r.g.Digest(), "\n"); !strings.Contains(d, "cal-cert") {
		t.Errorf("low finding not in digest: %s", d)
	}

	// Still there on the next pass, and after a restart: handled once.
	r.now = r.now.Add(7 * time.Hour)
	r.reopen(t)
	if n := r.pass(t); n != 0 || len(r.c.got) != 1 || len(r.texts) != 1 || r.fx.calls != 1 {
		t.Fatalf("re-handled: n=%d contained=%d texts=%d fixes=%d", n, len(r.c.got), len(r.texts), r.fx.calls)
	}
	// Fixed: the owner, texted about the pause, is texted that it cleared
	// and that the pause stays.
	b.pkgs[0].Version = "3.0.14"
	r.pass(t)
	if len(r.texts) != 2 || !strings.Contains(r.texts[1], "Cleared: openssl. The network gateway stays paused until you resume it on my Wi-Fi page.") {
		t.Fatalf("cleared text %q", r.texts)
	}
	// Back within a day: handled again (contained, evidence), but not
	// texted; the digest says "again".
	b.pkgs[0].Version = "3.0.13"
	r.fx.cand.Files = change.Tree{"config/facts.json": facts("3.0.15")}
	if n := r.pass(t); n != 1 || len(r.c.got) != 2 {
		t.Fatalf("reappearance: n=%d contained=%d", n, len(r.c.got))
	}
	// Evidence keeps one record per finding digest, counting appearances.
	if got := checks(r.g.Evidence())[CheckAdvisory]; got != 1 {
		t.Fatalf("advisory evidence records = %d, want 1", got)
	}
	for _, e := range r.g.Evidence() {
		if e.Finding.Check == CheckAdvisory && e.Seen != 2 {
			t.Fatalf("seen %d, want 2", e.Seen)
		}
	}
	if len(r.texts) != 2 {
		t.Fatalf("texts after reappearance: %q", r.texts)
	}
	if d := strings.Join(r.g.Digest(), "\n"); !strings.Contains(d, "Security check: Again: Known vulnerability in openssl") {
		t.Fatalf("digest %s", d)
	}

	// Containment that fails is recorded and said, never silent.
	b2 := cleanBox()
	b2.measured["guest-image/openclaw"] = "tampered"
	r2 := newGuardRig(t, b2)
	r2.c.fail = true
	if _, err := r2.g.Pass(context.Background()); err == nil {
		t.Fatal("failed containment returned no error")
	}
	if len(r2.texts) != 1 || !strings.Contains(r2.texts[0], "Could not pause the agent machine. STOP pauses everything.") {
		t.Fatalf("texts %q", r2.texts)
	}
}

// LOOP-9 with a bad feed: automatic pauses are capped per pass, and the
// owner is texted about each finding left unpaused.
func TestPauseCap(t *testing.T) {
	b := cleanBox()
	b.pkgs = nil
	b.snap.Advisories = nil
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		b.pkgs = append(b.pkgs, Package{Name: n, Version: "1.0", Contain: &Target{Kind: "grant", Name: "g-" + n}})
		b.snap.Advisories = append(b.snap.Advisories, Advisory{ID: "ADV-" + n, Package: n, Fixed: "1.1", Severity: "low"})
	}
	r := newGuardRig(t, b)
	if n := r.pass(t); n != 5 {
		t.Fatalf("findings = %d", n)
	}
	if len(r.c.got) != 3 {
		t.Fatalf("paused %d, want 3", len(r.c.got))
	}
	// One text for the pass, the rest on MORE: each pause is told at once,
	// though the advisories are Low (security L2 on W5a).
	all := strings.Join(append(r.texts, r.g.More()...), " ")
	if len(r.texts) != 1 || strings.Count(all, "Not paused (too many findings at once)") != 2 || strings.Count(all, "Paused the affected tool") != 3 {
		t.Fatalf("texts %q, all %q", r.texts, all)
	}
}

// L3 S1 on #169: a pause that ended while the guard could not hear it (a
// cascade revoke before the hook covered it, or a crash between the
// journal's resume and the guard's save) is dropped by Reconcile, so the
// digest does not list it and a new pause of the target is texted (L2).
func TestReconcileDropsPausesTheGateNoLongerHolds(t *testing.T) {
	b := cleanBox()
	b.pkgs = []Package{{Name: "a", Version: "1.0", Contain: &Target{Kind: "grant", Name: "G2"}},
		{Name: "b", Version: "1.0", Contain: &Target{Kind: "grant", Name: "G3"}}}
	b.snap.Advisories = []Advisory{{ID: "ADV-a", Package: "a", Fixed: "1.1", Severity: "low"},
		{ID: "ADV-b", Package: "b", Fixed: "1.1", Severity: "low"}}
	r := newGuardRig(t, b)
	r.pass(t)
	if len(r.c.got) != 2 || len(r.texts) != 1 {
		t.Fatalf("paused %v, texts %q", r.c.got, r.texts)
	}
	// Both clear; the owner ends G2's pause, but the guard never hears it.
	b.snap.Advisories = nil
	r.now = r.now.Add(6 * time.Hour)
	r.pass(t)
	r.reopen(t)
	if err := r.g.Reconcile(func(t Target) bool { return t.Name == "G3" }); err != nil {
		t.Fatal(err)
	}
	r.reopen(t) // Reconcile saved
	if d := strings.Join(r.g.Digest(), " "); strings.Contains(d, "Cleared: a.") || !strings.Contains(d, "Cleared: b.") {
		t.Fatalf("digest after Reconcile: %q", d)
	}
	b.snap.Advisories = []Advisory{{ID: "ADV-a", Package: "a", Fixed: "1.1", Severity: "low"},
		{ID: "ADV-b", Package: "b", Fixed: "1.1", Severity: "low"}}
	r.now = r.now.Add(7 * 24 * time.Hour)
	r.texts = nil
	r.pass(t)
	all := strings.Join(append(r.texts, r.g.More()...), " ")
	if strings.Count(all, "Paused the affected tool") != 1 {
		t.Fatalf("only G2's new pause is texted; G3 is still paused: %q", all)
	}
}

// Security L2 on W5a: automatic pauses are also capped per day, so a feed
// that drips findings across passes cannot pause a grant set either.
func TestPauseCapPerDay(t *testing.T) {
	b := cleanBox()
	b.pkgs, b.snap.Advisories = nil, nil
	r := newGuardRig(t, b)
	paused := 0
	for i := range 6 {
		n := fmt.Sprint("p", i)
		for j := range 2 {
			m := fmt.Sprint(n, j)
			b.pkgs = append(b.pkgs, Package{Name: m, Version: "1.0", Contain: &Target{Kind: "grant", Name: "g-" + m}})
			b.snap.Advisories = append(b.snap.Advisories, Advisory{ID: "ADV-" + m, Package: m, Fixed: "1.1", Severity: "high"})
		}
		r.now = r.now.Add(time.Hour)
		r.reopen(t)
		r.pass(t)
		paused = len(r.c.got)
	}
	if paused != 10 {
		t.Fatalf("paused %d in a day, want 10", paused)
	}
	r.now = r.now.Add(24 * time.Hour)
	b.pkgs = append(b.pkgs, Package{Name: "next", Version: "1.0", Contain: &Target{Kind: "grant", Name: "g-next"}})
	b.snap.Advisories = append(b.snap.Advisories, Advisory{ID: "ADV-next", Package: "next", Fixed: "1.1", Severity: "high"})
	r.reopen(t)
	r.pass(t)
	if len(r.c.got) != 11 {
		t.Fatalf("the next day paused %d in all", len(r.c.got))
	}
}

// LOOP-9 fixtures never block a legitimate later release (security lens
// B1): a hash finding adds no fixture, and an advisory fixture passes on a
// tree that no longer has the package.
func TestFixturesAllowLaterReleases(t *testing.T) {
	b := cleanBox()
	b.measured["guest-image/openclaw"] = "tampered"
	r := newGuardRig(t, b)
	r.pass(t)
	for _, e := range r.g.Evidence() {
		if e.Finding.Check == CheckHash && (e.Fixture != "" || e.Finding.Rule != nil) {
			t.Fatalf("hash finding made a fixture: %+v", e)
		}
	}
	// The next signed release changes the artifact; nothing in the suite
	// pins the old digest, so the box takes it.
	b.signed["guest-image/openclaw"], b.measured["guest-image/openclaw"] = "cc", "cc"
	if n := r.pass(t); n != 0 {
		t.Fatalf("after new release: %d findings", n)
	}

	in := fixtureInput(FixtureRule{Check: CheckAdvisory, Subject: "openssl", Fixed: "3.0.14"})
	for _, c := range []struct {
		facts Facts
		want  string
	}{
		{Facts{Versions: map[string]string{"openssl": "3.0.13"}}, "fails"},
		{Facts{Versions: map[string]string{"openssl": "3.0.14-1"}}, FixtureOK},
		{Facts{Versions: map[string]string{}}, FixtureOK}, // package dropped
		{Facts{}, FixtureOK},
	} {
		if got := string(AnswerFixture(in, c.facts)); got != c.want {
			t.Errorf("%+v: %s, want %s", c.facts, got, c.want)
		}
	}
	if got := string(AnswerFixture([]byte(`{"check":"hash","subject":"x"}`), Facts{})); got == FixtureOK {
		t.Error("an unknown fixture kind passed")
	}
}

// LOOP-9 for the owner: a pause outlives its cleared finding in the digest
// until resumed, and a finding that comes back is texted again only if it
// stayed clear for a day.
func TestPausedAndFlapping(t *testing.T) {
	b := cleanBox()
	b.pkgs[0].Version = "3.0.13"
	r := newGuardRig(t, b)
	r.pass(t)
	b.pkgs[0].Version = "3.0.14"
	r.pass(t)
	d := strings.Join(r.g.Digest(), "\n")
	if !strings.Contains(d, "Cleared: openssl. The network gateway stays paused until you resume it on my Wi-Fi page.") {
		t.Fatalf("digest: %s", d)
	}
	must(t, r.g.Resumed(Target{Kind: "executor", Name: "egress", Label: "the network gateway"}))
	if d := strings.Join(r.g.Digest(), "\n"); strings.Contains(d, "still paused") {
		t.Fatalf("after resume: %s", d)
	}

	// A High finding with nothing to pause flaps. The owner is texted the
	// alert and that it cleared (S39); a return within ReText after that
	// texted "Cleared" is texted again, led "It is back: ", so their last
	// text is never a false all-clear (L3 #585 point 1), and that
	// return's own clearing is texted once more, so it never ends on "it
	// is back" after it closed (P3-4b-3r-text). Later returns within
	// ReText go to the digest only: at most four texts per ReText. The
	// told mark survives a restart between the clear and the return
	// (P3-4b-3r-told requirement 3; the json:"-" mutant fails here).
	b2 := cleanBox()
	b2.live["config/quiet.json"] = "edited"
	r2 := newGuardRig(t, b2)
	r2.pass(t)
	b2.live["config/quiet.json"] = "c1"
	r2.pass(t)
	if len(r2.texts) != 2 || !strings.Contains(r2.texts[1], "Cleared: config/quiet.json.") {
		t.Fatalf("texts %q, want the alert and one cleared", r2.texts)
	}
	r2.reopen(t)
	b2.live["config/quiet.json"] = "edited"
	r2.pass(t)
	if len(r2.texts) != 3 || !strings.HasPrefix(r2.texts[2], "Security checks: It is back: Setting file config/quiet.json") {
		t.Fatalf("return after a texted Cleared: texts %q, want it texted as back", r2.texts)
	}
	b2.live["config/quiet.json"] = "c1"
	r2.pass(t)
	if len(r2.texts) != 4 || !strings.Contains(r2.texts[3], "Cleared: config/quiet.json.") || r2.urgent[3] {
		t.Fatalf("texts %q urgent %v, want the back's clearing texted once, not urgent", r2.texts, r2.urgent)
	}
	for i := 0; i < 3; i++ {
		b2.live["config/quiet.json"] = "edited"
		r2.pass(t)
		b2.live["config/quiet.json"] = "c1"
		r2.pass(t)
	}
	if len(r2.texts) != 4 {
		t.Fatalf("flapping texts %q, want 4", r2.texts)
	}
	r2.now = r2.now.Add(25 * time.Hour)
	b2.live["config/quiet.json"] = "edited"
	r2.pass(t)
	if len(r2.texts) != 5 || strings.Contains(r2.texts[4], "Cleared") || strings.Contains(r2.texts[4], "It is back") {
		t.Fatalf("texts after a day %q, want a first alert again", r2.texts)
	}
}

// P3-4b-3r-told requirement 1, through Pass: two texted findings share a
// plain name (config/a! and config/a both read config/a). The one that
// closes while the other is open says no "Cleared", so it is not marked,
// and its return within ReText is digest-only. Two that close together
// share one line and are both marked, so each one's return is texted.
func TestPassMarksOnlyAClearItSaid(t *testing.T) {
	b := cleanBox()
	b.live["config/a!"], b.live["config/a"] = "x", "y"
	r := newGuardRig(t, b)
	r.pass(t)
	before := len(r.texts)
	delete(b.live, "config/a!")
	r.now = r.now.Add(time.Hour)
	r.pass(t)
	b.live["config/a!"] = "x"
	r.now = r.now.Add(time.Hour)
	r.pass(t)
	if got := r.texts[before:]; len(got) != 0 {
		t.Fatalf("held clear, then its return: texts %q", got)
	}
	delete(b.live, "config/a!")
	delete(b.live, "config/a")
	r.now = r.now.Add(25 * time.Hour)
	r.pass(t)
	if got := clearedTexts(r.texts, before); len(got) != 1 || len(r.g.st.ToldCleared) != 1 {
		t.Fatalf("cleared %q, marked %v", got, r.g.st.ToldCleared)
	}
	// config/a! came back as an untexted Again, so its close is digest
	// only; config/a was texted, said and marked.
	before = len(r.texts)
	b.live["config/a"] = "y"
	r.now = r.now.Add(time.Hour)
	r.pass(t)
	if got := r.texts[before:]; len(got) != 1 || !strings.HasPrefix(got[0], "Security checks: It is back: ") {
		t.Fatalf("a marked return: texts %q", got)
	}

	b2 := cleanBox()
	b2.live["config/a!"], b2.live["config/a"] = "x", "y"
	r2 := newGuardRig(t, b2)
	r2.pass(t)
	delete(b2.live, "config/a!")
	delete(b2.live, "config/a")
	r2.now = r2.now.Add(time.Hour)
	r2.pass(t)
	if got := clearedTexts(r2.texts, 0); len(got) != 1 || len(r2.g.st.ToldCleared) != 2 {
		t.Fatalf("closed together: cleared %q, marked %v", got, r2.g.st.ToldCleared)
	}
}

// LOOP-9 owner text: one text per pass within three segments, the rest
// on MORE; an expiry alone is not urgent; the digest groups advisories per
// package and shows at most three findings.
func TestOwnerText(t *testing.T) {
	b := cleanBox()
	b.signed, b.measured = map[string]string{}, map[string]string{}
	for i := 0; i < 8; i++ {
		b.live[fmt.Sprintf("config/file-number-%d.json", i)] = "x"
	}
	r := newGuardRig(t, b)
	r.pass(t)
	if len(r.texts) != 1 || len(r.texts[0]) > textBudget || !strings.HasSuffix(r.texts[0], "Reply MORE for the rest.") {
		t.Fatalf("texts %q", r.texts)
	}
	shown := strings.Count(r.texts[0], "Setting file") + strings.Count(r.texts[0], "File ")
	if more := r.g.More(); shown+len(more) != 10 || len(r.g.More()) != 0 {
		t.Fatalf("shown %d + more %d, want 10, once", shown, len(more))
	}
	d := r.g.Digest()
	if !strings.Contains(strings.Join(d, "\n"), "And 7 more security findings") {
		t.Fatalf("digest %q", d)
	}

	b2 := cleanBox()
	b2.expiries = []Expiry{{Name: "old-token", NotAfter: t0.Add(-time.Hour)}}
	b2.pkgs[0].Version = "3.0.15" // no advisory
	r2 := newGuardRig(t, b2)
	r2.pass(t)
	if len(r2.texts) != 1 || r2.urgent[0] || !strings.Contains(r2.texts[0], "Credential old-token has expired. Replace it on my Wi-Fi page.") {
		t.Fatalf("expiry text %q urgent %v", r2.texts, r2.urgent)
	}

	b3 := cleanBox()
	b3.pkgs[0].Version = "3.0.1"
	b3.snap.Advisories = append(b3.snap.Advisories, Advisory{ID: "ADV-2", Package: "openssl", Fixed: "3.0.12", Severity: "low"})
	r3 := newGuardRig(t, b3)
	r3.pass(t)
	if d := strings.Join(r3.g.Digest(), "\n"); !strings.Contains(d, "Known vulnerabilities in openssl (ADV-1, ADV-2), all fixed in 3.0.14.") {
		t.Fatalf("grouped digest %s", d)
	}
}

// LOOP-8: a version that cannot be compared is reported plainly in the
// digest, with nothing paused, texted, or pinned as a fixture; and the
// owner wording is exact.
func TestUncomparedAndWording(t *testing.T) {
	b := cleanBox()
	b.pkgs[0].Version = "build-42" // not a dpkg version
	r := newGuardRig(t, b)
	r.pass(t)
	ev := r.g.Evidence()
	if len(ev) != 1 || ev[0].Contained != "none" || ev[0].Fixture != "" || ev[0].Finding.Severity != Low || len(r.c.got) != 0 || len(r.texts) != 0 {
		t.Fatalf("uncompared: %+v paused %d texts %q", ev, len(r.c.got), r.texts)
	}
	want := "Security check: Could not check openssl version build-42 against known vulnerabilities. Check it on my Wi-Fi page."
	if d := r.g.Digest(); len(d) != 1 || d[0] != want {
		t.Fatalf("digest %q\nwant %q", d, want)
	}
	// One finding per package and version, however many advisories.
	b.snap.Advisories = append(b.snap.Advisories, Advisory{ID: "ADV-9", Package: "openssl", Fixed: "3.1", Severity: "high"})
	if n := r.pass(t); n != 0 {
		t.Fatalf("second advisory made %d findings", n)
	}
	// Still uncomparable after 7 days: texted once, then not again.
	r.now = r.now.Add(8 * 24 * time.Hour)
	r.pass(t)
	r.now = r.now.Add(24 * time.Hour)
	r.pass(t)
	if len(r.texts) != 1 || !strings.Contains(r.texts[0], "Could not check openssl version build-42") || len(r.c.got) != 0 {
		t.Fatalf("texts %q", r.texts)
	}

	for _, c := range []struct {
		f    Finding
		want string
	}{
		{Finding{Check: CheckHash, Subject: "guest-image/openclaw", Detail: "differs from the signed release"}, "File guest-image/openclaw does not match the signed release."},
		{Finding{Check: CheckHash, Subject: "dep/libfoo", Detail: "could not be measured"}, "File dep/libfoo could not be checked."},
		{Finding{Check: CheckDrift, Subject: "config/quiet.json", Detail: "changed outside the change pipeline"}, "Setting file config/quiet.json changed outside my change process."},
		{Finding{Check: CheckExpiry, Subject: "cal-cert", Detail: "expires 2026-10-08"}, "Credential cal-cert expires 2026-10-08. Replace it on my Wi-Fi page."},
		{Finding{Check: CheckAdvisory, Subject: "openssl", Detail: "ADV-1", Fixed: "3.0.14"}, "Known vulnerability in openssl (ADV-1), fixed in 3.0.14. I take the fix when an update has it."},
	} {
		if got := findingText(c.f); got != c.want {
			t.Errorf("got  %q\nwant %q", got, c.want)
		}
	}
}

// K-S1: with fixtures not live, a finding records its fixture as deferred
// and the suite does not grow, so Loop 1 and updates keep adopting.
func TestFixturesDeferred(t *testing.T) {
	b := cleanBox()
	b.pkgs[0].Version = "3.0.13"
	r := newGuardRig(t, b)
	r.deferFixtures = true
	r.reopen(t)
	r.pass(t)
	ev := r.g.Evidence()
	if len(ev) != 1 || ev[0].Fixture != "deferred" || len(r.c.got) != 1 || len(r.texts) != 1 {
		t.Fatalf("deferred: %+v", ev)
	}
	rep, err := r.p.Propose(context.Background(), change.Candidate{Source: change.Local, Files: change.Tree{"config/facts.json": facts("3.0.1")}})
	if err != nil || strings.Contains(rep.Reason, "security suite") || rep.Security != 0 {
		t.Fatalf("suite grew while deferred: %+v %v", rep, err)
	}
}

// L3 round 2 on #54: the pause cap and the text go to tampering first, so
// Low findings from a noisy feed cannot use up the cap (F1, F3); a hash
// text is urgent (T1); version text keeps "~" and "+" (F2); an unreadable
// fixed version names the advisory (F4).
func TestSeverityOrder(t *testing.T) {
	b := cleanBox()
	b.pkgs, b.snap.Advisories = nil, nil
	for _, n := range []string{"a", "b", "c"} {
		b.pkgs = append(b.pkgs, Package{Name: n, Version: "1.0", Contain: &Target{Kind: "grant", Name: "g-" + n, Label: "pre-allowance " + n}})
		b.snap.Advisories = append(b.snap.Advisories, Advisory{ID: "ADV-" + n, Package: n, Fixed: "1.1", Severity: "low"})
	}
	b.measured["guest-image/openclaw"] = "tampered"
	r := newGuardRig(t, b)
	r.pass(t)
	if len(r.c.got) != 3 || r.c.got[0] != *b.Box().Artifacts[0].Contain {
		t.Fatalf("paused %+v: the tampered image must be paused first", r.c.got)
	}
	if len(r.texts) != 1 || !r.urgent[0] || !strings.HasPrefix(r.texts[0], "Security checks: File guest-image/openclaw does not match the signed release. Paused the agent machine.") {
		t.Fatalf("texts %q urgent %v", r.texts, r.urgent)
	}

	// A new tamper alert leads the text even when a cleared line is due.
	b2 := cleanBox()
	b2.pkgs[0].Version = "3.0.13"
	r2 := newGuardRig(t, b2)
	r2.pass(t)
	b2.pkgs[0].Version = "3.0.14"
	b2.measured["guest-image/openclaw"] = "tampered"
	r2.pass(t)
	if len(r2.texts) != 2 || !strings.HasPrefix(r2.texts[1], "Security checks: File guest-image/openclaw") || !strings.Contains(r2.texts[1], "Cleared: openssl.") {
		t.Fatalf("texts %q", r2.texts)
	}

	f := Finding{Check: CheckAdvisory, Subject: "openssl", Detail: "DSA-1", Fixed: "1:3.0.14-1~deb12u1+b1"}
	if got, want := findingText(f), "Known vulnerability in openssl (DSA-1), fixed in 1:3.0.14-1~deb12u1+b1. I take the fix when an update has it."; got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}

	b3 := cleanBox()
	b3.snap.Advisories[0].Fixed = "not-a-version!"
	r3 := newGuardRig(t, b3)
	r3.pass(t)
	want := "Security check: Could not read the fixed version in advisory ADV-1 for openssl. Check it on my Wi-Fi page."
	if d := r3.g.Digest(); len(d) != 1 || d[0] != want || len(r3.c.got) != 0 {
		t.Fatalf("digest %q\nwant %q", d, want)
	}
	// Like an uncomparable installed version, texted once after 7 days.
	r3.now = r3.now.Add(8 * 24 * time.Hour)
	r3.pass(t)
	r3.now = r3.now.Add(24 * time.Hour)
	r3.pass(t)
	if len(r3.texts) != 1 || !strings.Contains(r3.texts[0], "Could not read the fixed version in advisory ADV-1 for openssl.") {
		t.Fatalf("unreadable texts %q", r3.texts)
	}

	// A High advisory on a later package still gets a pause ahead of Low
	// ones on earlier packages, past the cap of 3.
	b4 := cleanBox()
	b4.pkgs, b4.snap.Advisories = nil, nil
	for _, n := range []string{"a", "b", "c", "z"} {
		sev := "low"
		if n == "z" {
			sev = "critical"
		}
		b4.pkgs = append(b4.pkgs, Package{Name: n, Version: "1.0", Contain: &Target{Kind: "grant", Name: "g-" + n}})
		b4.snap.Advisories = append(b4.snap.Advisories, Advisory{ID: "ADV-" + n, Package: n, Fixed: "1.1", Severity: sev})
	}
	r4 := newGuardRig(t, b4)
	r4.pass(t)
	if len(r4.c.got) != 3 || r4.c.got[0].Name != "g-z" {
		t.Fatalf("paused %+v: the High advisory must be paused first", r4.c.got)
	}
}

// LOOP-10: a fix that disables a check, widens authority, or fails a
// security fixture fails qualification, and Loop 2 only adds fixtures.
func TestFixesCannotWeaken(t *testing.T) {
	b := cleanBox()
	b.pkgs[0].Version = "3.0.13"
	for _, c := range []struct {
		name  string
		files change.Tree
		why   string
	}{
		{"disables a check", change.Tree{"checks/advisory.json": []byte(`{"off":true}`)}, "LOOP-10"},
		{"widens authority", change.Tree{"grants/mail.json": []byte(`{"send":"any"}`)}, "LOOP-10"},
		{"edits the suite", change.Tree{"security/loop2.json": []byte(`[]`)}, "CHG-2"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newGuardRig(t, b)
			r.fx = &fixer{cand: change.Candidate{Files: c.files}}
			r.reopen(t)
			r.pass(t)
			var adv Record
			for _, e := range r.g.Evidence() {
				if e.Finding.Check == CheckAdvisory {
					adv = e
				}
			}
			if adv.Fix != string(change.StateRejected) {
				t.Fatalf("fix state %q, want rejected", adv.Fix)
			}
			if !strings.Contains(adv.FixReason, c.why) {
				t.Fatalf("reason %q, want %q", adv.FixReason, c.why)
			}
		})
	}

	// While the finding is open, the fixture only must not regress (PS1):
	// the box already fails it, so a candidate that leaves it failing is
	// not failed by it. The fixture outlives the fix: once the fix is
	// adopted, a later candidate that brings the vulnerable version back
	// is rejected by the pipeline itself.
	r := newGuardRig(t, b)
	r.pass(t)
	rep, err := r.p.Propose(context.Background(), change.Candidate{Source: change.Local, Files: change.Tree{"config/facts.json": facts("3.0.12")}})
	if err != nil || rep.Reason == "fails the security suite" {
		t.Fatalf("a candidate leaving the open finding: %+v %v", rep, err)
	}
	if rep, err := r.p.Propose(context.Background(), change.Candidate{Source: change.Local, Files: change.Tree{"config/facts.json": facts("3.0.14")}}); err != nil || rep.State != change.StateAdopted {
		t.Fatalf("the fix: %+v %v", rep, err)
	}
	rep, err = r.p.Propose(context.Background(), change.Candidate{Source: change.Local, Files: change.Tree{"config/facts.json": facts("3.0.1")}})
	if err != nil || rep.State != change.StateRejected || rep.Reason != "fails the security suite" {
		t.Fatalf("regressing candidate: %+v %v", rep, err)
	}
	// A duplicate fixture (the same finding after restart with a lost
	// state) is not an error: the suite already has it.
	r.store = &change.MemStore{}
	r.reopen(t)
	if n := r.pass(t); n != 1 {
		t.Fatalf("n=%d", n)
	}
}

// LOOP-3 with Loop 2: the scheduler runs the passive pass as spare work,
// measures its value as new findings, and Loop 2 sleeps until due.
func TestGuardInScheduler(t *testing.T) {
	b := cleanBox()
	b.pkgs[0].Version = "3.0.13"
	gr := newGuardRig(t, b)
	r := newRig(t, gr.g)
	gr.now = r.clk.now()
	if job, ok := gr.g.Next(context.Background(), false); !ok || job.UsesModel {
		t.Fatalf("first pass not offered without model budget: %v %+v", ok, job)
	}
	if ran, _ := r.s.Tick(context.Background()); !ran {
		t.Fatal("pass did not run")
	}
	if len(gr.g.Evidence()) != 1 {
		t.Fatalf("evidence %+v", gr.g.Evidence())
	}
	if _, ok := gr.g.Next(context.Background(), true); ok {
		t.Fatal("offered again before due")
	}
	gr.g.Trigger()
	if _, ok := gr.g.Next(context.Background(), true); !ok {
		t.Fatal("Trigger did not make a pass due")
	}
	if sh := r.s.Share()[Secure]; sh != 1 {
		t.Fatalf("share %v", sh)
	}
}

// W5a, potency follow-up on #54 (S3): the passive pass makes no model
// calls, so three clean passes do not hold it past its 6 h cadence: while
// a pass is due the guard is Urgent, and the scheduler offers it even
// though L5 parked Loop 2.
func TestThePassiveCadenceOutlivesParking(t *testing.T) {
	r := newRig(t)
	g, err := NewGuard(GuardConfig{Box: cleanBox().Box(), Pipeline: newPipe(t), Store: &change.MemStore{}, Now: r.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	r.restart(g)
	for i := 0; i < 3; i++ {
		if !g.Urgent() {
			t.Fatalf("pass %d not due", i)
		}
		if ran, _ := r.s.Tick(context.Background()); !ran {
			t.Fatalf("pass %d did not run", i)
		}
		if g.Urgent() {
			t.Fatal("still urgent right after a pass")
		}
		r.clk.add(6 * time.Hour)
	}
	if ran, _ := r.s.Tick(context.Background()); !ran {
		t.Fatal("the passive pass waited out the park")
	}
}
