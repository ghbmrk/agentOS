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
}

func (b *box) Box() Box {
	return Box{
		Signed: func() (map[string]string, error) { return b.signed, nil },
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
		Live:       func() (map[string]string, error) { return b.live, nil },
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
	if d := strings.Join(g.Digest(), " "); !strings.Contains(d, "not run: file hashes, known vulnerabilities, settings, credential expiry") {
		t.Errorf("unwired checks: %s", d)
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
		!strings.Contains(r.texts[0], "Paused the network gateway. It stays paused until you turn it back on.") ||
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
	if len(r.texts) != 2 || !strings.Contains(r.texts[1], "Cleared: openssl. The network gateway is still paused; ask your agent to turn it back on.") {
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
	capped := strings.Count(strings.Join(r.texts, " "), "Not paused (too many findings at once)")
	if capped != 2 || len(r.texts) != 1 { // one text for the pass
		t.Fatalf("texts %q", r.texts)
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
	if !strings.Contains(d, "Cleared: openssl. The network gateway is still paused; ask your agent to turn it back on.") {
		t.Fatalf("digest: %s", d)
	}
	must(t, r.g.Resumed(Target{Kind: "executor", Name: "egress", Label: "the network gateway"}))
	if d := strings.Join(r.g.Digest(), "\n"); strings.Contains(d, "still paused") {
		t.Fatalf("after resume: %s", d)
	}

	// A High finding with nothing to pause flaps: texted once a day.
	b2 := cleanBox()
	b2.live["config/quiet.json"] = "edited"
	r2 := newGuardRig(t, b2)
	r2.pass(t)
	for i := 0; i < 3; i++ {
		b2.live["config/quiet.json"] = "c1"
		r2.pass(t)
		b2.live["config/quiet.json"] = "edited"
		r2.pass(t)
	}
	if len(r2.texts) != 1 {
		t.Fatalf("flapping texts %d, want 1", len(r2.texts))
	}
	b2.live["config/quiet.json"] = "c1"
	r2.pass(t)
	r2.now = r2.now.Add(25 * time.Hour)
	b2.live["config/quiet.json"] = "edited"
	r2.pass(t)
	if len(r2.texts) != 2 {
		t.Fatalf("texts after a day %d, want 2", len(r2.texts))
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
	if len(r2.texts) != 1 || r2.urgent[0] || !strings.Contains(r2.texts[0], "Credential old-token has expired. Replace it on the box page.") {
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
	want := "Security check: Could not check openssl version build-42 against known vulnerabilities. Check it on the box page."
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
		{Finding{Check: CheckDrift, Subject: "config/quiet.json", Detail: "changed outside the change pipeline"}, "Setting file config/quiet.json changed outside the box's change process."},
		{Finding{Check: CheckExpiry, Subject: "cal-cert", Detail: "expires 2026-10-08"}, "Credential cal-cert expires 2026-10-08. Replace it on the box page."},
		{Finding{Check: CheckAdvisory, Subject: "openssl", Detail: "ADV-1", Fixed: "3.0.14"}, "Known vulnerability in openssl (ADV-1), fixed in 3.0.14. The box takes the fix when an update has it."},
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
		{"fails the new fixture", change.Tree{"config/facts.json": facts("3.0.12")}, "security suite"},
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

	// The fixture outlives the fix: a later candidate that brings the
	// vulnerable version back is rejected by the pipeline itself.
	r := newGuardRig(t, b)
	r.pass(t)
	rep, err := r.p.Propose(context.Background(), change.Candidate{Source: change.Local, Files: change.Tree{"config/facts.json": facts("3.0.1")}})
	if err != nil || rep.State != change.StateRejected || rep.SecurityPassed == rep.Security {
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
