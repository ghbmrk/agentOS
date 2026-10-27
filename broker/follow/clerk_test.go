package follow_test

// REQ: UPD-2, UPD-8, CH-10, KRN-4, KRN-8

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"go/parser"
	"go/token"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clock"
	"github.com/ghbmrk/agentos/broker/follow"
	"github.com/ghbmrk/agentos/broker/follow/followclerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/maintain"
	"github.com/ghbmrk/agentos/broker/update"
)

func seedKey(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	p := ed25519.NewKeyFromSeed(s)
	return p.Public().(ed25519.PublicKey), p
}

// Synthetic keys only: every update key is generated per test.
func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// rootOf is a fresh 2-of-2 repository's first root.
func rootOf(t *testing.T) []byte {
	t.Helper()
	r1, r2 := newKey(t), newKey(t)
	pub := func(ks ...ed25519.PrivateKey) []ed25519.PublicKey {
		var out []ed25519.PublicKey
		for _, k := range ks {
			out = append(out, k.Public().(ed25519.PublicKey))
		}
		return out
	}
	dir := filepath.Join(t.TempDir(), "repo")
	repo, err := update.Init(dir, update.RootConfig{Root: pub(r1, r2), Targets: pub(r1, r2),
		Snapshot: pub(newKey(t)), Timestamp: pub(newKey(t)), RootThreshold: 2, TargetsThreshold: 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []ed25519.PrivateKey{r1, r2} {
		if err := repo.Sign("root", k); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "staged", "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type guardClock struct {
	at    time.Time
	calls int
}

func (c *guardClock) Latest(context.Context) (time.Time, clock.Status) {
	c.calls++
	return c.at, clock.Status{State: clock.Agreed}
}

// countStore counts the switches that reach the update store.
type countStore struct {
	*update.Store
	switches int
}

func (s *countStore) FollowFork(root []byte, links [][]byte, shipped []byte, approved, name string, o update.Options) error {
	s.switches++
	return s.Store.FollowFork(root, links, shipped, approved, name, o)
}

func (s *countStore) FollowProject(root []byte, links [][]byte, shipped []byte, approved string, o update.Options) error {
	s.switches++
	return s.Store.FollowProject(root, links, shipped, approved, o)
}

// clerkRig is a follow clerk over a fresh update store under a kernel whose
// log holds the owner's root for change-account on the follow clerk,
// granted a hold before the test, and the owner's enrolled phone passkey,
// which taps approvals. The kernel's times are the guard clock's, so the
// clerk's own clock (Latest) agrees with the step it was handed.
type clerkRig struct {
	t       *testing.T
	shipped []byte
	fork    []byte
	store   *update.Store
	st      *countStore
	clk     *guardClock
	alerts  []string
	pending string
	recs    string
	x       *follow.Executor
	c       *followclerk.Clerk
	k       *kernel.Kernel
	mem     *kernel.MemStore
	anc     *kernel.MemAnchor
	anchors []key.PublicKey
	root    key.Key
	phone   ed25519.PrivateKey
}

func newClerkRig(t *testing.T) *clerkRig {
	t.Helper()
	r := &clerkRig{t: t, clk: &guardClock{at: time.Now().Add(time.Hour)}, mem: &kernel.MemStore{}, anc: &kernel.MemAnchor{}}
	r.shipped, r.fork = rootOf(t), rootOf(t)
	st, err := update.InitStore(filepath.Join(t.TempDir(), "box"), r.shipped, 0)
	if err != nil {
		t.Fatal(err)
	}
	r.store, r.st = st, &countStore{Store: st}
	r.pending = filepath.Join(st.Dir, "follow-alert")
	r.recs = t.TempDir()
	if err := os.Chmod(r.recs, 0o700); err != nil {
		t.Fatal(err)
	}
	opub, opriv := seedKey(1)
	bpub, bpriv := seedKey(12)
	r.anchors = []key.PublicKey{key.Ed25519(opub), key.Ed25519(bpub)}
	r.x, r.c = r.restart()
	r.boot(r.c)
	at := r.now() - kernel.GrantHold
	r.root = key.Issue(key.Ed25519Signer(opriv), key.Root{Clerk: followclerk.Name, Verbs: []key.Verb{key.ChangeAccount}, Serial: "r1"})
	batch := []key.Key{r.root}
	if err := r.k.Issue(at, []key.Cosign{key.Approve(key.Ed25519Signer(opriv), kernel.BatchHash(batch...)), key.Approve(key.Ed25519Signer(bpriv), kernel.BatchHash(batch...))}, batch...); err != nil {
		t.Fatal(err)
	}
	phonePub, phone := seedKey(8)
	if err := r.k.Enroll(at, key.Enroll(key.Ed25519Signer(opriv), key.Ed25519(phonePub))); err != nil {
		t.Fatal(err)
	}
	r.phone = phone
	return r
}

// restart is the clerk as a process restarted over the same store would
// have it: holding nothing the page described before.
func (r *clerkRig) restart() (*follow.Executor, *followclerk.Clerk) {
	r.t.Helper()
	x, err := follow.New(follow.Config{Store: r.st, Shipped: r.shipped, Clock: r.clk, Pending: r.pending,
		Alert: func(_ context.Context, text string) error { r.alerts = append(r.alerts, text); return nil }})
	if err != nil {
		r.t.Fatal(err)
	}
	c, err := followclerk.New(x, r.anchors, r.recs)
	if err != nil {
		r.t.Fatal(err)
	}
	return x, c
}

func (r *clerkRig) now() int64 { return r.clk.at.UnixMilli() }

// boot (re)starts the kernel over the rig's log with c as its follow clerk.
func (r *clerkRig) boot(c kernel.Clerk) {
	r.t.Helper()
	kpub, kpriv := seedKey(3)
	l, err := kernel.Open(kernel.Config{Store: r.mem, Anchor: r.anc, Pub: kpub, Sign: kpriv, Rand: mrand.NewChaCha8([32]byte{1})})
	if err != nil {
		r.t.Fatal(err)
	}
	if r.k, err = kernel.Boot(l, r.anchors, map[string]kernel.Clerk{followclerk.Name: c}, r.now()); err != nil {
		r.t.Fatal(err)
	}
}

// describe is the page showing root to the owner.
func (r *clerkRig) describe(root []byte) string {
	r.t.Helper()
	sum, err := r.x.Describe(context.Background(), root)
	if err != nil {
		r.t.Fatal(err)
	}
	return sum.Digest
}

// approved is the owner's tap on the page: the phone passkey signs the plan
// of this one switch under the bare root (CH-10 tier 4).
func (r *clerkRig) approved(id, digest, name string) kernel.Plan {
	return kernel.SignPlan(kernel.Plan{ID: id, Key: r.root, Steps: []kernel.PlanStep{followclerk.Step(digest, name)}}, r.phone)
}

func (r *clerkRig) submit(p kernel.Plan) {
	r.t.Helper()
	if err := r.k.Submit(r.now(), p); err != nil {
		r.t.Fatal(err)
	}
}

func (r *clerkRig) run(p kernel.Plan) kernel.StepState {
	r.t.Helper()
	r.submit(p)
	if err := r.k.Tick(r.now()); err != nil {
		r.t.Fatal(err)
	}
	return r.k.State().Plans[p.ID].Steps[0]
}

func (r *clerkRig) trusts(root []byte) bool {
	r.t.Helper()
	b, err := r.store.TrustedRoot()
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b) == string(root)
}

func (r *clerkRig) unchanged() {
	r.t.Helper()
	if !r.trusts(r.shipped) || len(r.alerts) != 0 || r.st.switches != 0 {
		r.t.Fatalf("switched or alerted: alerts %q", r.alerts)
	}
	if src, _ := r.store.Following(); src != (update.Followed{}) {
		r.t.Fatalf("source %+v", src)
	}
}

// UPD-2, CH-10: the clerk follows exactly the bytes the page showed under
// the approved digest. Bytes changed after the owner saw them, in the
// caller's buffer or as another root, never reach the store.
func TestFollowsOnlyTheShownDigest(t *testing.T) {
	r := newClerkRig(t)
	shown := append([]byte(nil), r.fork...)
	d := r.describe(shown)
	// The page's buffer is overwritten with another root after the owner
	// saw it: the clerk holds its own copy.
	other := rootOf(t)
	copy(shown, other)
	// A root the page never showed, named by its own digest, is refused.
	od, err := update.RootDigest(other)
	if err != nil {
		t.Fatal(err)
	}
	if st := r.run(r.approved("p0", od, "Other")); st.Phase != kernel.PFailed || !strings.Contains(st.Detail, "no longer holds") {
		t.Fatalf("unshown root: %+v", st)
	}
	r.unchanged()
	st := r.run(r.approved("p1", d, "Acme Fork"))
	if st.Phase != kernel.PDone || !r.trusts(r.fork) || r.st.switches != 1 {
		t.Fatalf("%+v switches %d", st, r.st.switches)
	}
	if src, err := r.store.Following(); err != nil || src.Name != "Acme Fork" {
		t.Fatalf("following %+v %v", src, err)
	}
	if len(r.alerts) != 1 || r.alerts[0] != maintain.FollowAlert("Acme Fork", r.clk.at) {
		t.Fatalf("alerts %q", r.alerts)
	}
}

// #957, CH-10: a name that folds to the project's own name (case, accents,
// confusables, ignorables, digits for letters) is refused, so a named
// follow never reads as switching back; plain names pass. The clerk
// refuses the step itself, not only the page.
func TestLookAlikeProjectNameRefused(t *testing.T) {
	for _, n := range []string{
		follow.ProjectName, "THE AGENTOS PROJECT", "agentOS Project", "agentos project fork",
		"the AgentÖS project", "the аgentOS project", // Cyrillic а
		"the agentOS\u200bproject", "AgentOSProject", "agentOS-Project", "agentOS_Project", "agentOS.Project", "Agent OS Project", "agent-os project", "the Agent0S project", "the ΑgentOS Ρroject", // Greek Α, Ρ
		"", " Acme", "Acme ", "Acme 123456", "Acme\nFork", "Acme‮Fork", strings.Repeat("a", follow.MaxName+1),
	} {
		if follow.NameOK(n) {
			t.Errorf("%q admitted", n)
		}
	}
	for _, n := range []string{"Acme Fork", "agentOS Community", "My builds 2026", "Projet Agé", strings.Repeat("a", follow.MaxName)} {
		if !follow.NameOK(n) {
			t.Errorf("%q refused", n)
		}
	}
	r := newClerkRig(t)
	if st := r.run(r.approved("p1", r.describe(r.fork), "The agentOS Project")); st.Phase != kernel.PFailed || st.Detail != followclerk.RMalformed {
		t.Fatalf("%+v", st)
	}
	r.unchanged()
}

// WF2, UPD-8: expiry is judged by the clock guard's Latest, never the wall
// clock: a root valid by the wall clock but expired by Latest is not
// followed, even with the owner's approval.
func TestExpiredRootRefusedByGuardClock(t *testing.T) {
	r := newClerkRig(t)
	d := r.describe(r.fork)
	r.clk.at = time.Now().Add(update.RootExpiry + 24*time.Hour)
	calls := r.clk.calls
	st := r.run(r.approved("p1", d, "Acme"))
	if st.Phase != kernel.PFailed || !strings.Contains(st.Detail, "expired") || r.clk.calls == calls {
		t.Fatalf("followed a root expired by Latest: %+v", st)
	}
	// The store judged it at Latest and refused it.
	r.st.switches = 0
	r.unchanged()
}

// KRN-8: the switch lands but the answer is lost when the kernel goes down.
// After the restart the kernel probes; the clerk reads the box's own root,
// answers done and re-sends the alert, and the switch is never made twice,
// by the clerk that survived or by one restarted with nothing held.
func TestFollowOnceAcrossCrash(t *testing.T) {
	r := newClerkRig(t)
	p := r.approved("p1", r.describe(r.fork), "Acme Fork")
	r.submit(p)
	cs, err := r.k.Calls(r.now())
	if err != nil || len(cs) != 1 || cs[0].Kind != kernel.ActDispatch {
		t.Fatalf("calls %+v %v", cs, err)
	}
	if res := r.c.Do(cs[0].Req, r.k.State()); res.Outcome != "ok" || r.st.switches != 1 {
		t.Fatalf("%+v", res)
	}
	// Asked again while the step is still in flight, the clerk finds the
	// switch made and does not make it again.
	if res := r.c.Do(cs[0].Req, r.k.State()); res.Outcome != "ok" || r.st.switches != 1 {
		t.Fatalf("second ask %+v switches %d", res, r.st.switches)
	}
	// The kernel restarts before it logs the answer.
	r.boot(r.c)
	r.alerts = nil
	// The probe is due a while after the restart.
	r.clk.at = r.clk.at.Add(time.Duration(r.k.State().Plans[p.ID].Steps[0].NextProbe-r.now()) * time.Millisecond)
	if err := r.k.Tick(r.now()); err != nil {
		t.Fatal(err)
	}
	if s := r.k.State().Plans[p.ID].Steps[0]; s.Phase != kernel.PDone || r.st.switches != 1 {
		t.Fatalf("after restart %+v switches %d", s, r.st.switches)
	}
	if len(r.alerts) != 1 || r.alerts[0] != maintain.FollowAlert("Acme Fork", r.clk.at) {
		t.Fatalf("alert not re-sent once: %q", r.alerts)
	}
	// A request replayed to the clerk changes nothing more.
	if res := r.c.Do(cs[0].Req, r.k.State()); res.Outcome != "failed" || r.st.switches != 1 {
		t.Fatalf("replay %+v switches %d", res, r.st.switches)
	}
	// A clerk restarted with nothing held reads the same from the store.
	_, fresh := r.restart()
	if res := fresh.Probe(cs[0].Req, r.k.State()); res.Outcome != "done" || r.st.switches != 1 {
		t.Fatalf("fresh probe %+v", res)
	}
}

// KRN-8: the probe answers from the box and the clerk's record, not the
// process. A step the clerk has no record of beginning is unknown, never
// notdone, and so is a root under a name the box does not hold it under.
func TestProbeReadsTheBoxNotTheProcess(t *testing.T) {
	r := newClerkRig(t)
	d := r.describe(r.fork)
	req := kernel.Request{Plan: r.approved("p1", d, "Acme Fork")}
	if res := r.c.Probe(req, nil); res.Outcome != "unknown" || len(r.alerts) != 0 {
		t.Fatalf("%+v", res)
	}
	if st := r.run(r.approved("p2", d, "Acme Fork")); st.Phase != kernel.PDone {
		t.Fatalf("%+v", st)
	}
	if res := r.c.Probe(kernel.Request{Plan: r.approved("p3", d, "Other")}, nil); res.Outcome != "unknown" {
		t.Fatalf("other name %+v", res)
	}
	sd, _ := update.RootDigest(r.shipped)
	if res := r.c.Probe(kernel.Request{Plan: r.approved("p4", sd, "Acme Fork")}, nil); res.Outcome != "unknown" {
		t.Fatalf("other root %+v", res)
	}
}

// KRN-4, CH-10: only the owner's own approval of this exact switch runs it.
// A plan under a key derived from the root (a standing or clerk key) is
// refused, and so is a step that is not change-account on this clerk.
func TestStepWithoutOwnerApprovalRefused(t *testing.T) {
	r := newClerkRig(t)
	d := r.describe(r.fork)
	hpub, hpriv := seedKey(2)
	_, opriv := seedKey(1)
	ck, err := key.ClerkKey(r.root, key.Ed25519Signer(opriv), hpub, r.now()-kernel.GrantHold, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	_, bpriv := seedKey(12)
	batch := []key.Key{ck}
	if err := r.k.Issue(r.now()-kernel.GrantHold, []key.Cosign{key.Approve(key.Ed25519Signer(opriv), kernel.BatchHash(batch...)), key.Approve(key.Ed25519Signer(bpriv), kernel.BatchHash(batch...))}, batch...); err != nil {
		t.Fatal(err)
	}
	p := kernel.SignPlan(kernel.Plan{ID: "standing", Key: ck, Steps: []kernel.PlanStep{followclerk.Step(d, "Acme")}}, hpriv)
	if st := r.run(p); st.Phase != kernel.PFailed || st.Detail != followclerk.ROwner {
		t.Fatalf("standing key: %+v", st)
	}
	// A plan the owner did not sign never reaches the clerk's switch.
	forged := r.approved("forged", d, "Acme")
	forged.Steps[0].Args[followclerk.ArgName] = "Other"
	if err := r.k.Submit(r.now(), forged); err == nil {
		if err := r.k.Tick(r.now()); err != nil {
			t.Fatal(err)
		}
	}
	if res := r.c.Do(kernel.Request{Plan: forged}, r.k.State()); res.Outcome != "failed" {
		t.Fatalf("forged %+v", res)
	}
	r.unchanged()
}

// The journal executor is the only old-core user left in the package, until
// f2 (#3430) deletes it with the agentosd wiring; the clerk's checks live in
// followclerk.
func TestOnlyTheExecutorImportsTheOldCore(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "executor.go" {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			// broker/clerk links the network exit, which agentosd, serving
			// Describe, must not (followclerk holds it).
			for _, old := range []string{"/broker/journal", "/broker/grants", "/broker/clerk"} {
				if strings.HasSuffix(p, old) {
					t.Errorf("%s imports %s", f, p)
				}
			}
		}
	}
}

// lostAck runs the clerk but loses the answers to the plans named, as a
// transport timeout would.
type lostAck struct {
	c    *followclerk.Clerk
	lose map[string]bool
}

func (l *lostAck) Do(r kernel.Request, v kernel.View) kernel.Result {
	res := l.c.Do(r, v)
	if l.lose[r.Plan.ID] {
		delete(l.lose, r.Plan.ID)
		return kernel.Result{Outcome: "unknown", Detail: "lost"}
	}
	return res
}

func (l *lostAck) Probe(r kernel.Request, v kernel.View) kernel.Result { return l.c.Probe(r, v) }

// probeAll advances the guard clock to each due probe of plan id and ticks.
func (r *clerkRig) probeAll(id string) kernel.StepState {
	r.t.Helper()
	for i := 0; i < 2*kernel.MaxChecks; i++ {
		s := r.k.State().Plans[id].Steps[0]
		if s.NextProbe > r.now() {
			r.clk.at = r.clk.at.Add(time.Duration(s.NextProbe-r.now()) * time.Millisecond)
		}
		if err := r.k.Tick(r.now()); err != nil {
			r.t.Fatal(err)
		}
	}
	return r.k.State().Plans[id].Steps[0]
}

// KRN-8, security 1 on #3444: a switch whose answer was lost is never run
// again over a later switch the owner approved. The kernel fences only an
// identical step, so the probe must not read "the box follows neither this
// root nor this name" as "it never happened".
func TestStaleSwitchNeverReplaysOverALaterOne(t *testing.T) {
	r := newClerkRig(t)
	r.boot(&lostAck{c: r.c, lose: map[string]bool{"p1": true}})
	dA := r.describe(r.fork)
	forkB := rootOf(t)
	dB := r.describe(forkB)
	if st := r.run(r.approved("p1", dA, "Acme Fork")); st.Phase == kernel.PDone {
		t.Fatalf("answer not lost: %+v", st)
	}
	if st := r.run(r.approved("p3", dB, "Beta")); st.Phase != kernel.PDone || !r.trusts(forkB) {
		t.Fatalf("p3 %+v", st)
	}
	if s := r.probeAll("p1"); s.Phase == kernel.PDone || s.Phase == kernel.PInflight {
		t.Fatalf("p1 settled as %+v", s)
	}
	if !r.trusts(forkB) || r.st.switches != 2 {
		t.Fatalf("the stale switch ran again: switches %d, trusts B %v", r.st.switches, r.trusts(forkB))
	}
	if src, _ := r.store.Following(); src.Name != "Beta" {
		t.Fatalf("source %+v", src)
	}
}

// flakyStore fails its first switch before writing anything, and cannot
// read the trusted root once after, so the clerk cannot tell and answers
// unknown.
type flakyStore struct {
	*countStore
	fail, blind int
}

func (s *flakyStore) FollowFork(root []byte, links [][]byte, shipped []byte, approved, name string, o update.Options) error {
	if s.fail > 0 {
		s.fail--
		s.switches++
		return errors.New("power cut")
	}
	return s.countStore.FollowFork(root, links, shipped, approved, name, o)
}

func (s *flakyStore) TrustedRoot() ([]byte, error) {
	if s.fail == 0 && s.blind > 0 {
		s.blind--
		return nil, errors.New("disk busy")
	}
	return s.countStore.TrustedRoot()
}

// KRN-8: the same when the clerk itself could not tell whether the first
// switch landed: its record says what the box followed before, and a box
// that has moved on since is unknown, never a reason to switch again.
func TestUnknownSwitchNeverReplaysOverALaterOne(t *testing.T) {
	r := newClerkRig(t)
	r.flaky(&flakyStore{countStore: r.st, fail: 1, blind: 1})
	if st := r.run(r.approved("p1", r.describe(r.fork), "Acme Fork")); st.Phase != kernel.PUnknown {
		t.Fatalf("p1 %+v", st)
	}
	forkB := rootOf(t)
	r.clk.at = r.clk.at.Add(time.Millisecond)
	if st := r.run(r.approved("p3", r.describe(forkB), "Beta")); st.Phase != kernel.PDone || !r.trusts(forkB) {
		t.Fatalf("p3 %+v", st)
	}
	if s := r.probeAll("p1"); s.Phase == kernel.PDone || s.Phase == kernel.PInflight {
		t.Fatalf("p1 settled as %+v", s)
	}
	if !r.trusts(forkB) || r.st.switches != 2 {
		t.Fatalf("the earlier switch ran again: switches %d", r.st.switches)
	}
}

// flaky puts the clerk over st, restarted.
func (r *clerkRig) flaky(st follow.Store) {
	r.t.Helper()
	var err error
	r.x, err = follow.New(follow.Config{Store: st, Shipped: r.shipped, Clock: r.clk, Pending: r.pending,
		Alert: func(_ context.Context, text string) error { r.alerts = append(r.alerts, text); return nil }})
	if err != nil {
		r.t.Fatal(err)
	}
	if r.c, err = followclerk.New(r.x, r.anchors, r.recs); err != nil {
		r.t.Fatal(err)
	}
	r.boot(r.c)
}

// KRN-8: a switch the clerk began but that never landed (the box still
// follows what it did just before) is notdone, so the kernel sends it again
// and it lands once.
func TestSwitchThatNeverLandedIsSentAgain(t *testing.T) {
	r := newClerkRig(t)
	r.flaky(&flakyStore{countStore: r.st, fail: 1, blind: 1})
	d := r.describe(r.fork)
	if st := r.run(r.approved("p1", d, "Acme Fork")); st.Phase != kernel.PUnknown {
		t.Fatalf("first try %+v", st)
	}
	if s := r.probeAll("p1"); s.Phase != kernel.PDone || !r.trusts(r.fork) || r.st.switches != 2 {
		t.Fatalf("%+v switches %d", s, r.st.switches)
	}
}

// UPD-2, WF1', security 2 on #3444: the switch back to the project's own
// root runs through the kernel. Its value is ArgProject, which no named
// follow can carry, and a root that is not the project's is refused.
func TestSwitchBackThroughTheKernel(t *testing.T) {
	if follow.NameOK(followclerk.ArgProject) {
		t.Fatal("a named follow could carry the switch back's value")
	}
	r := newClerkRig(t)
	if st := r.run(r.approved("p1", r.describe(r.fork), "Acme Fork")); st.Phase != kernel.PDone {
		t.Fatalf("%+v", st)
	}
	// The fork is not the project's root, so it is no switch back.
	if st := r.run(r.approved("p2", r.describe(r.fork), "")); st.Phase != kernel.PFailed || !strings.Contains(st.Detail, "switching back needs the project's own root") {
		t.Fatalf("fork as the project: %+v", st)
	}
	st := r.run(r.approved("p3", r.describe(r.shipped), ""))
	if st.Phase != kernel.PDone || !r.trusts(r.shipped) {
		t.Fatalf("switch back %+v", st)
	}
	if src, err := r.store.Following(); err != nil || src.Name != "" {
		t.Fatalf("source %+v %v", src, err)
	}
	if last := r.alerts[len(r.alerts)-1]; last != maintain.FollowAlert(follow.ProjectName, r.clk.at) {
		t.Fatalf("alert %q", last)
	}
}

// KRN-4: a root that also grants another verb on the follow clerk still
// runs nothing but change-account.
func TestOnlyChangeAccountRuns(t *testing.T) {
	r := newClerkRig(t)
	d := r.describe(r.fork)
	_, opriv := seedKey(1)
	_, bpriv := seedKey(12)
	root := key.Issue(key.Ed25519Signer(opriv), key.Root{Clerk: followclerk.Name, Verbs: []key.Verb{key.ChangeAccount, key.Send}, Serial: "r2"})
	batch := []key.Key{root}
	if err := r.k.Issue(r.now()-kernel.GrantHold, []key.Cosign{key.Approve(key.Ed25519Signer(opriv), kernel.BatchHash(batch...)), key.Approve(key.Ed25519Signer(bpriv), kernel.BatchHash(batch...))}, batch...); err != nil {
		t.Fatal(err)
	}
	r.clk.at = r.clk.at.Add(time.Millisecond)
	p := kernel.SignPlan(kernel.Plan{ID: "send", Key: root, Steps: []kernel.PlanStep{{Verb: key.Send, Clerk: followclerk.Name, Args: map[string]string{"to": d, "msg": "Acme"}}}}, r.phone)
	if st := r.run(p); st.Phase != kernel.PFailed || st.Detail != followclerk.RVerb {
		t.Fatalf("%+v", st)
	}
	r.unchanged()
}
