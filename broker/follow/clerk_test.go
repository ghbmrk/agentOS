package follow

// REQ: UPD-2, UPD-8, CH-10, KRN-4, KRN-8

import (
	"crypto/ed25519"
	"go/parser"
	"go/token"
	"math/rand/v2"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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

// clerkRig is the follow rig's clerk under a kernel whose log holds the
// owner's root for change-account on the follow clerk, granted a hold
// before the test, and the owner's enrolled phone passkey, which taps
// approvals. The kernel's times are the rig's guard clock, so the clerk's
// own clock (Latest) agrees with the step it was handed.
type clerkRig struct {
	*rig
	st      *countStore
	k       *kernel.Kernel
	mem     *kernel.MemStore
	anc     *kernel.MemAnchor
	anchors []key.PublicKey
	root    key.Key
	phone   ed25519.PrivateKey
}

func newClerkRig(t *testing.T) *clerkRig {
	t.Helper()
	r := &clerkRig{rig: newRig(t), mem: &kernel.MemStore{}, anc: &kernel.MemAnchor{}}
	r.st = &countStore{Store: r.store}
	r.x = r.with(r.st)
	opub, opriv := seedKey(1)
	bpub, bpriv := seedKey(12)
	r.anchors = []key.PublicKey{key.Ed25519(opub), key.Ed25519(bpub)}
	r.x.cfg.Anchors = r.anchors
	r.boot(r.x)
	at := r.now() - kernel.GrantHold
	r.root = key.Issue(key.Ed25519Signer(opriv), key.Root{Clerk: ClerkName, Verbs: []key.Verb{key.ChangeAccount}, Serial: "r1"})
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

func (r *clerkRig) now() int64 { return r.clk.at.UnixMilli() }

// boot (re)starts the kernel over the rig's log with c as its follow clerk.
func (r *clerkRig) boot(c kernel.Clerk) {
	r.t.Helper()
	kpub, kpriv := seedKey(3)
	l, err := kernel.Open(kernel.Config{Store: r.mem, Anchor: r.anc, Pub: kpub, Sign: kpriv, Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		r.t.Fatal(err)
	}
	if r.k, err = kernel.Boot(l, r.anchors, map[string]kernel.Clerk{ClerkName: c}, r.now()); err != nil {
		r.t.Fatal(err)
	}
}

// approved is the owner's tap on the page: the phone passkey signs the plan
// of this one switch under the bare root (CH-10 tier 4).
func (r *clerkRig) approved(id, digest, name string) kernel.Plan {
	return kernel.SignPlan(kernel.Plan{ID: id, Key: r.root, Steps: []kernel.PlanStep{PlanStep(digest, name)}}, r.phone)
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

func (r *clerkRig) unchanged() {
	r.t.Helper()
	if !r.trusts(r.shipped) || len(r.alerts) != 0 {
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
	other := rootOf(t, newKey(t), newKey(t))
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
		"the AgentOS project", "THE AGENTOS PROJECT", "AgentOS Project", "agentos project fork",
		"the AgentÖS project", "the аgentOS project", // Cyrillic а
		"the AgentOS​project", "AgentOSProject", "the Agent0S project", "the ΑgentOS Ρroject", // Greek Α, Ρ
		"", " Acme", "Acme ", "Acme 123456", "Acme\nFork", "Acme‮Fork", strings.Repeat("a", MaxName+1),
	} {
		if NameOK(n) {
			t.Errorf("%q admitted", n)
		}
	}
	for _, n := range []string{"Acme Fork", "AgentOS Community", "My builds 2026", "Projet Agé", strings.Repeat("a", MaxName)} {
		if !NameOK(n) {
			t.Errorf("%q refused", n)
		}
	}
	r := newClerkRig(t)
	if st := r.run(r.approved("p1", r.describe(r.fork), "The AgentOS Project")); st.Phase != kernel.PFailed || st.Detail != RMalformed {
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
	if res := r.x.Do(cs[0].Req, r.k.State()); res.Outcome != "ok" || r.st.switches != 1 {
		t.Fatalf("%+v", res)
	}
	// Asked again while the step is still in flight, the clerk finds the
	// switch made and does not make it again.
	if res := r.x.Do(cs[0].Req, r.k.State()); res.Outcome != "ok" || r.st.switches != 1 {
		t.Fatalf("second ask %+v switches %d", res, r.st.switches)
	}
	// The kernel restarts before it logs the answer.
	r.boot(r.x)
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
	if res := r.x.Do(cs[0].Req, r.k.State()); res.Outcome != "failed" || r.st.switches != 1 {
		t.Fatalf("replay %+v switches %d", res, r.st.switches)
	}
	// A clerk restarted with nothing held reads the same from the store.
	fresh := r.with(r.st)
	if res := fresh.Probe(cs[0].Req, r.k.State()); res.Outcome != "done" || r.st.switches != 1 {
		t.Fatalf("fresh probe %+v", res)
	}
}

// KRN-8: power pulled before the switch was written leaves the old root and
// source: the probe answers notdone, so the kernel may send it again, and
// a root under a name the box does not hold it under is unknown.
func TestProbeReadsTheBoxNotTheProcess(t *testing.T) {
	r := newClerkRig(t)
	d := r.describe(r.fork)
	req := kernel.Request{Plan: r.approved("p1", d, "Acme Fork")}
	if res := r.x.Probe(req, nil); res.Outcome != "notdone" || len(r.alerts) != 0 {
		t.Fatalf("%+v", res)
	}
	if st := r.run(r.approved("p2", d, "Acme Fork")); st.Phase != kernel.PDone {
		t.Fatalf("%+v", st)
	}
	if res := r.x.Probe(kernel.Request{Plan: r.approved("p3", d, "Other")}, nil); res.Outcome != "unknown" {
		t.Fatalf("other name %+v", res)
	}
	sd, _ := update.RootDigest(r.shipped)
	if res := r.x.Probe(kernel.Request{Plan: r.approved("p4", sd, "Acme Fork")}, nil); res.Outcome != "unknown" {
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
	p := kernel.SignPlan(kernel.Plan{ID: "standing", Key: ck, Steps: []kernel.PlanStep{PlanStep(d, "Acme")}}, hpriv)
	if st := r.run(p); st.Phase != kernel.PFailed || st.Detail != ROwner {
		t.Fatalf("standing key: %+v", st)
	}
	// A plan the owner did not sign never reaches the clerk's switch.
	forged := r.approved("forged", d, "Acme")
	forged.Steps[0].Args[ArgName] = "Other"
	if err := r.k.Submit(r.now(), forged); err == nil {
		if err := r.k.Tick(r.now()); err != nil {
			t.Fatal(err)
		}
	}
	if res := r.x.Do(kernel.Request{Plan: forged}, r.k.State()); res.Outcome != "failed" {
		t.Fatalf("forged %+v", res)
	}
	r.unchanged()
}

// The journal executor is the only old-core user left in the package, until
// f2 (#3430) deletes it with the agentosd wiring.
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
			for _, old := range []string{"/broker/journal", "/broker/grants"} {
				if strings.HasSuffix(p, old) {
					t.Errorf("%s imports %s", f, p)
				}
			}
		}
	}
}
