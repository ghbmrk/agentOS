package browser

// REQ: CLK-2, CLK-3, CLK-5, KRN-8

import (
	"crypto/ed25519"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const hour = int64(3600_000)

func seedKey(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	p := ed25519.NewKeyFromSeed(s)
	return p.Public().(ed25519.PublicKey), p
}

type clerkRig struct {
	h     *harness
	c     *Clerk
	k     *kernel.Kernel
	owner []ed25519.PublicKey // the anchors
	root  key.Key             // the home clerk's key
	phone ed25519.PrivateKey  // the owner's enrolled phone passkey, which taps approvals
}

// newClerkRig boots a kernel whose only clerk is a browser clerk over h, and
// logs a root key for read and post on it; no post is ever sent.
func newClerkRig(t *testing.T, h *harness) *clerkRig {
	t.Helper()
	opub, opriv := seedKey(1)
	hpub, _ := seedKey(2)
	kpub, kpriv := seedKey(3)
	bpub, bpriv := seedKey(12) // the second hardware key co-signs new power (D-146)
	anchors := []ed25519.PublicKey{opub, bpub}
	c := NewClerk("web", anchors, h.g)
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: kpub,
		Sign: kpriv, Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	k, err := kernel.Boot(l, anchors, map[string]kernel.Clerk{"web": c}, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The passkey's grant to the home clerk, a hold before the test (D-146).
	root, err := key.ClerkKey(key.Issue(opriv, key.Root{Clerk: "web", Verbs: []key.Verb{key.Read, key.Post}, Serial: "r1"}), opriv, hpub, time.Now().UnixMilli(), 1<<40) // a clerk with no Clock reads the wall clock
	if err != nil {
		t.Fatal(err)
	}
	batch := []key.Key{{Root: root.Root}, root}
	if err := k.Issue(-kernel.GrantHold, []key.Cosign{key.Approve(opriv, kernel.BatchHash(batch...)), key.Approve(bpriv, kernel.BatchHash(batch...))}, batch...); err != nil {
		t.Fatal(err)
	}
	phonePub, phone := seedKey(8)
	if err := k.Enroll(-kernel.GrantHold, key.Enroll(opriv, phonePub)); err != nil {
		t.Fatal(err)
	}
	return &clerkRig{h, c, k, anchors, root, phone}
}

func (r *clerkRig) held(t *testing.T, base, novel int64) key.Key {
	t.Helper()
	hpub, hpriv := seedKey(2)
	d, err := key.Derive(r.root, hpriv, hpub, key.LimitHold(base, novel))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func read(line string) kernel.PlanStep {
	return kernel.PlanStep{Verb: key.Read, Clerk: "web", Args: map[string]string{"query": line}}
}

func post(to, line string) kernel.PlanStep {
	return kernel.PlanStep{Verb: key.Post, Clerk: "web", Args: map[string]string{"to": to, "msg": line}}
}

// plan is s alone under k, signed by the holder of every key here.
func plan(id string, k key.Key, s kernel.PlanStep) kernel.Plan {
	_, hpriv := seedKey(2)
	return kernel.SignPlan(kernel.Plan{ID: id, Key: k, Steps: []kernel.PlanStep{s}}, hpriv)
}

func (r *clerkRig) run(t *testing.T, now int64, id string, k key.Key, s kernel.PlanStep) {
	t.Helper()
	if err := r.k.Submit(now, plan(id, k, s)); err != nil {
		t.Fatal(err)
	}
	if err := r.k.Tick(now); err != nil {
		t.Fatal(err)
	}
}

func (r *clerkRig) step(id string) kernel.StepState {
	return r.k.State().Plans[id].Steps[0]
}

// results counts the step.result entries in the log that contain sub.
func (r *clerkRig) results(sub string) int {
	n := 0
	for _, e := range r.k.Log().Entries() {
		if e.Type == "step.result" && strings.Contains(string(e.Body), sub) {
			n++
		}
	}
	return n
}

const navUnsub = `{"v":0,"verb":"navigate","url":"` + unsubURL + `"}`

// A step that claims read for an action that may change state is refused
// before anything reaches the driver (CLK-3, CLK-5).
func TestReadThatChangesStateIsRefusedUnsent(t *testing.T) {
	r := newClerkRig(t, newHarness(t, nil, "", 0))
	r.run(t, 0, "p1", r.root, read(navUnsub))
	if s := r.step("p1"); s.Phase != kernel.PFailed || r.results("approval_required") != 1 {
		t.Fatalf("phase %s", s.Phase)
	}
	if got := r.h.received(t); len(got) != 0 {
		t.Fatalf("the driver received %q", got)
	}
	// An action that cannot change state goes through as a read.
	r.run(t, 1, "p2", r.root, read(`{"v":0,"verb":"navigate","url":"https://shop.example.test/products/kettle"}`))
	if s := r.step("p2"); s.Phase != kernel.PDone || len(r.h.received(t)) != 1 {
		t.Fatalf("phase %s, driver got %q", s.Phase, r.h.received(t))
	}
}

// No key covers a submit until the owner approves its print: a post with
// no print is refused by the clerk's own facts, even after its key's hold
// window, and a standing key covers no post at all; nothing is sent. A fresh clerk, as after a restart, probes a read that
// cannot change state notdone and a post unknown (CLK-3, KRN-8).
func TestPostIsRefusedUnsent(t *testing.T) {
	r := newClerkRig(t, newHarness(t, nil, "", 0))
	k := r.held(t, hour, hour)
	r.run(t, 0, "p1", k, post(unsubShown, navUnsub))
	r.run(t, 1, "p2", r.root, post("https://shop.example.test/products/kettle",
		`{"v":0,"verb":"navigate","url":"https://shop.example.test/products/kettle"}`))
	if err := r.k.Tick(3 * hour); err != nil {
		t.Fatal(err)
	}
	if s := r.step("p1"); s.Phase != kernel.PFailed || s.Detail != clerk.RClaim {
		t.Fatalf("p1: phase %s (%s)", s.Phase, s.Detail)
	}
	if s := r.step("p2"); s.Phase != kernel.PFailed || s.Detail != "unapproved" {
		t.Fatalf("p2: phase %s (%s)", s.Phase, s.Detail)
	}
	if got := r.h.received(t); len(got) != 0 {
		t.Fatalf("the driver received %q", got)
	}
	fresh := NewClerk("web", r.owner, r.h.g)
	for s, want := range map[*kernel.PlanStep]string{
		ptr(read(`{"v":0,"verb":"snapshot"}`)): "notdone",
		ptr(post(unsubShown, navUnsub)):        "unknown",
	} {
		req := kernel.Request{Plan: plan("p", r.root, *s)}
		if p := fresh.Probe(req, r.k.State()); p != want {
			t.Fatalf("%s probe %s, want %s", s.Verb, p, want)
		}
	}
}

func ptr[T any](v T) *T { return &v }

// Logged out, a button press is sent but may change state: an answer lost
// after the write is unknown, the kernel parks it and nothing is sent
// twice, and a fresh clerk probes it unknown too; one that succeeded probes
// done (KRN-8, D-147).
func TestLoggedOutEffectIsParkedNotResent(t *testing.T) {
	h := newHarness(t, map[string]any{"click": "hang"}, "", 300*time.Millisecond)
	h.g.cfg.LoggedOut = true
	h.g.refs["e6"] = link{role: "button", name: "Send message"}
	r := newClerkRig(t, h)
	press := read(`{"v":0,"verb":"click","ref":"e6"}`)
	r.run(t, 0, "p1", r.root, press)
	if s := r.step("p1"); s.Phase != kernel.PUnknown {
		t.Fatalf("phase %s", s.Phase)
	}
	for i := int64(1); i <= kernel.MaxChecks+1; i++ {
		if err := r.k.Tick(i * kernel.ProbeEvery); err != nil {
			t.Fatal(err)
		}
	}
	if s := r.step("p1"); s.Phase != kernel.PParked {
		t.Fatalf("phase %s after %d checks", s.Phase, kernel.MaxChecks)
	}
	if got := forwarded(t, h, "click"); len(got) != 1 {
		t.Fatalf("driver got %q", got)
	}
	req := kernel.Request{Plan: plan("p1", r.root, press)}
	if p := NewClerk("web", r.owner, h.g).Probe(req, r.k.State()); p != "unknown" {
		t.Fatalf("fresh clerk probe %s", p)
	}

	ok := newHarness(t, nil, "", 0)
	ok.g.cfg.LoggedOut = true
	ok.g.refs["e6"] = link{role: "button", name: "Send message"}
	r = newClerkRig(t, ok)
	r.run(t, 0, "p2", r.root, press)
	req = kernel.Request{Plan: plan("p2", r.root, press)}
	if s, p := r.step("p2").Phase, r.c.Probe(req, r.k.State()); s != kernel.PDone || p != "done" {
		t.Fatalf("phase %s, probe %s", s, p)
	}
}

// The clerk re-checks what the kernel decided: another clerk's step, a root
// absent from the log, a step the log has not dispatched, and a claim the
// clerk's own facts contradict (CLK-2, KEY-2).
func TestClerkRefusesWhatTheKeyDoesNot(t *testing.T) {
	r := newClerkRig(t, newHarness(t, nil, "", 0))
	safe := read(`{"v":0,"verb":"navigate","url":"https://shop.example.test/products/kettle"}`)
	r.run(t, 0, "p0", r.root, safe)
	if s := r.step("p0"); s.Phase != kernel.PDone {
		t.Fatalf("valid read: phase %s", s.Phase)
	}
	other := safe
	other.Clerk = "bank"
	_, opriv := seedKey(1)
	hpub, _ := seedKey(2)
	ghost, err := key.ClerkKey(key.Issue(opriv, key.Root{Clerk: "web", Verbs: []key.Verb{key.Read}, Serial: "unlogged"}), opriv, hpub, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	labelled := safe
	labelled.Labels = []string{"private"}
	for want, req := range map[string]kernel.Request{
		key.RClerk:        {Plan: plan("p1", r.root, other)},
		kernel.CUngranted: {Plan: plan("p2", ghost, safe)},
		clerk.RDispatch:   {Plan: plan("p3", r.root, safe)},
		clerk.RClaim:      {Plan: plan("p4", r.root, labelled)},
	} {
		if res := r.c.Do(req, r.k.State()); res.Outcome != "failed" || res.Detail != want {
			t.Fatalf("want %s: %+v", want, res)
		}
	}
	if got := r.h.received(t); len(got) != 1 {
		t.Fatalf("the driver received %q, want only the valid read", got)
	}
}

// The clerk checks the key on its own clock, not the kernel's (CLK-2): a
// key that expires at 10 runs while the clerk's clock reads 5 and is
// refused unsent once it reads 20, though the kernel dispatched both at 0.
func TestClerkChecksOnItsOwnClock(t *testing.T) {
	r := newClerkRig(t, newHarness(t, nil, "", 0))
	hpub, hpriv := seedKey(2)
	k, err := key.Derive(r.root, hpriv, hpub, key.LimitExpires(10))
	if err != nil {
		t.Fatal(err)
	}
	safe := read(`{"v":0,"verb":"navigate","url":"https://shop.example.test/products/kettle"}`)
	r.c.Clock = func() int64 { return 5 }
	r.run(t, 0, "p1", k, safe)
	r.c.Clock = func() int64 { return 20 }
	r.run(t, 0, "p2", k, safe)
	if a, b := r.step("p1").Phase, r.step("p2").Phase; a != kernel.PDone || b != kernel.PFailed {
		t.Fatalf("phases %s, %s", a, b)
	}
	if got := r.h.received(t); len(got) != 1 {
		t.Fatalf("the driver received %q", got)
	}
}
