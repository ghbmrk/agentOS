package browser

// REQ: CLK-2, CLK-3, CLK-5, KRN-8

import (
	"crypto/ed25519"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

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
	owner ed25519.PublicKey
	root  key.Key
}

// newClerkRig boots a kernel whose only clerk is a browser clerk over h, and
// logs a root key for read and post on it.
func newClerkRig(t *testing.T, h *harness) *clerkRig {
	t.Helper()
	opub, opriv := seedKey(1)
	hpub, _ := seedKey(2)
	kpub, kpriv := seedKey(3)
	c := NewClerk("web", opub, h.g)
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: kpub,
		Sign: kpriv, Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	k, err := kernel.Boot(l, opub, map[string]kernel.Clerk{"web": c}, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := key.Issue(opriv, key.Root{Holder: hpub, Clerk: "web", Verbs: []key.Verb{key.Read, key.Post}, Serial: "r1"})
	if err := k.Issue(0, root); err != nil {
		t.Fatal(err)
	}
	return &clerkRig{h, c, k, opub, root}
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

const navUnsub = `{"v":0,"verb":"navigate","url":"` + unsubURL + `"}`

// A step that claims read for an action that may change state is refused
// before anything reaches the driver (CLK-3).
func TestReadThatChangesStateIsRefusedUnsent(t *testing.T) {
	r := newClerkRig(t, newHarness(t, nil, "", 0))
	r.run(t, 0, "p1", r.root, read(navUnsub))
	if s := r.step("p1"); s.Phase != kernel.PFailed {
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

// A post waits out the key's hold window, then is sent once, and its result
// is in the log (CLK-2, CLK-5).
func TestPostIsHeldThenSentOnce(t *testing.T) {
	r := newClerkRig(t, newHarness(t, nil, "", 0))
	k := r.held(t, hour, hour)
	r.run(t, 0, "p1", k, post(unsubShown, navUnsub))
	if err := r.k.Tick(hour - 1); err != nil {
		t.Fatal(err)
	}
	if got := r.h.received(t); len(got) != 0 || r.step("p1").Phase != kernel.PHeld {
		t.Fatalf("sent inside the window: %q, phase %s", got, r.step("p1").Phase)
	}
	if err := r.k.Tick(hour); err != nil {
		t.Fatal(err)
	}
	if got := r.h.received(t); len(got) != 1 || got[0] != navUnsub || r.step("p1").Phase != kernel.PDone {
		t.Fatalf("driver got %q, phase %s", got, r.step("p1").Phase)
	}
	if err := r.k.Tick(3 * hour); err != nil {
		t.Fatal(err)
	}
	if len(r.h.received(t)) != 1 {
		t.Fatal("a done post was sent again")
	}
	logged := false
	for _, e := range r.k.Log().Entries() {
		logged = logged || e.Type == "step.result" && strings.Contains(string(e.Body), `"ok"`)
	}
	if !logged {
		t.Fatal("no step.result in the log")
	}
	// The same Idem again is the remembered result, not a second send.
	req := kernel.Request{Plan: plan("p1", k, post(unsubShown, navUnsub)), Idem: kernel.Idem("p1", 0), Now: 4 * hour}
	if res := r.c.Do(req, r.k.State()); res.Outcome != "ok" || len(r.h.received(t)) != 1 {
		t.Fatalf("redo %+v, driver got %q", res, r.h.received(t))
	}
}

// A post whose to does not name what the action reaches is refused unsent:
// by the kernel when to is missing, else by the clerk.
func TestPostToAnotherTargetIsRefused(t *testing.T) {
	r := newClerkRig(t, newHarness(t, nil, "", 0))
	for i, to := range []string{unsubURL, "https://shop.example.test/unsubscribe/all?token=[REDACTED]", ""} {
		id := "p" + string(rune('1'+i))
		r.run(t, 0, id, r.root, post(to, navUnsub))
		if p := r.k.State().Plans[id]; p.Status != kernel.SRejected && p.Steps[0].Phase != kernel.PFailed {
			t.Fatalf("to %q: plan %s", to, p.Status)
		}
	}
	if got := r.h.received(t); len(got) != 0 {
		t.Fatalf("the driver received %q", got)
	}
}

// A post whose answer was lost is unknown and is never sent again: the
// kernel probes, the clerk cannot tell, and the step parks (KRN-8).
func TestLostPostIsParkedNotResent(t *testing.T) {
	r := newClerkRig(t, newHarness(t, map[string]any{"navigate": "hang"}, "", 300*time.Millisecond))
	r.run(t, 0, "p1", r.root, post(unsubShown, navUnsub))
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
	if got := forwarded(t, r.h, "navigate"); len(got) != 1 {
		t.Fatalf("driver got %q", got)
	}
	// A read whose answer was lost is safe to run again.
	if p := r.c.Probe(kernel.Request{Plan: plan("p9", r.root, read(navUnsub)), Idem: "other"}, r.k.State()); p != "notdone" {
		t.Fatalf("read probe %s", p)
	}
}

// The clerk re-checks what the kernel decided: another clerk's step, a
// revoked key, a root absent from the log, and the key's own bounds (CLK-2).
func TestClerkRefusesWhatTheKeyDoesNot(t *testing.T) {
	r := newClerkRig(t, newHarness(t, nil, "", 0))
	req := func(idem string, k key.Key, s kernel.PlanStep) kernel.Request {
		return kernel.Request{Plan: plan("p", k, s), Idem: idem, Now: 1}
	}
	safe := `{"v":0,"verb":"navigate","url":"https://shop.example.test/products/kettle"}`
	if res := r.c.Do(req("i0", r.root, read(safe)), r.k.State()); res.Outcome != "ok" {
		t.Fatalf("valid read refused: %+v", res)
	}
	other := read(safe)
	other.Clerk = "bank"
	if res := r.c.Do(req("i1", r.root, other), r.k.State()); res.Outcome != "failed" {
		t.Fatalf("another clerk's step: %+v", res)
	}
	_, opriv := seedKey(1)
	hpub, hpriv := seedKey(2)
	ghost := key.Issue(opriv, key.Root{Holder: hpub, Clerk: "web", Verbs: []key.Verb{key.Read}, Serial: "unlogged"})
	if res := r.c.Do(req("i2", ghost, read(safe)), r.k.State()); res.Outcome != "failed" {
		t.Fatalf("unknown root: %+v", res)
	}
	bound, err := key.Derive(r.root, hpriv, hpub, key.LimitArg(key.ArgBound{Name: "to", OneOf: []string{"https://shop.example.test/other"}}))
	if err != nil {
		t.Fatal(err)
	}
	if res := r.c.Do(req("i3", bound, post(unsubShown, navUnsub)), r.k.State()); res.Outcome != "failed" {
		t.Fatalf("recipient outside the key's bound: %+v", res)
	}
	if err := r.k.Revoke(1, r.root.Tip()); err != nil {
		t.Fatal(err)
	}
	if res := r.c.Do(req("i4", r.root, read(safe)), r.k.State()); res.Outcome != "failed" {
		t.Fatalf("revoked key: %+v", res)
	}
	if got := r.h.received(t); len(got) != 1 {
		t.Fatalf("the driver received %q, want only the valid read", got)
	}
}
