package browser

// REQ: CLK-2, CLK-3, CLK-5, KRN-8

import (
	"crypto/ed25519"
	"math/rand/v2"
	"strings"
	"testing"

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
	owner ed25519.PublicKey
	root  key.Key
}

// newClerkRig boots a kernel whose only clerk is a browser clerk over h, and
// logs a root key for read and post on it; no post is ever sent.
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

// No key covers a submit until the owner approves the exact request, so a
// post is refused unsent even after its key's hold window, whatever it
// names (CLK-3).
func TestPostIsRefusedUnsent(t *testing.T) {
	r := newClerkRig(t, newHarness(t, nil, "", 0))
	k := r.held(t, hour, hour)
	r.run(t, 0, "p1", k, post(unsubShown, navUnsub))
	r.run(t, 1, "p2", r.root, post("https://shop.example.test/products/kettle",
		`{"v":0,"verb":"navigate","url":"https://shop.example.test/products/kettle"}`))
	if err := r.k.Tick(3 * hour); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"p1", "p2"} {
		if s := r.step(id); s.Phase != kernel.PFailed {
			t.Fatalf("%s: phase %s", id, s.Phase)
		}
	}
	if n := r.results("approval_required"); n != 2 {
		t.Fatalf("%d step results name approval_required", n)
	}
	if got := r.h.received(t); len(got) != 0 {
		t.Fatalf("the driver received %q", got)
	}
}

// The clerk sends only reads, which are safe to run again, so it keeps no
// memory: a fresh clerk, as after a restart, probes every step notdone,
// and the kernel never parks a browser step (KRN-8).
func TestEveryStepProbesNotDone(t *testing.T) {
	r := newClerkRig(t, newHarness(t, nil, "", 0))
	fresh := NewClerk("web", r.owner, r.h.g)
	for _, s := range []kernel.PlanStep{read(navUnsub), post(unsubShown, navUnsub)} {
		req := kernel.Request{Plan: plan("p", r.root, s)}
		if p := fresh.Probe(req, r.k.State()); p != "notdone" {
			t.Fatalf("%s probe %s", s.Verb, p)
		}
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
	ghost := key.Issue(opriv, key.Root{Holder: hpub, Clerk: "web", Verbs: []key.Verb{key.Read}, Serial: "unlogged"})
	labelled := safe
	labelled.Labels = []string{"private"}
	for want, req := range map[string]kernel.Request{
		key.RClerk:          {Plan: plan("p1", r.root, other)},
		kernel.CUnknownRoot: {Plan: plan("p2", ghost, safe)},
		clerk.RDispatch:     {Plan: plan("p3", r.root, safe)},
		clerk.RClaim:        {Plan: plan("p4", r.root, labelled)},
	} {
		if res := r.c.Do(req, r.k.State()); res.Outcome != "failed" || res.Detail != want {
			t.Fatalf("want %s: %+v", want, res)
		}
	}
	if got := r.h.received(t); len(got) != 1 {
		t.Fatalf("the driver received %q, want only the valid read", got)
	}
}
