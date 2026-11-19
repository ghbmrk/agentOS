package check_test

// REQ: CLK-2, KEY-2

import (
	"crypto/ed25519"
	"math/rand/v2"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/check"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// pairOf is the ed25519 pair seeded by seed.
func pairOf(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	p := ed25519.NewKeyFromSeed(s)
	return p.Public().(ed25519.PublicKey), p
}

// idle is a clerk the kernel never runs here: the tests call Check themselves.
type idle struct{}

func (idle) Do(kernel.Request, kernel.View) kernel.Result    { return kernel.Result{} }
func (idle) Probe(kernel.Request, kernel.View) kernel.Result { return kernel.Result{} }

// inFlight is the kernel's state with one step held as the test says.
type inFlight struct {
	*kernel.State
	d kernel.Dispatch
}

func (v inFlight) Dispatched(kernel.Request) (kernel.Dispatch, bool) { return v.d, true }

// echo is facts that agree with every claim the step makes.
func echo(s key.Step) (string, []string, int64) { return s.Content, s.Labels, s.Amount }

// granted boots a kernel whose log grants "mail" a clerk key for verb,
// narrowed by c, and returns the kernel, the anchors and a request for one
// step of verb under that key, signed by its holder.
func granted(t *testing.T, verb key.Verb, c ...key.Caveat) (*kernel.Kernel, []key.PublicKey, kernel.Request) {
	t.Helper()
	opub, opriv := pairOf(1)
	hpub, hpriv := pairOf(2)
	kpub, kpriv := pairOf(3)
	bpub, bpriv := pairOf(12)
	anchors := []key.PublicKey{key.Ed25519(opub), key.Ed25519(bpub)}
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: kpub,
		Sign: kpriv, Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	k, err := kernel.Boot(l, anchors, map[string]kernel.Clerk{"mail": idle{}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := key.ClerkKey(key.Issue(key.Ed25519Signer(opriv), key.Root{Clerk: "mail", Verbs: []key.Verb{verb}, Serial: "r1"}),
		key.Ed25519Signer(opriv), hpub, 0, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	keys := []key.Key{{Root: ck.Root}, ck}
	h := kernel.BatchHash(keys...)
	if err := k.Issue(-kernel.GrantHold, []key.Cosign{key.Approve(key.Ed25519Signer(opriv), h), key.Approve(key.Ed25519Signer(bpriv), h)}, keys...); err != nil {
		t.Fatal(err)
	}
	if len(c) > 0 {
		if ck, err = key.Derive(ck, hpriv, hpub, c...); err != nil {
			t.Fatal(err)
		}
	}
	ps := kernel.PlanStep{Verb: verb, Clerk: "mail", Args: map[string]string{}}
	for _, n := range key.ArgNames(verb) {
		ps.Args[n] = "x"
	}
	return k, anchors, kernel.Request{Plan: kernel.SignPlan(kernel.Plan{ID: "p1", Key: ck, Steps: []kernel.PlanStep{ps}}, hpriv)}
}

// Each of the clerk's own checks refuses with its own code and reason, and
// a request that passes them all returns its verified chain. Catches a
// check dropped from Check: the request it guards then passes, or is
// refused later for another reason (CLK-2, #6023).
func TestEachCheckRefusesWithItsCode(t *testing.T) {
	k, anchors, r := granted(t, key.Trash)
	v := inFlight{k.State(), kernel.Dispatch{Seq: k.State().Seq + 1}}
	if ver, rf := check.Verify(anchors, "mail", echo, 1, r, v); rf != nil || ver == nil {
		t.Fatalf("a valid request: %v, %v", ver, rf)
	}
	other := func(key.Step) (string, []string, int64) { return "other", nil, 0 }
	forged := r
	_, wrong := pairOf(9)
	forged.Plan = kernel.SignPlan(forged.Plan, wrong)
	for _, tc := range []struct {
		name, clerk string
		facts       check.Facts
		r           kernel.Request
		v           kernel.View
		want        key.Code
		detail      string
	}{
		{"another clerk's step", "bank", echo, r, v, key.RClerk, "mail"},
		{"no facts", "mail", nil, r, v, check.RClaim, "clerk has no facts to judge the step's claims"},
		{"facts differ", "mail", other, r, v, check.RClaim, "step claims differ from the clerk's facts"},
		{"not the holder's signature", "mail", echo, forged, v, kernel.CKey, ""},
		{"not in flight", "mail", echo, r, k.State(), check.RDispatch, "the log has no such step in flight"},
	} {
		ver, rf := check.Verify(anchors, tc.clerk, tc.facts, 1, tc.r, tc.v)
		if rf == nil || rf.Code() != tc.want || (tc.detail != "" && rf.Detail != tc.detail) || ver != nil {
			t.Errorf("%s: %v, %v; want %s %q", tc.name, ver, rf, tc.want, tc.detail)
		}
	}
}

// An irreversible step under a hold passes only once the log held it and
// its window is over: unheld, or held and still in its window, it is
// refused as a hold, each with its own reason (CLK-2, KEY-8).
func TestAHeldStepWaitsOutItsWindow(t *testing.T) {
	const hour = int64(3_600_000)
	k, anchors, r := granted(t, key.Unsubscribe, key.LimitHold(hour, hour))
	seq := k.State().Seq + 1
	for _, tc := range []struct {
		name   string
		d      kernel.Dispatch
		detail string
	}{
		{"never held", kernel.Dispatch{Seq: seq}, "step was not held"},
		{"in its window", kernel.Dispatch{Seq: seq, Held: true, HeldAt: 10 * hour}, "window not over"},
		{"past its window", kernel.Dispatch{Seq: seq, Held: true, HeldAt: 7 * hour}, ""},
		{"approved in its window", kernel.Dispatch{Seq: seq, Held: true, HeldAt: 10 * hour, Approved: true}, ""},
	} {
		rf := check.Check(anchors, "mail", echo, 10*hour, r, inFlight{k.State(), tc.d})
		switch {
		case tc.detail == "" && rf != nil:
			t.Errorf("%s: refused: %v", tc.name, rf)
		case tc.detail != "" && (rf == nil || rf.Code() != check.RHold || rf.Detail != tc.detail):
			t.Errorf("%s: %v, want %s %q", tc.name, rf, check.RHold, tc.detail)
		}
	}
}
