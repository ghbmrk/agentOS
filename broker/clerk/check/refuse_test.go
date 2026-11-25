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

// grant is a kernel whose log grants "mail" a clerk key for verbs, with
// the owner's, the holder's keys and the anchors.
type grant struct {
	k       *kernel.Kernel
	anchors []key.PublicKey
	ck      key.Key
	owner   ed25519.PrivateKey
	holder  ed25519.PrivateKey
}

// granted boots a kernel whose log grants "mail" a clerk key for verbs, a
// grant hold before 0, so it is live from 0.
func granted(t *testing.T, verbs ...key.Verb) grant {
	t.Helper()
	opub, opriv := pairOf(1)
	hpub, hpriv := pairOf(2)
	kpub, kpriv := pairOf(3)
	bpub, bpriv := pairOf(12)
	g := grant{anchors: []key.PublicKey{key.Ed25519(opub), key.Ed25519(bpub)}, owner: opriv, holder: hpriv}
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: kpub,
		Sign: kpriv, Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	if g.k, err = kernel.Boot(l, g.anchors, map[string]kernel.Clerk{"mail": idle{}}, 0); err != nil {
		t.Fatal(err)
	}
	if g.ck, err = key.ClerkKey(key.Issue(key.Ed25519Signer(opriv), key.Root{Clerk: "mail", Verbs: verbs, Serial: "r1"}),
		key.Ed25519Signer(opriv), hpub, 0, 1<<40); err != nil {
		t.Fatal(err)
	}
	keys := []key.Key{{Root: g.ck.Root}, g.ck}
	h := kernel.BatchHash(keys...)
	if err := g.k.Issue(-kernel.GrantHold, []key.Cosign{key.Approve(key.Ed25519Signer(opriv), h), key.Approve(key.Ed25519Signer(bpriv), h)}, keys...); err != nil {
		t.Fatal(err)
	}
	return g
}

// narrowed is the clerk key narrowed by c, held by the holder.
func (g grant) narrowed(t *testing.T, c ...key.Caveat) key.Key {
	t.Helper()
	k, err := key.Derive(g.ck, g.holder, g.holder.Public().(ed25519.PublicKey), c...)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// stepOf is one step of verb at "mail", every argument "x".
func stepOf(verb key.Verb) kernel.PlanStep {
	ps := kernel.PlanStep{Verb: verb, Clerk: "mail", Args: map[string]string{}}
	for _, n := range key.ArgNames(verb) {
		ps.Args[n] = "x"
	}
	return ps
}

// request is plan p1 of ps under k, signed by by.
func request(k key.Key, by ed25519.PrivateKey, ps kernel.PlanStep) kernel.Request {
	return kernel.Request{Plan: kernel.SignPlan(kernel.Plan{ID: "p1", Key: k, Steps: []kernel.PlanStep{ps}}, by)}
}

// lineless is a view under which any one-off spend needs a second passkey.
type lineless struct{ inFlight }

func (lineless) OneOffLine(key.ID, int64) int64 { return 0 }

// Each of the clerk's own checks refuses with its own code and reason, and
// a request that passes them all returns its verified chain. Catches a
// check dropped from Check: the request it guards then passes, or is
// refused later for another reason (CLK-2, #6023).
func TestEachCheckRefusesWithItsCode(t *testing.T) {
	g := granted(t, key.Trash, key.Buy)
	r := request(g.ck, g.holder, stepOf(key.Trash))
	v := inFlight{g.k.State(), kernel.Dispatch{Seq: g.k.State().Seq + 1}}
	if ver, rf := check.Verify(g.anchors, "mail", echo, 1, r, v); rf != nil || ver == nil {
		t.Fatalf("a valid request: %v, %v", ver, rf)
	}
	other := func(key.Step) (string, []string, int64) { return "other", nil, 0 }
	_, wrong := pairOf(9)
	buy := stepOf(key.Buy)
	buy.Args[key.ArgAmount] = "5"
	for _, tc := range []struct {
		name, clerk string
		facts       check.Facts
		at          int64
		r           kernel.Request
		v           kernel.View
		want        key.Code
		detail      string
	}{
		{"another clerk's step", "bank", echo, 1, r, v, key.RClerk, "mail"},
		{"no facts", "mail", nil, 1, r, v, check.RClaim, "clerk has no facts to judge the step's claims"},
		{"facts differ", "mail", other, 1, r, v, check.RClaim, "step claims differ from the clerk's facts"},
		{"not the holder's signature", "mail", echo, 1, request(g.ck, wrong, stepOf(key.Trash)), v, kernel.CKey, ""},
		{"before its grant is live", "mail", echo, -1, r, v, kernel.CGrantHeld, "live at 0"},
		{"a one-off past the line, alone", "mail", echo, 1, request(key.Key{Root: g.ck.Root}, g.owner, buy), lineless{v}, kernel.CCosign, "5"},
		{"not in flight", "mail", echo, 1, r, g.k.State(), check.RDispatch, "the log has no such step in flight"},
		{"a verb outside the key", "mail", echo, 1, request(g.ck, g.holder, stepOf(key.Send)), v, key.RVerb, ""},
	} {
		ver, rf := check.Verify(g.anchors, tc.clerk, tc.facts, tc.at, tc.r, tc.v)
		if rf == nil || rf.Code() != tc.want || (tc.detail != "" && rf.Detail != tc.detail) || ver != nil {
			t.Errorf("%s: %v, %v; want %s %q", tc.name, ver, rf, tc.want, tc.detail)
		}
	}
}

// The clerk judges the step's claimed labels as a set, in any order, and
// leaves its facts' own slice as it was (KEY-2).
func TestClaimedLabelsAreASet(t *testing.T) {
	g := granted(t, key.Trash)
	ps := stepOf(key.Trash)
	ps.Labels = []string{"b", "c", "a"}
	r := request(g.ck, g.holder, ps)
	mine := []string{"c", "a", "b"}
	facts := func(key.Step) (string, []string, int64) { return "", mine, 0 }
	if rf := check.Check(g.anchors, "mail", facts, 1, r, inFlight{g.k.State(), kernel.Dispatch{Seq: g.k.State().Seq + 1}}); rf != nil {
		t.Fatalf("the same labels in another order: %v", rf)
	}
	if mine[0] != "c" || mine[1] != "a" || mine[2] != "b" {
		t.Fatalf("the clerk's facts were reordered: %v", mine)
	}
}

// The step's rung is the log's dispatch's, never the request's: a step
// under a P3 key passes when the log dispatched it at P3 (CH-3).
func TestTheRungIsTheLogs(t *testing.T) {
	g := granted(t, key.Trash)
	r := request(g.narrowed(t, key.LimitRung(key.P3)), g.holder, stepOf(key.Trash))
	seq := g.k.State().Seq + 1
	if rf := check.Check(g.anchors, "mail", echo, 1, r, inFlight{g.k.State(), kernel.Dispatch{Seq: seq, Rung: key.P3}}); rf != nil {
		t.Fatalf("a P3 dispatch under a P3 key: %v", rf)
	}
	if rf := check.Check(g.anchors, "mail", echo, 1, r, inFlight{g.k.State(), kernel.Dispatch{Seq: seq, Rung: key.P2}}); rf == nil || rf.Code() != key.RRung {
		t.Fatalf("a P2 dispatch under a P3 key: %v", rf)
	}
}

// An irreversible step under a hold passes only once the log held it and
// its window is over, at its end exactly or with an approval; unheld, or
// held and still in its window, it is refused as a hold, each with its own
// reason. With no hold on the key it needs none (CLK-2, KEY-8).
func TestAHeldStepWaitsOutItsWindow(t *testing.T) {
	const hour = int64(3_600_000)
	g := granted(t, key.Unsubscribe)
	seq := g.k.State().Seq + 1
	held := request(g.narrowed(t, key.LimitHold(hour, hour)), g.holder, stepOf(key.Unsubscribe))
	for _, tc := range []struct {
		name   string
		r      kernel.Request
		d      kernel.Dispatch
		detail string
	}{
		{"never held", held, kernel.Dispatch{Seq: seq}, "step was not held"},
		{"in its window", held, kernel.Dispatch{Seq: seq, Held: true, HeldAt: 10 * hour}, "window not over"},
		{"at its window's end", held, kernel.Dispatch{Seq: seq, Held: true, HeldAt: 9 * hour}, ""},
		{"approved in its window", held, kernel.Dispatch{Seq: seq, Held: true, HeldAt: 10 * hour, Approved: true}, ""},
		{"no hold on the key", request(g.narrowed(t, key.LimitHold(0, 0)), g.holder, stepOf(key.Unsubscribe)), kernel.Dispatch{Seq: seq}, ""},
	} {
		rf := check.Check(g.anchors, "mail", echo, 10*hour, tc.r, inFlight{g.k.State(), tc.d})
		switch {
		case tc.detail == "" && rf != nil:
			t.Errorf("%s: refused: %v", tc.name, rf)
		case tc.detail != "" && (rf == nil || rf.Code() != check.RHold || rf.Detail != tc.detail):
			t.Errorf("%s: %v, want %s %q", tc.name, rf, check.RHold, tc.detail)
		}
	}
}
