package inbox

// REQ: CLK-2, VRB-2

import (
	"crypto/ed25519"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const (
	t0      = int64(1_792_400_000_000)
	dayMS   = int64(86_400_000)
	secret  = "0123456789abcdef0123"
	mailKey = "owner-1"
)

func seed(b byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	s[0] = b
	p := ed25519.NewKeyFromSeed(s)
	return p.Public().(ed25519.PublicKey), p
}

type rig struct {
	acct    *Account
	k       *kernel.Kernel
	planner key.Key
	world   *World
}

// newRig boots a real kernel over the fixture mailbox, with an extra mail of
// class alert whose text would pass VRB-2, and derives a planner key.
func newRig(t *testing.T, retention int, caveats ...key.Caveat) *rig {
	t.Helper()
	w, mails, raw := loadFixture(t)
	var ms []Mail
	for _, m := range mails {
		ms = append(ms, Mail{ID: m.ID, Raw: raw[m.ID], Class: m.Class})
	}
	ms = append(ms, Mail{ID: "A01", Raw: raw["M01"], Class: "alert"})
	ownerPub, ownerPriv := seed(1)
	holderPub, holderPriv := seed(2)
	headPub, headPriv := seed(3)
	plannerPub, _ := seed(4)
	r := &rig{world: &w}
	var err error
	r.acct, err = NewAccount(ownerPub, []byte(secret), func() World { return *r.world }, ms, retention, "List-Unsubscribe=One-Click")
	if err != nil {
		t.Fatal(err)
	}
	log, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: headPub, Sign: headPriv,
		Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	r.k, err = kernel.Boot(log, ownerPub, map[string]kernel.Clerk{Name: r.acct}, t0-dayMS)
	if err != nil {
		t.Fatal(err)
	}
	r.acct.Bind(r.k.State())
	root := key.Issue(ownerPriv, key.Root{Holder: holderPub, Clerk: Name, Verbs: []key.Verb{key.Organize, key.Trash, key.Unsubscribe}, Serial: mailKey})
	if err := r.k.Issue(t0-dayMS, root); err != nil {
		t.Fatal(err)
	}
	if err := log.Anchor(); err != nil {
		t.Fatal(err)
	}
	r.planner, err = key.Derive(root, holderPriv, plannerPub, caveats...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rig) step(id string, v key.Verb, args map[string]string) kernel.Plan {
	a := map[string]key.Arg{}
	for n, val := range args {
		a[n] = key.Arg{Value: val}
	}
	return kernel.Plan{ID: id, Key: r.planner, Steps: []key.Step{kernel.Normalize(id, key.Step{Verb: v, Clerk: Name, Args: a})}}
}

func (r *rig) run(t *testing.T, p kernel.Plan, ticks ...int64) {
	t.Helper()
	if err := r.k.Submit(t0, p); err != nil {
		t.Fatal(err)
	}
	for _, at := range append([]int64{t0}, ticks...) {
		if err := r.k.Tick(at); err != nil {
			t.Fatal(err)
		}
	}
}

func (r *rig) lastRefusal(t *testing.T) Refusal {
	t.Helper()
	rs := r.acct.Refusals()
	if len(rs) == 0 {
		t.Fatal("clerk recorded no refusal")
	}
	return rs[len(rs)-1]
}

// staleView is the caller's own account of the world: everything held, known.
type staleView struct{ kernel.View }

func (staleView) Known(key.ID) bool                   { return true }
func (staleView) Held(uint64) (kernel.HeldInfo, bool) { return kernel.HeldInfo{}, true }

func handleOfMail(t *testing.T, r *rig, id string) string {
	t.Helper()
	for _, it := range r.acct.Listing() {
		if it.Mail == id && it.Sender != "" {
			return it.Sender
		}
	}
	t.Fatalf("%s has no sender handle", id)
	return ""
}

// Security 1: a request the kernel did not dispatch does nothing, whatever the
// caller says about the key or the view.
func TestForcedTrashOfPersonalMailIsRefusedAndRecorded(t *testing.T) {
	r := newRig(t, 30)
	p := r.step("forced", key.Trash, map[string]string{"target": "M22"})
	res := r.acct.Do(kernel.Request{Plan: "forced", Step: p.Steps[0], Key: r.planner, Idem: kernel.Idem("forced", 0), Attempt: 1, Now: t0}, r.k.State())
	if res.Outcome == "ok" || len(r.acct.Effects()) != 0 {
		t.Fatalf("forced trash ran: %+v %v", res, r.acct.Effects())
	}
	if rf := r.lastRefusal(t); rf.Reason != "not-dispatched" || rf.At != "clerk" {
		t.Fatalf("refusal %+v", rf)
	}
}

func TestForcedUnsubscribeWithFakeViewPostsNothing(t *testing.T) {
	r := newRig(t, 30)
	h := handleOfMail(t, r, "M01")
	p := r.step("forced", key.Unsubscribe, map[string]string{"to": h})
	res := r.acct.Do(kernel.Request{Plan: "forced", Step: p.Steps[0], Key: r.planner, Idem: kernel.Idem("forced", 0), Attempt: 1, HeldSeq: 1, Now: t0}, staleView{})
	if res.Outcome == "ok" || len(r.acct.Posts()) != 0 {
		t.Fatalf("forced unsubscribe ran: %+v", res)
	}
	if rf := r.lastRefusal(t); rf.Reason != "not-dispatched" {
		t.Fatalf("refusal %+v", rf)
	}
}

// A request that copies a dispatched one but changes the step is not it.
func TestChangedStepOfDispatchedRequestIsRefused(t *testing.T) {
	r := newRig(t, 30)
	p := r.step("real", key.Organize, map[string]string{"target": "M22", "label": "agentOS/personal"})
	r.run(t, p)
	forged := r.step("real", key.Trash, map[string]string{"target": "M22"})
	r.acct.Do(kernel.Request{Plan: "real", Step: forged.Steps[0], Key: r.planner, Idem: kernel.Idem("real", 0), Attempt: 1, Now: t0}, r.k.State())
	for _, e := range r.acct.Effects() {
		if e.Verb == string(key.Trash) {
			t.Fatalf("trash ran: %+v", e)
		}
	}
}

// Security 3: the class check is the clerk's. A planner key that allows trash
// still cannot trash personal mail or an alert, and the kernel logs the failure.
func TestTrashOnlySpamAndPhishing(t *testing.T) {
	for _, tc := range []struct {
		mail string
		ok   bool
	}{{"M19", true}, {"M20", true}, {"M22", false}, {"A01", false}, {"M01", false}} {
		r := newRig(t, 30)
		r.run(t, r.step("t", key.Trash, map[string]string{"target": tc.mail}))
		got := len(r.acct.Effects()) == 1
		if got != tc.ok {
			t.Errorf("%s: trashed %v, want %v (%v)", tc.mail, got, tc.ok, r.acct.Refusals())
		}
		if !tc.ok && r.lastRefusal(t).Reason != "not-trashable" {
			t.Errorf("%s: %+v", tc.mail, r.lastRefusal(t))
		}
	}
}

func TestTrashNeedsRestorableRetention(t *testing.T) {
	r := newRig(t, 3)
	r.run(t, r.step("t", key.Trash, map[string]string{"target": "M19"}))
	if len(r.acct.Effects()) != 0 || r.lastRefusal(t).Reason != "trash-not-restorable" {
		t.Fatalf("effects %v refusals %v", r.acct.Effects(), r.acct.Refusals())
	}
}

// Security 3: the cap is a caveat on the planner key and holds at the clerk.
func TestPlannerKeyCapStopsTheNextAction(t *testing.T) {
	r := newRig(t, 30, key.LimitRate(2))
	for i, m := range []string{"M19", "M20", "M19"} {
		id := []string{"a", "b", "c"}[i]
		p := r.step(id, key.Trash, map[string]string{"target": m})
		if err := r.k.Submit(t0, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.k.Tick(t0); err != nil {
		t.Fatal(err)
	}
	if n := len(r.acct.Effects()); n > 2 {
		t.Fatalf("%d trashes under a cap of 2", n)
	}
}

// Security 2: the 90 days belong to the clerk, and a date it cannot read is no
// evidence the owner stopped opening the mail.
func TestUnopenedDaysIsTheClerksConstant(t *testing.T) {
	w, _, raw := loadFixture(t)
	if unopenedDays != 90 {
		t.Fatalf("unopenedDays = %d", unopenedDays)
	}
	if r, _ := Evaluate(raw["M01"], w); r != ROK {
		t.Fatalf("M01: %s", r)
	}
	bad := w
	bad.LastOpened = map[string]string{"news@shop.test": "not-a-date"}
	if r, _ := Evaluate(raw["M01"], bad); r != RBadDate {
		t.Errorf("malformed last_opened: %s", r)
	}
	bad = w
	bad.Today = ""
	if r, _ := Evaluate(raw["M01"], bad); r != RBadDate {
		t.Errorf("malformed today: %s", r)
	}
	missing := w
	missing.LastOpened = nil
	if r, _ := Evaluate(raw["M02"], missing); r != ROK {
		t.Errorf("never opened: %s", r)
	}
}

// Security 2: eligibility is judged again when the hold ends.
func TestUnsubscribeIsReEvaluatedWhenTheHoldEnds(t *testing.T) {
	r := newRig(t, 30, key.LimitHold(600_000, dayMS))
	h := handleOfMail(t, r, "M01")
	if err := r.k.Submit(t0, r.step("u", key.Unsubscribe, map[string]string{"to": h})); err != nil {
		t.Fatal(err)
	}
	if err := r.k.Tick(t0); err != nil {
		t.Fatal(err)
	}
	// While the step is held the owner opens the sender's mail.
	opened := *r.world
	opened.LastOpened = map[string]string{"news@shop.test": opened.Today}
	*r.world = opened
	for _, at := range []int64{t0 + 600_000, t0 + dayMS} {
		if err := r.k.Tick(at); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.acct.Posts()) != 0 {
		t.Fatalf("posted after the mail was opened: %v", r.acct.Posts())
	}
	if rf := r.lastRefusal(t); rf.Reason != "no-longer-eligible" {
		t.Fatalf("refusal %+v", rf)
	}
}

func TestHandleIsKeyedAndWide(t *testing.T) {
	a := newRig(t, 30).acct
	h := a.Handle("news@shop.test")
	if !strings.HasPrefix(h, "sender-") || len(h) != len("sender-")+2*minSecret {
		t.Fatalf("handle %q", h)
	}
	if h != a.Handle("news@shop.test") || h == a.Handle("letters@weekly.test") {
		t.Fatal("handle is not a function of the address")
	}
	other, err := NewAccount(nil, []byte("another-secret-key-0"), func() World { return World{} }, nil, 30, "")
	if err != nil {
		t.Fatal(err)
	}
	if other.Handle("news@shop.test") == h {
		t.Fatal("handle does not depend on the secret")
	}
	if _, err := NewAccount(nil, []byte("short"), func() World { return World{} }, nil, 30, ""); err == nil {
		t.Fatal("a secret under 128 bits was accepted")
	}
}

func TestLabelsLiveUnderTheAgentOSNamespace(t *testing.T) {
	r := newRig(t, 30)
	for _, p := range Plans(r.acct.Listing(), r.planner) {
		for _, s := range p.Steps {
			if l := s.Args["label"].Value; s.Verb == key.Organize && !strings.HasPrefix(l, "agentOS/") {
				t.Fatalf("label %q outside agentOS/", l)
			}
		}
	}
}

func TestAlertsAreNeitherUnsubscribableNorPlannedForTrash(t *testing.T) {
	r := newRig(t, 30)
	for _, it := range r.acct.Listing() {
		if it.Mail == "A01" && it.Sender != "" {
			t.Fatal("alert mail was offered for unsubscribe")
		}
	}
	for _, p := range Plans(r.acct.Listing(), r.planner) {
		if strings.HasSuffix(p.ID, "A01") && strings.HasPrefix(p.ID, "trash") {
			t.Fatal("alert mail was planned for trash")
		}
	}
}
