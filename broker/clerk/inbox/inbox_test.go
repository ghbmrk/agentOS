package inbox

// REQ: CLK-2, VRB-2

import (
	"crypto/ed25519"
	"math/rand/v2"
	"strconv"
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
	acct        *Account
	k           *kernel.Kernel
	planner     key.Key
	plannerPriv ed25519.PrivateKey
	bulk        key.Key
	unsub       key.Key
	world       *World
	now         int64 // the clerk's own clock
}

// tick runs the kernel at now, with the clerk's own clock at now too.
func (r *rig) tick(now int64) error {
	r.now = now
	return r.k.Tick(now)
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
	plannerPub, plannerPriv := seed(4)
	r := &rig{world: &w, plannerPriv: plannerPriv, now: t0}
	var err error
	r.acct, err = NewAccount([]ed25519.PublicKey{ownerPub}, []byte(secret), func() World { return *r.world }, ms, retention, "List-Unsubscribe=One-Click")
	if err != nil {
		t.Fatal(err)
	}
	log, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: headPub, Sign: headPriv,
		Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	r.k, err = kernel.Boot(log, anchors(), map[string]kernel.Clerk{Name: r.acct}, t0-dayMS)
	if err != nil {
		t.Fatal(err)
	}
	r.acct.Bind(r.k.State())
	r.acct.Clock = func() int64 { return r.now }
	// The passkey granted the root and the home clerk's key at setup (D-146).
	root, err := key.ClerkKey(key.Issue(ownerPriv, key.Root{Clerk: Name, Verbs: []key.Verb{key.Organize, key.Trash, key.Unsubscribe}, Serial: mailKey}),
		ownerPriv, holderPub, t0, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, backup := seed(12) // the second hardware key co-signs the setup grants (D-146)
	batch := []key.Key{{Root: root.Root}, root}
	if err := r.k.Issue(t0-dayMS-kernel.GrantHold, []key.Cosign{key.Approve(backup, kernel.BatchHash(batch...))}, batch...); err != nil {
		t.Fatal(err)
	}
	if err := log.Anchor(); err != nil {
		t.Fatal(err)
	}
	r.planner, err = key.Derive(root, holderPriv, plannerPub, caveats...)
	if err != nil {
		t.Fatal(err)
	}
	r.bulk, r.unsub, err = PlannerKeys(root, holderPriv, plannerPub, 600_000, dayMS)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// onKey is step on a given key.
func (r *rig) onKey(k key.Key, id string, v key.Verb, args map[string]string) kernel.Plan {
	p := r.step(id, v, args)
	p.Key = k
	return kernel.SignPlan(p, r.plannerPriv)
}

func (r *rig) step(id string, v key.Verb, args map[string]string) kernel.Plan {
	return kernel.SignPlan(kernel.Plan{ID: id, Key: r.planner, Steps: []kernel.PlanStep{{Verb: v, Clerk: Name, Args: args}}}, r.plannerPriv)
}

func (r *rig) run(t *testing.T, p kernel.Plan, ticks ...int64) {
	t.Helper()
	if err := r.k.Submit(t0, p); err != nil {
		t.Fatal(err)
	}
	for _, at := range append([]int64{t0}, ticks...) {
		if err := r.tick(at); err != nil {
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

func (staleView) Granted(key.ID) (int64, bool) { return 0, true }
func (staleView) Dispatched(kernel.Request) (kernel.Dispatch, bool) {
	return kernel.Dispatch{Held: true}, true
}

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
	res := r.acct.Do(kernel.Request{Plan: p}, r.k.State())
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
	res := r.acct.Do(kernel.Request{Plan: p}, staleView{})
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
	r.acct.Do(kernel.Request{Plan: forged}, r.k.State())
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

// REQ: VRB-2, KEY-3 (assumption MIG-3-15)
// A planner that strips its bulk key back to the root, or to the unsubscribe
// key's root, and signs as itself is refused: the root's holder is the home
// clerk, so the cap and the hold stay on the key it was handed.
func TestStrippedPlannerKeyDoesNothing(t *testing.T) {
	r := newRig(t, 30)
	for i, k := range []key.Key{{Root: r.bulk.Root}, {Root: r.unsub.Root}} {
		id := "strip-" + strconv.Itoa(i)
		p := r.onKey(k, id, key.Organize, map[string]string{"target": "M19", "label": labelPrefix + r.acct.mails["M19"].Class})
		if err := r.k.Submit(t0, p); err == nil && r.k.State().Plans[id].Status != kernel.SRejected {
			t.Fatalf("plan %s on a stripped key was admitted", id)
		}
	}
	_ = r.tick(t0)
	if n := len(r.acct.Effects()); n != 0 {
		t.Fatalf("%d effects from stripped keys", n)
	}
}

// REQ: VRB-2 (assumption MIG-3-15)
// The cap is the key's, counted at the clerk from the log: a hostile planner
// pushing 250 organizes on the key Run derives gets 200, and a restart in the
// middle of the day does not reset the count. Unsubscribe is not counted.
func TestBulkKeyCapsOrganizeAndTrashAtTheClerkAcrossARestart(t *testing.T) {
	r := newRig(t, 30)
	organize := func(i int) kernel.Plan {
		return r.onKey(r.bulk, "hostile-"+strconv.Itoa(i), key.Organize,
			map[string]string{"target": "M19", "label": labelPrefix + r.acct.mails["M19"].Class})
	}
	for i := 0; i < 150; i++ {
		if err := r.k.Submit(t0, organize(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.tick(t0); err != nil {
		t.Fatal(err)
	}
	// Restart: a new kernel over the same log, as after a crash.
	k2, err := kernel.Boot(r.k.Log(), anchors(), map[string]kernel.Clerk{Name: r.acct}, t0)
	if err != nil {
		t.Fatal(err)
	}
	r.k = k2
	r.acct.Bind(k2.State())
	for i := 150; i < 250; i++ {
		_ = r.k.Submit(t0, organize(i))
	}
	if err := r.tick(t0); err != nil {
		t.Fatal(err)
	}
	if n := len(r.acct.Effects()); n != DailyCap {
		t.Fatalf("%d effects from 250 organizes, want %d", n, DailyCap)
	}
	// A trash is the 201st action of the same key and is refused too.
	_ = r.k.Submit(t0, r.onKey(r.bulk, "trash-201", key.Trash, map[string]string{"target": "M19"}))
	_ = r.tick(t0)
	if n := len(r.acct.Effects()); n != DailyCap {
		t.Fatalf("%d effects after a 201st trash", n)
	}
	// Unsubscribe is another key and is not counted.
	var h string
	for _, it := range r.acct.Listing() {
		if it.Sender != "" {
			h = it.Sender
			break
		}
	}
	if h == "" {
		t.Fatal("no eligible sender in the fixture")
	}
	r.run(t, r.onKey(r.unsub, "unsub-after-cap", key.Unsubscribe, map[string]string{"to": h}), t0+dayMS)
	if n := len(r.acct.Effects()); n != DailyCap+1 {
		t.Fatalf("%d effects, want the unsubscribe on top of the cap", n)
	}
}

// REQ: VRB-2 (assumption MIG-3-15)
// The bulk key cannot unsubscribe, and the unsubscribe key cannot organize.
func TestSiblingKeysCarryOnlyTheirOwnVerbs(t *testing.T) {
	r := newRig(t, 30)
	_ = r.k.Submit(t0, r.onKey(r.bulk, "u", key.Unsubscribe, map[string]string{"to": "x"}))
	_ = r.k.Submit(t0, r.onKey(r.unsub, "o", key.Organize, map[string]string{"target": "M19", "label": "agentOS/spam"}))
	for _, id := range []string{"u", "o"} {
		if p := r.k.State().Plans[id]; p == nil || p.Status != kernel.SRejected {
			t.Fatalf("plan %s was not rejected", id)
		}
	}
}

// REQ: CLK-2, VRB-2 (assumption MIG-3-16)
// A label is exactly agentOS/ plus the class the clerk assigned to that mail,
// whatever the key allows: an owner-namespace label is refused at the clerk.
func TestClerkRefusesAnyLabelButItsOwnClassLabel(t *testing.T) {
	r := newRig(t, 30)
	class := r.acct.mails["M19"].Class
	for i, l := range []string{"Owner/Label", "agentOS/", "agentOS/other", "agentOS/" + class + "/x", "", "agentos/" + class} {
		id := "lbl-" + strconv.Itoa(i)
		r.run(t, r.onKey(r.bulk, id, key.Organize, map[string]string{"target": "M19", "label": l}))
		if rf := r.lastRefusal(t); rf.Reason != "bad-label" {
			t.Fatalf("label %q: refusal %+v", l, rf)
		}
	}
	if n := len(r.acct.Effects()); n != 0 {
		t.Fatalf("%d effects from bad labels", n)
	}
	r.run(t, r.onKey(r.bulk, "lbl-ok", key.Organize, map[string]string{"target": "M19", "label": "agentOS/" + class}))
	if n := len(r.acct.Effects()); n != 1 {
		t.Fatalf("%d effects from the right label", n)
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
	if err := r.tick(t0); err != nil {
		t.Fatal(err)
	}
	// While the step is held the owner opens the sender's mail.
	opened := *r.world
	opened.LastOpened = map[string]string{"news@shop.test": opened.Today}
	*r.world = opened
	for _, at := range []int64{t0 + 600_000, t0 + dayMS} {
		if err := r.tick(at); err != nil {
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
	plans, _ := Plans(r.acct.Listing(), r.bulk, r.unsub, r.plannerPriv)
	for _, p := range plans {
		for _, s := range p.Steps {
			if l := s.Args["label"]; s.Verb == key.Organize && !strings.HasPrefix(l, "agentOS/") {
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
	plans, _ := Plans(r.acct.Listing(), r.bulk, r.unsub, r.plannerPriv)
	for _, p := range plans {
		if strings.HasSuffix(p.ID, "A01") && strings.HasPrefix(p.ID, "trash") {
			t.Fatal("alert mail was planned for trash")
		}
	}
}

func TestPlansSpendTheCapOnTrashFirstAndCountWhatIsLeft(t *testing.T) {
	var l []Item
	for i := 0; i < DailyCap; i++ {
		l = append(l, Item{Mail: "M" + strconv.Itoa(i), Class: "newsletter"})
	}
	l = append(l, Item{Mail: "S1", Class: "spam"}, Item{Mail: "U1", Class: "bulk", Sender: "h1"})
	plans, left := Plans(l, key.Key{}, key.Key{}, seedPriv(4))
	var trash, org, unsub int
	for _, p := range plans {
		switch p.Steps[0].Verb {
		case key.Trash:
			trash++
		case key.Organize:
			org++
		case key.Unsubscribe:
			unsub++
		}
	}
	if trash != 1 || org != DailyCap-1 || unsub != 1 || left != (Left{Organize: 3}) {
		t.Fatalf("trash %d organize %d unsub %d left %+v", trash, org, unsub, left)
	}
}

func seedPriv(b byte) ed25519.PrivateKey { _, p := seed(b); return p }

// anchors are the kernel's: the owner's passkey and the second hardware key.
func anchors() []ed25519.PublicKey {
	o, _ := seed(1)
	b, _ := seed(12)
	return []ed25519.PublicKey{o, b}
}

// The inbox clerk judges a hold on its own clock: a kernel whose clock runs
// past the window releases the unsubscribe, and the clerk, still inside it,
// refuses and posts nothing (CLK-2, KEY-8).
func TestInboxClerkKeepsTheHoldOnItsOwnClock(t *testing.T) {
	r := newRig(t, 30, key.LimitHold(600_000, dayMS))
	h := handleOfMail(t, r, "M01")
	if err := r.k.Submit(t0, r.step("u", key.Unsubscribe, map[string]string{"to": h})); err != nil {
		t.Fatal(err)
	}
	if err := r.tick(t0); err != nil { // held at t0
		t.Fatal(err)
	}
	r.now = t0 + 1 // the clerk's clock: inside both windows
	if err := r.k.Tick(t0 + 2*dayMS); err != nil {
		t.Fatal(err)
	}
	if len(r.acct.Posts()) != 0 {
		t.Fatalf("posted inside the hold on the clerk's clock: %v", r.acct.Posts())
	}
	if rf := r.lastRefusal(t); rf.Reason != "hold" {
		t.Fatalf("refusal %+v, want hold", rf)
	}
}
