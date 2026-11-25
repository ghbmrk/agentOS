package owner

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: CH-2, CH-10, CH-12, CH-13, CH-18, SM-AJ-4
// MUT-kill-5974-owner (#6670): each approvals.go statement that mutgate's
// deletion left alive on #5974 is pinned here by a test that fails without
// it. The tests call the channel's own methods under its lock where they
// can, so they reach as little of the package as the line they pin.

// sendFailModem refuses every text.
type sendFailModem struct{ modem.Modem }

func (sendFailModem) Send(string, string) error { return errors.New("no signal") }

// cycleRand repeats one byte pattern forever, so two channels given it draw
// the same IDs.
type cycleRand struct {
	b []byte
	i int
}

func (c *cycleRand) Read(p []byte) (int, error) {
	for k := range p {
		p[k] = c.b[c.i%len(c.b)]
		c.i++
	}
	return len(p), nil
}

// mutOpen opens a request for items without texting it.
func mutOpen(t *testing.T, ch *Channel, items []Item, deadline time.Time, local bool) *request {
	t.Helper()
	ch.mu.Lock()
	defer ch.mu.Unlock()
	r, err := ch.openLocked(items, deadline, ch.cfg.Now(), local)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// mutRender is a request's text, rendered without sending it.
func mutRender(ch *Channel, r *request) string {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	return ch.renderLocked(r)
}

// mutAnswer applies one reply under the lock, as Handle does after it parsed it.
func mutAnswer(ch *Channel, rp reply, page bool) ([]string, []Decision) {
	var ds []Decision
	ch.mu.Lock()
	defer ch.mu.Unlock()
	out, _, _ := ch.answerLocked(rp, ch.cfg.Now(), &ds, page)
	return out, ds
}

func TestMutRequestsNeedAModem(t *testing.T) {
	r := newRig(t, nil)
	r.edit = func(c *Config) { c.Modem = nil }
	r.ch = r.open()
	if _, err := r.ch.Request([]Item{lowItem("a")}, 0); err == nil || err.Error() != "owner: no modem" {
		t.Fatalf("Request: %v", err)
	}
	if _, err := r.ch.RequestEach([]Item{lowItem("a")}, []time.Time{{}}); err == nil || err.Error() != "owner: no modem" {
		t.Fatalf("RequestEach: %v", err)
	}
	if _, err := r.ch.RequestLocal(localItem("a"), 0); err == nil || err.Error() != "owner: no modem" {
		t.Fatalf("RequestLocal: %v", err)
	}
	if n := len(r.ch.open); n != 0 {
		t.Fatalf("%d requests opened with no modem", n)
	}
}

// A request whose text was not sent is closed and its ID retired.
func TestMutAnUnsentRequestIsDroppedAndRetired(t *testing.T) {
	r := newRig(t, nil)
	r.edit = func(c *Config) { c.Modem = sendFailModem{r.box} }
	r.ch = r.open()
	if _, err := r.ch.Request([]Item{lowItem("a")}, 0); err == nil {
		t.Fatal("sent")
	}
	if n := len(r.ch.open); n != 0 {
		t.Fatalf("%d requests still open", n)
	}
	if p := r.ch.codes.st.Pending; len(p) != 0 {
		t.Fatalf("still pending: %+v", p)
	}
	if n := len(r.ch.codes.st.Retired); n != 1 {
		t.Fatalf("%d IDs retired", n)
	}
}

// A local request the record cannot hold is refused, not texted.
func TestMutALocalRequestThatCannotBeSavedIsRefused(t *testing.T) {
	fs := &failStore{}
	r := newRig(t, fs)
	fs.fail = true
	if _, err := r.ch.RequestLocal(localItem("a"), 0); err == nil {
		t.Fatal("opened")
	}
}

func TestMutARequestHoldsOneToTwentyItems(t *testing.T) {
	r := newRig(t, nil)
	many := make([]Item, 21)
	for i := range many {
		many[i] = lowItem(fmt.Sprint(i))
	}
	for _, items := range [][]Item{nil, many} {
		r.ch.mu.Lock()
		_, err := r.ch.openLocked(items, time.Time{}, r.clock(), false)
		r.ch.mu.Unlock()
		if err == nil || err.Error() != "owner: a request has 1 to 20 items" {
			t.Fatalf("%d items: %v", len(items), err)
		}
	}
}

// No request outlives MaxTTL, and a low-tier one not CodeTTL (CH-10).
func TestMutExpiryIsCapped(t *testing.T) {
	r := newRig(t, nil)
	now := r.clock()
	if got := mutOpen(t, r.ch, []Item{localItem("a")}, now.Add(48*time.Hour), true).expires; !got.Equal(now.Add(MaxTTL)) {
		t.Fatalf("local: expires %v", got)
	}
	if got := mutOpen(t, r.ch, []Item{lowItem("b")}, now.Add(2*time.Hour), false).expires; !got.Equal(now.Add(DefaultCodeTTL)) {
		t.Fatalf("low: expires %v", got)
	}
}

// Requests are numbered in the order they open, for the local page.
func TestMutRequestsAreNumberedInOrder(t *testing.T) {
	r := newRig(t, nil)
	a := mutOpen(t, r.ch, []Item{lowItem("a")}, time.Time{}, false)
	b := mutOpen(t, r.ch, []Item{lowItem("b")}, time.Time{}, false)
	if a.n != 1 || b.n != 2 {
		t.Fatalf("numbered %d, %d", a.n, b.n)
	}
}

// A re-issued item keeps the time it was first asked in the record.
func TestMutAReissuedItemKeepsItsAskedTime(t *testing.T) {
	r := newRig(t, nil)
	it := lowItem("a")
	it.Asked = r.clock().Add(-time.Hour)
	mutOpen(t, r.ch, []Item{it}, time.Time{}, false)
	if p := r.ch.codes.st.Pending; len(p) != 1 || !p[0].Asked.Equal(it.Asked) {
		t.Fatalf("pending %+v", p)
	}
}

// A local notice warns of unverified fields and of an owner retry.
func TestMutLocalNoticeWarnings(t *testing.T) {
	r := newRig(t, nil)
	it := localItem("a")
	it.Unverified = true
	if got := mutRender(r.ch, mutOpen(t, r.ch, []Item{it}, time.Time{}, true)); !strings.HasPrefix(got, "UNVERIFIED: Can I ") {
		t.Fatalf("unverified: %q", got)
	}
	it = localItem("b")
	it.Retried = r.clock().Add(-time.Hour)
	if got := mutRender(r.ch, mutOpen(t, r.ch, []Item{it}, time.Time{}, true)); !strings.Contains(got, "\" again? It may go twice; first tried 11:00 Oct 4.") {
		t.Fatalf("retried: %q", got)
	}
}

// A high-tier batch asks for the code generator and says how to approve some.
func TestMutAHighBatchSaysHowToApproveSome(t *testing.T) {
	r := newRig(t, nil)
	q := mutOpen(t, r.ch, []Item{highItem("a"), highItem("b")}, time.Time{}, false)
	want := fmt.Sprintf("Reply YES %s and a code from your code generator%s (add item numbers to approve some; the rest are denied), or NO %s.", q.id, r.ch.gridOr(), q.id)
	if got := mutRender(r.ch, q); !strings.HasSuffix(got, want) {
		t.Fatalf("text %q\nwant suffix %q", got, want)
	}
}

// MORE: an unknown ID is said; a closed item is skipped; items that do not
// fit end the list once.
func TestMutMoreListsOpenItemsThatFit(t *testing.T) {
	r := newRig(t, nil)
	more := func(id string) string {
		r.ch.mu.Lock()
		defer r.ch.mu.Unlock()
		return r.ch.moreLocked(id)
	}
	if got := more("Z9"); got != "No open request Z9." {
		t.Fatalf("unknown: %q", got)
	}
	var items []Item
	for i := 0; i < 20; i++ {
		it := lowItem(fmt.Sprint(i))
		it.Object = fmt.Sprintf("invoice %02d %s", i, strings.Repeat("x", 30))
		items = append(items, it)
	}
	q := mutOpen(t, r.ch, items, time.Time{}, false)
	q.done[0] = true
	got := more(q.id)
	if !strings.HasPrefix(got, q.id+": 2 ") {
		t.Fatalf("start: %q", got)
	}
	if n := strings.Count(got, "Rest on my Wi-Fi page."); n != 1 {
		t.Fatalf("%d rests: %q", n, got)
	}
}

// A request past its expiry when answered is expired there and kept for
// the digest (CH-10, CH-13).
func TestMutAnAnswerExpiresALateRequestForTheDigest(t *testing.T) {
	r := newRig(t, nil)
	q := mutOpen(t, r.ch, []Item{lowItem("a")}, time.Time{}, false)
	r.advance(time.Hour)
	out, ds := mutAnswer(r.ch, reply{word: "NO", id: q.id}, false)
	if len(ds) != 1 || ds[0].Why != "expired" {
		t.Fatalf("decided %+v (%q)", ds, out)
	}
	if exp, _ := r.ch.TakeExpired(); len(exp) != 1 {
		t.Fatalf("digest %+v", exp)
	}
}

// A wrong ID-less code whose count cannot be saved says so (CH-18).
func TestMutAnUnsavedWrongCodeSaysSo(t *testing.T) {
	fs := &failStore{}
	r := newRig(t, fs)
	fs.fail = true
	if out, _ := mutAnswer(r.ch, reply{word: "YES", code: "123456"}, false); !reflect.DeepEqual(out, []string{stateErr}) {
		t.Fatalf("reply %q", out)
	}
}

// An item number past the batch, or already closed, is refused.
func TestMutAnswersNameOnlyOpenItems(t *testing.T) {
	r := newRig(t, nil)
	q := mutOpen(t, r.ch, []Item{lowItem("a"), lowItem("b")}, time.Time{}, false)
	want := fmt.Sprintf("%s has no open item 3.", q.id)
	if out, ds := mutAnswer(r.ch, reply{word: "NO", id: q.id, items: []int{3}}, false); !reflect.DeepEqual(out, []string{want}) || len(ds) != 0 {
		t.Fatalf("item 3: %q %+v", out, ds)
	}
	q.done[0] = true
	want = fmt.Sprintf("%s has no open item 1.", q.id)
	if out, ds := mutAnswer(r.ch, reply{word: "NO", id: q.id, items: []int{1}}, false); !reflect.DeepEqual(out, []string{want}) || len(ds) != 0 {
		t.Fatalf("closed item 1: %q %+v", out, ds)
	}
}

// A partial YES on the page: the chosen item is approved by the owner on
// the page, the other denied as not chosen, and only the approval carries
// the page's mark.
func TestMutAPartialPageYesMarksOnlyTheApproval(t *testing.T) {
	r := newRig(t, nil)
	q := mutOpen(t, r.ch, []Item{highItem("a"), highItem("b")}, time.Time{}, false)
	_, ds := mutAnswer(r.ch, reply{word: "YES", id: q.id, items: []int{1}, code: r.totp()}, true)
	if len(ds) != 2 {
		t.Fatalf("decided %+v", ds)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i].Item < ds[j].Item })
	if a := ds[0]; !a.Approved || a.Why != "owner" || !a.Page || a.Sum == "" {
		t.Fatalf("approved %+v", a)
	}
	if d := ds[1]; d.Approved || d.Why != "not chosen" || d.Page || d.Sum != "" {
		t.Fatalf("denied %+v", d)
	}
}

// An approved item that cannot be held is not queued to run (REV-3).
func TestMutAnUnheldItemIsNotQueued(t *testing.T) {
	r := newRig(t, &holdFailStore{})
	it := heldItem("a")
	q := mutOpen(t, r.ch, []Item{it, highItem("b")}, time.Time{}, false)
	_, ds := mutAnswer(r.ch, reply{word: "YES", id: q.id, code: r.totp()}, false)
	for _, d := range ds {
		if d.Ref == "a" && (d.Approved || d.Hold != "") {
			t.Fatalf("unheld item %+v", d)
		}
	}
	if n := len(r.ch.queued); n != 0 {
		t.Fatalf("%d queued", n)
	}
}

// revRec records what the checker was asked to withdraw.
type revRec struct {
	Verifier
	revoked []string
}

func (v *revRec) RevokeActs(acts ...string) error { v.revoked = append(v.revoked, acts...); return nil }
func (v *revRec) ReleaseActs(...string) error     { return nil }
func (v *revRec) AllowActs(...CheckerAct) error   { return nil }

// Only real acts reach the checker; an item with none adds nothing.
func TestMutOnlyRealActsAreWithdrawn(t *testing.T) {
	r := newRig(t, nil)
	v := &revRec{}
	r.ch.codes.verify = v
	if err := r.ch.revoke("", "act-a", ""); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(v.revoked, []string{"act-a"}) {
		t.Fatalf("revoked %q", v.revoked)
	}
}

func TestMutNoOpenRequestsIsSaid(t *testing.T) {
	r := newRig(t, nil)
	r.ch.mu.Lock()
	_, msg := r.ch.findLocked(reply{word: "NO"})
	r.ch.mu.Unlock()
	if msg != "No open requests." {
		t.Fatalf("%q", msg)
	}
}

// Retiring an ID drops only it from the record and forgets retirements
// older than RetireFor (CH-18).
func TestMutRetiringDropsOnlyThatID(t *testing.T) {
	r := newRig(t, nil)
	now := r.clock()
	st := &r.ch.codes.st
	st.Pending = []PendingRef{{ID: "A2"}, {ID: "B3"}}
	st.Queued = []QueuedRef{{ID: "A2"}, {ID: "C4"}}
	st.Retired = map[string]time.Time{"D5": now.Add(-RetireFor), "E6": now.Add(-time.Minute)}
	r.ch.mu.Lock()
	err := r.ch.retireLocked("A2", now)
	r.ch.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(st.Pending, []PendingRef{{ID: "B3"}}) || !reflect.DeepEqual(st.Queued, []QueuedRef{{ID: "C4"}}) {
		t.Fatalf("pending %+v queued %+v", st.Pending, st.Queued)
	}
	if !reflect.DeepEqual(st.Retired, map[string]time.Time{"A2": now, "E6": now.Add(-time.Minute)}) {
		t.Fatalf("retired %+v", st.Retired)
	}
}

// A retirement that saves clears an earlier unsaved one's report (SM-AJ-4).
func TestMutASavedRetirementClearsTheReport(t *testing.T) {
	fs := &failStore{}
	r := newRig(t, fs)
	fs.fail = true
	r.ch.mu.Lock()
	r.ch.retireLocked("A2", r.clock())
	r.ch.mu.Unlock()
	if r.ch.RetireErr() == nil {
		t.Fatal("no report")
	}
	fs.fail = false
	r.ch.mu.Lock()
	r.ch.retireLocked("B3", r.clock())
	r.ch.mu.Unlock()
	if err := r.ch.RetireErr(); err != nil {
		t.Fatal(err)
	}
}

// An expired RESUME code is dropped.
func TestMutAnExpiredResumeCodeIsDropped(t *testing.T) {
	r := newRig(t, nil)
	r.ch.mu.Lock()
	r.ch.resume = &resumeCode{expires: r.clock()}
	r.ch.expireLocked(r.clock())
	gone := r.ch.resume == nil
	r.ch.mu.Unlock()
	if !gone {
		t.Fatal("kept")
	}
}

// The digest keeps MaxExpired entries and counts the rest; taking it
// clears both.
func TestMutTheDigestIsBoundedAndTaken(t *testing.T) {
	r := newRig(t, nil)
	r.ch.mu.Lock()
	r.ch.addExpiredLocked(make([]Decision, MaxExpired+5))
	r.ch.mu.Unlock()
	if ds, more := r.ch.TakeExpired(); len(ds) != MaxExpired || more != 5 {
		t.Fatalf("%d kept, %d more", len(ds), more)
	}
	if ds, more := r.ch.TakeExpired(); len(ds) != 0 || more != 0 {
		t.Fatalf("taken twice: %d, %d", len(ds), more)
	}
}

func TestMutNoDeciderIsCalledWhenNoneIsSet(t *testing.T) {
	r := newRig(t, nil)
	r.ch.cfg.Decide = nil
	r.ch.decide([]Decision{{Request: "A2"}})
}

func TestMutOpenIDsAreSorted(t *testing.T) {
	r := newRig(t, nil)
	r.ch.mu.Lock()
	for i := 0; i < 12; i++ {
		r.ch.open[fmt.Sprintf("%c2", 'A'+i)] = &request{}
	}
	ids := r.ch.openIDsLocked()
	r.ch.mu.Unlock()
	if !sort.StringsAreSorted(ids) || len(ids) != 12 {
		t.Fatalf("%q", ids)
	}
}

// A new ID is a letter and a digit while those are free, and never one an
// open request, queued reply, pending or queued record holds (CH-12, CH-18).
func TestMutNewIDsAreShortAndFree(t *testing.T) {
	pattern := []byte{0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac}
	fresh := func(hold func(*Channel, string)) (first, got string) {
		r := newRig(t, nil)
		r.edit = func(c *Config) { c.Rand = &cycleRand{b: pattern} }
		ch := r.open()
		ch.mu.Lock()
		defer ch.mu.Unlock()
		first, err := ch.newIDLocked(r.clock())
		if err != nil {
			t.Fatal(err)
		}
		if hold == nil {
			return first, first
		}
		ch.cfg.Rand = &cycleRand{b: pattern}
		hold(ch, first)
		got, err = ch.newIDLocked(r.clock())
		if err != nil {
			t.Fatal(err)
		}
		return first, got
	}
	if id, _ := fresh(nil); len(id) != 2 {
		t.Fatalf("first ID %q", id)
	}
	for name, hold := range map[string]func(*Channel, string){
		"open":    func(c *Channel, id string) { c.open[id] = &request{} },
		"queued":  func(c *Channel, id string) { c.queued[id] = &Queued{} },
		"pending": func(c *Channel, id string) { c.codes.st.Pending = []PendingRef{{ID: id}} },
		"record":  func(c *Channel, id string) { c.codes.st.Queued = []QueuedRef{{ID: id}} },
	} {
		if first, got := fresh(hold); got == first {
			t.Fatalf("%s: reused %q", name, got)
		}
	}
}
