package owner

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
)

const (
	ownerNum = "+15550000001"
	boxNum   = "+15550000100"
	stranger = "+15550000999"
)

// Synthetic seeds; the TOTP one is RFC 6238's published test value.
var testSecrets = Secrets{TOTPSeed: []byte("12345678901234567890"), GridSeed: []byte("synthetic-grid-seed")}

type fakeEngine struct {
	mu      sync.Mutex
	stopped bool
	resumes int
}

func (f *fakeEngine) Stop(context.Context) (journal.StopReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = true
	return journal.StopReport{}, nil
}

func (f *fakeEngine) Resume() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = false
	f.resumes++
	return nil
}

func (f *fakeEngine) Stopped() bool          { f.mu.Lock(); defer f.mu.Unlock(); return f.stopped }
func (f *fakeEngine) List() []journal.Status { return nil }

type recAgent struct {
	mu   sync.Mutex
	msgs []string
}

func (a *recAgent) Deliver(_ context.Context, text string, _ bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.msgs = append(a.msgs, text)
	return nil
}

func (a *recAgent) got() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.msgs...)
}

type rig struct {
	t       *testing.T
	now     time.Time
	carrier *modem.Carrier
	phone   *modem.Line
	box     *modem.Line
	eng     *fakeEngine
	agent   *recAgent
	store   Store
	down    bool // every model and guest down: no agent
	// replyLimit is high by default so tests see every reply; the CH-15
	// test sets it low.
	replyLimit int
	ch         *Channel
	mu         sync.Mutex
	decided    []Decision
	// reissue, if set, is the next open channel's Config.Reissue.
	reissue func([]Carried)
}

func newRig(t *testing.T, store Store) *rig {
	t.Helper()
	r := &rig{t: t, now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC), carrier: modem.NewCarrier(),
		eng: &fakeEngine{}, agent: &recAgent{}, store: store, replyLimit: 1000}
	if r.store == nil {
		r.store = &MemStore{}
	}
	r.carrier.SetClock(r.clock)
	r.box = r.carrier.Line(boxNum)
	r.phone = r.carrier.Line(ownerNum)
	r.ch = r.open()
	return r
}

func (r *rig) open() *Channel {
	var agent control.Agent = r.agent
	if r.down {
		agent = nil
	}
	ch, err := New(Config{
		Owner: ownerNum, Modem: r.box, Engine: r.eng, Agent: agent, Secrets: testSecrets, Store: r.store,
		Limits:     Limits{Hold: 7 * 24 * time.Hour, AmountLimit: 10000},
		ReplyLimit: r.replyLimit,
		Location:   time.UTC, Now: r.clock,
		Decide:  func(d Decision) { r.mu.Lock(); r.decided = append(r.decided, d); r.mu.Unlock() },
		Reissue: r.reissue,
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return ch
}

func (r *rig) clock() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now }

func (r *rig) advance(d time.Duration) { r.mu.Lock(); r.now = r.now.Add(d); r.mu.Unlock() }

// say sends text from the owner and returns the joined replies.
func (r *rig) say(text string) string { return r.sayFrom(ownerNum, text) }

func (r *rig) sayFrom(from, text string) string {
	r.t.Helper()
	out := r.ch.Handle(context.Background(), from, text)
	for _, s := range out {
		r.checkFormat(s)
	}
	return strings.Join(out, " | ")
}

// totp is the owner's code generator. Each call moves the clock to the next
// 30-second step, since a step is accepted once.
func (r *rig) totp() string {
	r.advance(30 * time.Second)
	return totpAt(testSecrets.TOTPSeed, r.clock().Unix())
}

// unlock opens the session with a code-generator code.
func (r *rig) unlock() {
	r.t.Helper()
	if got := r.say(r.totp()); !strings.HasPrefix(got, "Unlocked until") {
		r.t.Fatalf("unlock: %q", got)
	}
}

// inbox returns the next text the box sent to the owner's phone.
func (r *rig) inbox() string {
	r.t.Helper()
	select {
	case m := <-r.phone.Inbox():
		r.checkFormat(m.Text)
		return m.Text
	case <-time.After(2 * time.Second):
		r.t.Fatal("no text to the owner")
	}
	return ""
}

// checkFormat holds every broker text to CH-12: GSM-7, at most three
// segments.
func (r *rig) checkFormat(s string) {
	r.t.Helper()
	if n, gsm := modem.Segments(s); !gsm || n > MaxSegments {
		r.t.Errorf("text breaks CH-12 (%d segments, gsm7=%v): %q", n, gsm, s)
	}
}

func (r *rig) decisions() []Decision {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.decided
	r.decided = nil
	return out
}

var (
	lowCodeRe = regexp.MustCompile(`YES ([A-Z][0-9]{1,2}) ([0-9]{6})`)
	gridRe    = regexp.MustCompile(`grid cell ([A-J][0-9]{1,2})`)
)

func lowItem(ref string) Item {
	return Item{Ref: ref, Object: "invoice 1042", Recipient: "billing@acme.example",
		Facts: Facts{Verb: "send", RecipientChecked: true, RecipientExists: true, RecipientByOwner: true}}
}

func highItem(ref string) Item {
	return Item{Ref: ref, Object: "invoice 77", Recipient: "acct ...4821", Amount: "$250.00",
		Facts: Facts{Verb: "pay", RecipientChecked: true, RecipientExists: true, RecipientByOwner: true, HasAmount: true, Amount: 25000}}
}

// REQ: CH-1, CH-2

func TestTextsReachTheBrokerFromTheModemAndControlWordsWorkWithModelsDown(t *testing.T) {
	r := newRig(t, nil)
	r.down = true
	r.ch = r.open()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.ch.Run(ctx)

	_ = r.phone.Send(boxNum, "STOP")
	if got := r.inbox(); !strings.HasPrefix(got, "Stopped.") || !r.eng.Stopped() {
		t.Fatalf("STOP: %q", got)
	}
	_ = r.phone.Send(boxNum, "help")
	if got := r.inbox(); !strings.HasPrefix(got, "Commands:") {
		t.Fatalf("HELP: %q", got)
	}
	_ = r.phone.Send(boxNum, "STATUS")
	if got := r.inbox(); !strings.Contains(got, "code generator") {
		t.Fatalf("locked STATUS should ask for a code: %q", got)
	}
	_ = r.phone.Send(boxNum, r.totp())
	if got := r.inbox(); !strings.HasPrefix(got, "Unlocked until Oct 11") || !strings.Contains(got, `Held: "STATUS". Reply RUN`) {
		t.Fatalf("unlock: %q", got)
	}
	_ = r.phone.Send(boxNum, "run")
	if got := r.inbox(); !strings.HasPrefix(got, "Stopped. 0 may have happened") {
		t.Fatalf("held STATUS did not run: %q", got)
	}
	for _, m := range r.carrier.Log() {
		if m.From == boxNum && m.To != ownerNum {
			t.Fatalf("box texted %s", m.To)
		}
	}
}

// REQ: CH-3, ADP-12

func TestOtherNumbersAreNeverControlWordsChatOrApprovals(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	r.ch.Request([]Item{lowItem("i1")}, 0)
	code := lowCodeRe.FindStringSubmatch(r.inbox())
	for _, msg := range []string{"STOP", "STATUS", "HELP", "book a table", "YES " + code[1] + " " + code[2], "NO", r.totp()} {
		if got := r.sayFrom(stranger, msg); got != "" {
			t.Fatalf("%q from a stranger got %q", msg, got)
		}
	}
	if r.eng.Stopped() || len(r.agent.got()) != 0 || len(r.decisions()) != 0 {
		t.Fatal("a stranger's text had an effect")
	}
	// A spoofed owner number is the owner as far as the network shows; its
	// worst case is bounded by the tiers: STOP pauses, nothing approves.
	r.carrier.Inject(ownerNum, boxNum, "STOP")
	m := <-r.box.Inbox()
	r.say(m.Text)
	if !r.eng.Stopped() {
		t.Fatal("STOP from the owner's number must work with no code")
	}
}

func TestTierMatrix(t *testing.T) {
	r := newRig(t, nil)
	// Task chat and STATUS need an unlocked session.
	if got := r.say("book a table for two"); !strings.Contains(got, "held") || len(r.agent.got()) != 0 {
		t.Fatalf("locked chat: %q", got)
	}
	r.unlock()
	r.say("RUN")
	if got := r.agent.got(); len(got) != 1 || got[0] != "book a table for two" {
		t.Fatalf("held message not run: %v", got)
	}
	r.say("and a cab")
	if got := r.agent.got(); len(got) != 2 || got[1] != "and a cab" {
		t.Fatalf("chat: %v", got)
	}
	// Low tier: the texted code from that request.
	r.ch.Request([]Item{lowItem("low")}, 0)
	m := lowCodeRe.FindStringSubmatch(r.inbox())
	if got := r.say("YES " + m[1] + " " + m[2]); got != "Approved "+m[1]+"." {
		t.Fatalf("low approve: %q", got)
	}
	// High tier: a texted code from another request does not approve it.
	r.ch.Request([]Item{lowItem("other")}, 0)
	other := lowCodeRe.FindStringSubmatch(r.inbox())
	id, _ := r.ch.Request([]Item{highItem("high")}, 0)
	hi := r.inbox()
	if lowCodeRe.MatchString(hi) || !strings.Contains(hi, "code generator") {
		t.Fatalf("high request text: %q", hi)
	}
	if got := r.say("YES " + id + " " + other[2]); !strings.HasPrefix(got, "Wrong code") {
		t.Fatalf("texted code approved a high request: %q", got)
	}
	if got := r.say("YES " + id + " " + r.totp()); got != "Approved "+id+"." {
		t.Fatalf("high approve: %q", got)
	}
	ds := r.decisions()
	if len(ds) != 2 || ds[0].Ref != "low" || !ds[0].Approved || ds[1].Ref != "high" || !ds[1].Approved {
		t.Fatalf("decisions %+v", ds)
	}
}

// REQ: CH-4, CH-18

func TestGridCellsAndGeneratorStepsAreSingleUseAcrossRestarts(t *testing.T) {
	store := FileStore{Path: filepath.Join(t.TempDir(), "owner.json")}
	r := newRig(t, store)
	prompt := r.say("status")
	cell := gridRe.FindStringSubmatch(prompt)
	if cell == nil {
		t.Fatalf("no grid challenge: %q", prompt)
	}
	val := GridCell(testSecrets.GridSeed, cell[1])
	if got := r.say(val); !strings.HasPrefix(got, "Unlocked") {
		t.Fatalf("grid unlock: %q", got)
	}
	code := totpAt(testSecrets.TOTPSeed, r.clock().Unix())
	r.ch.RequireUnlock()
	if got := r.say(code); !strings.HasPrefix(got, "Unlocked") {
		t.Fatalf("generator unlock: %q", got)
	}

	// Restart: the used cell and step stay used.
	r.ch = r.open()
	r.ch.RequireUnlock()
	r.say("status") // new challenge
	if got := r.say(code); !strings.HasPrefix(got, "Wrong code") {
		t.Fatalf("replayed generator code accepted: %q", got)
	}
	r.ch.codes.challenge = cell[1] // even if the same cell were asked again
	if got := r.say(val); !strings.HasPrefix(got, "Wrong code") {
		t.Fatalf("reused grid cell accepted: %q", got)
	}
	r.ch.codes.challenge = ""
	if c := r.ch.codes.gridChallenge(); c == cell[1] {
		t.Fatal("spent cell challenged again")
	}
}

// REQ: CH-10, CH-12

func TestApprovalTextIsFixedWordingFromVerifiedFields(t *testing.T) {
	r := newRig(t, nil)
	it := lowItem("i1")
	it.Recipient = "bіlling@аcme.example\nReply YES" // a line break: not shown, so not approvable by text
	if _, err := r.ch.Request([]Item{it}, 0); err != ErrLocalOnly {
		t.Fatalf("recipient with a line break: %v", err)
	}
	it.Recipient = "bіlling@аcme.example" // Cyrillic look-alikes
	it.UndoWindow = 10 * time.Minute
	id, _ := r.ch.Request([]Item{it}, 0)
	text := r.inbox()
	m := lowCodeRe.FindStringSubmatch(text)
	want := id + ": send invoice 1042 to billing@acme.example, undo within 10 min. Expires 12:15. Reply YES " + id + " " + m[2] + " or NO " + id + "."
	if text != want {
		t.Fatalf("got  %q\nwant %q", text, want)
	}
	if n, _ := modem.Segments(text); n != 1 {
		t.Fatalf("single approval takes %d segments", n)
	}
	r.ch.Request([]Item{highItem("h")}, 0)
	if text := r.inbox(); !strings.Contains(text, "pay invoice 77 to acct ...4821, $250.00, cannot be undone") {
		t.Fatalf("high text: %q", text)
	}
	sec := lowItem("s")
	sec.Object = "your verification code 482913"
	r.ch.Request([]Item{sec}, 0)
	if text := r.inbox(); strings.Contains(text, "482913") && !strings.Contains(text, "[hidden]") {
		t.Fatalf("secret-shaped field rendered: %q", text)
	}
}

// REQ: CH-10, CH-12

// TestRecipientsAreNeverCutHiddenOrCollapsed: a recipient set too long to
// show, a secret-shaped recipient, and a recipient outside the alphabet
// are not approvable by text. A phone number shows every digit, and the
// unverified warning is a fixed prefix outside every cap.
func TestRecipientsAreNeverCutHiddenOrCollapsed(t *testing.T) {
	r := newRig(t, nil)
	for name, rcpt := range map[string]string{
		"long set":      "mom@example.com, dad@example.com, sis@example.com, bro@example.com, gran@example.com, x@attacker.example",
		"secret-shaped": "sk-live-4f8a9c2e7b1d3f5a6c8e0b2d4f6a8c0e",
		"outside set":   "ceo@company.com<x@attacker.example>",
	} {
		it := lowItem(name)
		it.Recipient = rcpt
		if SMSApprovable(it) {
			t.Errorf("%s: approvable by text", name)
		}
		if _, err := r.ch.Request([]Item{it}, 0); err != ErrLocalOnly {
			t.Errorf("%s: %v", name, err)
		}
		if l := it.line(); strings.Contains(l, "attacker") || !strings.Contains(l, "see the Wi-Fi page") {
			t.Errorf("%s: line %q", name, l)
		}
	}
	it := lowItem("phone")
	it.Recipient, it.Unverified = "+15551234821", true
	it.Object = strings.Repeat("o", 60)
	r.ch.Request([]Item{it}, 0)
	text := r.inbox()
	if !strings.Contains(text, "to +15551234821") || !strings.Contains(text, ": UNVERIFIED, details on the Wi-Fi page: send ") {
		t.Fatalf("text %q", text)
	}
}

func TestIDsAreShortUniqueAndNotReusedForADay(t *testing.T) {
	r := newRig(t, nil)
	seen := map[string]bool{}
	for i := 0; i < MaxOpen; i++ {
		id, err := r.ch.Request([]Item{lowItem("x")}, 0)
		if err != nil {
			t.Fatal(err)
		}
		r.inbox()
		if len(id) > 3 || seen[id] || !isID(id) {
			t.Fatalf("id %q (dup=%v)", id, seen[id])
		}
		seen[id] = true
	}
	if _, err := r.ch.Request([]Item{lowItem("x")}, 0); err != ErrFull {
		t.Fatalf("51st request: %v", err)
	}
	if _, err := r.ch.QueueAutoReply(AutoReply{Recipients: []string{"a@b.example"}, Body: "Thanks."}); err != ErrFull {
		t.Fatalf("auto-reply past the cap: %v", err)
	}
	// STOP still answers at the cap (CH-2).
	if got := r.say("STOP"); !strings.HasPrefix(got, "Stopped.") {
		t.Fatalf("STOP at the cap: %q", got)
	}
	// Closed IDs stay retired for RetireFor, across many more requests.
	r.advance(16 * time.Minute)
	r.ch.Tick()
	for i := 0; i < 300; i++ {
		id, err := r.ch.Request([]Item{lowItem("y")}, 0)
		if err != nil {
			t.Fatal(err)
		}
		r.inbox()
		if seen[id] {
			t.Fatalf("ID %s reused within a day", id)
		}
		seen[id] = true
		r.say("NO " + id)
	}
}

func TestIDSpaceExhaustionFailsInsteadOfHanging(t *testing.T) {
	r := newRig(t, nil)
	r.ch.mu.Lock()
	for _, l := range idLetters {
		for d := 0; d < 100; d++ {
			r.ch.codes.st.Retired[fmt.Sprintf("%c%d", l, d)] = r.clock()
			r.ch.codes.st.Retired[fmt.Sprintf("%c%02d", l, d)] = r.clock()
		}
	}
	r.ch.mu.Unlock()
	done := make(chan error, 1)
	go func() { _, err := r.ch.Request([]Item{lowItem("x")}, 0); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("got an ID from an exhausted space")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Request hung on ID exhaustion")
	}
	if got := r.say("STOP"); !strings.HasPrefix(got, "Stopped.") {
		t.Fatalf("STOP after exhaustion: %q", got)
	}
}

// REQ: CH-13

func TestBatchRepliesPartialYesNoAndExpiry(t *testing.T) {
	r := newRig(t, nil)
	items := []Item{lowItem("a"), lowItem("b"), lowItem("c")}
	id, _ := r.ch.Request(items, 0)
	text := r.inbox()
	m := lowCodeRe.FindStringSubmatch(text)
	if !strings.Contains(text, "3 items. 1 send") || !strings.Contains(text, "YES "+id+" 1 2 "+m[2]+" for some") {
		t.Fatalf("batch text: %q", text)
	}
	if got := r.say("NO 2"); got != "Denied "+id+" item 2." {
		t.Fatalf("NO 2: %q", got)
	}
	if got := r.say("yes 1, 3 " + m[2]); got != "Approved "+id+" item 1, 3." {
		t.Fatalf("partial YES: %q", got)
	}
	ds := r.decisions()
	if len(ds) != 3 || ds[0].Ref != "b" || ds[0].Approved || !ds[1].Approved || !ds[2].Approved {
		t.Fatalf("decisions %+v", ds)
	}

	// Partial YES closes the batch; unlisted items are denied.
	id2, _ := r.ch.Request(items, 0)
	m2 := lowCodeRe.FindStringSubmatch(r.inbox())
	if got := r.say("YES " + id2 + " 2 " + m2[2]); got != "Approved "+id2+" item 2. Denied 1, 3." {
		t.Fatalf("partial: %q", got)
	}
	r.decisions()

	// Unanswered items expire as denied and are kept for the digest.
	id3, _ := r.ch.Request(items[:2], 0)
	r.inbox()
	r.advance(16 * time.Minute)
	r.ch.Tick()
	ds = r.decisions()
	if len(ds) != 2 || ds[0].Why != "expired" || ds[0].Approved {
		t.Fatalf("expiry %+v", ds)
	}
	if ex, more := r.ch.TakeExpired(); len(ex) != 2 || more != 0 || ex[0].Request != id3 {
		t.Fatalf("digest list %+v", ex)
	}
	if got := r.say("YES " + id3 + " 123456"); got != "No open request "+id3+"." {
		t.Fatalf("expired: %q", got)
	}
}

func TestReplyMustNameItsRequestWhenSeveralAreOpen(t *testing.T) {
	r := newRig(t, nil)
	r.ch.Request([]Item{lowItem("a")}, 0)
	a := lowCodeRe.FindStringSubmatch(r.inbox())
	id, _ := r.ch.Request([]Item{highItem("b")}, 0)
	r.inbox()
	if got := r.say("NO"); !strings.Contains(got, "Reply with an ID") {
		t.Fatalf("ambiguous NO: %q", got)
	}
	// A texted code names its own request.
	if got := r.say("YES " + a[2]); got != "Approved "+a[1]+"." {
		t.Fatalf("code-bound YES: %q", got)
	}
	if got := r.say("yes"); got != "Include the ID and the code: YES "+id+" <code>." {
		t.Fatalf("bare yes: %q", got)
	}
	if got := r.say("MORE " + id); !strings.Contains(got, "1 pay invoice 77") {
		t.Fatalf("MORE: %q", got)
	}
}

func TestLongBatchFitsThreeSegmentsAndPointsToMore(t *testing.T) {
	r := newRig(t, nil)
	var items []Item
	for i := 0; i < 12; i++ {
		items = append(items, lowItem("x"))
	}
	id, _ := r.ch.Request(items, 0)
	text := r.inbox()
	if !strings.Contains(text, "MORE "+id) || !strings.Contains(text, "12 items") {
		t.Fatalf("long batch: %q", text)
	}
	if got := r.say("MORE " + id); !strings.Contains(got, "Rest on the box's Wi-Fi page") {
		t.Fatalf("MORE overflow: %q", got)
	}
}

// REQ: CH-14, CH-19

func TestInlineUnlockHoldsTheMessageAndAcceptsAnAppendedCode(t *testing.T) {
	r := newRig(t, nil)
	if got := r.say("what's on my calendar"); !strings.Contains(got, "held for 15 min") {
		t.Fatalf("hold: %q", got)
	}
	if got := r.say(r.totp()); got != `Unlocked until Oct 11 12:00. Held: "what's on my calendar". Reply RUN to send it.` {
		t.Fatalf("unlock: %q", got)
	}
	if len(r.agent.got()) != 0 {
		t.Fatal("a code-only unlock ran the held message")
	}
	r.say("RUN")
	if got := r.agent.got(); len(got) != 1 || got[0] != "what's on my calendar" {
		t.Fatalf("held: %v", got)
	}
	if got := r.say("run"); got != "Nothing is held." || len(r.agent.got()) != 1 {
		t.Fatalf("RUN with nothing held: %q", got)
	}
	// The unlock lasts the default 7 days.
	r.advance(7*24*time.Hour - time.Minute)
	r.say("still there?")
	r.advance(2 * time.Minute)
	if got := r.say("and now?"); !strings.Contains(got, "held") {
		t.Fatalf("unlock outlived 7 days: %q", got)
	}
	// A code appended to a message unlocks and is stripped.
	if got := r.say("summarize my mail " + r.totp()); !strings.HasPrefix(got, "Unlocked until") {
		t.Fatalf("appended code: %q", got)
	}
	if got := r.agent.got(); got[len(got)-1] != "summarize my mail" {
		t.Fatalf("appended code reached the agent: %v", got)
	}
	// While unlocked, numbers are chat: not checked, not stripped.
	if got := r.say("remind me about 482913"); got != "" || r.agent.got()[len(r.agent.got())-1] != "remind me about 482913" {
		t.Fatalf("number in unlocked chat: %q", got)
	}
	// A texted (low-tier) code never unlocks a session.
	r.ch.RequireUnlock()
	r.eng.stopped = true
	resume := r.say("RESUME")
	code := regexp.MustCompile(`[0-9]{6}`).FindString(resume)
	if got := r.say(code); !strings.HasPrefix(got, "Wrong code") {
		t.Fatalf("texted code unlocked the session: %q", got)
	}
}

func TestStaleHeldMessageIsNotRun(t *testing.T) {
	r := newRig(t, nil)
	r.say("send the report")
	r.advance(20 * time.Minute)
	if got := r.say(r.totp()); got != "Unlocked until Oct 11 12:20." {
		t.Fatalf("unlock: %q", got)
	}
	if len(r.agent.got()) != 0 {
		t.Fatal("stale held message ran")
	}
}

// REQ: CH-18

func TestWrongCodesVoidRequestsThenLockTheLowTier(t *testing.T) {
	r := newRig(t, nil)
	id, _ := r.ch.Request([]Item{lowItem("a")}, 0)
	r.inbox()
	r.say("YES " + id + " 000001")
	r.say("YES " + id + " 000002")
	if got := r.say("YES " + id + " 000003"); !strings.Contains(got, "void and denied") {
		t.Fatalf("third wrong: %q", got)
	}
	if ds := r.decisions(); len(ds) != 1 || ds[0].Why != "void" {
		t.Fatalf("%+v", ds)
	}
	id2, _ := r.ch.Request([]Item{lowItem("b")}, 0)
	m := lowCodeRe.FindStringSubmatch(r.inbox())
	r.say("YES " + id2 + " 000004")
	got := r.say("YES " + id2 + " 000005")
	if !strings.Contains(got, "texted codes are off") {
		t.Fatalf("fifth wrong code did not lock the low tier: %q", got)
	}
	// The right texted code no longer works; a generator code does.
	if got := r.say("YES " + id2 + " " + m[2]); !strings.Contains(got, "void") {
		t.Fatalf("texted code accepted while locked: %q", got)
	}
	r.ch.Request([]Item{lowItem("c")}, 0)
	if text := r.inbox(); !strings.Contains(text, "code generator") || lowCodeRe.MatchString(text) {
		t.Fatalf("low request while locked: %q", text)
	}
	c, _ := r.ch.Request([]Item{lowItem("d")}, 0)
	r.inbox()
	if got := r.say("YES " + r.totp()); !strings.Contains(got, "Reply with an ID") {
		t.Fatalf("generator code without ID: %q", got)
	}
	if got := r.say("YES " + c + " " + r.totp()); !strings.HasPrefix(got, "Approved") {
		t.Fatalf("generator code: %q", got)
	}
	if r.ch.codes.st.LowLocked {
		t.Fatal("a generator code should lift the low-tier lock")
	}
}

// REQ: CH-11

func TestResumeNeedsATextedCodeAndStopVoidsIt(t *testing.T) {
	r := newRig(t, nil)
	if got := r.say("RESUME"); got != "Not stopped. Nothing to resume." {
		t.Fatalf("%q", got)
	}
	r.say("STOP")
	code := regexp.MustCompile(`RESUME ([0-9]{6})`).FindStringSubmatch(r.say("resume"))[1]
	r.say("STOP")
	if got := r.say("RESUME " + code); !strings.HasPrefix(got, "No valid code") {
		t.Fatalf("code survived STOP: %q", got)
	}
	code = regexp.MustCompile(`RESUME ([0-9]{6})`).FindStringSubmatch(r.say("resume"))[1]
	if got := r.say("Resume " + code + "."); got != "Resumed. 0 held actions may now run." || r.eng.Stopped() {
		t.Fatalf("resume: %q", got)
	}
	if got := r.say("RESUME " + code); got != "Not stopped. Nothing to resume." {
		t.Fatalf("reuse: %q", got)
	}
}

// REQ: CH-19

func TestAgentTextsCarryNoCodesOrKeys(t *testing.T) {
	r := newRig(t, nil)
	r.ch.Notify("Your Acme verification code is 482913")
	if got := r.inbox(); got != Hidden {
		t.Fatalf("got %q", got)
	}
	r.ch.Notify("Invoice 482913 was paid on 2026-10-04.")
	if got := r.inbox(); got != "Invoice 482913 was paid on 2026-10-04." {
		t.Fatalf("got %q", got)
	}
}

// REQ: ADP-11, CH-16

func TestAutoReplyAlertUndoAndCommitmentFilter(t *testing.T) {
	r := newRig(t, nil)
	res, err := r.ch.QueueAutoReply(AutoReply{Ref: "r1", Recipients: []string{"sam@example.com"}, Body: "Thanks Sam, got it.\nMore later."})
	if err != nil || res.Queued == nil {
		t.Fatalf("%+v %v", res, err)
	}
	id := res.Queued.ID
	if got := r.inbox(); got != `Auto-reply to sam@example.com: "Thanks Sam, got it.". Sends 12:10. Reply UNDO `+id+" to stop it." {
		t.Fatalf("alert: %q", got)
	}
	if got := r.say("undo " + id); got != "Cancelled "+id+". The reply was not sent." {
		t.Fatalf("undo: %q", got)
	}
	if len(r.ch.DueAutoReplies()) != 0 {
		t.Fatal("cancelled reply still due")
	}

	res, _ = r.ch.QueueAutoReply(AutoReply{Ref: "r2", Recipients: []string{"sam@example.com"}, Body: "Sounds good."})
	r.inbox()
	r.advance(9 * time.Minute)
	if len(r.ch.DueAutoReplies()) != 0 {
		t.Fatal("sent inside the undo window")
	}
	r.advance(time.Minute)
	if due := r.ch.DueAutoReplies(); len(due) != 1 || due[0].Reply.Ref != "r2" {
		t.Fatalf("due %+v", due)
	}
	if got := r.say("UNDO " + res.Queued.ID); !strings.HasPrefix(got, "Nothing to undo") {
		t.Fatalf("undo after send: %q", got)
	}

	// A commitment makes it a normal approval request.
	res, _ = r.ch.QueueAutoReply(AutoReply{Ref: "r3", Recipients: []string{"sam@example.com"}, Body: "Yes, I confirm.",
		Facts: Facts{Verb: "send", RecipientChecked: true, RecipientExists: true, RecipientByOwner: true}})
	if res.Queued != nil || res.Request == "" || res.Matched != "commitment" {
		t.Fatalf("%+v", res)
	}
	if text := r.inbox(); !strings.HasPrefix(text, res.Request+": send reply (commitment) to sam@example.com") {
		t.Fatalf("approval: %q", text)
	}
}
