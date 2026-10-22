package main

// REQ: CH-20, CH-19, CH-10, CAP-3, CH-3

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
)

type evRig struct {
	mu    sync.Mutex
	sent  []string
	ev    *evidence
	now   time.Time
	store *change.MemStore
}

func newEvRig(t *testing.T) *evRig {
	r := &evRig{now: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC), store: &change.MemStore{}}
	r.ev = &evidence{
		notify: func(s string) error { r.mu.Lock(); r.sent = append(r.sent, s); r.mu.Unlock(); return nil },
		kept:   &keptReplies{store: r.store, now: func() time.Time { return r.now }},
		logf:   t.Logf,
	}
	return r
}

func (r *evRig) texts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.sent)
}

func noPage(t *testing.T, s string) {
	t.Helper()
	if strings.Contains(strings.ToLower(s), "page") {
		t.Fatalf("text names a page: %q", s)
	}
}

// TestLongRepliesAreKept: a reply too long for three
// texts is kept whole (potency C1) and the third text says where it was
// cut and what to ask (UX ruling on #148; CH-12, D-127).
func TestLongRepliesAreKept(t *testing.T) {
	if textRoom(true) != control.MaxText-len(owner.AgentPrefix) {
		t.Fatal("the owner channel's text limit changed")
	}
	r := newEvRig(t)
	long := strings.Repeat("All of this is the reply. ", 80)
	r.ev.sendSplit("agent", long)
	got := r.texts()[2]
	if len(owner.AgentPrefix+got) > control.MaxText || !strings.HasSuffix(got, " "+keptLong) || !strings.HasPrefix(got, "All of this") {
		t.Fatalf("text %q", got)
	}
	noPage(t, got)
	if k := r.ev.kept.list(); len(k) != 1 || k[0].Text != long {
		t.Fatalf("kept %+v", k)
	}
	fits := strings.Repeat("x", control.MaxText-len(owner.AgentPrefix))
	r.ev.sendSplit("agent", fits)
	if r.texts()[3] != fits || len(r.ev.kept.list()) != 1 {
		t.Fatal("a reply that fits was kept")
	}
}

// TestADeletionForgetsKeptReplies: a deletion's reach (CAP-3) forgets
// every kept reply, which may quote the deleted record (security C6).
func TestADeletionForgetsKeptReplies(t *testing.T) {
	r := newEvRig(t)
	r.ev.kept.keep("quotes the record")
	n, err := forgetFan{kept: r.ev.kept}.ForgetTasks("agent/1")
	if n != 0 || err != nil || len(r.ev.kept.list()) != 0 {
		t.Fatalf("forgot %d %v %d", n, err, len(r.ev.kept.list()))
	}
	r.ev.kept.keep("again")
	if _, err := (forgetFan{kept: r.ev.kept}).ForgetTasks(); err != nil || len(r.ev.kept.list()) != 0 {
		t.Fatalf("again: %v", err)
	}
}

// REQ: CAP3-F1
// TestADeletionCountsHeldAgentTexts: a deletion's reach returns how many
// held agent texts the owner channel dropped, so the forget reply can
// tell the owner (CAP3-F1).
func TestADeletionCountsHeldAgentTexts(t *testing.T) {
	r := newEvRig(t)
	o := pacedOwner(t, quiet22to7(), at23)
	r.ev.wireOwner(func() *owner.Channel { return o.ch })
	if err := o.ch.Notify("Held agent text."); err != nil {
		t.Fatal(err)
	}
	n, err := forgetFan{kept: r.ev.kept}.ForgetTasks("agent/1")
	if n != 1 || err != nil {
		t.Fatalf("forgot %d %v", n, err)
	}
	if n, err := (forgetFan{kept: r.ev.kept}).ForgetTasks(); n != 0 || err != nil {
		t.Fatalf("again: %d %v", n, err)
	}
}

// REQ: CAP3-F1
// A reply routed across a deletion drops the held agent texts again in
// settle; the owner is told that count alone, never the text, and a
// settle with no deletion between tells nothing.
func TestSettleAcrossADeletionCountsHeldAgentTexts(t *testing.T) {
	r := newEvRig(t)
	o := pacedOwner(t, quiet22to7(), at23)
	r.ev.wireOwner(func() *owner.Channel { return o.ch })
	gen, _ := r.ev.kept.pending(&fakeOutbox{})
	r.ev.kept.settle(gen)
	if err := o.ch.Notify("Held agent text."); err != nil {
		t.Fatal(err)
	}
	if got := o.sent(); len(got) != 0 {
		t.Fatalf("no deletion: sent %q", got)
	}
	if _, err := r.ev.kept.forget(); err != nil {
		t.Fatal(err)
	}
	if err := o.ch.Notify("Held agent text, again."); err != nil {
		t.Fatal(err)
	}
	r.ev.kept.settle(gen)
	got := o.sent()
	if len(got) != 1 || got[0] != "A deletion dropped 1 held agent text." {
		t.Fatalf("sent %q", got)
	}
}

// REQ: CAP3-F1
// With learning off a deletion still counts the held agent texts it
// dropped; a settle across a deletion that dropped none tells nothing;
// and recall's count goes out as the same broker text (later items on
// #2510).
func TestHeldDroppedCountHasOneSender(t *testing.T) {
	r := newEvRig(t)
	o := pacedOwner(t, quiet22to7(), at23)
	own := func() *owner.Channel { return o.ch }
	r.ev.wireOwner(own)
	if err := o.ch.Notify("Held agent text."); err != nil {
		t.Fatal(err)
	}
	if n, err := (forgetFan{kept: r.ev.kept}).ForgetTasks("agent/1"); n != 1 || err != nil {
		t.Fatalf("learning off: forgot %d %v", n, err)
	}
	gen, _ := r.ev.kept.pending(&fakeOutbox{})
	if _, err := r.ev.kept.forget(); err != nil {
		t.Fatal(err)
	}
	r.ev.kept.settle(gen)
	if got := o.sent(); len(got) != 0 {
		t.Fatalf("none held: sent %q", got)
	}
	if err := recallHeldDropped(own)(2); err != nil {
		t.Fatal(err)
	}
	if got := o.sent(); len(got) != 1 || got[0] != "A deletion dropped 2 held agent texts." {
		t.Fatalf("recall: sent %q", got)
	}
}

// REQ: CAP3-F1
// The count of held agent texts a deletion dropped is a broker text: held
// in quiet hours under URGENT APPROVAL OFF beside recall's agent-text
// confirmation, it survives a second forget that drops the confirmation,
// and goes at the next release.
func TestHeldDroppedCountSurvivesNextForget(t *testing.T) {
	o := pacedOwner(t, quiet22to7Held(), at23)
	own := func() *owner.Channel { return o.ch }
	if err := recallNotify(own)("Done: root forgot a mail you deleted."); err != nil {
		t.Fatal(err)
	}
	if err := recallHeldDropped(own)(2); err != nil {
		t.Fatal(err)
	}
	if got := o.sent(); len(got) != 0 {
		t.Fatalf("quiet hours: sent %q", got)
	}
	if n := o.ch.ForgetRecent(); n != 1 {
		t.Fatalf("second forget dropped %d, want only the confirmation", n)
	}
	o.set(at23.Add(8*time.Hour + time.Minute)) // 07:01
	if err := o.ch.Release(); err != nil {
		t.Fatal(err)
	}
	got := o.sent()
	if len(got) != 1 || !strings.Contains(got[0], "A deletion dropped 2 held agent texts.") || strings.Contains(got[0], "Done:") {
		t.Fatalf("released %q, want only the count", got)
	}
}

// forgettingOutbox is an outbox a deletion can reach, as the guest
// plane's is (guest.Plane.ForgetReplies).
type forgettingOutbox struct {
	fakeOutbox
	fail error
	done []string // replies the worker retired
}

func (f *forgettingOutbox) ForgetReplies() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending = nil
	return f.fail
}

func (f *forgettingOutbox) ReplyDone(machine, id string) error {
	f.mu.Lock()
	f.done = append(f.done, id)
	f.mu.Unlock()
	return f.fakeOutbox.ReplyDone(machine, id)
}

func (f *forgettingOutbox) retired() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.done)
}

// REQ: CAP-3 (DEL-1-f1b, DEL-1-f1c)
// DEL-1-f1b: a deletion's reach (CAP-3) takes in the replies waiting in
// the guest plane's outbox, which may quote the deleted record as a kept
// reply may; a failure to drop them is reported, and an outbox that
// cannot drop them fails the deletion rather than passing it.
func TestDEL1f1DeletionReachesTheOutbox(t *testing.T) {
	r := newEvRig(t)
	if _, err := (forgetFan{kept: r.ev.kept}).ForgetTasks("agent/1"); err != nil {
		t.Fatalf("before the plane opens: %v", err)
	}
	src := &forgettingOutbox{fakeOutbox: fakeOutbox{sent: r.texts}}
	src.add("quotes the record")
	r.ev.kept.keep("quotes it too")
	r.ev.serve(src)
	if _, err := (forgetFan{kept: r.ev.kept}).ForgetTasks("agent/1"); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if len(src.PendingReplies()) != 0 || len(r.ev.kept.list()) != 0 {
		t.Fatalf("left %d waiting, %d kept", len(src.PendingReplies()), len(r.ev.kept.list()))
	}
	src.fail = errors.New("outbox not saved")
	if _, err := (forgetFan{kept: r.ev.kept}).ForgetTasks("agent/1"); !errors.Is(err, src.fail) {
		t.Fatalf("failed drop: %v", err)
	}
	r.ev.serve(&fakeOutbox{sent: r.texts})
	if _, err := (forgetFan{kept: r.ev.kept}).ForgetTasks("agent/1"); err == nil {
		t.Fatal("an outbox the deletion cannot reach passed")
	}
}

// DEL-1-f1c: a deletion while the worker is routing a reply: no other
// reply that was waiting is handed on afterwards, and the reply in
// flight, which cannot be recalled, leaves no kept copy behind though
// its text failed after the deletion.
func TestDEL1f1ForgetDuringARoute(t *testing.T) {
	r := newEvRig(t)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	// The first text blocks until the deletion has run, then fails, so the
	// worker keeps the two-text reply after the deletion dropped the rest.
	r.ev.notify = func(string) error {
		err := errors.New("no owner channel")
		once.Do(func() { close(started); <-release })
		return err
	}
	src := &forgettingOutbox{fakeOutbox: fakeOutbox{sent: r.texts}}
	long := strings.Repeat(" two texts", control.MaxText/10)
	for i := 0; i < 3; i++ {
		src.add(fmt.Sprint("canary-del1f1-", i, long))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.ev.wake = make(chan struct{}, 1)
	go r.ev.run(ctx)
	r.ev.serve(src)
	<-started
	if _, err := (forgetFan{kept: r.ev.kept}).ForgetTasks("agent/1"); err != nil {
		t.Fatal(err)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for len(src.retired()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	r.ev.poke()
	time.Sleep(20 * time.Millisecond)
	if got := src.retired(); !slices.Equal(got, []string{"idcanary-del1f1-0" + long}) {
		t.Fatalf("handed on %q", got)
	}
	if got := r.texts(); len(got) != 0 {
		t.Fatalf("texted %q", got)
	}
	if k := r.ev.kept.list(); len(k) != 0 {
		t.Fatalf("kept after the deletion: %+v", k)
	}
}

// CH-11 (#2196): once the evidence worker serves the guest plane's
// outbox, an agent reaction a guest posts is refused in the answer to
// its POST, a 400 the bridge does not retry, in broker-written words; it
// is never queued or texted, and a text reply to the same message then
// goes out. Before, the plane answered 204 and Converse's refusal later
// reached only the log.
func TestGuestReactionIsRefusedToTheGuest(t *testing.T) {
	// REQ: CH-11
	r := newEvRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.ev.wake = make(chan struct{}, 1)
	plane, err := guest.New(guest.Config{Dir: t.TempDir(), Machines: oneLineage{}, Effects: canaryEffects{}, Replies: r.ev.poke})
	if err != nil {
		t.Fatal(err)
	}
	defer plane.Shutdown()
	go r.ev.run(ctx)
	r.ev.serve(plane)
	mdir, err := plane.Open("m1")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(mdir, guest.Socket)
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	do := func(method, path, body string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, "http://broker"+path, strings.NewReader(body))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, strings.TrimSpace(string(b))
	}
	id, err := plane.DeliverOwner("m1", "can you book the dentist?", false)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := do("GET", "/owner/next", ""); code != 200 || !strings.Contains(body, id) {
		t.Fatalf("next: %d %s", code, body)
	}
	reply := func(text string) string {
		b, _ := json.Marshal(map[string]string{"id": id, "text": text})
		return string(b)
	}
	code, body := do("POST", "/owner/reply", reply(`Liked "can you book the dentist?"`))
	if code != http.StatusBadRequest || body != guestReactionRefused {
		t.Fatalf("reaction: %d %q", code, body)
	}
	if n := len(plane.PendingReplies()); n != 0 || len(r.texts()) != 0 {
		t.Fatalf("refused reaction queued %d, texted %q", n, r.texts())
	}
	if code, body := do("POST", "/owner/reply", reply("Booked for Tuesday at 10.")); code != http.StatusNoContent {
		t.Fatalf("text reply: %d %s", code, body)
	}
	waitFor(t, "the text reply", func() bool { return len(r.texts()) == 1 && len(plane.PendingReplies()) == 0 })
	if got := r.texts(); got[0] != "Booked for Tuesday at 10." {
		t.Fatalf("texted %q", got)
	}
}

// REQ: CH-12
// TestCH12SplitCountsUCS2Room: a reply with emoji needs UCS-2, 3 x 67
// UTF-16 units a text. One of about two and a half texts goes as three
// texts in order, each within three UCS-2 segments with AgentPrefix, none
// cut inside a joined emoji, and nothing is kept; control and bidi
// characters are gone before the split.
func TestCH12SplitCountsUCS2Room(t *testing.T) {
	var b strings.Builder
	for {
		n, _ := control.Units(b.String())
		if n >= textRoom(false)*5/2-20 {
			break
		}
		b.WriteString("We meet Thursday 👩‍💻 at nine. ")
	}
	long := strings.TrimSpace(b.String())
	r := newEvRig(t)
	r.ev.sendSplit("agent", "‮"+long+"\u0007")
	got := r.texts()
	if len(got) != 3 {
		t.Fatalf("%d texts", len(got))
	}
	for i, s := range got {
		n, gsm7 := modem.Segments(owner.AgentPrefix + s)
		if gsm7 || n > control.Segments {
			t.Fatalf("text %d: %d segments, gsm7 %v", i, n, gsm7)
		}
		if strings.Count(s, "👩") != strings.Count(s, "💻") || strings.ContainsAny(s, "‮\u0007") {
			t.Fatalf("text %d cut inside an emoji or kept a control: %q", i, s)
		}
	}
	if strings.Join(got, " ") != long {
		t.Fatal("the texts do not join back to the reply")
	}
	if k := r.ev.kept.list(); len(k) != 0 {
		t.Fatalf("a reply that fits three texts was kept: %d", len(k))
	}
}

// TestCH12ControlGapStillWithholdsReply: a reply whose code word and code are joined only by a
// stripped control is still withheld (CH-19, CH-12, #2346).
func TestCH12ControlGapStillWithholdsReply(t *testing.T) {
	for _, gap := range []string{"\r", "\v", "\f", "\u0085", "\x01", "\u202E", "\u2066", "\u2067", "\u2068", "\u2069", "\u200F"} {
		text := "Your code" + gap + "482913"
		r := newEvRig(t)
		r.ev.sendSplit("agent", text)
		if got := r.texts(); len(got) != 1 || owner.Disclose(got[0]) != owner.Hidden {
			t.Errorf("reply %q texted %q", text, got)
		}
	}
}

// TestCH12CcInsideTokenStillWithholdsReply: a reply whose key or code a
// Cc control splits
// mid-token is still withheld: CH-19 also reads the gap removed
// (owner.AgentSecret, CH-19, CH-12, #2346).
func TestCH12CcInsideTokenStillWithholdsReply(t *testing.T) {
	for _, g := range []string{"\r", "\x01", "\x00", "\u0080", "\x7f"} {
		for _, tok := range [][2]string{
			{"key sk-abcdefghij", "klmnopqrstuvwx"},
			{"AKIAABCDEFGH", "IJKLMNOP"},
			{"token ghp_abcdefghijklmn", "opqrstuvwxyz0123456789"},
			{"key: eyJhbGciOi", ".eyJzdWIiOi.SflKxwRJSM"},
			{"code AB", "C1"},
			{"code A", "1B2"},
		} {
			text := tok[0] + g + tok[1]
			r := newEvRig(t)
			r.ev.sendSplit("agent", text)
			if got := r.texts(); len(got) != 1 || got[0] != text {
				t.Errorf("reply %q texted %q", text, got)
			}
		}
	}
}

// TestCH12GuestRefusesWrappedReaction: a reaction wrapped in bidi
// controls is refused at the guest's POST like a bare one (CH-11, CH-12).
func TestCH12GuestRefusesWrappedReaction(t *testing.T) {
	if got := refuseGuestReply("\u202ELiked \u201cYour invoice is drafted.\u201d\u2069"); got != guestReactionRefused {
		t.Fatalf("refuseGuestReply = %q", got)
	}
	if got := refuseGuestReply("Booked 👍"); got != "" {
		t.Fatalf("refuseGuestReply refused text: %q", got)
	}
}

// TestCH12KeptReplyIsStripped: a reply too long for three texts is kept
// for the local UI without its bidi controls (CH-12).
func TestCH12KeptReplyIsStripped(t *testing.T) {
	r := newEvRig(t)
	r.ev.sendSplit("agent", "\u202E"+strings.Repeat("We meet Thursday at nine. ", 80)+"\u2066")
	k := r.ev.kept.list()
	if len(k) != 1 || strings.ContainsAny(k[0].Text, "\u202E\u2066") {
		t.Fatalf("kept %+v", k)
	}
}

// REQ: CH-20
// TestEvidenceSettingIsNotYet: with no share route to an owner
// destination, the destination commands are answered by the box in an
// unlocked session and never reach the agent as task chat; a locked
// session gets the unlock prompt, and other texts pass on (CH-20, DEP-3).
func TestEvidenceSettingIsNotYet(t *testing.T) {
	cfg := daemon.Config{Settings: func(context.Context, string, bool) (string, bool) { return "loops", true }}
	newEvRig(t).ev.wire(&cfg)
	for _, msg := range []string{"EVIDENCE ON", "evidence off", "EVIDENCE TO me@example.test", "Email replies on", "EMAIL REPLIES OFF", "EMAIL REPLIES TO me@example.test"} {
		if r, ok := cfg.Settings(context.Background(), msg, true); !ok || r != evidenceNotYet {
			t.Errorf("%q: %q %v", msg, r, ok)
		}
		if r, _ := cfg.Settings(context.Background(), msg, false); r != "loops" {
			t.Errorf("%q locked: %q", msg, r)
		}
	}
	for _, msg := range []string{"EVIDENCE", "EMAIL REPLIES", "EVIDENCE TO nobody", "email replies to the landlord", "Email the reply to me"} {
		if r, _ := cfg.Settings(context.Background(), msg, true); r != "loops" {
			t.Errorf("%q: %q", msg, r)
		}
	}
}
