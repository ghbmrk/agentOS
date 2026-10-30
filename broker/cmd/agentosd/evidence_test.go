package main

// REQ: CH-20, CH-19, CH-21, CH-10, CAP-3, CH-3

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
	"github.com/ghbmrk/agentos/broker/localapi"
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
	r.ev.kept.keep("long", "quotes the record")
	n, err := r.ev.kept.forget()
	if n != 0 || err != nil || len(r.ev.kept.list()) != 0 {
		t.Fatalf("forgot %d %v %d", n, err, len(r.ev.kept.list()))
	}
	r.ev.kept.keep("long", "again")
	if _, err := r.ev.kept.forget(); err != nil || len(r.ev.kept.list()) != 0 {
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
	n, err := r.ev.kept.forget()
	if n != 1 || err != nil {
		t.Fatalf("forgot %d %v", n, err)
	}
	if n, err := r.ev.kept.forget(); n != 0 || err != nil {
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
// and a count told directly goes out as the same broker text (later
// items on #2510).
func TestHeldDroppedCountHasOneSender(t *testing.T) {
	r := newEvRig(t)
	o := pacedOwner(t, quiet22to7(), at23)
	own := func() *owner.Channel { return o.ch }
	r.ev.wireOwner(own)
	if err := o.ch.Notify("Held agent text."); err != nil {
		t.Fatal(err)
	}
	if n, err := r.ev.kept.forget(); n != 1 || err != nil {
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
	if err := tellHeldDropped(own(), 2); err != nil {
		t.Fatal(err)
	}
	if got := o.sent(); len(got) != 1 || got[0] != "A deletion dropped 2 held agent texts." {
		t.Fatalf("told: sent %q", got)
	}
}

// REQ: CAP3-F1
// The count of held agent texts a deletion dropped is a broker text: held
// in quiet hours under URGENT APPROVAL OFF beside an approval-class
// agent-text confirmation, it survives a second forget that drops the confirmation,
// and goes at the next release.
func TestHeldDroppedCountSurvivesNextForget(t *testing.T) {
	o := pacedOwner(t, quiet22to7Held(), at23)
	own := func() *owner.Channel { return o.ch }
	if err := o.ch.NotifyAs(owner.ClassApproval, "Done: root forgot a mail you deleted."); err != nil {
		t.Fatal(err)
	}
	if err := tellHeldDropped(own(), 2); err != nil {
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
	if _, err := r.ev.kept.forget(); err != nil {
		t.Fatalf("before the plane opens: %v", err)
	}
	src := &forgettingOutbox{fakeOutbox: fakeOutbox{sent: r.texts}}
	src.add("quotes the record")
	r.ev.kept.keep("long", "quotes it too")
	r.ev.serve(src)
	if _, err := r.ev.kept.forget(); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if len(src.PendingReplies()) != 0 || len(r.ev.kept.list()) != 0 {
		t.Fatalf("left %d waiting, %d kept", len(src.PendingReplies()), len(r.ev.kept.list()))
	}
	src.fail = errors.New("outbox not saved")
	if _, err := r.ev.kept.forget(); !errors.Is(err, src.fail) {
		t.Fatalf("failed drop: %v", err)
	}
	r.ev.serve(&fakeOutbox{sent: r.texts})
	if _, err := r.ev.kept.forget(); err == nil {
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
	if _, err := r.ev.kept.forget(); err != nil {
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
	plane, err := guest.New(guest.Config{Dir: t.TempDir(), Machines: oneLineage{}, Replies: r.ev.poke})
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

// TestKeptSurvivesRestart (HELD-2): what was kept is still listed, with
// the same id, kind and text, by a store opened again on the same file.
func TestKeptSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kept.json")
	ev := newEvidence(path, defaultKeepFor, t.Logf)
	if err := ev.kept.Keep(owner.KeptCode, "I fixed the code."); err != nil {
		t.Fatal(err)
	}
	before := ev.kept.list()
	after := newEvidence(path, defaultKeepFor, t.Logf).kept.list()
	if len(before) != 1 || before[0].ID == "" || !slices.Equal(before, after) || after[0].Kind != owner.KeptCode || after[0].Text != "I fixed the code." {
		t.Fatalf("kept %+v, after a restart %+v", before, after)
	}
}

// TestKeptExpiresOnlyByTime (HELD-2): 25 items are all kept (no count
// eviction); on day 29 they are listed, on day 30 + 1 s each is a stub
// with no text, on the page as on disk once swept, and 30 days later the
// stubs are gone.
func TestKeptExpiresOnlyByTime(t *testing.T) {
	r := newEvRig(t)
	const canary = "CANARY-held-482913"
	for i := range 25 {
		if err := r.ev.kept.keep(localapi.HeldLong, fmt.Sprintf("%s %d", canary, i)); err != nil {
			t.Fatal(err)
		}
	}
	start := r.now
	r.now = start.Add(29 * 24 * time.Hour)
	l := r.ev.kept.list()
	if len(l) != 25 || l[0].Text != canary+" 0" || l[0].Expired {
		t.Fatalf("day 29: %d kept", len(l))
	}
	r.now = start.Add(defaultKeepFor + time.Second)
	h := r.ev.kept.held()
	if len(h.Items) != 25 || !h.Items[0].Expired || h.Items[0].Text != "" || h.Items[0].ID != l[24].ID {
		t.Fatalf("day 30 + 1 s: %+v", h.Items[0])
	}
	r.ev.kept.sweep()
	if raw, _ := r.store.Load(); strings.Contains(string(raw), canary) {
		t.Fatal("an expired text is still on disk")
	}
	r.now = start.Add(defaultKeepFor + stubFor + time.Second)
	if l := r.ev.kept.list(); len(l) != 0 {
		t.Fatalf("stubs outlived their 30 days: %d", len(l))
	}
}

// TestFullStoreRefusesNotEvicts (HELD-2): an item that would take the file
// past its byte cap is refused, every older item stays as it was, and the
// owner channel then says the text could not be kept.
func TestFullStoreRefusesNotEvicts(t *testing.T) {
	r := newEvRig(t)
	big := strings.Repeat("x", maxKeptBytes/3)
	for i := range 2 {
		if err := r.ev.kept.keep(localapi.HeldLong, big+fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := r.store.Load()
	if err := r.ev.kept.Keep(owner.KeptSecret, big); !errors.Is(err, errKeptFull) {
		t.Fatalf("a full store kept it: %v", err)
	}
	if after, _ := r.store.Load(); string(after) != string(before) {
		t.Fatal("a refused keep changed the older items")
	}
	long := strings.Repeat("All of this is the reply. ", 80)
	r.ev.sendSplit("agent", long+big)
	got := r.texts()
	if len(got) != 3 || !strings.HasSuffix(got[2], " "+keptLongNotKept) || len(owner.AgentPrefix+got[2]) > control.MaxText {
		t.Fatalf("a long reply not kept ended %q", got[len(got)-1])
	}
	noPage(t, got[2])
}

// TestUnsentNotKeptIsTold: a reply that did not go and could not be kept
// is logged, and the owner is told in the broker's own words.
func TestUnsentNotKeptIsTold(t *testing.T) {
	r := newEvRig(t)
	r.ev.kept.store = failStore{}
	var told []string
	r.ev.inform = func(s string) error { told = append(told, s); return nil }
	n := 0
	r.ev.notify = func(string) error {
		if n++; n == 2 {
			return errNoSend
		}
		return nil
	}
	r.ev.sendSplit("agent", strings.Repeat("A reply in two texts. ", 30))
	if len(told) != 1 || told[0] != unsentNotKept {
		t.Fatalf("told %q", told)
	}
	noPage(t, unsentNotKept)
}

type failStore struct{}

func (failStore) Load() ([]byte, error) { return nil, nil }
func (failStore) Save([]byte) error     { return errors.New("disk full") }

// TestHeldListsNewestFirst: the page's view lists what is kept newest
// first, then the expired stubs, and reading it removes nothing (HELD-3).
func TestHeldListsNewestFirst(t *testing.T) {
	r := newEvRig(t)
	start := r.now
	for i, k := range []string{owner.KeptSecret, owner.KeptCode, localapi.HeldUnsent} {
		r.now = start.Add(time.Duration(i) * 24 * time.Hour)
		if err := r.ev.kept.keep(k, k+" text"); err != nil {
			t.Fatal(err)
		}
	}
	r.now = start.Add(defaultKeepFor + time.Hour)
	for range 2 {
		h := r.ev.kept.held()
		if len(h.Items) != 3 || h.Items[0].Kind != localapi.HeldUnsent || h.Items[1].Kind != owner.KeptCode || !h.Items[2].Expired || h.Items[2].Kind != owner.KeptSecret {
			t.Fatalf("held %+v", h.Items)
		}
	}
	if owner.KeptSecret != localapi.HeldSecret || owner.KeptCode != localapi.HeldCode {
		t.Fatal("the owner channel's kinds are not the page's")
	}
}

// TestRetriedKeepIsKeptOnce: a held text offered again while it is still
// kept, as a retried owner question is on every try (#3986 L3 1; owner's
// TestRetriedHeldTextKeepsAskingTheKeeper), is kept once, so retries
// never fill the store; another kind, or the same text once expired, is a
// new item.
func TestRetriedKeepIsKeptOnce(t *testing.T) {
	r := newEvRig(t)
	const q = "I fixed the code. Shall I push it?"
	for range 120 {
		if err := r.ev.kept.Keep(owner.KeptCode, q); err != nil {
			t.Fatal(err)
		}
	}
	if l := r.ev.kept.list(); len(l) != 1 {
		t.Fatalf("kept %d copies of one retried text", len(l))
	}
	if err := r.ev.kept.keep(localapi.HeldUnsent, q); err != nil {
		t.Fatal(err)
	}
	r.now = r.now.Add(defaultKeepFor + time.Second)
	if err := r.ev.kept.Keep(owner.KeptCode, q); err != nil {
		t.Fatal(err)
	}
	if l := r.ev.kept.list(); len(l) != 3 || l[2].Expired {
		t.Fatalf("kept %+v", l)
	}
}

// TestLegacyKeptGetsAStableID: a reply kept before items had ids is
// listed with one, the same before and after its text expires.
func TestLegacyKeptGetsAStableID(t *testing.T) {
	r := newEvRig(t)
	if err := r.store.Save([]byte(`[{"text":"an old reply","at":"2026-10-04T09:00:00Z"}]`)); err != nil {
		t.Fatal(err)
	}
	live := r.ev.kept.list()
	r.now = r.now.Add(defaultKeepFor)
	r.ev.kept.sweep()
	stub := r.ev.kept.list()
	if len(live) != 1 || live[0].ID == "" || len(stub) != 1 || !stub[0].Expired || stub[0].ID != live[0].ID {
		t.Fatalf("live %+v, stub %+v", live, stub)
	}
}

// TestNotKeptTextsGiveAStep: each could-not-be-kept text fits one GSM-7
// segment, names no page, and says what the owner can do (CH-12);
// keptLongNotKept fits where keptLong would.
func TestNotKeptTextsGiveAStep(t *testing.T) {
	for _, s := range []string{keptLongNotKept, unsentNotKept} {
		if n, gsm := modem.Segments(s); !gsm || n != 1 || !strings.Contains(s, "Ask me") {
			t.Fatalf("%q", s)
		}
		noPage(t, s)
	}
	if len(keptLongNotKept) > len(keptLong) {
		t.Fatal("keptLongNotKept is longer than keptLong")
	}
}

// TestRepeatNearExpiryLastsFromItsPointer: the same text withheld again a
// minute before the first copy expires is kept for keepFor from then, so
// the page still shows it 2 minutes after the second pointer and until
// 30 days after it, as one item with the first id, listed newest (#3986
// delta L3 1; HELD-1, HELD-2).
func TestRepeatNearExpiryLastsFromItsPointer(t *testing.T) {
	r := newEvRig(t)
	const q = "Your code is 482913"
	if err := r.ev.kept.Keep(owner.KeptCode, q); err != nil {
		t.Fatal(err)
	}
	if err := r.ev.kept.Keep(owner.KeptSecret, "other"); err != nil {
		t.Fatal(err)
	}
	first := r.ev.kept.list()[0].ID
	r.now = r.now.Add(defaultKeepFor - time.Minute)
	if err := r.ev.kept.Keep(owner.KeptCode, q); err != nil {
		t.Fatal(err)
	}
	second := r.now
	r.now = second.Add(2 * time.Minute)
	h := r.ev.kept.held()
	if len(h.Items) != 2 || h.Items[0].Expired || h.Items[0].Text != q || h.Items[0].ID != first || !h.Items[0].At.Equal(second) {
		t.Fatalf("2 minutes after the second pointer: %+v", h.Items)
	}
	r.now = second.Add(defaultKeepFor - time.Second)
	if l := r.ev.kept.list(); len(l) != 2 || l[1].Expired || l[1].Text != q {
		t.Fatalf("day 30 after the second pointer: %+v", l)
	}
	r.now = second.Add(defaultKeepFor)
	if l := r.ev.kept.list(); !l[1].Expired {
		t.Fatal("kept past keepFor from its latest pointer")
	}
}

// TestHeldCodeExpiresAtTheHour (CODEH-4): a code the owner channel kept is
// readable until the owner-set hour; from then the page shows the item
// with its other text readable and the code expired, the swept file no
// longer holds the code, and the item stays until its kept days end. A
// key kept beside it keeps its days (CH-19, #906).
func TestHeldCodeExpiresAtTheHour(t *testing.T) {
	const code = "482913"
	text := "Hi, your Acme verification code is " + code + ". Ask me if it fails."
	for _, hours := range []int{1, 24} {
		r := newEvRig(t)
		r.ev.kept.codeFor, _ = codeFor(hours)
		if err := r.ev.kept.Keep(owner.KeptOneTime, text); err != nil {
			t.Fatal(err)
		}
		if err := r.ev.kept.Keep(owner.KeptSecret, "key AKIACANARY0000000000"); err != nil {
			t.Fatal(err)
		}
		start := r.now
		r.now = start.Add(time.Duration(hours)*time.Hour - time.Second)
		if h := r.ev.kept.held(); h.Items[1].Text != text || h.Items[1].CodeExpired {
			t.Fatalf("%dh: before the hour %+v", hours, h.Items[1])
		}
		r.now = start.Add(time.Duration(hours) * time.Hour)
		h := r.ev.kept.held()
		want := "Hi, your Acme verification code is " + owner.ExpiredCode + ". Ask me if it fails."
		if it := h.Items[1]; it.Text != want || !it.CodeExpired || it.Expired || it.Kind != localapi.HeldOneTime {
			t.Fatalf("%dh: at the hour %+v", hours, it)
		}
		if it := h.Items[0]; it.Text != "key AKIACANARY0000000000" || it.CodeExpired {
			t.Fatalf("%dh: the key went with the code: %+v", hours, it)
		}
		r.ev.kept.sweep()
		if raw, _ := r.store.Load(); strings.Contains(string(raw), code) || !strings.Contains(string(raw), "Ask me if it fails.") {
			t.Fatalf("%dh: swept file %s", hours, raw)
		}
		r.now = start.Add(defaultKeepFor - time.Second)
		if l := r.ev.kept.list(); len(l) != 2 || l[0].Expired || l[0].Text != want {
			t.Fatalf("%dh: the item did not keep its days: %+v", hours, l)
		}
	}
}

// TestCodeHoursBound (CODEH-5): -code-hours takes 1 to 24 and defaults to
// 1; anything else is refused (CH-19, #906).
func TestCodeHoursBound(t *testing.T) {
	for h, ok := range map[int]bool{-1: false, 0: false, 1: true, 12: true, 24: true, 25: false} {
		d, err := codeFor(h)
		if (err == nil) != ok || ok && d != time.Duration(h)*time.Hour {
			t.Errorf("codeFor(%d) = %v, %v", h, d, err)
		}
	}
	r := newEvRig(t)
	if err := r.ev.kept.Keep(owner.KeptOneTime, "code 482913"); err != nil {
		t.Fatal(err)
	}
	if l := r.ev.kept.list(); l[0].CodeUntil != r.now.Add(time.Hour) || defaultCodeFor != time.Hour {
		t.Fatalf("default code hours: %+v", l[0])
	}
}

// TestHeldCodeBesideAKeyExpires (CODEH-7, #4014 L3 1): a code kept beside
// a key leaves the disk at the hour while the key stays for its days, and
// a kept code the stored text cannot show expires with the whole text.
func TestHeldCodeBesideAKeyExpires(t *testing.T) {
	r := newEvRig(t)
	for _, text := range []string{"Your login code is 482913 and your key is AKIACANARY0000000000", "co de 482913"} {
		if err := r.ev.kept.Keep(owner.KeptOneTime, text); err != nil {
			t.Fatal(err)
		}
	}
	r.now = r.now.Add(time.Hour)
	r.ev.kept.sweep()
	raw, _ := r.store.Load()
	if strings.Contains(string(raw), "482913") || !strings.Contains(string(raw), "AKIACANARY0000000000") {
		t.Fatalf("swept file %s", raw)
	}
	if l := r.ev.kept.list(); len(l) != 2 || l[1].Text != owner.ExpiredCode || !l[1].CodeExpired || l[1].Expired {
		t.Fatalf("kept %+v", l)
	}
}

// TestHeldCodeShowsItsExpiredView (CODEH-8, #4014 delta L3): at the hour a
// code kept with KeepCode reads as the view the owner channel gave, and
// the swept file holds neither code.
func TestHeldCodeShowsItsExpiredView(t *testing.T) {
	r := newEvRig(t)
	text := "Your code is 482913. Also verifi cation 4829 13"
	if err := r.ev.kept.KeepCode(text, owner.ExpiredView("Your code is 482913. Also verifi\x07cation 4829\x0713")); err != nil {
		t.Fatal(err)
	}
	if l := r.ev.kept.list(); l[0].Text != text {
		t.Fatalf("before the hour %+v", l[0])
	}
	r.now = r.now.Add(time.Hour)
	r.ev.kept.sweep()
	raw, _ := r.store.Load()
	if strings.Contains(string(raw), "4829") {
		t.Fatalf("swept file %s", raw)
	}
	if l := r.ev.kept.list(); l[0].Text != owner.ExpiredCode || !l[0].CodeExpired {
		t.Fatalf("at the hour %+v", l[0])
	}
}

// TestRetriedHeldCodeKeepsTheStricterView (CODEH-9, #4014 Security): a
// code text kept once as received with a control and once clean is kept
// once, and at the hour shows the stricter view, so the code a control
// hid does not outlive its hours, in either order.
func TestRetriedHeldCodeKeepsTheStricterView(t *testing.T) {
	hidden := "Your code is 482913. Also verifi\x07cation 4829\x0713"
	clean := "Your code is 482913. Also verifi cation 4829 13"
	for _, order := range [][]string{{hidden, clean}, {clean, hidden}} {
		r := newEvRig(t)
		for _, in := range order {
			if err := r.ev.kept.KeepCode(control.StripControls(in), owner.ExpiredView(in)); err != nil {
				t.Fatal(err)
			}
		}
		r.now = r.now.Add(time.Hour)
		r.ev.kept.sweep()
		raw, _ := r.store.Load()
		if l := r.ev.kept.list(); len(l) != 1 || strings.Contains(string(raw), "4829") || l[0].Text != owner.ExpiredCode {
			t.Fatalf("%q then %q: kept %+v", order[0], order[1], l)
		}
	}
}
