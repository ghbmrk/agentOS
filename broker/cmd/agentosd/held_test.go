package main

// REQ: CAP-3, A8, CH-12

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeclient"
	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/recovery"
)

// heldOwnerNumber is a synthetic number from the fictional 555-01xx range.
const heldOwnerNumber = "+15550100100"

func newHeldMode(t *testing.T, learn string) heldMode {
	t.Helper()
	dir, err := os.MkdirTemp("", "ah")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	uid, gid := os.Getuid(), os.Getgid()
	return heldMode{Learn: learn, Dir: filepath.Join(dir, "run"), Owner: heldOwnerNumber,
		PeerUID: &uid, PeerGID: &gid, Retry: 20 * time.Millisecond, Logf: t.Logf}
}

func writeMarker(t *testing.T, dir, reason, notice string) {
	t.Helper()
	marker := reason + "\n" + notice + "\n"
	if err := os.WriteFile(filepath.Join(dir, forgetLogFile+recovery.PendingSuffix), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakeBridge plays agentos-modem on the owner socket.
type fakeBridge struct {
	t *testing.T
	c bridgeclient.Client
}

func (b fakeBridge) call(op string, args, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.c.Call(ctx, op, args, out)
}

// next polls the outbox until a text comes, reports it sent, and returns
// it.
func (b fakeBridge) next() bridgeproto.Item {
	b.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var out struct{ Item *bridgeproto.Item }
		if err := b.call(bridgeproto.OpOutbox, nil, &out); err != nil {
			b.t.Fatalf("outbox: %v", err)
		}
		if out.Item != nil {
			if err := b.call(bridgeproto.OpSent, bridgeproto.Sent{ID: out.Item.ID, Code: bridgeproto.CodeOK}, nil); err != nil {
				b.t.Fatalf("sent: %v", err)
			}
			return *out.Item
		}
	}
	b.t.Fatal("no text to the owner")
	return bridgeproto.Item{}
}

// none checks one poll hands out nothing.
func (b fakeBridge) none() {
	b.t.Helper()
	var out struct{ Item *bridgeproto.Item }
	if err := b.call(bridgeproto.OpOutbox, nil, &out); err != nil || out.Item != nil {
		b.t.Fatalf("outbox: %v %+v", err, out.Item)
	}
}

func (b fakeBridge) inbound(id, from, text string) {
	b.t.Helper()
	in := bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: from, Text: text, ID: id}
	if err := b.call(bridgeproto.OpInbound, in, nil); err != nil {
		b.t.Fatalf("inbound %q: %v", text, err)
	}
}

// #409 UX U2: a held box texts the owner what holds it and takes their
// answer from the owner line alone; the right answer releases it, and
// agentosd stops serving the held mode.
func TestAHeldBoxTextsTheOwnerAndTakesTheirAnswer(t *testing.T) {
	learn := t.TempDir()
	writeHeld(t, learn, recovery.PendingUnanchored, 2, nil)
	m := newHeldMode(t, learn)
	m.Link = modemlink.New(modemlink.Config{Owner: heldOwnerNumber, PollWait: 100 * time.Millisecond})
	done := make(chan error, 1)
	go func() { done <- m.run(context.Background()) }()
	b := fakeBridge{t: t, c: bridgeclient.Client{Path: filepath.Join(m.Dir, daemon.OwnerSocket)}}
	deadline := time.Now().Add(5 * time.Second)
	// The first text waits for the bridge to report the owner line.
	for b.call(bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil) != nil {
		if time.Now().After(deadline) {
			t.Fatal("owner.sock never served")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ask := b.next()
	if ask.To != heldOwnerNumber || ask.Text != mustHeldText(t, learn) {
		t.Fatalf("first text %+v", ask)
	}
	// Another sender's letter is no answer (CAP-3, #436 L3 point 4).
	b.inbound("x1", "+15550100199", "c")
	b.none()
	if restoreHold(learn) == nil {
		t.Fatal("another sender released the hold")
	}
	b.inbound("o1", heldOwnerNumber, "yes")
	if again := b.next(); again.Text != ask.Text {
		t.Fatalf("an unclear reply got %q", again.Text)
	}
	b.inbound("o2", heldOwnerNumber, "c")
	if got := b.next(); got.Text != heldReleased {
		t.Fatalf("the right answer got %q", got.Text)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("held mode did not end at release")
	}
	if restoreHold(learn) != nil {
		t.Fatal("still held")
	}
	if _, err := os.Stat(filepath.Join(m.Dir, daemon.OwnerSocket)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owner.sock left serving the held mode: %v", err)
	}
}

// Without the bridge, "message" answers only the owner's number.
func TestHeldMessageAnswersOnlyTheOwner(t *testing.T) {
	learn := t.TempDir()
	writeHeld(t, learn, recovery.PendingUnanchored, 2, nil)
	m := newHeldMode(t, learn)
	m.Message = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.run(ctx) }()
	b := fakeBridge{t: t, c: bridgeclient.Client{Path: filepath.Join(m.Dir, daemon.OwnerSocket)}}
	msg := func(from, text string) []string {
		var out struct{ Replies []string }
		deadline := time.Now().Add(5 * time.Second)
		for {
			err := b.call("message", map[string]string{"From": from, "Text": text}, &out)
			if err == nil {
				return out.Replies
			}
			if time.Now().After(deadline) {
				t.Fatalf("message: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if r := msg("+15550100199", "C"); len(r) != 0 {
		t.Fatalf("another sender got %q", r)
	}
	if r := msg(heldOwnerNumber, "STATUS"); len(r) != 1 || r[0] != mustHeldText(t, learn) {
		t.Fatalf("STATUS got %q", r)
	}
	if restoreHold(learn) == nil {
		t.Fatal("released by another sender")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run: %v", err)
	}
	if restoreHold(learn) == nil {
		t.Fatal("a stop released the hold")
	}
}

// #436 L3 point 5: replies are taken one at a time, so two right answers
// at once release the restore once, and a wrong one racing the right one
// cannot both close and release it.
func TestHeldRepliesAreTakenOneAtATime(t *testing.T) {
	learn := t.TempDir()
	writeHeld(t, learn, recovery.PendingUnanchored, 2, nil)
	h := &heldReplies{dir: learn, logf: t.Logf}
	var wg sync.WaitGroup
	var mu sync.Mutex
	released := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			text, rel := h.reply("C")
			mu.Lock()
			defer mu.Unlock()
			if rel && text == heldReleased {
				released++
			}
		}()
	}
	wg.Wait()
	if released != 1 || restoreHold(learn) != nil {
		t.Fatalf("released %d times; hold %v", released, restoreHold(learn))
	}
}

// #436 L3 point 8: a long reply is no choice, whatever it holds.
func TestALongReplyIsNoChoice(t *testing.T) {
	learn := t.TempDir()
	writeHeld(t, learn, recovery.PendingUnanchored, 2, nil)
	h := &heldReplies{dir: learn, logf: t.Logf}
	text, rel := h.reply("C" + strings.Repeat(" ", heldReplyMax))
	if rel || text != mustHeldText(t, learn) || restoreHold(learn) == nil {
		t.Fatalf("a long reply: %v %q", rel, text)
	}
	if _, rel := h.reply("C"); !rel {
		t.Fatal("the short reply after it")
	}
}

// A reply that cannot be saved holds the restore for the rest of this
// start: no answer, right or wrong, counts after it.
func TestAnAnswerThatCannotBeSavedFailsClosed(t *testing.T) {
	learn := t.TempDir()
	writeHeld(t, learn, recovery.PendingUnanchored, 2, nil)
	h := &heldReplies{dir: learn, logf: t.Logf}
	orig := syncDir
	syncDir = func(string) error { return errors.New("synthetic sync failure") }
	text, rel := h.reply("A")
	syncDir = orig
	if rel || text != heldNotice(learn) {
		t.Fatalf("a failed save: %v %q", rel, text)
	}
	if text, rel := h.reply("C"); rel || text != heldNotice(learn) || restoreHold(learn) == nil {
		t.Fatalf("an answer after a failed save: %v %q", rel, text)
	}
}

// A hold with no question (rolled back, forged, or a question that does
// not read) texts the marker's notice, at start and to every reply.
func TestAHoldWithNoQuestionTextsItsNotice(t *testing.T) {
	for _, reason := range []string{recovery.PendingRolledBack, recovery.PendingForged} {
		t.Run(reason, func(t *testing.T) {
			learn := t.TempDir()
			writeMarker(t, learn, reason, recovery.PendingNotice(reason))
			h := &heldReplies{dir: learn, logf: t.Logf}
			if got := h.opening(); got != recovery.PendingNotice(reason) {
				t.Fatalf("opening %q", got)
			}
			if got, rel := h.reply("A"); rel || got != recovery.PendingNotice(reason) {
				t.Fatalf("reply %v %q", rel, got)
			}
		})
	}
	learn := t.TempDir()
	writeHeld(t, learn, recovery.PendingUnanchored, 2, nil)
	if err := os.WriteFile(filepath.Join(learn, forgetLogFile+recovery.ConfirmSuffix), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &heldReplies{dir: learn, logf: t.Logf}
	if got := h.opening(); got != recovery.PendingNotice(recovery.PendingUnanchored) {
		t.Fatalf("an unreadable question: %q", got)
	}
}

// A notice that is not a fit owner text (empty, not GSM-7, or past three
// segments) is replaced by a fixed one.
func TestAnUnfitNoticeFallsBack(t *testing.T) {
	for _, notice := range []string{"", "Restore on hold \u2713", strings.Repeat("Restore on hold. ", 40)} {
		learn := t.TempDir()
		writeMarker(t, learn, recovery.PendingForged, notice)
		if got := heldNotice(learn); got != heldFallback {
			t.Fatalf("%q gave %q", notice, got)
		}
	}
}

// The number held mode texts: -owner, else setup's finished record; with
// neither there is no one to text and agentosd does not start.
func TestHeldOwnerIsTheFlagOrTheFinishedRecord(t *testing.T) {
	dir := t.TempDir()
	rec := localsrv.FileRecord{Path: filepath.Join(dir, "setup.json")}
	if o, err := heldOwner(heldOwnerNumber, rec); err != nil || o != heldOwnerNumber {
		t.Fatalf("flag: %q %v", o, err)
	}
	if _, err := heldOwner("", rec); err == nil {
		t.Fatal("no record")
	}
	if err := rec.Save(localsrv.SetupRecord{Enrolled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := heldOwner("", rec); err == nil {
		t.Fatal("an unfinished record")
	}
	if err := rec.Save(localsrv.SetupRecord{Enrolled: true, Finished: true, Owner: "+15550100101"}); err != nil {
		t.Fatal(err)
	}
	if o, err := heldOwner("", rec); err != nil || o != "+15550100101" {
		t.Fatalf("record: %q %v", o, err)
	}
}

// #436 UX points 1 and 2: the unanchored header names this PC, and with
// no newer backup the wrong-answer text names a way to answer again.
func TestHeldTextsNameThisPCAndARetry(t *testing.T) {
	dir := t.TempDir()
	writeHeld(t, dir, recovery.PendingUnanchored, 2, nil)
	if text := mustHeldText(t, dir); !strings.HasPrefix(text, "Restore on hold: this PC can't check your forget list.") {
		t.Fatalf("header: %q", text)
	}
	reply, _, err := answerHeld(dir, "A")
	if err != nil || !strings.Contains(reply, "If you picked by mistake, restore this backup again to answer again.") {
		t.Fatalf("no newer backup: %q %v", reply, err)
	}
	dir = t.TempDir()
	writeHeld(t, dir, recovery.PendingUnanchored, 2, []recovery.BackupEntry{{Destination: "Cloud box", Created: time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)}})
	if reply, _, _ := answerHeld(dir, "A"); strings.Contains(reply, "by mistake") {
		t.Fatalf("with a newer backup: %q", reply)
	}
}

// heldSteps are the steps an owner text can name, as the CH-12 check
// (#409 UX U6, reviews/ux/README.md) finds them.
var heldSteps = map[string]*regexp.Regexp{
	"reply":           regexp.MustCompile(`Reply ([A-Z])(?:, ([A-Z]))*(?: or ([A-Z]))?\.`),
	"restore-same":    regexp.MustCompile(`(?i)restore this backup again`),
	"restore-newer":   regexp.MustCompile(`(?i)restore (?:a|your) newer backup`),
	"restore-old":     regexp.MustCompile(`(?i)from your old drive`),
	"restore-orig":    regexp.MustCompile(`(?i)restoring on your original PC`),
	"restore-again":   regexp.MustCompile(`(?i)restore again`),
	"wait-update":     regexp.MustCompile(`(?i)(?:wait for an update|until an update)`),
	"control-word":    regexp.MustCompile(`\b(?:STOP|STATUS|HELP|START)\b`),
	"restart":         regexp.MustCompile(`(?i)\brestart\b`),
	"reply-word":      regexp.MustCompile(`(?i)\breply (?:yes|no|y|n)\b`),
	"local-page":      regexp.MustCompile(`(?i)\b(?:local page|this PC's page)\b`),
	"connect-all":     regexp.MustCompile(`(?i)every backup destination connected`),
	"starts-shortly":  regexp.MustCompile(`(?i)starts again shortly`),
	"open-the-backup": regexp.MustCompile(`(?i)open the backup`),
}

// The CH-12 recurring kind "a problem text names a step that cannot work"
// (#409 UX U6), as a check: every text a held box can send is GSM-7 and
// within three segments, holds nothing forgotten, names only steps that
// work in its state, and, when it asks, lists exactly the replies taken.
func TestHeldOwnerTextsNameOnlyStepsThatWork(t *testing.T) {
	newer := []recovery.BackupEntry{{Destination: "Cloud box", Created: time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)}}
	type text struct {
		name, text string
		steps      []string // the steps that work in this state
		choices    int      // replies taken; 0 when it asks nothing
	}
	var texts []text
	for _, c := range heldCases() {
		for _, n := range []struct {
			name  string
			newer []recovery.BackupEntry
		}{{"", nil}, {"-newer", newer}} {
			dir := t.TempDir()
			writeHeld(t, dir, c.reason, c.answer, n.newer)
			q, _, err := loadHeld(dir)
			if err != nil {
				t.Fatal(err)
			}
			texts = append(texts, text{c.name + n.name + "-ask", askText(q), []string{"reply"}, q.choices()})
			wrong := 0
			if c.answer == 0 {
				wrong = 1
			}
			reply, _, err := answerHeld(dir, string(rune('A'+wrong)))
			if err != nil {
				t.Fatal(err)
			}
			// Restoring the same backup again writes its question afresh
			// (recovery writeQuestion), so it can be answered again.
			steps := []string{"restore-same", "restore-newer", "restore-old"}
			texts = append(texts, text{c.name + n.name + "-wrong", reply, steps, 0})
		}
	}
	texts = append(texts,
		text{"released", heldReleased, []string{"starts-shortly"}, 0},
		text{"fallback", heldFallback, []string{"wait-update"}, 0},
		// The notices a hold with no question texts; an unreadable
		// question texts its reason's notice.
		text{"notice-unanchored", recovery.PendingNotice(recovery.PendingUnanchored), []string{"restore-orig"}, 0},
		text{"notice-missing", recovery.PendingNotice(recovery.PendingMissing), []string{"wait-update"}, 0},
		text{"notice-rolled-back", recovery.PendingNotice(recovery.PendingRolledBack), []string{"restore-again", "connect-all", "wait-update"}, 0},
		text{"notice-forged", recovery.PendingNotice(recovery.PendingForged), []string{"wait-update"}, 0},
	)
	for _, tx := range texts {
		t.Run(tx.name, func(t *testing.T) {
			n, gsm7 := modem.Segments(tx.text)
			if !gsm7 || n > 3 || strings.Contains(tx.text, heldCanary) {
				t.Fatalf("%d segments, gsm7 %v:\n%s", n, gsm7, tx.text)
			}
			var named []string
			for step, re := range heldSteps {
				if re.MatchString(tx.text) {
					named = append(named, step)
				}
			}
			sort.Strings(named)
			allowed := map[string]bool{}
			for _, s := range tx.steps {
				allowed[s] = true
			}
			for _, s := range named {
				if !allowed[s] {
					t.Errorf("names %q, which cannot work here:\n%s", s, tx.text)
				}
			}
			m := heldSteps["reply"].FindString(tx.text)
			if (m != "") != (tx.choices > 0) {
				t.Fatalf("asks %v, lists replies %q:\n%s", tx.choices > 0, m, tx.text)
			}
			if m == "" {
				return
			}
			if !strings.HasSuffix(tx.text, m) {
				t.Errorf("the replies do not end the text:\n%s", tx.text)
			}
			var letters []string
			for _, f := range strings.FieldsFunc(strings.TrimPrefix(m, "Reply "), func(r rune) bool { return r == ',' || r == ' ' || r == '.' }) {
				if f != "or" {
					letters = append(letters, f)
				}
			}
			if len(letters) != tx.choices {
				t.Fatalf("lists %d replies, takes %d:\n%s", len(letters), tx.choices, tx.text)
			}
			for i, l := range letters {
				if c, ok := parseChoice(l, tx.choices); !ok || c != i {
					t.Errorf("reply %q is not taken as choice %d", l, i)
				}
			}
		})
	}
}

// agentosd enters the held mode before it opens anything a restore brought
// back, or setup: the learning plane's directory, recall, the daemon.
func TestTheHeldModeComesFirstInTheStart(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	held := strings.Index(s, "if held := restoreHold(learn.Dir); held != nil {")
	if held < 0 || strings.Index(s, "log.Fatal(err)\n\t}\n\tsleepHours") >= 0 {
		t.Fatal("main.go does not enter the held mode on the marker")
	}
	for _, later := range []string{"setupMode{", "os.MkdirAll(learn.Dir", "daemon.Run(ctx, cfg)", "modemlink.New(modemlink.Config{Owner: cfg.OwnerNumber})"} {
		if i := strings.Index(s, later); i < 0 || i < held {
			t.Errorf("%q comes before the held mode (%d < %d)", later, i, held)
		}
	}
}
