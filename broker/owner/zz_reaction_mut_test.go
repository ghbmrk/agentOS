package owner

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// REQ: CH-3, CH-11, CH-14, CH-15, CH-16
// MUT-kill-5974-owner (#6670), part 4: the reaction.go and autoreply.go
// statements mutgate's deletion left alive, each pinned by a test that
// fails without it. They call the function that holds the line directly
// where they can.

// reactAt is the clock the bare-window tests use.
var reactAt = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

// reactRequest is a guarded text: an approval request.
func reactRequest(text string, at time.Time) sentText {
	return sentText{text: text, at: at, request: true, ids: []string{"K7"}}
}

// queuedIDs is the channel's queued reply IDs, in memory and saved.
func queuedIDs(ch *Channel) (mem int, saved []string) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	for _, q := range ch.codes.st.Queued {
		saved = append(saved, q.ID)
	}
	return len(ch.queued), saved
}

// shapeForm trims the text first: a trailing space leaves the quote whole,
// not read as a cut quote that ends in its closing mark.
func TestMutReactionShapeFormTrims(t *testing.T) {
	lead, quote, ok := shapeForm(`Pinned "Lunch at noon on Friday" `)
	if !ok || lead != "Pinned" || quote != "Lunch at noon on Friday" {
		t.Fatalf("shapeForm: %q %q %v", lead, quote, ok)
	}
}

// A listed form whose quote holds quote marks is a reaction when it marks
// a recent text that is not guarded.
func TestMutReactionListedFormWithQuoteMarks(t *testing.T) {
	r := newRig(t, nil)
	r.ch.recent.add(sentText{text: `Say "hi" to Sam at lunch today`, at: r.clock()})
	rx, ok := r.ch.readReaction(`Liked "Say "hi" to Sam at lunch today"`)
	if !ok || rx.tell || rx.kind != "liked" {
		t.Fatalf("readReaction: %+v %v", rx, ok)
	}
}

// A listed form that marks no recent text is chat, even when its text has
// another shape whose quote would mark a guarded text: the listed form's
// quote is the one read.
func TestMutReactionListedFormMissIsChat(t *testing.T) {
	r := newRig(t, nil)
	r.ch.recent.add(reactRequest(`Can I send from "abcdef"gh to Sam? Reply YES K7 with the code or NO K7.`, r.clock()))
	text := `Removed a " from "abcdef"gh"`
	if q, ok := peelForm(text); !ok || q != `abcdef"gh` {
		t.Fatalf("peelForm: %q %v", q, ok)
	}
	if rx, ok := r.ch.readReaction(text); ok {
		t.Fatalf("read as a reaction: %+v", rx)
	}
}

// forget keeps the guarded texts and drops the rest.
func TestMutReactionForgetKeepsGuarded(t *testing.T) {
	var w recentWindow
	req := "Can I send invoice 1042 to billing? Reply YES K7 482913 or NO K7."
	w.add(reactRequest(req, reactAt))
	w.add(sentText{text: "Lunch is booked for Friday at noon.", at: reactAt})
	w.forget(reactAt)
	if _, ok := w.match(req, reactAt); !ok {
		t.Fatal("forget dropped a guarded text")
	}
	if _, ok := w.match("Lunch is booked for Friday at noon.", reactAt); ok {
		t.Fatal("forget kept a plain text")
	}
}

// An empty quote marks nothing, not a text that normalizes to empty.
func TestMutReactionEmptyQuoteMarksNothing(t *testing.T) {
	var w recentWindow
	w.add(sentText{text: "...", at: reactAt})
	if _, ok := w.match("…", reactAt); ok {
		t.Fatal("an empty quote matched")
	}
}

// A text older than the window is never matched, by match or within.
func TestMutReactionOldTextsAgeOut(t *testing.T) {
	var w recentWindow
	text := "Lunch is booked for Friday at noon."
	w.add(sentText{text: text, at: reactAt})
	late := reactAt.Add(recentMaxAge + time.Minute)
	if _, ok := w.match(text, reactAt); !ok {
		t.Fatal("a recent text did not match")
	}
	if _, ok := w.match(text, late); ok {
		t.Fatal("match found a text past the window")
	}
	all := func(sentText) bool { return true }
	if _, ok := w.within("Loved it: "+text, reactAt, all); !ok {
		t.Fatal("within missed a recent text")
	}
	if _, ok := w.within("Loved it: "+text, late, all); ok {
		t.Fatal("within found a text past the window")
	}
}

// within reads a restored text, saved code-masked, against the quote with
// its codes masked too.
func TestMutReactionWithinRestoredMasks(t *testing.T) {
	var w recentWindow
	w.texts = append(w.texts, sentText{text: maskCodes(normQuote("Your code is 482913 for K7")), at: reactAt, restored: true})
	if _, ok := w.within("Liked: Your code is 482913 for K7 ok", reactAt, sentText.guarded); !ok {
		t.Fatal("within missed a restored text")
	}
}

// quoteLayers stops at the first layer that is not a form.
func TestMutReactionQuoteLayersStop(t *testing.T) {
	if got := quoteLayers("plain words"); !slices.Equal(got, []string{"plain words"}) {
		t.Fatalf("layers %q", got)
	}
	if got := quoteLayers(`Liked "Loved "plain words""`); !slices.Equal(got, []string{`Liked "Loved "plain words""`, `Loved "plain words"`, "plain words"}) {
		t.Fatalf("layers %q", got)
	}
}

// Delivering a reaction marks the owner active; a stale one does not.
func TestMutReactionDeliverMarksActive(t *testing.T) {
	r := newRig(t, nil)
	at := r.clock().Add(time.Minute)
	r.ch.deliverReaction(context.Background(), ownerNum, route{react: "Owner reaction: liked a text.", reactGen: r.ch.recent.gen(), at: at})
	r.ch.mu.Lock()
	got := r.ch.active
	r.ch.mu.Unlock()
	if !got.Equal(at) {
		t.Fatalf("active %v, want %v", got, at)
	}
	r.ch.deliverReaction(context.Background(), ownerNum, route{react: "Owner reaction: liked a text.", reactGen: r.ch.recent.gen() + 1, at: at.Add(time.Hour)})
	r.ch.mu.Lock()
	got = r.ch.active
	r.ch.mu.Unlock()
	if !got.Equal(at) {
		t.Fatalf("a stale event moved active to %v", got)
	}
}

// recordReplies records only replies to the owner.
func TestMutReactionRecordRepliesOwnerOnly(t *testing.T) {
	r := newRig(t, nil)
	r.ch.recordReplies("+15550001111", []string{"A reply to someone else entirely."})
	if _, ok := r.ch.recent.match("A reply to someone else entirely.", r.clock()); ok {
		t.Fatal("a reply to another number was recorded")
	}
	r.ch.recordReplies(ownerNum, []string{"A reply to the owner, recorded."})
	if _, ok := r.ch.recent.match("A reply to the owner, recorded.", r.clock()); !ok {
		t.Fatal("a reply to the owner was not recorded")
	}
}

// replyPointer names each kind of text's valid replies.
func TestMutReactionReplyPointer(t *testing.T) {
	for _, c := range []struct {
		t    sentText
		want string
	}{
		{sentText{request: true, ids: []string{"K7"}, local: true}, "A reaction does not approve anything. Approve or deny K7 on my Wi-Fi page, or reply NO K7."},
		{sentText{text: "Lunch is booked.", request: true}, "A reaction is not a reply. Reply in words, as that text says."},
		{sentText{text: "Reply UNDO K7 to stop it."}, "A reaction is not a reply. Reply in words, as that text says."},
		{sentText{text: "Lunch is booked."}, ""},
	} {
		if got := replyPointer(c.t); got != c.want {
			t.Errorf("%+v: %q, want %q", c.t, got, c.want)
		}
	}
}

// A request sent on a count Spend made uses that count: it is taken off
// spent and not counted again (CH-15).
func TestMutAutoReplyRequestUsesSpend(t *testing.T) {
	r := newRig(t, nil)
	if _, ok := r.ch.Spend(false); !ok {
		t.Fatal("spend refused")
	}
	if _, err := r.ch.Request([]Item{lowItem("x1")}, 0); err != nil {
		t.Fatal(err)
	}
	r.ch.mu.Lock()
	spent, sent := len(r.ch.spent), len(r.ch.codes.st.Sent)
	r.ch.mu.Unlock()
	if spent != 0 || sent != 1 {
		t.Fatalf("spent %d, sent %d; want 0 and 1", spent, sent)
	}
}

// QueueAutoReply refuses with no modem, and without recipients or a body.
func TestMutAutoReplyRefuses(t *testing.T) {
	r := newRig(t, nil)
	ch := pacerNoModem(r)
	if _, err := ch.QueueAutoReply(AutoReply{Ref: "r1", Recipients: []string{"sam@example.com"}, Body: "Thanks."}); err == nil || err.Error() != "owner: no modem" {
		t.Fatalf("no modem: %v", err)
	}
	for _, ar := range []AutoReply{{Ref: "r1", Body: "Thanks."}, {Ref: "r1", Recipients: []string{"sam@example.com"}, Body: "  "}} {
		res, err := r.ch.QueueAutoReply(ar)
		if err == nil || res.Queued != nil {
			t.Fatalf("%+v: %+v %v", ar, res, err)
		}
	}
	if mem, saved := queuedIDs(r.ch); mem != 0 || len(saved) != 0 {
		t.Fatalf("queued %d, saved %q", mem, saved)
	}
}

// A reply the commitment filter matches asks to send it when its facts
// name no verb.
func TestMutAutoReplyCommitmentDefaultsToSend(t *testing.T) {
	r := newRig(t, nil)
	res, err := r.ch.QueueAutoReply(AutoReply{Ref: "r3", Recipients: []string{"sam@example.com"}, Body: "Yes, I confirm.",
		Facts: Facts{RecipientChecked: true, RecipientExists: true, RecipientByOwner: true}})
	if err != nil || res.Request == "" {
		t.Fatalf("%+v %v", res, err)
	}
	if text := r.inbox(); !strings.HasPrefix(text, `Can I send "reply (commitment)" to sam@example.com?`) {
		t.Fatalf("approval: %q", text)
	}
}

// With no free ID, the reply is refused and nothing is queued.
func TestMutAutoReplyNoFreeID(t *testing.T) {
	r := newRig(t, nil)
	r.ch.mu.Lock()
	if r.ch.codes.st.Retired == nil {
		r.ch.codes.st.Retired = map[string]time.Time{}
	}
	for _, l := range idLetters {
		for d := range 100 {
			r.ch.codes.st.Retired[fmt.Sprintf("%c%d", l, d)] = r.clock()
			r.ch.codes.st.Retired[fmt.Sprintf("%c%02d", l, d)] = r.clock()
		}
	}
	r.ch.mu.Unlock()
	res, err := r.ch.QueueAutoReply(AutoReply{Ref: "r1", Recipients: []string{"sam@example.com"}, Body: "Thanks."})
	if err == nil || res.Queued != nil {
		t.Fatalf("%+v %v", res, err)
	}
	if mem, saved := queuedIDs(r.ch); mem != 0 || len(saved) != 0 {
		t.Fatalf("queued %d, saved %q", mem, saved)
	}
}

// A reply whose alert cannot be sent is dropped, in memory and saved.
func TestMutAutoReplyAlertFailsDrops(t *testing.T) {
	r := newRig(t, nil)
	r.box.SetDown(true)
	res, err := r.ch.QueueAutoReply(AutoReply{Ref: "r1", Recipients: []string{"sam@example.com"}, Body: "Thanks."})
	if err == nil || res.Queued != nil {
		t.Fatalf("%+v %v", res, err)
	}
	if mem, saved := queuedIDs(r.ch); mem != 0 || len(saved) != 0 {
		t.Fatalf("queued %d, saved %q", mem, saved)
	}
}

// A released ID, and a late UNDO of it, are forgotten after RetireFor:
// UNDO then finds nothing.
func TestMutAutoReplyReleasedRetires(t *testing.T) {
	r := newRig(t, nil)
	res, err := r.ch.QueueAutoReply(AutoReply{Ref: "r1", Recipients: []string{"sam@example.com"}, Body: "Thanks."})
	if err != nil {
		t.Fatal(err)
	}
	r.inbox()
	id := res.Queued.ID
	r.advance(DefaultUndoWindow)
	if len(r.ch.DueAutoReplies()) != 1 {
		t.Fatal("not released")
	}
	if got := r.say("UNDO " + id); got != id+" is past its undo window; it was released." || !r.ch.UndoneAfterRelease(id) {
		t.Fatalf("late undo: %q", got)
	}
	r.advance(RetireFor)
	r.ch.DueAutoReplies()
	if r.ch.UndoneAfterRelease(id) {
		t.Fatal("a late UNDO outlived RetireFor")
	}
	r.ch.mu.Lock()
	_, kept := r.ch.released[id]
	r.ch.mu.Unlock()
	if kept {
		t.Fatal("a released ID outlived RetireFor")
	}
	if got := r.say("UNDO " + id); got != "Nothing to undo for "+id+"." {
		t.Fatalf("undo: %q", got)
	}
}

// UNDO retires the reply's saved record, and a held effect's decision
// names its hold.
func TestMutAutoReplyUndoRetiresAndNamesHold(t *testing.T) {
	r := newRig(t, nil)
	res, _ := r.ch.QueueAutoReply(AutoReply{Ref: "r1", Recipients: []string{"sam@example.com"}, Body: "Thanks."})
	r.inbox()
	if got := r.say("UNDO " + res.Queued.ID); !strings.HasPrefix(got, "Cancelled ") {
		t.Fatalf("undo: %q", got)
	}
	if mem, saved := queuedIDs(r.ch); mem != 0 || len(saved) != 0 {
		t.Fatalf("queued %d, saved %q", mem, saved)
	}
	if ds := r.decisions(); len(ds) != 1 || ds[0].Hold != "" {
		t.Fatalf("reply decisions %+v", ds)
	}

	r.ch.Request([]Item{heldItem("e1")}, 0)
	m := lowCodeRe.FindStringSubmatch(r.inbox())
	u := holdRe.FindStringSubmatch(r.say("YES " + m[1] + " " + m[2]))
	r.decisions()
	if got := r.say("UNDO " + u[1]); got != "Cancelled "+u[1]+". It did not run." {
		t.Fatalf("undo: %q", got)
	}
	if ds := r.decisions(); len(ds) != 1 || ds[0].Hold != u[1] {
		t.Fatalf("held decisions %+v", ds)
	}
}

// SetUndo(nil) removes the hook.
func TestMutAutoReplySetUndoNil(t *testing.T) {
	r := newRig(t, nil)
	r.ch.SetUndo(func(context.Context, string) (string, bool) { return "hooked", true })
	r.ch.SetUndo(nil)
	if got := r.ch.undoElsewhere(context.Background(), "Z9"); got != "Nothing to undo for Z9." {
		t.Fatalf("undo: %q", got)
	}
}

// RESUME names the re-windowed IDs in order.
func TestMutAutoReplyRewindowSorts(t *testing.T) {
	r := newRig(t, nil)
	ids := []string{"A2", "B3", "C4", "D5", "E6"}
	for range 20 {
		r.ch.mu.Lock()
		r.ch.queued = map[string]*Queued{}
		for _, id := range ids {
			r.ch.queued[id] = &Queued{ID: id, SendAt: r.clock()}
		}
		got := r.ch.rewindowLocked(r.clock(), "")
		r.ch.mu.Unlock()
		if !strings.HasPrefix(got, " "+strings.Join(ids, ", ")+" run at ") {
			t.Fatalf("tail %q", got)
		}
	}
}

// firstLine trims before it cuts at a line break.
func TestMutAutoReplyFirstLineTrims(t *testing.T) {
	if got := firstLine("\n Thanks Sam.\nMore later."); got != "Thanks Sam." {
		t.Fatalf("firstLine %q", got)
	}
}
