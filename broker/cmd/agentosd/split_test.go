package main

// REQ: CH-12, CH-19

import (
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/owner"
)

// room is what one GSM-7 text leaves for agent text, which carries no
// label (CH-21).
const room = control.MaxText

// sentences is n bytes or a little more of whole sentences.
func sentences(n int) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		b.WriteString("The plumber can come on Thursday morning between nine and noon. ")
	}
	return strings.TrimSpace(b.String())
}

// TestLongReplyArrivesWhole: a reply of about two and a half texts goes as
// three texts in order, each within one text, cut at sentence ends, and
// nothing is kept or cut (CH-12, D-127).
func TestLongReplyArrivesWhole(t *testing.T) {
	r := newEvRig(t)
	long := sentences(room*5/2 - 40)
	r.ev.sendSplit("agent", long)
	got := r.texts()
	if len(got) != 3 {
		t.Fatalf("%d texts: %q", len(got), got)
	}
	for _, s := range got {
		if len(s) > control.MaxText {
			t.Fatalf("text over one text: %d bytes", len(s))
		}
		if !strings.HasSuffix(s, ".") || strings.Contains(s, keptLong) {
			t.Fatalf("text not cut at a sentence end: %q", s)
		}
	}
	if strings.Join(got, " ") != long {
		t.Fatal("the texts do not join back to the reply")
	}
	if k := r.ev.kept.list(); len(k) != 0 {
		t.Fatalf("a reply that fits three texts was kept: %d", len(k))
	}
}

// TestTooLongReplyIsCutInTheThirdText: a reply of about four texts goes as
// three, the third ending with the cut note, and is kept whole (CH-12).
func TestTooLongReplyIsCutInTheThirdText(t *testing.T) {
	r := newEvRig(t)
	long := sentences(room * 4)
	r.ev.sendSplit("agent", long)
	got := r.texts()
	if len(got) != 3 {
		t.Fatalf("%d texts", len(got))
	}
	for i, s := range got {
		if len(s) > control.MaxText {
			t.Fatalf("text %d over one text", i)
		}
		if (i == 2) != strings.HasSuffix(s, " "+keptLong) {
			t.Fatalf("text %d: %q", i, s)
		}
		noPage(t, s)
	}
	if !strings.HasPrefix(long, strings.Join(got[:2], " ")) {
		t.Fatal("the first two texts are not the reply's start")
	}
	if k := r.ev.kept.list(); len(k) != 1 || k[0].Text != long {
		t.Fatalf("kept %d", len(k))
	}
}

// TestSplitPrefersParagraphsThenLines: a paragraph break past half a text
// is taken over a later sentence end; a line break the same; with neither,
// a sentence end; with no sentence end, a word boundary (CH-12).
func TestSplitPrefersParagraphsThenLines(t *testing.T) {
	head := sentences(room * 2 / 3)
	for _, sep := range []string{"\n\n", "\n"} {
		text := head + sep + sentences(room/2)
		parts, cut := splitReply(text)
		if cut || len(parts) != 2 || parts[0] != head {
			t.Fatalf("sep %q: cut %v, first %q", sep, cut, parts[0])
		}
	}
	words := strings.Repeat("word ", room/5*2)
	parts, _ := splitReply(words)
	for _, p := range parts {
		if len(p) > room || strings.TrimSpace(p) != p {
			t.Fatalf("part %q", p)
		}
		for _, w := range strings.Fields(p) {
			if w != "word" {
				t.Fatalf("a word was cut: %q", w)
			}
		}
	}
	// A line break in the first half does not leave a stub text.
	parts, _ = splitReply("Hi.\n" + sentences(room+100))
	if len(parts[0]) <= room/2 {
		t.Fatalf("stub first text %q", parts[0])
	}
}

// TestSplitKeepsRunesAndEmoji: a run with no boundary is cut on a rune
// boundary, never inside a joined emoji (CH-12).
func TestSplitKeepsRunesAndEmoji(t *testing.T) {
	text := strings.Repeat("👩‍💻", room)
	parts, _ := splitReply(text)
	for _, p := range parts {
		if n, _ := control.Units(p); n > textRoom(false) || strings.HasPrefix(p, "‍") || strings.HasSuffix(p, "‍") {
			t.Fatalf("part cuts an emoji: %q", p[len(p)-8:])
		}
	}
}

// TestSecretIsCheckedBeforeTheSplit: CH-19's check runs on the whole reply
// before it is split (CH-12), so a code whose label ends one text and whose
// digits start the next is still caught: the reply goes as one text, which
// the owner channel replaces with the local-UI pointer.
func TestSecretIsCheckedBeforeTheSplit(t *testing.T) {
	filler := strings.Repeat("ok ", (room-len(" your verification code"))/3)
	long := filler + "your verification code 482913 " + strings.Repeat("ok ", room/3)
	parts, _ := splitReply(long)
	if len(parts) < 2 || owner.SecretShaped(parts[0]) || owner.SecretShaped(parts[1]) {
		t.Fatal("the fixture no longer straddles a text boundary")
	}
	if !owner.SecretShaped(long) {
		t.Fatal("the fixture is not secret-shaped")
	}
	r := newEvRig(t)
	r.ev.sendSplit("agent", long)
	if got := r.texts(); len(got) != 1 || owner.Disclose(got[0]) != owner.Hidden {
		t.Fatalf("a split secret went out as %d texts", len(got))
	}
}

// TestFailedTextStopsTheRest: when a text does not go, the later ones are
// not sent out of order and the reply is kept (CH-12).
func TestFailedTextStopsTheRest(t *testing.T) {
	r := newEvRig(t)
	n := 0
	r.ev.notify = func(string) error { n++; return errNoSend }
	r.ev.sendSplit("agent", sentences(room*2))
	if n != 1 || len(r.ev.kept.list()) != 1 {
		t.Fatalf("sent %d after a failure, kept %d", n, len(r.ev.kept.list()))
	}
}

var errNoSend = errors.New("not sent")
