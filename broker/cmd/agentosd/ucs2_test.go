package main

// REQ: CH-12, CH-19

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
)

// emojiSentences is n bytes or a little more of whole sentences with an
// emoji in each, so every part needs UCS-2.
func emojiSentences(n int) string {
	var b strings.Builder
	for b.Len() < n {
		b.WriteString("The plumber 🔧 comes Thursday. ")
	}
	return strings.TrimSpace(b.String())
}

// TestEmojiReplySplitsForUCS2: a reply with emoji is split so each text
// keeps three segments in UCS-2 (201 units), not GSM-7's 459 septets, and
// the texts join back to the reply with its emoji (CH-12).
func TestEmojiReplySplitsForUCS2(t *testing.T) {
	r := newEvRig(t, "")
	long := emojiSentences(450)
	r.ev.reply("agent", true, long, "")
	got := r.texts()
	if len(got) < 2 || len(got) > maxReplyTexts {
		t.Fatalf("%d texts", len(got))
	}
	for i, s := range got {
		n, gsm7 := modem.Segments(owner.AgentPrefix + s)
		if n > 3 || gsm7 {
			t.Fatalf("text %d: %d segments, gsm7 %v", i, n, gsm7)
		}
		if !strings.HasSuffix(s, ".") {
			t.Fatalf("text %d not cut at a sentence end: %q", i, s)
		}
	}
	if strings.Join(got, " ") != long {
		t.Fatal("the texts do not join back to the reply")
	}
	if k := r.ev.kept.list(); len(k) != 0 {
		t.Fatalf("kept %d", len(k))
	}
}

// TestTooLongEmojiReplyIsCut: an emoji reply past three UCS-2 texts ends
// the third with the cut note, within the limit, and is kept (CH-12).
func TestTooLongEmojiReplyIsCut(t *testing.T) {
	r := newEvRig(t, "")
	long := emojiSentences(2000)
	r.ev.reply("agent", true, long, "")
	got := r.texts()
	if len(got) != maxReplyTexts || !strings.HasSuffix(got[2], " "+keptLong) {
		t.Fatalf("%d texts: %q", len(got), got)
	}
	for i, s := range got {
		if n, _ := modem.Segments(owner.AgentPrefix + s); n > 3 {
			t.Fatalf("text %d: %d segments", i, n)
		}
	}
	if k := r.ev.kept.list(); len(k) != 1 {
		t.Fatalf("kept %d", len(k))
	}
}

// TestControlsGoBeforeTheWholeReplyCheck: a code broken by direction
// controls across a split is cleaned before CH-19's whole-reply check, so
// the reply goes as the pointer, not in parts (CH-12, CH-19).
func TestControlsGoBeforeTheWholeReplyCheck(t *testing.T) {
	long := strings.Repeat("ok ", 140) + "your verification code 48‮29‬13 " + strings.Repeat("ok ", 140)
	r := newEvRig(t, "")
	r.ev.reply("agent", true, long, "")
	if got := r.texts(); len(got) != 1 || owner.Disclose(got[0]) != owner.Hidden {
		t.Fatalf("a bidi-split code went out as %d texts", len(got))
	}
}

// TestPlainReplyRoomIsUnchanged: plain GSM-7 replies still get the whole
// 459-septet room, less the prefix (CH-12).
func TestPlainReplyRoomIsUnchanged(t *testing.T) {
	long := sentences(room * 2)
	parts, _ := splitReply(long, room)
	if len(parts[0]) < room-80 {
		t.Fatalf("first part %d bytes, room %d", len(parts[0]), room)
	}
}
