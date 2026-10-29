package owner

import (
	"strings"
	"testing"
	"time"
)

// REQ: CH-12
//
// An approval text reads as a first-person question (D-127) and still
// carries every verified field, in the order the line gave them (verb,
// object, detail, recipient, amount, reversibility), then the expiry and
// the valid replies with the request ID, within three GSM-7 segments at
// the longest values each field allows. It has no leading ID label and no
// "your agent wants".
func TestApprovalTextIsAFirstPersonQuestionWithEveryField(t *testing.T) {
	sent := time.Date(2026, 10, 4, 9, 5, 0, 0, time.UTC)
	long := func(it *Item) {
		it.Facts.Verb = "Abcdefghijkl"
		it.Object = strings.Repeat("quarterly report ", 6)
		it.Detail = strings.Repeat("tested on 40 tasks ", 4)
		it.Recipient = strings.Repeat("abcdefghij@acme.example, ", 3) + "zbcdefghij@acme.example"
		it.Amount = "$1,234,567,890.12"
	}
	for name, mod := range map[string]func(*Item){
		"plain":      func(it *Item) {},
		"undo":       func(it *Item) { it.UndoWindow = 72 * time.Hour },
		"undoby":     func(it *Item) { it.UndoBy = strings.Repeat("LEARN OFF ", 4) },
		"unverified": func(it *Item) { it.Unverified = true },
		"repeat":     func(it *Item) { it.Sent = sent },
		"erased":     func(it *Item) { it.Sent, it.SentErased = sent, true; it.Asked = sent },
		"retried":    func(it *Item) { it.Retried, it.Unverified, it.Asked = sent, true, sent },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, nil)
			it := highItem("h")
			long(&it)
			mod(&it)
			id, err := r.ch.Request([]Item{it}, 0)
			if err != nil {
				t.Fatal(err)
			}
			text := r.inbox()
			// Request IDs run to 3 characters: the budget holds for the longest.
			if !fits(text+strings.Repeat("x", 2*(3-len(id)))) || strings.HasPrefix(text, id+":") || strings.Contains(text, "your agent wants") {
				t.Fatalf("budget or voice: %q", text)
			}
			want := []string{
				"Can I abcdefghijkl ",
				`"` + field(it.Object, 40) + `"`,
				", " + field(it.Detail, 40) + ",",
				" to " + it.Recipient,
				" for " + field(it.Amount, 16),
				"?",
			}
			switch {
			case it.UndoWindow > 0:
				want = append(want, " It can be undone within 3 days.")
			case it.UndoBy != "":
				want = append(want, " To undo: "+field(it.UndoBy, 24)+".")
			default:
				want = append(want, " It can't be undone.")
			}
			want = append(want, " Expires 12:15.", "Reply YES "+id+" ", "or NO "+id+".")
			at := 0
			for _, f := range want {
				i := strings.Index(text[at:], f)
				if i < 0 {
					t.Fatalf("missing or out of order %q in %q", f, text)
				}
				at += i + len(f)
			}
			if it.Unverified && !strings.HasPrefix(text, "UNVERIFIED, see my Wi-Fi page: Can I ") {
				t.Fatalf("unverified %q", text)
			}
			again := strings.Contains(text, ` again?`)
			if again != (name == "repeat" || name == "retried") {
				t.Fatalf("again %v in %q", again, text)
			}
			for n, f := range map[string]string{
				"repeat":  "It was already sent 09:05 Oct 4.",
				"erased":  "It may repeat a send whose record was erased (it went 09:05 Oct 4).",
				"retried": "It may go twice; first tried 09:05 Oct 4.",
			} {
				if strings.Contains(text, f) != (n == name) {
					t.Fatalf("notice %q in %q", f, text)
				}
			}
			if it.Asked.IsZero() == strings.Contains(text, "Asked 09:05, before a restart.") {
				t.Fatalf("asked %q", text)
			}
		})
	}
}

// REQ: CH-12
//
// A batch asks one question and lists its items under it; the request ID
// is in the replies, not a label.
func TestABatchIsOneQuestion(t *testing.T) {
	r := newRig(t, nil)
	id, _ := r.ch.Request([]Item{lowItem("a"), lowItem("b")}, 0)
	text := r.inbox()
	if !strings.HasPrefix(text, "Can I do these 2 things? 1 send invoice 1042 to billing@acme.example, cannot be undone. 2 send ") ||
		strings.HasPrefix(text, id+":") || !strings.HasSuffix(text, "or NO "+id+".") || !fits(text) {
		t.Fatalf("batch %q", text)
	}
}
