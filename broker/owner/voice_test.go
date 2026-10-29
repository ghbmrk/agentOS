package owner

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

// REQ: CH-12
//
// An approval text reads as a first-person question (D-127) and still
// carries every verified field, in the order the line gave them (verb,
// object, detail, recipient, amount, reversibility), then its notice, the
// expiry and the valid replies with the request ID, within three GSM-7
// segments. Every combination of reversibility, notice, UNVERIFIED and a
// restart is checked with each field at its cap, a 100-character
// recipient list, a two-digit day, high-tier replies and the longest
// request ID and grid cell. A text that would not fit takes the short
// form (CH12V-4), which keeps every field, notice and restart note. It has no leading ID
// label and no "your agent wants".
func TestApprovalTextIsAFirstPersonQuestionWithEveryField(t *testing.T) {
	sent := time.Date(2026, 10, 14, 19, 5, 0, 0, time.UTC)
	recip := strings.Repeat("abcdefghij@acme.example, ", 3) + "zbcdefghijkl@acme.example"
	if len(recip) != MaxRecipientChars {
		t.Fatalf("recipient %d chars", len(recip))
	}
	undos := map[string]func(*Item){
		"none":   func(it *Item) {},
		"window": func(it *Item) { it.UndoWindow = 9999 * 24 * time.Hour },
		"undoby": func(it *Item) { it.UndoBy = strings.Repeat("LEARN OFF ", 4) },
	}
	notices := map[string]func(*Item){
		"none":    func(it *Item) {},
		"repeat":  func(it *Item) { it.Sent = sent },
		"erased":  func(it *Item) { it.Sent, it.SentErased = sent, true },
		"retried": func(it *Item) { it.Retried = sent },
	}
	r := newRig(t, nil)
	cell := regexp.MustCompile(`grid cell ([A-J][0-9]+)`)
	shorts, longest := 0, 0
	for un, undo := range undos {
		for nn, notice := range notices {
			for _, unverified := range []bool{false, true} {
				for _, asked := range []bool{false, true} {
					it := highItem("h")
					it.Facts.Verb = "Abcdefghijkl"
					it.Object = strings.Repeat("quarterly report ", 6)
					it.Detail = strings.Repeat("tested on 40 tasks ", 4)
					it.Recipient = recip
					it.Amount = "$1,234,567,890.12"
					it.Unverified = unverified
					if asked {
						it.Asked = sent
					}
					undo(&it)
					notice(&it)
					name := fmt.Sprintf("%s/%s/unverified=%t/asked=%t", un, nn, unverified, asked)
					id, err := r.ch.Request([]Item{it}, 0)
					if err != nil {
						t.Fatal(err)
					}
					text := r.inbox()
					// Request IDs and grid cells run to 3 characters: the
					// budget must hold for the longest.
					pad := 2 * (3 - len(id))
					if m := cell.FindStringSubmatch(text); m != nil {
						pad += 3 - len(m[1])
					} else {
						t.Fatalf("%s: no grid cell in %q", name, text)
					}
					if !fits(text+strings.Repeat("x", pad)) || strings.HasPrefix(text, id+":") || strings.Contains(text, "your agent wants") {
						t.Fatalf("%s: budget or voice (%d chars + %d): %q", name, len(text), pad, text)
					}
					want := []string{
						"Can I abcdefghijkl ",
						`"` + field(it.Object, 40) + `"`,
						", " + field(it.Detail, 40) + ",",
						" to " + it.Recipient,
						" for " + field(it.Amount, 16),
					}
					if nn == "repeat" || nn == "retried" {
						want = append(want, " again?")
					} else {
						want = append(want, "?")
					}
					switch un {
					case "window":
						want = append(want, " It can be undone within 9999 days.")
					case "undoby":
						want = append(want, " To undo: "+field(it.UndoBy, 24)+".")
					default:
						want = append(want, " It can't be undone.")
					}
					long := map[string]string{
						"repeat":  " It was already sent 19:05 Oct 14.",
						"erased":  " It may repeat a send whose record was erased (it went 19:05 Oct 14).",
						"retried": " It may go twice; first tried 19:05 Oct 14.",
					}
					brief := map[string]string{
						"repeat":  " Already sent 19:05 Oct 14.",
						"erased":  " May repeat an erased send (19:05 Oct 14).",
						"retried": " May go twice; tried 19:05 Oct 14.",
					}
					switch {
					case nn == "none":
					case strings.Contains(text, long[nn]):
						want = append(want, long[nn])
					default:
						want = append(want, brief[nn])
					}
					want = append(want, " Expires 12:15.", "Reply YES "+id+" ", "or NO "+id+".")
					at := 0
					for _, f := range want {
						i := strings.Index(text[at:], f)
						if i < 0 {
							t.Fatalf("%s: missing or out of order %q in %q", name, f, text)
						}
						at += i + len(f)
					}
					if unverified && !strings.HasPrefix(text, "UNVERIFIED") {
						t.Fatalf("%s: unverified %q", name, text)
					}
					if asked != strings.Contains(text, " Asked 19:05, before a restart. Expires") {
						t.Fatalf("%s: restart note %q", name, text)
					}
					full := strings.Contains(text, " to "+recip+" for") && (!unverified || strings.HasPrefix(text, "UNVERIFIED, see my Wi-Fi page: ")) &&
						(nn == "none" || strings.Contains(text, long[nn]))
					// The short form is taken only when the full one would
					// not fit.
					if !full {
						shorts++
						if len(text)+pad > longest {
							longest = len(text) + pad
						}
						r2 := strings.NewReplacer(brief["repeat"], long["repeat"], brief["erased"], long["erased"], brief["retried"], long["retried"],
							"UNVERIFIED: ", "UNVERIFIED, see my Wi-Fi page: ").Replace(text)
						if fits(r2 + "xxx") {
							t.Fatalf("%s: short form though the full one fits: %q", name, text)
						}
					}
				}
			}
		}
	}
	t.Logf("%d of 48 at caps took the short form; the longest, with the longest ID and cell, is %d chars", shorts, longest)
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
