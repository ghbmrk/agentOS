package inbox

// REQ: CLK-2, VRB-2

// Edge cases the rest of the suite leaves unpinned: a step run twice, a step
// on a mail the clerk never read, the planner's key choice and trash cap, the
// From and DMARC readers' missing inputs, and the wording net's text reader.
// Its own file keeps its imports off the other tests (row #6242).

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// spamRig is a rig over one plain spam mail, so these tests reach no more of
// the package than a step needs.
func spamRig(t *testing.T) *rig {
	t.Helper()
	w, _, _ := loadFixture(t)
	ms := []Mail{{ID: "S1", Raw: []byte(rawMail("<s1@spam.test>", "x@spam.test", "Hi")), Class: "spam"}}
	return newRigOn(t, w, ms, Synthetic{}, 30)
}

// A step the clerk already ran answers "already done" and changes nothing,
// however often a view that still shows it dispatched hands it back (an
// unbound account, as in the clerk's own process, after a kernel restart).
func TestADoneStepIsNotRunAgain(t *testing.T) {
	r := spamRig(t)
	r.acct.Bind(nil)
	p := r.step("t", key.Trash, map[string]string{"target": "S1"})
	r.run(t, p)
	if len(r.acct.Effects()) != 1 {
		t.Fatalf("first run: effects %v refusals %v", r.acct.Effects(), r.acct.Refusals())
	}
	for i := 0; i < 2; i++ {
		got := r.acct.Do(kernel.Request{Plan: p}, staleView{r.k.State()})
		if got != (kernel.Result{Outcome: "ok", Detail: "already done"}) {
			t.Fatalf("run %d again: %+v, want already done", i+2, got)
		}
	}
	if len(r.acct.Effects()) != 1 {
		t.Fatalf("a done step ran again: %v", r.acct.Effects())
	}
}

// A step on a mail the clerk never read is refused as unknown, never as some
// other mail's verdict.
func TestAStepOnAnUnreadMailIsRefusedAsUnknown(t *testing.T) {
	r := spamRig(t)
	r.run(t, r.step("x", key.Trash, map[string]string{"target": "never-read"}))
	if rf := r.lastRefusal(t); rf.Reason != "unknown-mail" || len(r.acct.Effects()) != 0 {
		t.Fatalf("trash of an unread mail: %+v, effects %v", rf, r.acct.Effects())
	}
}

// Each plan is signed on the key for its verb: unsubscribes on the unsubscribe
// key (which carries the hold), the rest on the bulk key (which carries the
// cap); spam past the cap is counted as left, never planned; a sender offered
// twice is unsubscribed from once.
func TestPlansUseEachVerbsKeyAndCountTrashPastTheCap(t *testing.T) {
	bulk, unsub := key.Key{Root: key.Root{Serial: "bulk"}}, key.Key{Root: key.Root{Serial: "unsub"}}
	var l []Item
	for i := 0; i <= DailyCap; i++ {
		l = append(l, Item{Mail: fmt.Sprintf("S%d", i), Class: "spam"})
	}
	l = append(l, Item{Mail: "U1", Sender: "h1"}, Item{Mail: "U2", Sender: "h1"})
	plans, left := Plans(l, bulk, unsub, seedPriv(4))
	trash, unsubs := 0, 0
	for _, p := range plans {
		want := bulk
		switch p.Steps[0].Verb {
		case key.Unsubscribe:
			want = unsub
			unsubs++
		case key.Trash:
			trash++
		}
		if !reflect.DeepEqual(p.Key, want) {
			t.Errorf("plan %s is on the wrong key", p.ID)
		}
	}
	if trash != DailyCap || unsubs != 1 || left != (Left{Organize: DailyCap + 1, Trash: 1}) {
		t.Fatalf("trash %d unsub %d left %+v", trash, unsubs, left)
	}
}

// A From header with a bare address, no angle brackets, still names it; one
// with no address names none.
func TestFromAddressReadsABareAddress(t *testing.T) {
	for from, want := range map[string]string{"News@Shop.example": "news@shop.example", "undisclosed": ""} {
		if got := FromAddress([]byte("From: " + from + "\r\n\r\nhi")); got != want {
			t.Errorf("FromAddress(%q) = %q, want %q", from, got, want)
		}
	}
}

// DMARC passes nothing without an authserv-id to match, a header, or a From
// address, even when the header's own id and From domain are empty too.
// (A matching header's pass is alert_test.go's.)
func TestDMARCPassNeedsEveryInput(t *testing.T) {
	for _, tc := range []struct{ header, from, authServ string }{
		{`"" ; dmarc=pass header.from=shop.example`, "a@shop.example", ""},
		{"mx.example; dmarc=pass", "", "mx.example"},
		{"", "a@shop.example", "mx.example"},
	} {
		if dmarcPass(tc.header, tc.from, tc.authServ) {
			t.Errorf("dmarcPass(%q, %q, %q) passed", tc.header, tc.from, tc.authServ)
		}
	}
}

// foldText folds fullwidth ASCII, every decimal digit set and case, and drops
// format characters, so look-alike wording reads as plain.
func TestFoldTextFoldsLookAlikes(t *testing.T) {
	for in, want := range map[string]string{
		"ＶＥＲＩＦＹ":     "verify",
		"code ٣٤":    "code 34",
		"pa​ss­word": "password",
	} {
		if got := foldText(in); got != want {
			t.Errorf("foldText(%q) = %q, want %q", in, got, want)
		}
	}
}

// mailText skips parts that are not text and stops after maxTextParts parts;
// what it cannot read is TestMailTextReportsWhatItCannotRead's.
func TestMailTextReadsTextPartsOnly(t *testing.T) {
	var b strings.Builder
	b.WriteString("Subject: S\r\nContent-Type: multipart/mixed; boundary=XX\r\n\r\n")
	b.WriteString("--XX\r\nContent-Type: application/octet-stream\r\n\r\nbinaryword\r\n")
	for i := 1; i <= maxTextParts+4; i++ {
		fmt.Fprintf(&b, "--XX\r\nContent-Type: text/plain\r\n\r\nword%02d\r\n", i)
	}
	b.WriteString("--XX--\r\n")
	got, ok := mailText([]byte(b.String()))
	if !ok || strings.Contains(got, "binaryword") {
		t.Errorf("read a part that is not text: %q", got)
	}
	// The top level and the binary part count too, so text parts 1 to
	// maxTextParts-2 are read and the rest are not.
	last := fmt.Sprintf("word%02d", maxTextParts-2)
	next := fmt.Sprintf("word%02d", maxTextParts-1)
	if !strings.Contains(got, "word01") || !strings.Contains(got, last) || strings.Contains(got, next) {
		t.Errorf("part bound: %q", got)
	}
}

// containsWord looks past a match inside a word for a later one at a word's
// start, and reports none when every match is inside a word.
func TestContainsWordSkipsMatchesInsideWords(t *testing.T) {
	for s, want := range map[string]bool{"xcode zycode": false, "xcode code": true} {
		if got := containsWord(s, "code"); got != want {
			t.Errorf("containsWord(%q, code) = %v, want %v", s, got, want)
		}
	}
}
