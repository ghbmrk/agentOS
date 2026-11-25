package owner

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// REQ: CH-10, CH-12, CH-18, CH-19, OP-3
// MUT-kill-5974-owner part 2 (#6670): the render.go, codes.go, state.go
// and skelfold.go statements that mutgate's deletion left alive on #5974
// are pinned here, each by a test that fails without it. The tests call
// the functions themselves, never the rig, so they reach as little of the
// package as the lines they pin.

// killAt is 14:02 on 13 Oct 2026, UTC: every time the texts below show.
var killAt = time.Date(2026, 10, 13, 14, 2, 0, 0, time.UTC)

func killChannel() *Channel { return &Channel{cfg: Config{Location: time.UTC}} }

func killItem() Item { return Item{Object: "invoice", Facts: Facts{Verb: "Send"}} }

func TestKillFoldMapsEachKindOfRune(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"\U0001D400\U0001D41A", "Aa"}, // mathematical bold A and a
		{"a\nb\tc", "a\nb\tc"},         // ASCII stays as typed
		{"a\u00A0b\u2003c", "a b c"},   // non-ASCII spaces become one space
		{"\u4E2D", "\u4E2D"},           // a letter with no fold stays
		{"\u0663\u0669\u0966", "390"},  // decimal digits of other scripts
		{"\uFF21\uFF42", "Ab"},         // fullwidth
		{"\u2462", "3"},                // circled three
		{"e\u0301\u200D", "e"},         // a mark and a joiner dropped
		{"\u0430", "a"},                // Cyrillic a
		{"x\u00A0\u00A0y", "x  y"},     // each space kept, not collapsed
		{"\U0001D433", "z"},            // the last bold lower-case letter
		{"\U0001D419", "Z"},            // the last bold capital
		{"\U0001D6A3", "z"},            // the last letter of the block
		{"\U0001D6A4", "\U0001D6A4"},   // past it: kept as is
		{"\u00E9", "e"},                // Latin with a mark
	} {
		if got := fold(c.in); got != c.want {
			t.Errorf("fold(%+q) = %+q, want %+q", c.in, got, c.want)
		}
	}
}

func TestKillDigitValueCountsBackToZero(t *testing.T) {
	for r, want := range map[rune]int{'0': 0, '7': 7, '\u0660': 0, '\u0663': 3, '\u0969': 3, '\uFF19': 9} {
		if got := digitValue(r); got != want {
			t.Errorf("digitValue(%+q) = %d, want %d", r, got, want)
		}
	}
}

func TestKillFieldHidesSecretsAndCutsLongDigits(t *testing.T) {
	token := "ghp_" + strings.Repeat("A1b2", 9)
	if got := field("key "+token, 80); got != "[hidden]" {
		t.Errorf("field(token) = %q, want [hidden]", got)
	}
	if got := field("ref 12345678 ok", 40); got != "ref ...5678 ok" {
		t.Errorf("field(long digits) = %q, want %q", got, "ref ...5678 ok")
	}
	if got := field("a\tb\nc", 40); got != "a b c" {
		t.Errorf("field(controls) = %q", got)
	}
}

func TestKillTermsEmptyIsEmpty(t *testing.T) {
	if got := NewTerms(nil); got != "" {
		t.Errorf("NewTerms(nil) = %q, want empty", got)
	}
	ts, ok := TermList("").List()
	if !ok || ts != nil {
		t.Errorf(`TermList("").List() = %v, %v; want nil, true`, ts, ok)
	}
	one := NewTerms([]Term{{"Reads", "mail"}})
	if ts, ok := one.List(); !ok || !reflect.DeepEqual(ts, []Term{{"Reads", "mail"}}) {
		t.Errorf("round trip = %v, %v", ts, ok)
	}
}

func TestKillItemSumCoversRecipientSince(t *testing.T) {
	a, b := killItem(), killItem()
	b.Facts.RecipientSince = killAt
	if ItemSum(a) == ItemSum(b) {
		t.Error("ItemSum ignores Facts.RecipientSince")
	}
	c := killItem()
	c.Facts.RecipientSince = killAt.In(time.FixedZone("x", 3600))
	if ItemSum(b) != ItemSum(c) {
		t.Error("ItemSum depends on RecipientSince's zone, not its instant")
	}
}

func TestKillItemLineShowsEveryNotice(t *testing.T) {
	c := killChannel()
	base := "Send invoice, cannot be undone"
	for _, k := range []struct {
		name string
		set  func(*Item)
		want string
	}{
		{"plain", func(*Item) {}, base},
		{"asked", func(it *Item) { it.Asked = killAt }, base + ", asked 14:02, re-sent after restart"},
		{"erased", func(it *Item) { it.Sent, it.SentErased = killAt, true },
			base + ", may repeat a send whose record was erased (it went 14:02 Oct 13); send it?"},
		{"sent", func(it *Item) { it.Sent = killAt }, base + ", already sent 14:02 Oct 13; send it again?"},
		{"retried", func(it *Item) { it.Retried = killAt }, base + ", may go twice, first tried 14:02 Oct 13"},
		{"sent beats retried", func(it *Item) { it.Sent, it.Retried = killAt, killAt.Add(-time.Hour) },
			base + ", already sent 14:02 Oct 13; send it again?"},
	} {
		it := killItem()
		k.set(&it)
		if got := c.itemLine(it); got != k.want {
			t.Errorf("%s: itemLine = %q\nwant %q", k.name, got, k.want)
		}
	}
}

func TestKillLineFields(t *testing.T) {
	it := killItem()
	it.Unverified = true
	it.Amount = "$120.00"
	it.UndoWindow = 10 * time.Minute
	want := "UNVERIFIED, details on the Wi-Fi page: Send invoice, $120.00, undo within 10 min"
	if got := it.line(); got != want {
		t.Errorf("line = %q\nwant %q", got, want)
	}
}

func TestKillQuestionWording(t *testing.T) {
	c := killChannel()
	for _, k := range []struct {
		name  string
		set   func(*Item)
		short bool
		want  string
	}{
		{"detail last", func(it *Item) { it.Detail = "March" }, false, `Can I send "invoice", March? It can't be undone.`},
		{"sent short", func(it *Item) { it.Sent = killAt }, true, `Can I send "invoice" again? It can't be undone. Already sent 14:02 Oct 13.`},
		{"sent", func(it *Item) { it.Sent = killAt }, false, `Can I send "invoice" again? It can't be undone. It was already sent 14:02 Oct 13.`},
		{"retried short", func(it *Item) { it.Retried = killAt }, true, `Can I send "invoice" again? It can't be undone. May go twice; tried 14:02 Oct 13.`},
		{"retried", func(it *Item) { it.Retried = killAt }, false, `Can I send "invoice" again? It can't be undone. It may go twice; first tried 14:02 Oct 13.`},
	} {
		it := killItem()
		k.set(&it)
		if got := c.question(it, k.short); got != k.want {
			t.Errorf("%s: question = %q\nwant %q", k.name, got, k.want)
		}
	}
}

func TestKillDurHours(t *testing.T) {
	for d, want := range map[time.Duration]string{
		2 * time.Hour: "2 h", 3*time.Hour + 59*time.Minute: "3 h", 47 * time.Hour: "47 h",
		48 * time.Hour: "2 days", 119 * time.Minute: "119 min",
	} {
		if got := dur(d); got != want {
			t.Errorf("dur(%v) = %q, want %q", d, got, want)
		}
	}
}

// killVerifier checks nothing and cannot allow or revoke acts.
type killVerifier struct{}

func (killVerifier) VerifyTOTP(string, int64, bool, ...CheckerAct) (int64, bool, error) {
	return 0, false, nil
}

func TestKillAllowNeedsARevoker(t *testing.T) {
	c := &codes{verify: killVerifier{}, store: &MemStore{}}
	ran := false
	err := c.allowThen([]CheckerAct{{Act: "a1"}}, func() error { ran = true; return nil })
	if !errors.Is(err, errAllow) || ran {
		t.Errorf("allowThen without a Revoker = %v (rest ran: %v), want errAllow and nothing run", err, ran)
	}
}

func TestKillWrongCodesLockAndCount(t *testing.T) {
	for _, failing := range []bool{false, true} {
		st := &failStore{fail: failing}
		c := &codes{store: st}
		var locked bool
		for i := 0; i < WrongToLock; i++ {
			l, err := c.wrong(killAt.Add(time.Duration(i) * time.Second))
			if failing != (err != nil) {
				t.Fatalf("failing=%v: wrong err = %v", failing, err)
			}
			locked = locked || l
		}
		if !locked || !c.st.LowLocked || c.st.Locks != 1 || len(c.st.Wrong) != WrongToLock {
			t.Errorf("failing=%v: after %d wrong codes locked=%v LowLocked=%v Locks=%d Wrong=%d; want true, true, 1, %d",
				failing, WrongToLock, locked, c.st.LowLocked, c.st.Locks, len(c.st.Wrong), WrongToLock)
		}
	}
}

func TestKillLockHoldsInMemoryWhenTheSaveFails(t *testing.T) {
	c := &codes{store: &failStore{fail: true}}
	c.st.UnlockedUntil = killAt.Add(time.Hour)
	if err := c.lock(); err == nil {
		t.Fatal("lock with a failing store returned nil")
	}
	if c.unlocked(killAt) || c.st.Locks != 1 {
		t.Errorf("after a failed lock: unlocked=%v Locks=%d; want false, 1", c.unlocked(killAt), c.st.Locks)
	}
}

func TestKillGridChallenge(t *testing.T) {
	if got := (&codes{}).gridChallenge(); got != "" {
		t.Errorf("no grid: challenge = %q, want empty", got)
	}
	c := &codes{sec: Secrets{GridSeed: []byte("seed")}, rand: &cycleRand{b: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}}}
	c.challenge = "C3"
	if got := c.gridChallenge(); got != "C3" {
		t.Errorf("live challenge C3: got %q", got)
	}
	c.st.GridUsed = append(c.st.GridUsed, "C3")
	if got := c.gridChallenge(); got == "C3" || got == "" {
		t.Errorf("spent challenge C3: got %q, want another cell", got)
	}
	c.st.GridUsed = GridLabels()
	if got := c.gridChallenge(); got != "" || c.challenge != "" {
		t.Errorf("spent grid: got %q (remembered %q), want both empty", got, c.challenge)
	}
}

// killBadRand fails every read.
type killBadRand struct{}

func (killBadRand) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestKillRandIntPanicsWithoutRandomness(t *testing.T) {
	defer func() {
		if r := recover(); r == nil || !strings.Contains(r.(string), "no system randomness") {
			t.Errorf("randInt on a failing reader: recovered %v", r)
		}
	}()
	randInt(killBadRand{}, 10)
	t.Error("randInt returned on a failing reader")
}

// killState is a State with one entry in every slice copyState copies.
func killState() State {
	s := State{
		GridUsed: []string{"A1"}, Wrong: []time.Time{killAt}, LocalSignIns: []time.Time{killAt},
		LocalAnswers: []LocalNote{{Text: "a"}}, Pending: []PendingRef{{ID: "a"}}, Queued: []QueuedRef{{ID: "a"}},
		Held: []HeldText{{Text: "a"}}, Waiting: []WaitingMsg{{ID: "a"}}, Guarded: []GuardedMark{{Text: "a"}},
		Sent: []time.Time{killAt}, Retired: map[string]time.Time{"a": killAt},
	}
	s.Pacing.Urgent = []Class{"a"}
	return s
}

func TestKillMemStoreCopiesState(t *testing.T) {
	var m MemStore
	s := killState()
	if err := m.Save(s); err != nil {
		t.Fatal(err)
	}
	// Writing through the saved value, or through a loaded one, must not
	// reach the store.
	write := func(s State) {
		s.GridUsed[0] = "Z9"
		s.Wrong[0], s.LocalSignIns[0], s.Sent[0] = time.Time{}, time.Time{}, time.Time{}
		s.LocalAnswers[0].Text = "x"
		s.Pending[0].ID = "x"
		s.Queued[0].ID = "x"
		s.Held[0].Text = "x"
		s.Waiting[0].ID = "x"
		s.Guarded[0].Text = "x"
		s.Pacing.Urgent[0] = "x"
		s.Retired["a"] = time.Time{}
	}
	write(s)
	got, _ := m.Load()
	if !reflect.DeepEqual(got, killState()) {
		t.Errorf("a write through Save's argument reached the store:\n got %+v\nwant %+v", got, killState())
	}
	write(got)
	if again, _ := m.Load(); !reflect.DeepEqual(again, killState()) {
		t.Errorf("a write through Load's result reached the store:\n got %+v\nwant %+v", again, killState())
	}
}

func TestKillFileStoreErrors(t *testing.T) {
	dir := t.TempDir()
	_, err := FileStore{Path: dir}.Load()
	var pe *fs.PathError
	if !errors.As(err, &pe) {
		t.Errorf("Load of a directory = %v, want the read's *fs.PathError", err)
	}
	path := filepath.Join(dir, "state.json")
	bad := State{Sent: []time.Time{time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}}
	if err := (FileStore{Path: path}).Save(bad); err == nil {
		t.Error("Save of an unencodable state returned nil")
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Save of an unencodable state wrote %s (stat: %v)", path, err)
	}
}

func TestKillSkelMapDecomposesHangul(t *testing.T) {
	for in, want := range map[string]string{
		"\uAC00": "\u1100\u1161",       // ga: no final
		"\uAC01": "\u1100\u1161\u11A8", // gag: final 1
		"\uD7A3": "\u1112\u1175\u11C2", // the last syllable
		"a":      "a",
	} {
		if got := skelMap(in, nil); got != want {
			t.Errorf("skelMap(%+q) = %+q, want %+q", in, got, want)
		}
	}
}

func TestKillCheckFoldsDropsMarksAndRepeats(t *testing.T) {
	if got := CheckFolds("abc"); !reflect.DeepEqual(got, []string{"abc"}) {
		t.Errorf(`CheckFolds("abc") = %q, want one fold`, got)
	}
	// U+0903's prototype is ":", so every fold of the text keeps it; only
	// the fold of the text with its marks dropped first reads "x".
	got := CheckFolds("x\u0903")
	found := false
	for _, f := range got {
		found = found || f == "x"
	}
	if !found {
		t.Errorf("CheckFolds(x+U+0903) = %+q, want the mark-dropped fold \"x\" among them", got)
	}
}
