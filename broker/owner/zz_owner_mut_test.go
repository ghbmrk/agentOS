package owner

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// REQ: CH-2, CH-12, CH-15, CH-18, CH-19, OP-3
// MUT-kill-5974-owner (#6670): the statements outside approvals.go that
// mutgate's deletion left alive once #6674's tests reached them, each
// pinned by a test that fails without it. They call the function that
// holds the line directly where they can, so they reach little else.

// copyState's copy shares no slice or map with the state it copies, so a
// change to the copy (saveLocked applies f to it after a failed save)
// never writes through to the original.
func TestMutCopyStateSharesNothing(t *testing.T) {
	var s State
	v := reflect.ValueOf(&s).Elem()
	fill := func(f reflect.Value) {
		switch f.Kind() {
		case reflect.Slice:
			f.Set(reflect.MakeSlice(f.Type(), 1, 4))
		case reflect.Map:
			f.Set(reflect.MakeMap(f.Type()))
		}
	}
	for i := 0; i < v.NumField(); i++ {
		fill(v.Field(i))
	}
	fill(v.FieldByName("Pacing").FieldByName("Urgent"))
	c := copyState(s)
	cv := reflect.ValueOf(c)
	check := func(name string, a, b reflect.Value) {
		switch a.Kind() {
		case reflect.Slice, reflect.Map:
			if a.Pointer() == b.Pointer() {
				t.Errorf("%s: the copy shares the original's backing store", name)
			}
		}
	}
	for i := 0; i < v.NumField(); i++ {
		check(v.Type().Field(i).Name, v.Field(i), cv.Field(i))
	}
	check("Pacing.Urgent", v.FieldByName("Pacing").FieldByName("Urgent"), cv.FieldByName("Pacing").FieldByName("Urgent"))
}

// New refuses a config without an owner, engine or store, and fills the
// reply limit, time zone and clock it leaves unset.
func TestMutNewRefusesAndFillsDefaults(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New accepted an empty config")
	}
	r := newRig(t, nil)
	r.edit = func(c *Config) { c.ReplyLimit, c.Location, c.Now = 0, nil, nil }
	ch := r.open()
	if ch.cfg.ReplyLimit != DefaultReplyLimit {
		t.Errorf("ReplyLimit %d, want %d", ch.cfg.ReplyLimit, DefaultReplyLimit)
	}
	if ch.cfg.Location != time.Local {
		t.Errorf("Location %v, want time.Local", ch.cfg.Location)
	}
	if ch.cfg.Now == nil {
		t.Fatal("no clock")
	}
}

// A wrong code counts, locks the low tier at WrongToLock and turns on
// challenge mode at WrongToChallenge, whether the save holds or fails
// (CH-18: the in-memory state takes the stricter values either way).
func TestMutWrongCodesCountLockAndChallenge(t *testing.T) {
	for _, fail := range []bool{false, true} {
		c := &codes{store: &failStore{fail: fail}}
		now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
		for i := 1; i <= WrongToChallenge; i++ {
			c.st.UnlockedUntil = now.Add(time.Hour)
			locked, err := c.wrong(now)
			if (err != nil) != fail {
				t.Fatalf("failing save %t: err %v", fail, err)
			}
			if locked != (i == WrongToLock) {
				t.Fatalf("failing save %t, wrong code %d: locked %t", fail, i, locked)
			}
			if n := len(c.st.Wrong); n != i {
				t.Fatalf("failing save %t, wrong code %d: %d counted", fail, i, n)
			}
			if c.st.LowLocked != (i >= WrongToLock) || c.st.Challenged != (i >= WrongToChallenge) {
				t.Fatalf("failing save %t, wrong code %d: low locked %t, challenged %t", fail, i, c.st.LowLocked, c.st.Challenged)
			}
			if i == WrongToLock && !c.st.UnlockedUntil.IsZero() {
				t.Fatalf("failing save %t: the lock left the session unlocked", fail)
			}
		}
		if c.st.Locks != 1 {
			t.Fatalf("failing save %t: %d locks", fail, c.st.Locks)
		}
	}
}

// The grid asks for no cell when there is no grid or every cell is spent.
func TestMutGridChallengeWithNoCellLeft(t *testing.T) {
	if got := (&codes{}).gridChallenge(); got != "" {
		t.Fatalf("no grid seed: challenge %q", got)
	}
	c := &codes{sec: Secrets{GridSeed: []byte("seed")}, rand: &cycleRand{b: []byte{7}}}
	c.st.GridUsed = GridLabels()
	c.challenge = c.st.GridUsed[0]
	if got := c.gridChallenge(); got != "" || c.challenge != "" {
		t.Fatalf("spent grid: challenge %q, kept %q", got, c.challenge)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// randInt stops with its own message when the system has no randomness.
func TestMutRandIntPanicsWithoutRandomness(t *testing.T) {
	defer func() {
		if p, _ := recover().(string); !strings.Contains(p, "no system randomness") {
			t.Fatalf("panic %v", p)
		}
	}()
	randInt(errReader{}, 10)
}

// Only approval and agent texts can be urgent (CH-15).
func TestMutPacingUrgentClasses(t *testing.T) {
	if !(Pacing{Urgent: []Class{ClassApproval, ClassAgent}}).valid() {
		t.Fatal("approval and agent refused")
	}
	if (Pacing{Urgent: []Class{"reply"}}).valid() {
		t.Fatal("an unknown class accepted as urgent")
	}
}

// A send that returns with the clock before its count leaves the count
// where it was, rather than moving it back.
func TestMutSettleKeepsACountWhenTheClockStepsBack(t *testing.T) {
	r := newRig(t, nil)
	at := r.now.Add(time.Minute)
	r.ch.mu.Lock()
	r.ch.codes.st.Sent = []time.Time{at}
	r.ch.mu.Unlock()
	r.ch.settle(at, nil)
	if got := r.ch.codes.st.Sent; len(got) != 1 || !got[0].Equal(at) {
		t.Fatalf("Sent %v, want [%v]", got, at)
	}
}

// saveLocked applies a change in memory even when its save fails.
func TestMutSaveLockedAppliesAFailedSave(t *testing.T) {
	fs := &failStore{}
	r := newRig(t, fs)
	fs.fail = true
	r.ch.mu.Lock()
	err := r.ch.saveLocked(func(s *State) { s.Locks = 7 })
	locks := r.ch.codes.st.Locks
	r.ch.mu.Unlock()
	if err == nil || locks != 7 {
		t.Fatalf("err %v, Locks %d", err, locks)
	}
}

// fold reads styled mathematical letters as plain ones and keeps ASCII,
// tabs and newlines as they are.
func TestMutFoldStyledLettersAndASCII(t *testing.T) {
	if got, want := fold("\U0001D400\U0001D41Aa\tb\nc"), "Aaa\tb\nc"; got != want {
		t.Fatalf("fold %q, want %q", got, want)
	}
}

// field hides a secret-shaped value and shows only the last four digits
// of a long number (CH-19).
func TestMutFieldHidesSecretsAndLongNumbers(t *testing.T) {
	if got := field("sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD", 40); got != "[hidden]" {
		t.Errorf("secret shown as %q", got)
	}
	if got, want := field("call 0123456789 now", 40), "call ...6789 now"; got != want {
		t.Errorf("field %q, want %q", got, want)
	}
}

// ItemSum changes with the recipient's first-seen time (OP-3).
func TestMutItemSumCoversRecipientSince(t *testing.T) {
	a := Item{Object: "rent", Facts: Facts{Verb: "Pay"}}
	b := a
	b.Facts.RecipientSince = time.Date(2026, 10, 4, 9, 30, 0, 0, time.UTC)
	if ItemSum(a) == ItemSum(b) {
		t.Fatal("RecipientSince not in the sum")
	}
}

// An item's line and short question say when it was asked before a
// restart, sent before (erased or not), or tried before (CH-12, D-116).
func TestMutItemLineAndShortQuestionNotices(t *testing.T) {
	ch := &Channel{cfg: Config{Location: time.UTC}}
	at := time.Date(2026, 10, 4, 9, 30, 0, 0, time.UTC)
	base := Item{Object: "rent", Facts: Facts{Verb: "Pay"}}
	with := func(f func(*Item)) Item { i := base; f(&i); return i }
	for _, c := range []struct {
		it      Item
		line, q string
	}{
		{with(func(i *Item) { i.Asked = at }),
			"Pay rent, cannot be undone, asked 09:30, re-sent after restart",
			`Can I pay "rent"? It can't be undone. Asked 09:30, before a restart.`},
		{with(func(i *Item) { i.Sent, i.SentErased = at, true }),
			"Pay rent, cannot be undone, may repeat a send whose record was erased (it went 09:30 Oct 4); send it?",
			`Can I pay "rent"? It can't be undone. May repeat an erased send (09:30 Oct 4).`},
		{with(func(i *Item) { i.Sent = at }),
			"Pay rent, cannot be undone, already sent 09:30 Oct 4; send it again?",
			`Can I pay "rent" again? It can't be undone. Already sent 09:30 Oct 4.`},
		{with(func(i *Item) { i.Retried = at }),
			"Pay rent, cannot be undone, may go twice, first tried 09:30 Oct 4",
			`Can I pay "rent" again? It can't be undone. May go twice; tried 09:30 Oct 4.`},
		{with(func(i *Item) { i.Unverified, i.Amount = true, "\u00a35" }),
			"UNVERIFIED, details on the Wi-Fi page: Pay rent, GBP 5, cannot be undone",
			`UNVERIFIED: Can I pay "rent" for GBP 5? It can't be undone.`},
	} {
		if got := ch.itemLine(c.it); got != c.line {
			t.Errorf("line %q\nwant %q", got, c.line)
		}
		if got := ch.question(c.it, true); got != c.q {
			t.Errorf("question %q\nwant %q", got, c.q)
		}
	}
	d := with(func(i *Item) { i.Detail = "May" })
	if got, want := ch.question(d, false), `Can I pay "rent", May? It can't be undone.`; got != want {
		t.Errorf("question %q\nwant %q", got, want)
	}
}

// A Hangul syllable (U+AC00 ga, U+AC01 gag) folds as its jamo do, final consonant included, as
// NFKD decomposes it.
func TestMutSkeletonFoldDecomposesHangul(t *testing.T) {
	for _, c := range [][2]string{{"\uAC00", "\u1100\u1161"}, {"\uAC01", "\u1100\u1161\u11A8"}} {
		if a, b := SkeletonFold(c[0], false), SkeletonFold(c[1], false); a != b {
			t.Errorf("%q folds to %q, its jamo to %q", c[0], a, b)
		}
	}
}

// CheckFolds adds the reading with marks dropped first (the Devanagari
// visarga, a spacing mark, folds to ":" but drops to nothing), and lists
// each fold once.
func TestMutCheckFoldsMarksAndRepeats(t *testing.T) {
	if got, want := CheckFolds("a\u0903"), []string{"a:", "a"}; !slices.Equal(got, want) {
		t.Errorf("CheckFolds %q, want %q", got, want)
	}
	if got := CheckFolds("abc"); !slices.Equal(got, []string{"abc"}) {
		t.Errorf("CheckFolds %q, want one fold", got)
	}
}

// FoldPattern's output is fixed: a space is one or more spaces and each
// character's folds are listed in order.
func TestMutFoldPatternIsFixed(t *testing.T) {
	for i := 0; i < 20; i++ {
		if got, want := FoldPattern("i m"), "(?:i|l) +(?:rn)"; got != want {
			t.Fatalf("FoldPattern %q, want %q", got, want)
		}
	}
}

// A text within one window is that window, byte for byte, even when it is
// not valid UTF-8.
func TestMutSkelWindowsKeepsAShortTextWhole(t *testing.T) {
	if got := skelWindows("\xff"); !slices.Equal(got, []string{"\xff"}) {
		t.Fatalf("windows %q", got)
	}
}
