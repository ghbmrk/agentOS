package kernel_test

// REQ: LOG-4, LOG-1, LOG-2, LOG-5

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

var errDown = errors.New("store down")

// flakyKeys is a key table whose Delete can be made to fail.
type flakyKeys struct {
	*kernel.MemKeys
	failDelete bool
}

func (f *flakyKeys) Delete(s string) error {
	if f.failDelete {
		return errDown
	}
	return f.MemKeys.Delete(s)
}

// flakyContent is a content store whose Delete can be made to fail.
type flakyContent struct {
	*kernel.MemContent
	failDelete bool
	deletes    int
}

func (f *flakyContent) Delete(h kernel.Hash) error {
	f.deletes++
	if f.failDelete {
		return errDown
	}
	return f.MemContent.Delete(h)
}

// downLog is a log store whose writes can be made to fail.
type downLog struct {
	kernel.MemStore
	down bool
}

func (d *downLog) Append(b []byte) error {
	if d.down {
		return errDown
	}
	return d.MemStore.Append(b)
}

// erig is a kernel with a key table and two content stores, whose log
// survives a reboot. Its nonce stream runs on across boots, so a subject
// opened after a reboot is not drawn again.
type erig struct {
	t      *testing.T
	head   pair
	log    *downLog
	anchor *flakyAnchor
	rnd    *rand.ChaCha8
	keys   *flakyKeys
	mail   *flakyContent
	notes  *flakyContent
	k      *kernel.Kernel
}

func newErig(t *testing.T) *erig {
	r := &erig{t: t, head: gen(3), log: &downLog{}, anchor: &flakyAnchor{MemAnchor: &kernel.MemAnchor{}},
		rnd: rand.NewChaCha8([32]byte{9}), keys: &flakyKeys{MemKeys: kernel.NewMemKeys()},
		mail: &flakyContent{MemContent: kernel.NewMemContent()}, notes: &flakyContent{MemContent: kernel.NewMemContent()}}
	r.boot()
	return r
}

// boot reopens the log and the content, as a restart does.
func (r *erig) boot() kernel.ContentReport {
	r.t.Helper()
	l, err := kernel.Open(kernel.Config{Store: r.log, Anchor: r.anchor, Pub: r.head.pub, Sign: r.head.priv, Rand: r.rnd})
	must(r.t, err)
	r.k, err = kernel.Boot(l, nil, nil, 0)
	must(r.t, err)
	rep, err := r.k.OpenContent(r.keys, map[string]kernel.ContentStore{"mail": r.mail, "notes": r.notes}, 0)
	must(r.t, err)
	return rep
}

func (r *erig) open() string {
	r.t.Helper()
	s, err := r.k.OpenSubject(1)
	must(r.t, err)
	return s
}

func (r *erig) seal(sub, store, class, text string) kernel.Hash {
	r.t.Helper()
	h, err := r.k.Seal(2, sub, store, class, []byte(text))
	must(r.t, err)
	return h
}

func (r *erig) replays() {
	r.t.Helper()
	re, err := kernel.Replay(nil, r.k.Log().Entries())
	must(r.t, err)
	if !reflect.DeepEqual(re, r.k.State()) {
		r.t.Fatal("replay differs from the live state (LOG-1)")
	}
	_, err = kernel.Rederive(nil, r.k.Box(), r.k.Log().Entries())
	must(r.t, err)
}

func (r *erig) count(typ string) int {
	n := 0
	for _, e := range r.k.Log().Entries() {
		if e.Type == typ {
			n++
		}
	}
	return n
}

// After Erase every item of the subject is unreadable, Seal on it is
// refused, and the key table no longer holds its key: an erase that only
// marked the log fails here (LOG-4).
func TestEraseMakesContentUnreadable(t *testing.T) {
	r := newErig(t)
	s := r.open()
	h1 := r.seal(s, "mail", kernel.ClassLabel, "Alice")
	h2 := r.seal(s, "notes", "message", "lunch on Tuesday")
	if pt, err := r.k.Read(h2); err != nil || string(pt) != "lunch on Tuesday" {
		t.Fatalf("read before erase: %q %v", pt, err)
	}
	c, err := r.k.Erase(3, s)
	must(t, err)
	if !reflect.DeepEqual(c, kernel.Confirmation{Subject: s, Confirmed: []string{kernel.KeyTable, "mail", "notes"}, BackupsUnknown: true}) {
		t.Fatalf("confirmation %+v", c)
	}
	for _, h := range []kernel.Hash{h1, h2} {
		if _, err := r.k.Read(h); !errors.Is(err, kernel.ErrErased) {
			t.Fatalf("read after erase: %v", err)
		}
	}
	if _, err := r.k.Seal(4, s, "mail", "message", []byte("x")); !errors.Is(err, kernel.ErrErased) {
		t.Fatalf("seal after erase: %v", err)
	}
	if _, ok, _ := r.keys.Get(s); ok {
		t.Fatal("the key table still holds the erased subject's key")
	}
	if len(r.mail.M)+len(r.notes.M) != 0 {
		t.Fatal("a store still holds an erased item")
	}
	if _, err := r.k.Erase(5, s); !errors.Is(err, kernel.ErrErased) {
		t.Fatalf("a second erase: %v", err)
	}
	r.replays()
}

// A crash after subject.erased is written and before the key is deleted:
// the next start deletes it, and the item stays unreadable even with its
// ciphertext still in the store.
func TestEraseSurvivesACrashBeforeTheKeyGoes(t *testing.T) {
	r := newErig(t)
	s := r.open()
	h := r.seal(s, "mail", "message", "secret")
	ct := r.mail.M[h]
	r.keys.failDelete, r.mail.failDelete = true, true // the crash: nothing after the entry lands
	r.k.Erase(3, s)
	r.keys.failDelete, r.mail.failDelete = false, false
	if _, ok, _ := r.keys.Get(s); !ok {
		t.Fatal("setup: the key should have survived the crash")
	}
	r.boot()
	if _, ok, _ := r.keys.Get(s); ok {
		t.Fatal("the start did not delete an erased subject's key")
	}
	r.mail.M[h] = ct // a copy left behind
	if _, err := r.k.Read(h); err == nil {
		t.Fatal("an erased item read after the restart")
	}
	if r.count(kernel.TSubjectErased) != 1 {
		t.Fatal("the erase is not one entry")
	}
	r.replays()
}

// A store whose Delete fails keeps the subject in Unerased across a
// restart, until Tick gets its confirmation, logged once (LOG-4 fails
// closed).
func TestAStoreThatCannotDeleteStaysListed(t *testing.T) {
	r := newErig(t)
	s := r.open()
	r.seal(s, "mail", "message", "a")
	r.seal(s, "notes", "message", "b")
	r.notes.failDelete = true
	c, err := r.k.Erase(3, s)
	must(t, err)
	if !slices.Equal(c.Confirmed, []string{kernel.KeyTable, "mail"}) || !slices.Equal(c.Unconfirmed, []string{"notes"}) {
		t.Fatalf("confirmation %+v", c)
	}
	want := []kernel.Unerased{{Subject: s, Items: 2, Stores: []string{"notes"}}}
	if got := r.k.State().Unerased(); !reflect.DeepEqual(got, want) {
		t.Fatalf("unerased %+v", got)
	}
	must(t, r.k.Tick(4))
	r.boot()
	if got := r.k.State().Unerased(); !reflect.DeepEqual(got, want) {
		t.Fatalf("unerased after restart %+v", got)
	}
	r.notes.failDelete = false
	must(t, r.k.Tick(kernel.RetryMin))
	must(t, r.k.Tick(kernel.RetryMin+1))
	if got := r.k.State().Unerased(); got != nil {
		t.Fatalf("still unerased %+v", got)
	}
	if r.count(kernel.TEraseConfirmed) != 3 {
		t.Fatalf("%d confirmations, want one per store and one for the key", r.count(kernel.TEraseConfirmed))
	}
	r.replays()
}

// A key delete that fails is returned, the confirmation and Unerased name
// the key table as not confirmed until it is, across a restart; Tick retries
// it, and so does the next OpenContent.
func TestAKeyDeleteFailureIsReturned(t *testing.T) {
	r := newErig(t)
	s := r.open()
	r.seal(s, "mail", "message", "a")
	r.keys.failDelete = true
	c, err := r.k.Erase(3, s)
	if !errors.Is(err, errDown) {
		t.Fatalf("erase with the key table down: %v", err)
	}
	if !slices.Equal(c.Unconfirmed, []string{kernel.KeyTable}) || !slices.Equal(c.Confirmed, []string{"mail"}) {
		t.Fatalf("confirmation with the key kept: %+v", c)
	}
	owed := []kernel.Unerased{{Subject: s, Items: 1, Stores: []string{kernel.KeyTable}}}
	if got := r.k.State().Unerased(); !reflect.DeepEqual(got, owed) {
		t.Fatalf("unerased with the key kept: %+v", got)
	}
	if rc, _ := r.k.State().Recall(s); !rc.Erased {
		t.Fatal("the subject is not erased in the log")
	}
	must(t, r.k.Tick(4))
	if _, ok, _ := r.keys.Get(s); !ok {
		t.Fatal("setup: the key should still be there")
	}
	r.boot()
	if got := r.k.State().Unerased(); !reflect.DeepEqual(got, owed) {
		t.Fatalf("unerased after a restart with the key kept: %+v", got)
	}
	r.keys.failDelete = false
	r.boot()
	if _, ok, _ := r.keys.Get(s); ok || r.k.State().Unerased() != nil {
		t.Fatal("OpenContent did not finish the key delete")
	}

	s2 := r.open()
	r.keys.failDelete = true
	r.k.Erase(5, s2)
	r.keys.failDelete = false
	must(t, r.k.Tick(5+kernel.RetryMin))
	if _, ok, _ := r.keys.Get(s2); ok {
		t.Fatal("Tick did not retry the key delete")
	}
}

// A key no subject.opened names (a crash between Put and the log write, or
// a log older than the table) is listed and kept: the log alone cannot
// tell a crash's leftover from a key whose entries it lost.
func TestAKeyNoEntryNamesIsListed(t *testing.T) {
	r := newErig(t)
	s := r.open()
	orphan := "0123456789abcdef0123456789abcdef"
	r.keys.Put(orphan, kernel.SubjectKey{1})
	if rep := r.boot(); !slices.Equal(rep.Unnamed, []string{orphan}) || rep.Missing != nil {
		t.Fatalf("report %+v", rep)
	}
	want := []string{s, orphan}
	slices.Sort(want)
	if got, _ := r.keys.List(); !slices.Equal(got, want) {
		t.Fatalf("keys after start %v", got)
	}
}

// An opened, unerased subject whose key is missing, or is not its own, is
// listed, and its content does not open.
func TestAMissingKeyIsListed(t *testing.T) {
	r := newErig(t)
	a, b, c := r.open(), r.open(), r.open()
	h := r.seal(a, "mail", "message", "x")
	r.keys.MemKeys.Delete(a)
	r.keys.Put(b, kernel.SubjectKey{7})
	rep := r.boot()
	want := []string{a, b}
	slices.Sort(want)
	if !slices.Equal(rep.Missing, want) {
		t.Fatalf("missing %v, want %v (not %s)", rep.Missing, want, c)
	}
	if _, err := r.k.Read(h); !errors.Is(err, kernel.ErrSubjectKey) {
		t.Fatalf("read with the key gone: %v", err)
	}
}

// Recall lists the items while the subject is live; once erased, only the
// erase time, the item count and the stores not yet confirmed, no hashes.
func TestRecallListsItemsThenOnlyTheErase(t *testing.T) {
	r := newErig(t)
	s := r.open()
	h := r.seal(s, "mail", kernel.ClassLabel, "Alice")
	rc, ok := r.k.State().Recall(s)
	if !ok || rc.Opened != 1 || rc.Erased || !reflect.DeepEqual(rc.Items, []kernel.Item{{Store: "mail", Hash: h, Class: kernel.ClassLabel, At: 2}}) {
		t.Fatalf("recall %+v", rc)
	}
	if got, unread, err := r.k.Named("Alice"); err != nil || !slices.Equal(got, []string{s}) || unread != nil {
		t.Fatalf("named %v %v", got, unread)
	}
	r.mail.failDelete = true
	r.k.Erase(3, s)
	rc, _ = r.k.State().Recall(s)
	if !reflect.DeepEqual(rc, kernel.Recall{Subject: s, Opened: 1, Erased: true, ErasedAt: 3, Count: 1, Unconfirmed: []string{"mail"}}) {
		t.Fatalf("recall after erase %+v", rc)
	}
	if got, _, _ := r.k.Named("Alice"); got != nil {
		t.Fatalf("an erased subject is still found by name: %v", got)
	}
	if _, ok := r.k.State().Recall("ffffffffffffffffffffffffffffffff"); ok {
		t.Fatal("recall of an unknown subject")
	}
}

// The log holds no data key, no name and no hash of a plaintext (LOG-4,
// LOG-2): every entry body is scanned.
func TestTheLogHoldsNoKeyNameOrPlaintextHash(t *testing.T) {
	r := newErig(t)
	s := r.open()
	r.seal(s, "mail", kernel.ClassLabel, "Alice Example")
	r.seal(s, "mail", "message", "the plaintext")
	dk, _, _ := r.keys.Get(s)
	r.k.Erase(3, s)
	ph := sha256.Sum256([]byte("the plaintext"))
	for _, e := range r.k.Log().Entries() {
		for _, bad := range [][]byte{dk[:], []byte(hex.EncodeToString(dk[:])), []byte("Alice"), ph[:], []byte(hex.EncodeToString(ph[:]))} {
			if bytes.Contains(e.Body, bad) {
				t.Fatalf("entry %d %s holds %q", e.Seq, e.Type, bad)
			}
		}
	}
}

// Erasing one subject leaves another's items readable.
func TestEraseLeavesOtherSubjects(t *testing.T) {
	r := newErig(t)
	a, b := r.open(), r.open()
	r.seal(a, "mail", "message", "a")
	hb := r.seal(b, "mail", "message", "b")
	_, err := r.k.Erase(3, a)
	must(t, err)
	if pt, err := r.k.Read(hb); err != nil || string(pt) != "b" {
		t.Fatalf("the other subject: %q %v", pt, err)
	}
	if _, err := r.k.Seal(4, b, "notes", "message", []byte("c")); err != nil {
		t.Fatal(err)
	}
}

// A state replayed from empty equals the live one, Unerased included
// (LOG-1).
func TestEraseStateRebuildsFromEmpty(t *testing.T) {
	r := newErig(t)
	a, b := r.open(), r.open()
	r.seal(a, "mail", "message", "a")
	r.seal(a, "notes", "message", "b")
	r.seal(b, "notes", "message", "c")
	r.notes.failDelete = true
	r.k.Erase(3, a)
	r.replays()
	re, _ := kernel.Replay(nil, r.k.Log().Entries())
	if !reflect.DeepEqual(re.Unerased(), r.k.State().Unerased()) || len(re.Unerased()) != 1 {
		t.Fatalf("unerased %+v", re.Unerased())
	}
	r.notes.failDelete = false
	must(t, r.k.Tick(3+kernel.RetryMin))
	if re := r.k.State().Unerased(); re != nil {
		t.Fatalf("still unerased %+v", re)
	}
	r.replays()
}

// The four entry types are known at version 1, none widens, and an
// unanchored subject.erased survives Open (LOG-5, LOG-2).
func TestEraseEntriesAreKnownAndNarrowing(t *testing.T) {
	for _, typ := range []string{kernel.TSubjectOpened, kernel.TContentStored, kernel.TSubjectErased, kernel.TEraseConfirmed} {
		if !kernel.Known(typ, 1) || kernel.Known(typ, 2) || kernel.Widening(typ) {
			t.Fatalf("%s: known %v, widening %v", typ, kernel.Known(typ, 1), kernel.Widening(typ))
		}
	}
	r := newErig(t)
	s := r.open()
	r.seal(s, "mail", "message", "a")
	r.anchor.down = true
	if _, err := r.k.Erase(3, s); err == nil {
		t.Fatal("an erase whose anchor failed returned nil")
	}
	if _, ok, _ := r.keys.Get(s); ok {
		t.Fatal("the key outlived an erase whose anchor failed")
	}
	r.anchor.down = false
	r.boot()
	if rc, _ := r.k.State().Recall(s); !rc.Erased {
		t.Fatal("Open dropped an unanchored subject.erased")
	}
}

// Seal and Read refuse until OpenContent has run; an erase before it is
// logged, and its key goes when OpenContent runs.
func TestContentIsClosedUntilOpenContent(t *testing.T) {
	r := newErig(t)
	s := r.open()
	h := r.seal(s, "mail", "message", "a")
	l, err := kernel.Open(kernel.Config{Store: r.log, Anchor: r.anchor, Pub: r.head.pub, Sign: r.head.priv, Rand: r.rnd})
	must(t, err)
	k, err := kernel.Boot(l, nil, nil, 0)
	must(t, err)
	if _, err := k.Read(h); !errors.Is(err, kernel.ErrContentClosed) {
		t.Fatalf("read before OpenContent: %v", err)
	}
	if _, err := k.Seal(3, s, "mail", "message", nil); !errors.Is(err, kernel.ErrContentClosed) {
		t.Fatalf("seal before OpenContent: %v", err)
	}
	if _, err := k.Erase(3, s); !errors.Is(err, kernel.ErrContentClosed) {
		t.Fatalf("erase before OpenContent: %v", err)
	}
	if _, err := k.OpenContent(r.keys, map[string]kernel.ContentStore{"mail": r.mail}, 4); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := r.keys.Get(s); ok || len(r.mail.M) != 0 {
		t.Fatal("OpenContent did not finish an erase logged before it")
	}
}

// Recall by name skips a subject whose label cannot be read and lists it
// apart, so one missing key or store down hides no other subject, whichever
// way the subjects sort.
func TestNamedSkipsAnUnreadableSubject(t *testing.T) {
	for _, badFirst := range []bool{true, false} {
		r := newErig(t)
		a, b := r.open(), r.open()
		r.seal(a, "mail", kernel.ClassLabel, "Alice")
		r.seal(b, "notes", kernel.ClassLabel, "Alice")
		bad, good := a, b
		if (a < b) != badFirst {
			bad, good = b, a
		}
		r.keys.MemKeys.Delete(bad)
		got, unread, err := r.k.Named("Alice")
		if err != nil || !slices.Equal(got, []string{good}) || !slices.Equal(unread, []string{bad}) {
			t.Errorf("unreadable sorts first=%v: named %v, unread %v, %v", badFirst, got, unread, err)
		}
	}
}

// A subject whose earlier label cannot be read and whose later one matches
// is found, and not also listed as unread.
func TestNamedFindsALaterLabel(t *testing.T) {
	r := newErig(t)
	s := r.open()
	h := r.seal(s, "mail", kernel.ClassLabel, "Al")
	r.seal(s, "notes", kernel.ClassLabel, "Alice")
	delete(r.mail.M, h)
	if got, unread, err := r.k.Named("Alice"); err != nil || !slices.Equal(got, []string{s}) || unread != nil {
		t.Fatalf("named %v, unread %v, %v", got, unread, err)
	}
	if got, unread, err := r.k.Named("Bob"); err != nil || got != nil || !slices.Equal(unread, []string{s}) {
		t.Fatalf("no match: named %v, unread %v, %v", got, unread, err)
	}
}

// Before OpenContent, Named says content is closed rather than calling
// every subject unreadable.
func TestNamedBeforeOpenContentIsClosed(t *testing.T) {
	r := newErig(t)
	s := r.open()
	r.seal(s, "mail", kernel.ClassLabel, "Alice")
	l, err := kernel.Open(kernel.Config{Store: r.log, Anchor: r.anchor, Pub: r.head.pub, Sign: r.head.priv, Rand: r.rnd})
	must(t, err)
	k, err := kernel.Boot(l, nil, nil, 0)
	must(t, err)
	if got, unread, err := k.Named("Alice"); !errors.Is(err, kernel.ErrContentClosed) || got != nil || unread != nil {
		t.Fatalf("named before OpenContent: %v, %v, %v", got, unread, err)
	}
}

// A delete that fails is not asked again on every Tick: it waits RetryMin,
// then twice as long each time up to RetryMax, stays in Unerased
// throughout, and a restart asks at once (LOG-4).
func TestARetriedDeleteBacksOff(t *testing.T) {
	r := newErig(t)
	s := r.open()
	r.seal(s, "notes", "message", "a")
	r.notes.failDelete = true
	r.keys.failDelete = true
	r.k.Erase(10, s)
	if r.notes.deletes != 1 {
		t.Fatalf("%d deletes at the erase", r.notes.deletes)
	}
	keyGets := func() bool { _, ok, _ := r.keys.Get(s); return ok }
	at, wait := int64(10), kernel.RetryMin
	for n := 2; n < 14; n++ {
		must(t, r.k.Tick(at+wait-1))
		if r.notes.deletes != n-1 {
			t.Fatalf("try %d: asked before its wait of %d ms", n, wait)
		}
		at += wait
		must(t, r.k.Tick(at))
		if r.notes.deletes != n {
			t.Fatalf("try %d: not asked after its wait of %d ms (%d deletes)", n, wait, r.notes.deletes)
		}
		if len(r.k.State().Unerased()) != 1 {
			t.Fatal("dropped from Unerased while backing off")
		}
		wait = min(2*wait, kernel.RetryMax)
	}
	if wait != kernel.RetryMax {
		t.Fatalf("setup: the wait should have reached RetryMax, at %d", wait)
	}
	r.keys.failDelete = false
	r.notes.failDelete = false
	before := r.notes.deletes
	r.boot()
	if r.notes.deletes != before+1 || keyGets() || r.k.State().Unerased() != nil {
		t.Fatalf("a restart did not ask again at once: %d deletes, unerased %+v", r.notes.deletes-before, r.k.State().Unerased())
	}
	r.replays()
}

// A delete that failed while the wall clock was ahead is retried once the
// clock steps back, not held until the clock catches up (L3 on #3182).
func TestARetryAfterTheClockStepsBack(t *testing.T) {
	r := newErig(t)
	s := r.open()
	r.seal(s, "notes", "message", "a")
	r.notes.failDelete = true
	r.k.Erase(86_400_000, s) // a day ahead
	r.notes.failDelete = false
	must(t, r.k.Tick(10))
	if u := r.k.State().Unerased(); u != nil {
		t.Fatalf("held after the clock stepped back: %+v", u)
	}
	r.replays()
}

// ReadFor logs content.read before it opens the item, so a failing log
// write returns no plaintext; after the erase, ErasedReads names each
// reader at its first read, and a later read does not move it. A delivery
// that leaves no record fails here (LOG-4, D-169).
func TestReadForLogsBeforeItOpens(t *testing.T) {
	r := newErig(t)
	s, kept := r.open(), r.open()
	h := r.seal(s, "mail", "message", "lunch on Tuesday")
	h2 := r.seal(s, "notes", "message", "dinner")
	k2 := r.seal(kept, "notes", "message", "kept")
	r.log.down = true
	if pt, err := r.k.ReadFor(5, h, "lin-a"); err == nil || pt != nil {
		t.Fatalf("a read whose entry was not written: %q, %v", pt, err)
	}
	r.log.down = false
	r.boot() // a failed write needs a reopen
	if r.count(kernel.TContentRead) != 0 {
		t.Fatal("a failed write left a content.read")
	}
	if pt, err := r.k.ReadFor(6, h, "lin-a"); err != nil || string(pt) != "lunch on Tuesday" {
		t.Fatalf("read for lin-a: %q, %v", pt, err)
	}
	if _, err := r.k.ReadFor(7, h2, "lin-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.k.ReadFor(8, h2, "lin-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.k.ReadFor(8, k2, "lin-c"); err != nil {
		t.Fatal(err)
	}
	if got := r.k.State().ErasedReads(); got != nil {
		t.Fatalf("reads of live subjects are listed: %+v", got)
	}
	for _, bad := range []string{"", strings.Repeat("l", 129), "a\nb"} {
		if _, err := r.k.ReadFor(9, h, bad); !errors.Is(err, kernel.ErrLineage) {
			t.Fatalf("lineage %q: %v", bad, err)
		}
	}
	if _, err := r.k.ReadFor(9, kernel.Hash{1}, "lin-a"); !errors.Is(err, kernel.ErrItem) {
		t.Fatalf("an unknown item: %v", err)
	}
	if _, err := r.k.Erase(10, s); err != nil {
		t.Fatal(err)
	}
	n := r.count(kernel.TContentRead)
	if _, err := r.k.ReadFor(11, h, "lin-d"); !errors.Is(err, kernel.ErrErased) || r.count(kernel.TContentRead) != n {
		t.Fatalf("a read after the erase: %v, logged %d", err, r.count(kernel.TContentRead)-n)
	}
	want := []kernel.ErasedRead{{Subject: s, Lineage: "lin-a", First: 6}, {Subject: s, Lineage: "lin-b", First: 8}}
	if got := r.k.State().ErasedReads(); !reflect.DeepEqual(got, want) {
		t.Fatalf("erased reads %+v, want %+v", got, want)
	}
	r.replays()
	r.boot()
	if got := r.k.State().ErasedReads(); !reflect.DeepEqual(got, want) {
		t.Fatalf("after a restart %+v, want %+v", got, want)
	}
}

// A replayed state equals the live one, ErasedReads included, also for
// reads that were not anchored (LOG-1).
func TestErasedReadsRebuildFromEmpty(t *testing.T) {
	r := newErig(t)
	a, b := r.open(), r.open()
	ha := r.seal(a, "mail", "message", "a")
	hb := r.seal(b, "notes", "message", "b")
	for _, c := range []struct {
		h kernel.Hash
		l string
	}{{ha, "x"}, {hb, "x"}, {ha, "y"}, {ha, "x"}} {
		if _, err := r.k.ReadFor(4, c.h, c.l); err != nil {
			t.Fatal(err)
		}
	}
	must(t, r.k.Log().Anchor())
	if _, err := r.k.ReadFor(5, hb, "z"); err != nil {
		t.Fatal(err)
	}
	r.k.Erase(6, a)
	r.k.Erase(7, b)
	r.replays()
	re, err := kernel.Replay(nil, r.k.Log().Entries())
	must(t, err)
	want := []kernel.ErasedRead{{Subject: a, Lineage: "x", First: 4}, {Subject: a, Lineage: "y", First: 4},
		{Subject: b, Lineage: "x", First: 4}, {Subject: b, Lineage: "z", First: 5}}
	slices.SortFunc(want, func(p, q kernel.ErasedRead) int { return strings.Compare(p.Subject+p.Lineage, q.Subject+q.Lineage) })
	if got := re.ErasedReads(); !reflect.DeepEqual(got, want) || !reflect.DeepEqual(got, r.k.State().ErasedReads()) {
		t.Fatalf("replayed %+v, live %+v, want %+v", got, r.k.State().ErasedReads(), want)
	}
}

// content.read is known at version 1, does not widen, and Rederive folds
// it as given (LOG-5).
func TestContentReadIsKnownAndNarrowing(t *testing.T) {
	if !kernel.Known(kernel.TContentRead, 1) || kernel.Known(kernel.TContentRead, 2) || kernel.Widening(kernel.TContentRead) {
		t.Fatal("content.read is not a known narrowing entry at version 1")
	}
	r := newErig(t)
	s := r.open()
	h := r.seal(s, "mail", "message", "a")
	if _, err := r.k.ReadFor(3, h, "lin"); err != nil {
		t.Fatal(err)
	}
	got, err := kernel.Rederive(nil, r.k.Box(), r.k.Log().Entries())
	must(t, err)
	if got.Recorded[kernel.TContentRead] != 1 {
		t.Fatalf("rederive %+v", got)
	}
}

// Named folds case and collapses whitespace: "alice  smith" finds "Alice
// Smith", and "Alicia" does not.
func TestNamedFoldsCaseAndSpace(t *testing.T) {
	r := newErig(t)
	s := r.open()
	r.seal(s, "mail", kernel.ClassLabel, "Alice Smith")
	for _, q := range []string{"alice  smith", " ALICE\tSmith ", "Alice Smith"} {
		if got, _, err := r.k.Named(q); err != nil || !slices.Equal(got, []string{s}) {
			t.Errorf("named %q: %v, %v", q, got, err)
		}
	}
	for _, q := range []string{"Alicia", "Alice", "alicesmith"} {
		if got, _, err := r.k.Named(q); err != nil || got != nil {
			t.Errorf("named %q found %v, %v", q, got, err)
		}
	}
}

// A blank or invalid-UTF-8 query is ErrLabel and finds nothing: "   " would
// fold to "" and match every blank label, and "\xff" a U+FFFD one (LOG-4,
// #3443; the Security probe on #3438).
func TestNamedRefusesBlankAndInvalidQuery(t *testing.T) {
	r := newErig(t)
	blank, odd, alice := r.open(), r.open(), r.open()
	r.seal(blank, "mail", kernel.ClassLabel, " ")
	r.seal(odd, "mail", kernel.ClassLabel, "\uFFFD")
	r.seal(alice, "mail", kernel.ClassLabel, "Alice")
	for _, q := range []string{"", "   ", "\t\n", "\xff", "Alice\xff"} {
		if got, unread, err := r.k.Named(q); !errors.Is(err, kernel.ErrLabel) || got != nil || unread != nil {
			t.Errorf("named %q: %v %v %v, want ErrLabel", q, got, unread, err)
		}
	}
	if got, _, err := r.k.Named("\uFFFD"); err != nil || !slices.Equal(got, []string{odd}) {
		t.Errorf("a typed U+FFFD label: %v %v", got, err)
	}
}
