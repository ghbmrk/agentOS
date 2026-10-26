package kernel_test

// REQ: LOG-4, BAK-1

import (
	"errors"
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

var errAppendOnly = errors.New("append-only")

// fakeBackups is a backup list whose re-seal drops every subject the state
// has erased, unless the backup is set to fail.
type fakeBackups struct {
	subs    map[string][]string // backup: the subjects its key table gives
	fail    map[string]error
	reseals map[string]int
	lie     bool // Reseal returns nil and changes nothing
}

func newFakeBackups(subs map[string][]string) *fakeBackups {
	return &fakeBackups{subs: subs, fail: map[string]error{}, reseals: map[string]int{}}
}

func (f *fakeBackups) List() []string             { return slices.Sorted(maps.Keys(f.subs)) }
func (f *fakeBackups) Subjects(b string) []string { return f.subs[b] }
func (f *fakeBackups) Reseal(b string, keys kernel.Keys, s *kernel.State) error {
	f.reseals[b]++
	if err := f.fail[b]; err != nil {
		return err
	}
	if keys == nil {
		return errors.New("no key table")
	}
	if !f.lie {
		f.subs[b] = slices.DeleteFunc(slices.Clone(f.subs[b]), func(sub string) bool {
			r, ok := s.Recall(sub)
			return !ok || r.Erased
		})
	}
	return nil
}

// An erase re-seals every backup that held the subject and names the ones
// it could not, with why; a backup that never held it is not asked or
// named (D-168, LOG-4). An erase that only said "older backups may hold
// it" fails here.
func TestEraseNamesTheBackupsItResealed(t *testing.T) {
	r := newErig(t)
	s, other := r.open(), r.open()
	r.seal(s, "mail", "message", "a")
	b := newFakeBackups(map[string][]string{"b1": {other, s}, "b2": {s}, "b3": {other}})
	b.fail["b2"] = errAppendOnly
	r.k.OpenBackups(b, 3)
	c, err := r.k.Erase(3, s)
	must(t, err)
	want := kernel.Confirmation{Subject: s, Confirmed: []string{kernel.KeyTable, "mail"},
		Resealed: []string{"b1"}, StillHeld: []kernel.BackupHold{{Backup: "b2", Why: "append-only"}}}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("confirmation %+v, want %+v", c, want)
	}
	if !slices.Equal(b.subs["b1"], []string{other}) || b.reseals["b3"] != 0 {
		t.Fatalf("b1 gives %v; b3 asked %d times", b.subs["b1"], b.reseals["b3"])
	}
	r.replays()
}

// Without a backup list the confirmation says any older backup may hold
// the subject: it never reads as "no backup holds it".
func TestEraseWithoutABackupListSaysSo(t *testing.T) {
	r := newErig(t)
	s := r.open()
	c, err := r.k.Erase(3, s)
	must(t, err)
	if !c.BackupsUnknown || c.Resealed != nil || c.StillHeld != nil {
		t.Fatalf("confirmation %+v", c)
	}
}

// A backup whose re-seal reports success but still gives the key is named
// as still holding it: the kernel checks, it does not take the word.
func TestAResealThatDidNotTakeIsStillHeld(t *testing.T) {
	r := newErig(t)
	s := r.open()
	b := newFakeBackups(map[string][]string{"b1": {s}})
	b.lie = true
	r.k.OpenBackups(b, 3)
	c, err := r.k.Erase(3, s)
	must(t, err)
	if c.Resealed != nil || len(c.StillHeld) != 1 || c.StillHeld[0].Backup != "b1" {
		t.Fatalf("confirmation %+v", c)
	}
}

// A backup that is down is retried with a content store's backoff: not
// before RetryMin, then twice as long each time up to RetryMax, and a
// restart asks at once. While it backs off an erase names it with the
// error that failed, not asked again. Once up, its table no longer gives
// the key.
func TestADownBackupBacksOffLikeAStore(t *testing.T) {
	r := newErig(t)
	s, s2 := r.open(), r.open()
	b := newFakeBackups(map[string][]string{"b1": {s, s2}})
	b.fail["b1"] = errDown
	r.k.OpenBackups(b, 10)
	c, err := r.k.Erase(10, s)
	must(t, err)
	if !reflect.DeepEqual(c.StillHeld, []kernel.BackupHold{{Backup: "b1", Why: errDown.Error()}}) || b.reseals["b1"] != 1 {
		t.Fatalf("confirmation %+v after %d re-seals", c, b.reseals["b1"])
	}
	c, err = r.k.Erase(11, s2)
	must(t, err)
	if !reflect.DeepEqual(c.StillHeld, []kernel.BackupHold{{Backup: "b1", Why: errDown.Error()}}) || b.reseals["b1"] != 1 {
		t.Fatalf("while backing off: confirmation %+v after %d re-seals", c, b.reseals["b1"])
	}
	at, wait := int64(10), kernel.RetryMin
	for n := 2; n < 14; n++ {
		must(t, r.k.Tick(at+wait-1))
		if b.reseals["b1"] != n-1 {
			t.Fatalf("try %d: asked before its wait of %d ms", n, wait)
		}
		at += wait
		must(t, r.k.Tick(at))
		if b.reseals["b1"] != n {
			t.Fatalf("try %d: not asked after its wait of %d ms", n, wait)
		}
		wait = min(2*wait, kernel.RetryMax)
	}
	if wait != kernel.RetryMax {
		t.Fatalf("setup: the wait should have reached RetryMax, at %d", wait)
	}
	delete(b.fail, "b1")
	before := b.reseals["b1"]
	r.boot()
	r.k.OpenBackups(b, at+1)
	if b.reseals["b1"] != before+1 || len(b.subs["b1"]) != 0 {
		t.Fatalf("a restart did not re-seal at once: %d asks, b1 gives %v", b.reseals["b1"]-before, b.subs["b1"])
	}
	must(t, r.k.Tick(at+2))
	if b.reseals["b1"] != before+1 {
		t.Fatal("a re-sealed backup is asked again")
	}
}

// An erase logged while content was closed reaches the backups once it
// opens: the confirmation names them as held, and OpenContent's start
// re-seals them.
func TestAnEraseBeforeContentOpensReachesTheBackupsAtStart(t *testing.T) {
	r := newErig(t)
	s := r.open()
	l, err := kernel.Open(kernel.Config{Store: r.log, Anchor: r.anchor, Pub: r.head.pub, Sign: r.head.priv, Rand: r.rnd})
	must(t, err)
	r.k, err = kernel.Boot(l, nil, nil, 0)
	must(t, err)
	b := newFakeBackups(map[string][]string{"b1": {s}})
	r.k.OpenBackups(b, 3)
	c, err := r.k.Erase(3, s)
	if !errors.Is(err, kernel.ErrContentClosed) || len(c.StillHeld) != 1 || b.reseals["b1"] != 0 {
		t.Fatalf("erase before OpenContent: %+v, %v, %d re-seals", c, err, b.reseals["b1"])
	}
	_, err = r.k.OpenContent(r.keys, map[string]kernel.ContentStore{"mail": r.mail, "notes": r.notes}, 4)
	must(t, err)
	if len(b.subs["b1"]) != 0 {
		t.Fatalf("b1 still gives %v after OpenContent", b.subs["b1"])
	}
}
