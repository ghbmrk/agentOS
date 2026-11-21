package kernel_test

// REQ: LOG-4, BAK-1

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// Tests that pin erase.go statements no other test failed without
// (MUT-kill-6032-kernel-erase, #6248).

// A content.read entry whose body does not decode fails the replay, as
// every other erase entry's does: a log the kernel did not write is
// refused, not folded into nothing (LOG-1).
func TestLOG4AContentReadWithABadBodyFailsTheReplay(t *testing.T) {
	es := []kernel.Entry{{Seq: 1, Type: kernel.TContentRead, V: 1, Body: json.RawMessage(`"x"`)}}
	if _, err := kernel.Replay(nil, es); err == nil {
		t.Fatal("a content.read with a string body replayed")
	}
}

// A lineage is up to 128 bytes: one of exactly 128 reads, and one byte
// more is refused before anything is logged.
func TestLOG4ALineageOf128BytesReads(t *testing.T) {
	r := newErig(t)
	s := r.open()
	h := r.seal(s, "mail", "message", "a")
	if pt, err := r.k.ReadFor(3, h, strings.Repeat("l", 128)); err != nil || string(pt) != "a" {
		t.Fatalf("a 128-byte lineage: %q, %v", pt, err)
	}
	if _, err := r.k.ReadFor(3, h, strings.Repeat("l", 129)); !errors.Is(err, kernel.ErrLineage) {
		t.Fatalf("a 129-byte lineage: %v", err)
	}
}

// Before OpenContent, ReadFor of a hash the log does not name is refused as
// closed, as Read is: an unknown item is not told apart from a store not
// yet opened.
func TestLOG4ReadForOfAnUnknownItemBeforeOpenContentIsClosed(t *testing.T) {
	r := newErig(t)
	l, err := kernel.Open(kernel.Config{Store: r.log, Anchor: r.anchor, Pub: r.head.pub, Sign: r.head.priv, Rand: r.rnd})
	must(t, err)
	k, err := kernel.Boot(l, nil, nil, 0)
	must(t, err)
	if _, err := k.ReadFor(1, kernel.Hash{7}, "lin"); !errors.Is(err, kernel.ErrContentClosed) {
		t.Fatalf("ReadFor of an unknown item before OpenContent: %v", err)
	}
	if _, err := r.k.ReadFor(1, kernel.Hash{7}, "lin"); !errors.Is(err, kernel.ErrItem) {
		t.Fatalf("ReadFor of an unknown item once open: %v", err)
	}
}

// prepFailing is a backup list whose Prepare fails, counting each call.
type prepFailing struct {
	subs  []string
	err   error
	calls int
}

func (p *prepFailing) List() []string           { return []string{"b1"} }
func (p *prepFailing) Subjects(string) []string { return p.subs }
func (p *prepFailing) Prepare(string, kernel.Keys, *kernel.State) (kernel.ResealIO, error) {
	p.calls++
	return nil, p.err
}

// A backup whose re-seal cannot even be prepared backs off like one whose
// re-seal failed: not handed out again before RetryMin, then handed out,
// and named with the error that failed (BAK-1, D-168).
func TestLOG4AFailedPrepareBacksOff(t *testing.T) {
	r := newErig(t)
	s := r.open()
	b := &prepFailing{subs: []string{s}, err: errors.New("prepare failed")}
	r.k.OpenBackups(b)
	c, err := r.k.Erase(10, s)
	must(t, err)
	if due := r.k.Reseals(10); len(due) != 0 || b.calls != 1 {
		t.Fatalf("first try: %d handed out after %d prepares", len(due), b.calls)
	}
	if due := r.k.Reseals(10 + kernel.RetryMin - 1); len(due) != 0 || b.calls != 1 {
		t.Fatalf("prepared again inside its backoff: %d prepares", b.calls)
	}
	want := []kernel.BackupHold{{Backup: "b1", Why: "prepare failed"}}
	if got := r.k.Confirm(c).StillHeld; !reflect.DeepEqual(got, want) {
		t.Fatalf("still held %+v", got)
	}
	if r.k.Reseals(10 + kernel.RetryMin); b.calls != 2 {
		t.Fatalf("not prepared again after its wait: %d prepares", b.calls)
	}
}

// A re-seal that commits clears its backup's backoff: a later confirmation
// that finds the key still given names that, not the earlier failure, and a
// later failure waits RetryMin again, not twice the last wait.
func TestLOG4AResealThatCommitsClearsItsBackoff(t *testing.T) {
	r := newErig(t)
	s := r.open()
	b := newFakeBackups(map[string][]string{"b1": {s}})
	b.fail["b1"] = errDown
	r.k.OpenBackups(b)
	c, err := r.k.Erase(10, s)
	must(t, err)
	r.k.ResealBackups(10)
	if got := r.k.Confirm(c).StillHeld; len(got) != 1 || got[0].Why != errDown.Error() {
		t.Fatalf("after a failed re-seal: %+v", got)
	}
	delete(b.fail, "b1")
	b.lie = true // the commit returns nil and the table still gives the key
	at := 10 + kernel.RetryMin
	r.k.ResealBackups(at)
	if b.reseals["b1"] != 2 {
		t.Fatalf("setup: %d re-seals", b.reseals["b1"])
	}
	if got := r.k.Confirm(c).StillHeld; len(got) != 1 || got[0].Why != "kernel: the backup's key table still gives the subject's key" {
		t.Fatalf("after a re-seal that committed: %+v", got)
	}
	b.lie, b.fail["b1"] = false, errDown
	r.k.ResealBackups(at)
	if b.reseals["b1"] != 3 {
		t.Fatalf("a committed re-seal left a backoff: %d re-seals", b.reseals["b1"])
	}
	if r.k.ResealBackups(at + kernel.RetryMin); b.reseals["b1"] != 4 {
		t.Fatalf("the failure after a commit waited past RetryMin: %d re-seals", b.reseals["b1"])
	}
}

// RetryBackup drops a backup's backoff: the next Reseals hands it out at
// once, and the confirmation no longer names the old failure.
func TestLOG4RetryBackupDropsTheBackoff(t *testing.T) {
	r := newErig(t)
	s := r.open()
	b := newFakeBackups(map[string][]string{"b1": {s}})
	b.fail["b1"] = errDown
	r.k.OpenBackups(b)
	c, err := r.k.Erase(10, s)
	must(t, err)
	r.k.ResealBackups(10)
	if len(r.k.Reseals(10)) != 0 {
		t.Fatal("setup: a failed re-seal did not back off")
	}
	r.k.RetryBackup("b1")
	if got := r.k.Confirm(c).StillHeld; len(got) != 1 || got[0].Why == errDown.Error() {
		t.Fatalf("after RetryBackup: %+v", got)
	}
	if due := r.k.Reseals(10); len(due) != 1 {
		t.Fatalf("RetryBackup did not hand the backup out: %d", len(due))
	}
}
