package guest

// REQ: KRN-2

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A link planted at the inbox file is refused, never read through
// (REV-CHK-links-daemon-a, #3944).
func TestOpenStoreRefusesPlantedLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{"inbox":{"m1":[{"id":"x","text":"planted"}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	inbox := filepath.Join(dir, "guest-inbox.json")
	if err := os.Symlink(target, inbox); err != nil {
		t.Fatal(err)
	}
	if _, err := openStore(inbox); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("openStore through a planted link: %v, want ELOOP", err)
	}
}

// Forgetting a goal the store never held writes nothing (G14).
func TestForgettingAnUnknownGoalWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbox.json")
	s, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.setGoal("l1", "", storedGoal{}.Last)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("forgetting an unknown goal wrote the file: %v", err)
	}
}

// A refresh of the same goal within a minute stays in memory; a new
// message, or the same one a minute or more after the last refresh, is
// written (G14).
func TestAGoalRefreshWithinAMinuteIsNotWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbox.json")
	s, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t0 := storedGoal{}.Last
	written := func(step string, want bool) {
		t.Helper()
		_, err := os.Stat(path)
		if got := err == nil; got != want {
			t.Fatalf("%s: written %v, want %v", step, got, want)
		}
		os.Remove(path)
	}
	s.setGoal("l1", "m", t0)
	written("first", true)
	s.setGoal("l1", "m", t0.Add(30e9))
	written("refresh after 30s", false)
	s.setGoal("l1", "m", t0.Add(89e9))
	written("refresh 59s after the last", false)
	s.setGoal("l1", "m", t0.Add(149e9))
	written("refresh a minute after the last", true)
	s.setGoal("l1", "n", t0.Add(150e9))
	written("a new message", true)
	if g := s.goal("l1"); g.Msg != "n" || !g.Last.Equal(t0.Add(150e9)) {
		t.Fatalf("goal %+v", g)
	}
}

// A failed write leaves the inbox as it was, for a machine that had
// messages and one that had none (G5).
func TestAFailedInboxWriteKeepsThePreviousMessages(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbox.json")
	s, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	before := []storedMsg{{ID: "a", Text: "one"}}
	if err := s.set("m1", before); err != nil {
		t.Fatal(err)
	}
	// A directory at the store's path fails the rename, even for root.
	os.Remove(path)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.set("m1", []storedMsg{{ID: "b", Text: "two"}}); err == nil {
		t.Fatal("set over a directory succeeded")
	}
	if got := s.load("m1"); len(got) != 1 || got[0] != before[0] {
		t.Fatalf("m1 after a failed set: %+v", got)
	}
	if err := s.set("m2", []storedMsg{{ID: "c", Text: "three"}}); err == nil {
		t.Fatal("set over a directory succeeded")
	}
	if got := s.load("m2"); len(got) != 0 {
		t.Fatalf("m2 after a failed set: %+v", got)
	}
	if entries, err := os.ReadDir(filepath.Dir(path)); err != nil || len(entries) != 1 {
		t.Fatalf("a failed write left %d entries (%v): its temporary file stayed", len(entries), err)
	}
}

// accept replaces the machine's messages, or drops them when none are
// left, and on a failed write changes nothing (DEL-1a).
func TestAcceptReplacesTheMessagesInOneWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbox.json")
	s, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	rest := []storedMsg{{ID: "b", Text: "two"}}
	if err := s.accept("m1", rest, PendingReply{Machine: "m1", Reply: Reply{ID: "a"}}, false); err != nil {
		t.Fatal(err)
	}
	if got := s.load("m1"); len(got) != 1 || got[0] != rest[0] {
		t.Fatalf("after accept: %+v", got)
	}
	os.Remove(path)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	rep := PendingReply{Machine: "m1", Reply: Reply{ID: "b"}, Hash: "h"}
	if err := s.accept("m1", nil, rep, true); err == nil {
		t.Fatal("accept over a directory succeeded")
	}
	if got := s.load("m1"); len(got) != 1 || got[0] != rest[0] {
		t.Fatalf("after a failed accept: %+v", got)
	}
	if _, ok := s.answered("m1", "b"); ok || len(s.pending()) != 0 {
		t.Fatal("a failed accept recorded its reply")
	}
	os.Remove(path)
	if err := s.accept("m1", nil, rep, true); err != nil {
		t.Fatal(err)
	}
	if got := s.load("m1"); len(got) != 0 {
		t.Fatalf("the last message stayed: %+v", got)
	}
	s2, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.load("m1"); len(got) != 0 || len(s2.pending()) != 1 {
		t.Fatalf("on disk: %+v, %d waiting", got, len(s2.pending()))
	}
}

// done remembers the last doneSize replies handed on, no fewer (DEL-1c).
func TestDoneRemembersTheLastReplies(t *testing.T) {
	s := &store{msgs: map[string][]storedMsg{}, goals: map[string]storedGoal{}}
	id := func(i int) string { return string(rune('a'+i%26)) + string(rune('a'+i/26)) }
	for i := range doneSize {
		if err := s.accept("m1", nil, PendingReply{Machine: "m1", Reply: Reply{ID: id(i)}}, false); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := s.answered("m1", id(0)); !ok {
		t.Fatalf("the first of %d replies was forgotten", doneSize)
	}
	if err := s.accept("m1", nil, PendingReply{Machine: "m1", Reply: Reply{ID: id(doneSize)}}, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.answered("m1", id(0)); ok {
		t.Fatalf("reply %d of %d is still remembered", 1, doneSize+1)
	}
	if _, ok := s.answered("m1", id(1)); !ok {
		t.Fatal("the second reply was forgotten")
	}
}

// A refused reply is no longer waiting once a retire or a forget makes
// room in the outbox (DEL-1e).
func TestRoomInTheOutboxEndsTheRefusal(t *testing.T) {
	full := func() *store {
		s := &store{msgs: map[string][]storedMsg{}, goals: map[string]storedGoal{}}
		for i := range MaxOutbox {
			if err := s.accept("m1", nil, PendingReply{Machine: "m1", Reply: Reply{ID: string(rune('A' + i))}}, true); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.accept("m1", nil, PendingReply{Machine: "m1", Reply: Reply{ID: "over"}}, true); !errors.Is(err, errOutboxFull) || !s.waiting() {
			t.Fatalf("a full outbox: %v, waiting %v", err, s.waiting())
		}
		return s
	}
	s := full()
	if err := s.retire("m1", "A"); err != nil || s.waiting() {
		t.Fatalf("after a retire: %v, waiting %v", err, s.waiting())
	}
	s = full()
	if err := s.forget(); err != nil || s.waiting() {
		t.Fatalf("after a forget: %v, waiting %v", err, s.waiting())
	}
}

// Writing and reading the store close every file they open.
func TestTheStoreClosesItsFiles(t *testing.T) {
	fds := func() int {
		e, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skipf("no /proc/self/fd: %v", err)
		}
		return len(e)
	}
	path := filepath.Join(t.TempDir(), "inbox.json")
	s, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	before := fds()
	for i := range 50 {
		if err := s.set("m1", []storedMsg{{ID: string(rune('a' + i))}}); err != nil {
			t.Fatal(err)
		}
		if _, err := openStore(path); err != nil {
			t.Fatal(err)
		}
	}
	if after := fds(); after > before+5 {
		t.Fatalf("%d files open after 50 writes and reads, %d before", after, before)
	}
}
