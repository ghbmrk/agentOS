package procguard

import (
	"os"
	"testing"
)

// REQ: ARC-1, CRED-1

// A peer-socket process refuses to run as its own peer, and once isolated
// cannot be dumped or traced by a process under its uid (SIM-split R3).
func TestIsolateRefusesItsPeerUIDAndDropsDumpable(t *testing.T) {
	me := os.Getuid()
	if err := Isolate(me+1, me); err == nil {
		t.Fatal("ran as one of its own peers")
	}
	if d, err := dumpable(); err != nil || !d {
		t.Skipf("process already non-dumpable (%v); nothing to observe", err)
	}
	if err := Isolate(me + 1); err != nil {
		t.Fatal(err)
	}
	if d, err := dumpable(); err != nil || d {
		t.Fatalf("still dumpable: %v %v", d, err)
	}
}
