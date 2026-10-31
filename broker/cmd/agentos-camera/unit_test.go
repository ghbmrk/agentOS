package main

// REQ: CLK-1, NET-2

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// TestTheClerkIsIsolatedBeforeItReadsItsKey: the clerk refuses its owner
// side's uid and turns non-dumpable before it reads its key, so no other
// process of its uid reads the key from its memory (CLK-1).
func TestTheClerkIsIsolatedBeforeItReadsItsKey(t *testing.T) {
	d := t.TempDir()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Close() // the kernel sent nothing: no key
	defer r.Close()
	args := func(owner int) []string {
		return []string{"-dir", d, "-owner-sock", filepath.Join(d, "owner.sock"), "-owner-uid", strconv.Itoa(owner),
			"-decoder", filepath.Join(d, "conn.sock")}
	}
	// Never as the owner side's uid: its uid check would be no boundary.
	if err := start(args(os.Getuid()), io.Discard, r); err == nil || !strings.Contains(err.Error(), "peer uid") {
		t.Fatalf("the clerk ran as its owner side's uid: %v", err)
	}
	if err := start(args(os.Getuid()+1), io.Discard, r); err == nil {
		t.Fatal("the clerk started with no key")
	}
	if v, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0); e != 0 || v != 0 {
		t.Fatalf("the clerk is dumpable: %d, %v", v, e)
	}
}
