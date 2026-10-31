package main

// REQ: CLK-1

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// TestIsolatedBeforeTheKey: the clerk refuses to run as its owner side's
// uid, whose peer check would then be no boundary, and turns non-dumpable
// before it reads its key, so no process under its uid can read the
// controller key from its memory (CLK-1, DEV-homekit-b2c).
func TestIsolatedBeforeTheKey(t *testing.T) {
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Close() // the kernel sent nothing: no key
	defer r.Close()
	args := func(owner int) []string {
		return []string{"-dir", d, "-owner-sock", filepath.Join(d, "owner.sock"), "-owner-uid", strconv.Itoa(owner)}
	}
	if err := start(args(os.Getuid()), io.Discard, r); err == nil || !strings.Contains(err.Error(), "peer uid") {
		t.Fatalf("the clerk ran as its owner side's uid: %v", err)
	}
	if err := start(args(os.Getuid()+1), io.Discard, r); err == nil {
		t.Fatal("the clerk started with no key")
	}
	if v, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0); e != 0 || v != 0 {
		t.Fatalf("the clerk is dumpable when it reads its key: %d, %v", v, e)
	}
}
