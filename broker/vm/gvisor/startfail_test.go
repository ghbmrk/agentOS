package gvisor

// REQ: RES-4, CAP-8
//
// #1701: a machine whose runsc run fails leaves runsc's message in the
// broker's exec log, since vm removes the machine's directory, and its
// console.log, on a failed create. The error names the exec log.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/childproc"
	"github.com/ghbmrk/agentos/broker/vm"
)

func TestFailedStartKeepsRunscsMessageInTheExecLog(t *testing.T) {
	r := fakeRunsc(t)
	if err := os.MkdirAll(r.StateDir, 0o700); err != nil { // as launch does
		t.Fatal(err)
	}
	dir := t.TempDir()
	l := vm.Launch{ID: "pw-1", Dir: dir, Root: filepath.Join(dir, "root")}
	err := r.startConsole(context.Background(), l, childproc.Options{}, r.launchArgs(l, "")...)
	if err == nil {
		t.Fatal("a failed runsc run started the machine")
	}
	if !strings.Contains(err.Error(), r.execLog()) || strings.Contains(err.Error(), runscCanary) {
		t.Fatalf("error %v: want the exec log named and none of runsc's text", err)
	}
	os.RemoveAll(dir) // as vm does after a failed create
	b, rerr := os.ReadFile(r.execLog())
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, want := range []string{"pw-1: runsc run failed (exit status 128)", "starting container: " + runscCanary + ": operation not permitted"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("exec log lacks %q:\n%s", want, b)
		}
	}
	if fi, err := os.Stat(r.execLog()); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("exec log mode: %v %v", fi, err)
	}
}
