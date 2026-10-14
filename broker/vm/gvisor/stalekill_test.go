package gvisor

// REQ: CAP-8, RES-4

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/vm"
)

// GVISOR-stale-kill (#1443): a cancelled Exec's in-sandbox kill runs off
// Exec's path. Kill must wait for it, or a Rollback or Rebuild that
// restarts the machine under the same container ID can have the late
// `runsc kill --pid` land in the new sandbox. The fake runsc here holds
// that kill at a gate and logs each verb, so the order is checked without
// depending on timing.
func TestKillWaitsForPendingExecKill(t *testing.T) {
	dir := t.TempDir()
	logf, mark, gate := filepath.Join(dir, "verbs"), filepath.Join(dir, "mark"), filepath.Join(dir, "gate")
	// runsc's environment is a fixed PATH (runscEnv), so the paths are
	// written into the script.
	sh := `#!/bin/sh
while [ $# -gt 0 ]; do
	case "$1" in
	--root|--internal-pid-file|--cwd|--user|--pass-fd) [ -z "$verb" ] && shift ;;
	exec|kill|delete) [ -z "$verb" ] && verb=$1 ;;
	esac
	case "$verb" in exec) [ "$1" = --internal-pid-file ] && pid=$2 ;; esac
	[ "$1" = --pid ] && kpid=$2
	shift
done
case "$verb" in
exec)
	echo 7 >"$pid"
	: >'` + mark + `'
	exec sleep 30
	;;
kill)
	if [ -n "$kpid" ]; then
		echo kill-pid-start >>'` + logf + `'
		i=0
		while [ ! -e '` + gate + `' ] && [ $i -lt 1000 ]; do sleep 0.01; i=$((i + 1)); done
		echo kill-pid-done >>'` + logf + `'
	else
		echo kill >>'` + logf + `'
	fi
	;;
delete) echo delete >>'` + logf + `' ;;
esac
`
	bin := filepath.Join(dir, "runsc")
	if err := os.WriteFile(bin, []byte(sh), 0o700); err != nil {
		t.Fatal(err)
	}
	r := &Runtime{Bin: bin, StateDir: filepath.Join(dir, "state")}
	verbs := func() string { b, _ := os.ReadFile(logf); return string(b) }
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		for end := time.Now().Add(10 * time.Second); !ok(); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(end) {
				t.Fatalf("no %s; verbs %q", what, verbs())
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	execDone := make(chan error, 1)
	go func() {
		_, err := r.Exec(ctx, "wk-1", vm.Command{Argv: []string{"guest"}})
		execDone <- err
	}()
	waitFor("guest start", func() bool { _, err := os.Stat(mark); return err == nil })
	cancel()
	if err := <-execDone; err == nil {
		t.Fatal("a cancelled exec read as a result")
	}
	waitFor("pending kill", func() bool { return strings.Contains(verbs(), "kill-pid-start") })

	killed := make(chan error, 1)
	go func() {
		killed <- r.Kill(context.Background(), vm.Launch{ID: "wk-1", Root: filepath.Join(dir, "root")})
	}()
	select {
	case err := <-killed:
		t.Fatalf("Kill returned (%v) while the cancelled exec's kill still ran; verbs %q", err, verbs())
	case <-time.After(500 * time.Millisecond):
	}
	if v := verbs(); strings.Contains(v, "\nkill\n") || strings.Contains(v, "delete") {
		t.Fatalf("Kill went ahead of the pending kill: %q", v)
	}
	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-killed:
		// A non-root test cannot unmount; only the order matters here.
		if err != nil && !errors.Is(err, os.ErrPermission) {
			t.Logf("Kill: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("Kill never returned; verbs %q", verbs())
	}
	if v, want := verbs(), "kill-pid-start\nkill-pid-done\nkill\ndelete\n"; v != want {
		t.Fatalf("verbs %q, want %q", v, want)
	}

	// The wait is per incarnation: a second Kill, with nothing pending,
	// does not block.
	done := make(chan struct{})
	go func() {
		r.Kill(context.Background(), vm.Launch{ID: "wk-1", Root: filepath.Join(dir, "root")})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a Kill with no pending exec kill blocked")
	}
}
