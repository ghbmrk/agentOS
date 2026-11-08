package gvisor

// REQ: CAP-8, RES-4

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/vm"
)

// staleKillRig is a Runtime over a fake runsc that logs each verb with its
// container ID to verbs. A cancelled exec's `kill --pid` for container c
// sleeps 20 s while it holds stderr if hang-c exists, then waits for gate-c,
// so the order of verbs is checked without depending on timing.
type staleKillRig struct {
	t   *testing.T
	dir string
	r   *Runtime
}

func newStaleKillRig(t *testing.T) *staleKillRig {
	t.Helper()
	dir := t.TempDir()
	// runsc's environment is a fixed PATH (runscEnv), so the directory is
	// written into the script.
	sh := `#!/bin/sh
d='` + dir + `'
while [ $# -gt 0 ]; do
	case "$1" in
	--root|--internal-pid-file|--cwd|--user|--pass-fd) [ -z "$verb" ] && shift ;;
	exec|kill|delete) [ -z "$verb" ] && verb=$1 ;;
	*_) [ -z "$c" ] && c=$1 ;;
	esac
	case "$verb" in exec) [ "$1" = --internal-pid-file ] && pid=$2 ;; esac
	[ "$1" = --pid ] && kpid=$2
	shift
done
case "$verb" in
exec)
	echo 7 >"$pid"
	: >"$d/mark-$c"
	exec sleep 30
	;;
kill)
	if [ -n "$kpid" ]; then
		echo "kill-pid-start $c" >>"$d/verbs"
		[ -e "$d/hang-$c" ] && sleep 20
		i=0
		while [ ! -e "$d/gate-$c" ] && [ $i -lt 1000 ]; do sleep 0.01; i=$((i + 1)); done
		echo "kill-pid-done $c" >>"$d/verbs"
	else
		echo "kill $c" >>"$d/verbs"
	fi
	;;
delete) echo "delete $c" >>"$d/verbs" ;;
esac
`
	bin := filepath.Join(dir, "runsc")
	if err := os.WriteFile(bin, []byte(sh), 0o700); err != nil {
		t.Fatal(err)
	}
	k := &staleKillRig{t: t, dir: dir, r: &Runtime{Bin: bin, StateDir: filepath.Join(dir, "state")}}
	// Registered after TempDir's, so it runs first: every gated kill ends
	// before the directory goes.
	t.Cleanup(func() {
		for _, id := range []string{"wk-1", "wk-2"} {
			k.open(id)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			k.r.waitPendingKills(ctx, id)
			cancel()
		}
	})
	return k
}

func (k *staleKillRig) verbs() string {
	b, _ := os.ReadFile(filepath.Join(k.dir, "verbs"))
	return string(b)
}

func (k *staleKillRig) touch(name string) {
	k.t.Helper()
	if err := os.WriteFile(filepath.Join(k.dir, name), nil, 0o600); err != nil {
		k.t.Fatal(err)
	}
}

// open lets id's gated `kill --pid` finish.
func (k *staleKillRig) open(id string) { k.touch("gate-" + cid(id)) }

func (k *staleKillRig) waitFor(what string, ok func() bool) {
	k.t.Helper()
	for end := time.Now().Add(10 * time.Second); !ok(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			k.t.Fatalf("no %s; verbs %q", what, k.verbs())
		}
	}
}

// cancelExec starts an Exec in id, cancels it once the guest runs, and
// returns when Exec has returned.
func (k *staleKillRig) cancelExec(id string) {
	k.t.Helper()
	mark := filepath.Join(k.dir, "mark-"+cid(id))
	os.Remove(mark)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	execDone := make(chan error, 1)
	go func() {
		_, err := k.r.Exec(ctx, id, vm.Command{Argv: []string{"guest"}})
		execDone <- err
	}()
	k.waitFor("guest start", func() bool { _, err := os.Stat(mark); return err == nil })
	cancel()
	if err := <-execDone; err == nil {
		k.t.Fatal("a cancelled exec read as a result")
	}
}

func (k *staleKillRig) kill(ctx context.Context, id string) <-chan error {
	done := make(chan error, 1)
	go func() { done <- k.r.Kill(ctx, vm.Launch{ID: id, Root: filepath.Join(k.dir, "root")}) }()
	return done
}

// killed waits for a Kill's result. A non-root test cannot unmount, so a
// permission error is not a failure here; only the order of verbs is.
func (k *staleKillRig) killed(done <-chan error, within time.Duration) error {
	k.t.Helper()
	select {
	case err := <-done:
		if errors.Is(err, os.ErrPermission) {
			return nil
		}
		return err
	case <-time.After(within):
		k.t.Fatalf("Kill did not return within %s; verbs %q", within, k.verbs())
		return nil
	}
}

// logBuf is log's output while a test runs.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func captureLog(t *testing.T) *logBuf {
	lb := &logBuf{}
	old := log.Writer()
	log.SetOutput(lb)
	t.Cleanup(func() { log.SetOutput(old) })
	return lb
}

// GVISOR-stale-kill (#1443): a cancelled Exec's in-sandbox kill runs off
// Exec's path. Kill must wait for it, or a Rollback or Rebuild that
// restarts the machine under the same container ID can have the late
// `runsc kill --pid` land in the new sandbox. A wait past a second is
// logged with its length (GVISOR-killwait-log).
func TestKillWaitsForPendingExecKill(t *testing.T) {
	k := newStaleKillRig(t)
	logs := captureLog(t)
	k.cancelExec("wk-1")
	k.waitFor("pending kill", func() bool { return strings.Contains(k.verbs(), "kill-pid-start") })

	killed := k.kill(context.Background(), "wk-1")
	select {
	case err := <-killed:
		t.Fatalf("Kill returned (%v) while the cancelled exec's kill still ran; verbs %q", err, k.verbs())
	case <-time.After(1200 * time.Millisecond):
	}
	if v := k.verbs(); strings.Contains(v, "kill wk-1_") || strings.Contains(v, "delete") {
		t.Fatalf("Kill went ahead of the pending kill: %q", v)
	}
	k.open("wk-1")
	if err := k.killed(killed, 15*time.Second); err != nil {
		t.Logf("Kill: %v", err)
	}
	if v, want := k.verbs(), "kill-pid-start wk-1_\nkill-pid-done wk-1_\nkill wk-1_\ndelete wk-1_\n"; v != want {
		t.Fatalf("verbs %q, want %q", v, want)
	}
	if l := logs.String(); !strings.Contains(l, "gvisor: wk-1: waited 1.") || !strings.Contains(l, "for a cancelled command's kill") {
		t.Fatalf("a wait over a second was not logged with its length: %q", l)
	}

	// The wait is per incarnation: a second Kill, with nothing pending,
	// does not block.
	k.killed(k.kill(context.Background(), "wk-1"), 5*time.Second)
}

// GVISOR-killwait-ctx: when Kill's context ends before a cancelled
// command's kill does, Kill fails without killing or deleting the sandbox,
// so the machine is not known dead and nothing restarts it. The kill stays
// pending, so the next Kill waits on it again.
func TestKillFailsClosedWhenItsContextEndsFirst(t *testing.T) {
	k := newStaleKillRig(t)
	k.cancelExec("wk-1")
	k.waitFor("pending kill", func() bool { return strings.Contains(k.verbs(), "kill-pid-start") })

	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		err := k.killed(k.kill(ctx, "wk-1"), 3*time.Second)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "a cancelled command's kill still runs") {
			t.Fatalf("Kill with its context ended before the pending kill: %v, want the pending kill named", err)
		}
		if v := k.verbs(); v != "kill-pid-start wk-1_\n" {
			t.Fatalf("Kill touched the sandbox while a cancelled command's kill ran: %q", v)
		}
	}
	k.open("wk-1")
	k.killed(k.kill(context.Background(), "wk-1"), 15*time.Second)
	if v, want := k.verbs(), "kill-pid-start wk-1_\nkill-pid-done wk-1_\nkill wk-1_\ndelete wk-1_\n"; v != want {
		t.Fatalf("verbs %q, want %q", v, want)
	}
}

// GVISOR-stale-kill-tests (M5): the wait is per machine ID. Kill of one
// machine does not wait on another machine's pending kill.
func TestKillWaitsOnlyForItsOwnMachinesKills(t *testing.T) {
	k := newStaleKillRig(t)
	k.cancelExec("wk-1")
	k.waitFor("pending kill", func() bool { return strings.Contains(k.verbs(), "kill-pid-start") })
	k.killed(k.kill(context.Background(), "wk-2"), 3*time.Second)
	if v, want := k.verbs(), "kill-pid-start wk-1_\nkill wk-2_\ndelete wk-2_\n"; v != want {
		t.Fatalf("verbs %q, want %q", v, want)
	}
}

// GVISOR-stale-kill-tests (M4): the kill is registered before it is
// handed off, inside Exec's cancel, so it is pending when Exec returns
// even if its goroutine has not run at all. goKill holds it back here.
func TestPendingKillRegisteredBeforeExecReturns(t *testing.T) {
	held := make(chan func(), 1)
	old := goKill
	goKill = func(f func()) { held <- f }
	t.Cleanup(func() { goKill = old })
	k := newStaleKillRig(t)
	k.open("wk-1")
	k.cancelExec("wk-1")

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	err := k.killed(k.kill(ctx, "wk-1"), 3*time.Second)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Kill before the cancelled command's kill started: %v, want DeadlineExceeded", err)
	}
	if v := k.verbs(); v != "" {
		t.Fatalf("verbs %q before the held kill ran", v)
	}
	go (<-held)()
	k.killed(k.kill(context.Background(), "wk-1"), 15*time.Second)
	if v, want := k.verbs(), "kill-pid-start wk-1_\nkill-pid-done wk-1_\nkill wk-1_\ndelete wk-1_\n"; v != want {
		t.Fatalf("verbs %q, want %q", v, want)
	}
}

// GVISOR-stale-kill-tests (M3): a group leaves the map when its last kill
// ends, so a later Exec's kill starts a fresh group and never joins (or
// closes again) one a Kill waited on. Run under -race in CI.
func TestPendingKillGroupIsNotReused(t *testing.T) {
	k := newStaleKillRig(t)
	k.open("wk-1")
	for i := range 10 {
		os.Remove(filepath.Join(k.dir, "verbs"))
		k.cancelExec("wk-1")
		k.killed(k.kill(context.Background(), "wk-1"), 15*time.Second)
		if v, want := k.verbs(), "kill-pid-start wk-1_\nkill-pid-done wk-1_\nkill wk-1_\ndelete wk-1_\n"; v != want {
			t.Fatalf("round %d: verbs %q, want %q", i, v, want)
		}
	}
	k.r.pendingMu.Lock()
	n := len(k.r.pending)
	k.r.pendingMu.Unlock()
	if n != 0 {
		t.Fatalf("%d groups left in the map with no kill pending", n)
	}
}

// GVISOR-stale-kill-tests (M8) and GVISOR-killwait-log: killExec is
// bounded by its timeout plus its stderr wait, even when the runsc it
// started leaves a child holding stderr, and the timeout is logged as one.
func TestKillExecIsBoundedByItsTimeout(t *testing.T) {
	// V37 names these bounds; a change to them is a change to V37.
	if killExecTimeout != 5*time.Second || killExecWaitDelay != time.Second {
		t.Fatalf("killExec's bounds are %s and %s, V37 says 5s and 1s", killExecTimeout, killExecWaitDelay)
	}
	oldT, oldW := killExecTimeout, killExecWaitDelay
	killExecTimeout, killExecWaitDelay = 200*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { killExecTimeout, killExecWaitDelay = oldT, oldW })
	k := newStaleKillRig(t)
	logs := captureLog(t)
	k.touch("hang-" + cid("wk-1"))
	k.cancelExec("wk-1")
	k.waitFor("pending kill", func() bool { return strings.Contains(k.verbs(), "kill-pid-start") })
	k.killed(k.kill(context.Background(), "wk-1"), 4*time.Second)
	if v, want := k.verbs(), "kill-pid-start wk-1_\nkill wk-1_\ndelete wk-1_\n"; v != want {
		t.Fatalf("verbs %q, want %q", v, want)
	}
	if l := logs.String(); !strings.Contains(l, "gvisor: wk-1: killing cancelled command 7: runsc kill timed out after 200ms") {
		t.Fatalf("the kill's timeout was not named: %q", l)
	}
}
