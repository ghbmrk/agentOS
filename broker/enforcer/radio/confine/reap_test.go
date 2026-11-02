package confine

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// REQ: NET-2

// leakArg makes this test binary a stack that passes its stderr out of its
// PID namespace, over its interface (fd 3), and then waits to be killed.
const leakArg = "confine-leak-stderr"

func leakStderr() int {
	if err := syscall.Sendmsg(3, []byte{1}, syscall.UnixRights(2), nil, 0); err != nil {
		return 3
	}
	time.Sleep(time.Hour)
	return 0
}

// TestStopReapsDespiteLeakedStderr (ENF-k-11, NET-2 Confined radio stacks;
// #4521): a stack whose Stderr is a writer, not a file, passes its end of
// the stderr pipe to a process outside its PID namespace (here the test,
// over fd 3) and stays alive. Stop still returns, with the stack's exit,
// killed, and the stack reaped, within stderrDrain and some slack, while
// the outside process still holds the pipe. Catches a Start without
// WaitDelay, whose Wait waits for the stderr copy forever, so the reap and
// its replacement's Attach never finish.
func TestStopReapsDespiteLeakedStderr(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a confined stack as another user")
	}
	dir, bin := viewDir(t)
	p := BLE(viewUID, viewUID)
	p.View = []Entry{{Path: filepath.Join(dir, vBus), Kind: Socket}}
	proc, conn, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{leakArg}, Stderr: testWriter{t}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pid := proc.Pid()

	sc, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var held []int
	var rerr error
	oob := make([]byte, syscall.CmsgSpace(4))
	if err := sc.Read(func(fd uintptr) bool {
		var n, oobn int
		n, oobn, _, _, rerr = syscall.Recvmsg(int(fd), make([]byte, 1), oob, 0)
		if rerr == syscall.EAGAIN {
			return false
		}
		if rerr == nil && n == 1 {
			var msgs []syscall.SocketControlMessage
			if msgs, rerr = syscall.ParseSocketControlMessage(oob[:oobn]); rerr == nil && len(msgs) == 1 {
				held, rerr = syscall.ParseUnixRights(&msgs[0])
			}
		}
		return true
	}); err != nil || rerr != nil || len(held) != 1 {
		proc.Stop()
		t.Fatalf("the stack's stderr never came out: %v, %v, %v", err, rerr, held)
	}
	defer syscall.Close(held[0]) // held until after Stop: the pipe stays open outside

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- proc.Stop() }()
	select {
	case err := <-done:
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Errorf("Stop returned %v, want the stack's exit", err)
		} else if ws, ok := exit.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
			t.Errorf("Stop returned %v, want killed", err)
		}
		if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
			t.Errorf("after Stop: kill 0 = %v, want ESRCH (reaped)", err)
		}
		if d := time.Since(start); d > stderrDrain+5*time.Second {
			t.Errorf("Stop took %v, want at most stderrDrain (%v) and slack", d, stderrDrain)
		}
	case <-time.After(stderrDrain + 20*time.Second):
		t.Fatal("Stop never returned while another process held the stack's stderr: the reap waits for the copy")
	}
}
