package confine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// REQ: NET-2

// leakArg makes this test binary a stack that passes its stderr out of its
// PID namespace, over its interface (fd 3), and then waits to be killed,
// or with "exit" after it, exits 0.
const leakArg = "confine-leak-stderr"

func leakStderr(exit bool) int {
	if err := syscall.Sendmsg(3, []byte{1}, syscall.UnixRights(2), nil, 0); err != nil {
		return 3
	}
	if !exit {
		time.Sleep(time.Hour)
	}
	return 0
}

// sleepArg makes this test binary a stack that only sleeps.
const sleepArg = "confine-sleep"

// initArg makes this test binary a stack that leaves a signal to the
// kernel's default action: "term" sends itself SIGTERM, writes one byte
// on fd 3, then echoes each byte it reads there (the test's own signals
// come in between); "fault" faults (SIGSEGV).
const initArg = "confine-init-signal"

func initSignal(mode string) int {
	sig := syscall.SIGTERM
	if mode == "fault" {
		sig = syscall.SIGSEGV
	}
	// struct sigaction as the kernel takes it: handler SIG_DFL, no flags.
	var sa [4]uint64
	if _, _, e := syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, uintptr(sig), uintptr(unsafe.Pointer(&sa)), 0, 8, 0, 0); e != 0 {
		return 3
	}
	if mode == "fault" {
		var p *byte
		*nilOf(&p) = 1 // the kernel's SIGSEGV, at its default action
		return 4
	}
	syscall.Kill(os.Getpid(), syscall.SIGTERM)
	time.Sleep(100 * time.Millisecond)
	if _, err := syscall.Write(3, []byte{1}); err != nil {
		return 5
	}
	for b := make([]byte, 1); ; {
		if n, _ := syscall.Read(3, b); n != 1 {
			return 6
		}
		if _, err := syscall.Write(3, b); err != nil {
			return 7
		}
	}
}

// nilOf returns *p, a nil pointer the compiler cannot see is nil.
//
//go:noinline
func nilOf(p **byte) *byte { return *p }

// receiveStderr takes the stderr descriptor a leakArg stack sent on conn.
func receiveStderr(t *testing.T, proc *Proc, conn *os.File) int {
	t.Helper()
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
	return held[0]
}

// signaled checks err is the stack's exit, by sig.
func signaled(t *testing.T, who string, err error, sig syscall.Signal) {
	t.Helper()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Errorf("%s returned %v, want the stack's exit", who, err)
	} else if ws, ok := exit.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != sig {
		t.Errorf("%s returned %v, want ended by %v", who, err, sig)
	}
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
	held := receiveStderr(t, proc, conn)
	defer syscall.Close(held) // held until after Stop: the pipe stays open outside

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- proc.Stop() }()
	select {
	case err := <-done:
		signaled(t, "Stop", err, syscall.SIGKILL)
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

// TestCleanExitDespiteLeakedStderr (ENF-k-11, NET-2 Confined radio stacks;
// #4521 item 6): a stack passes its end of the stderr pipe out of its PID
// namespace, as in TestStopReapsDespiteLeakedStderr, and then exits 0
// while the outside process still holds the pipe. Wait closes the pipe
// after stderrDrain and returns nil, the stack's clean exit, with the
// stack reaped. Catches a Wait that returns exec.ErrWaitDelay there, which
// a launcher would read as a failed exit.
func TestCleanExitDespiteLeakedStderr(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a confined stack as another user")
	}
	dir, bin := viewDir(t)
	p := BLE(viewUID, viewUID)
	p.View = []Entry{{Path: filepath.Join(dir, vBus), Kind: Socket}}
	proc, conn, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{leakArg, "exit"}, Stderr: testWriter{t}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pid := proc.Pid()
	held := receiveStderr(t, proc, conn)
	defer syscall.Close(held) // held until after Wait: the pipe stays open outside

	done := make(chan error, 1)
	go func() { done <- proc.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Wait returned %v for a stack that exited 0, want nil", err)
		}
		if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
			t.Errorf("after Wait: kill 0 = %v, want ESRCH (reaped)", err)
		}
		if err := proc.Stop(); err != nil {
			t.Errorf("Stop after the clean exit returned %v, want nil", err)
		}
	case <-time.After(stderrDrain + 20*time.Second):
		proc.Stop()
		t.Fatal("Wait never returned while another process held the stack's stderr")
	}
}

// TestStackIsInitOfItsNamespace (ENF-k-12, NET-2 Confined radio stacks;
// #4521 item 4): each stack is the init of its own PID namespace, so a
// signal at the kernel's default action is dropped, whoever sends it: a
// stack that sends itself SIGTERM still answers, and still answers after
// the enforcer sends it SIGTERM from outside. Its crash is not dropped: a
// fault at the default action still ends it, by SIGSEGV, and the
// enforcer's SIGKILL (Stop) ends the other. SIGSTOP from outside is not
// dropped: the stack stops (state T) and answers nothing, until SIGCONT
// resumes it and it answers again (#4638). This pins
// the limit ENF-k-12 names; a launcher that stops making the stack init
// (or adds an init of its own in front of it) fails here until that row
// is rewritten.
func TestStackIsInitOfItsNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a confined stack as another user")
	}
	dir, bin := viewDir(t)
	p := BLE(viewUID, viewUID)
	p.View = []Entry{{Path: filepath.Join(dir, vBus), Kind: Socket}}

	term, conn, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{initArg, "term"}, Stderr: testWriter{t}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Errorf("the stack did not answer after its own SIGTERM: %v (%v)", err, term.Stop())
	} else {
		if err := syscall.Kill(term.Pid(), syscall.SIGTERM); err != nil {
			t.Fatalf("the enforcer's SIGTERM: %v (%v)", err, term.Stop())
		}
		time.Sleep(100 * time.Millisecond)
		conn.Write([]byte{1})
		if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
			t.Errorf("the stack did not answer after the enforcer's SIGTERM: %v (%v)", err, term.Stop())
		} else if stopAndContinue(t, term, conn) {
			signaled(t, "Stop", term.Stop(), syscall.SIGKILL)
		}
	}

	fault, fconn, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{initArg, "fault"}, Stderr: testWriter{t}})
	if err != nil {
		t.Fatal(err)
	}
	defer fconn.Close()
	done := make(chan error, 1)
	go func() { done <- fault.Wait() }()
	select {
	case err := <-done:
		signaled(t, "Wait", err, syscall.SIGSEGV)
	case <-time.After(20 * time.Second):
		fault.Stop()
		t.Fatal("a stack that faulted at the default action was not ended: init kept it alive")
	}
}

// stopAndContinue sends a stack that echoes on conn SIGSTOP from outside
// and checks it stops and answers nothing, then SIGCONT and checks it
// answers again (ENF-k-12, #4638). It reports whether the stack still
// runs; otherwise it has stopped it.
func stopAndContinue(t *testing.T, p *Proc, conn *os.File) bool {
	t.Helper()
	if err := syscall.Kill(p.Pid(), syscall.SIGSTOP); err != nil {
		t.Errorf("the enforcer's SIGSTOP: %v (%v)", err, p.Stop())
		return false
	}
	state := ""
	for end := time.Now().Add(10 * time.Second); state != "T" && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		state = procState(p.Pid())
	}
	if state != "T" {
		t.Errorf("after the enforcer's SIGSTOP the stack is in state %q, want T (stopped): init dropped it (%v)", state, p.Stop())
		return false
	}
	conn.Write([]byte{2})
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, err := conn.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("a stopped stack answered: %d bytes, %v (%v)", n, err, p.Stop())
		return false
	}
	if err := syscall.Kill(p.Pid(), syscall.SIGCONT); err != nil {
		t.Errorf("the enforcer's SIGCONT: %v (%v)", err, p.Stop())
		return false
	}
	conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	b := make([]byte, 1)
	if _, err := io.ReadFull(conn, b); err != nil || b[0] != 2 {
		t.Errorf("the stack did not answer after SIGCONT: %v, %v (%v)", b, err, p.Stop())
		return false
	}
	return true
}

// procState is the state letter /proc/pid/stat shows, or "" if it reads none.
func procState(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	i := bytes.LastIndexByte(b, ')')
	if err != nil || i < 0 || len(b) < i+3 {
		return ""
	}
	return string(b[i+2])
}

// TestNetRefIsCloseOnExec (NET-2 Confined radio stacks; #4616 item 2):
// the descriptor netRef hands Start for a join is close-on-exec from the
// start, so a fork elsewhere in the enforcer meanwhile never inherits the
// other stack's namespace. Catches F_DUPFD in place of F_DUPFD_CLOEXEC,
// which no other test sees, since Trampoline's close_range marks every
// descriptor before the stack runs.
func TestNetRefIsCloseOnExec(t *testing.T) {
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	p := &Proc{net: ns}
	defer ns.Close()
	f, err := netRef(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	flags, _, e := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFD, 0)
	if e != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Errorf("netRef's descriptor: flags %#x (%v), want FD_CLOEXEC", flags, e)
	}
	if f.Fd() == ns.Fd() {
		t.Error("netRef returned the stack's own descriptor, which Stop closes")
	}
}

// TestJoinHoldsItsOwnNamespace (ENF-t-2, NET-2 Confined radio stacks;
// #4521 item 5): a stack joining another's network namespace (Matter
// into Thread's, Spec.Net) starts there even when that other stack is
// stopped mid-start, after Start took its reference and before the fork,
// as a link fault does: the joiner is in the namespace the other had, not
// one reached through a closed or reused descriptor. Once the other has
// been stopped, a join is refused (ErrNoNet). Catches a Start that uses the
// other stack's own descriptor, which Stop closes under it.
func TestJoinHoldsItsOwnNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a confined stack as another user")
	}
	dir, bin := viewDir(t)
	p := BLE(viewUID, viewUID)
	p.View = []Entry{{Path: filepath.Join(dir, vBus), Kind: Socket}}
	host, hconn, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{sleepArg}, Stderr: testWriter{t}})
	if err != nil {
		t.Fatal(err)
	}
	defer hconn.Close()
	defer host.Stop()
	want, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", host.Pid()))
	if err != nil {
		t.Fatal(err)
	}

	real := netRef
	t.Cleanup(func() { netRef = real })
	netRef = func(q *Proc) (*os.File, error) {
		f, err := real(q)
		if q == host {
			// Opens a descriptor first, so a closed one's number is reused.
			host.Stop()
			if g, err := os.Open("/proc/self/ns/net"); err == nil {
				t.Cleanup(func() { g.Close() })
			}
		}
		return f, err
	}
	joined, jconn, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{sleepArg}, Stderr: testWriter{t}, Net: host})
	if err != nil {
		t.Fatalf("a join whose host stopped after Start took its namespace failed: %v", err)
	}
	defer jconn.Close()
	defer joined.Stop()
	if got, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", joined.Pid())); err != nil || got != want {
		t.Errorf("the joined stack is in %q (%v), want its host's %q", got, err, want)
	}

	netRef = real
	if _, _, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{sleepArg}, Stderr: testWriter{t}, Net: host}); !errors.Is(err, ErrNoNet) {
		t.Errorf("a join to a stopped stack: %v, want ErrNoNet", err)
	}
}
