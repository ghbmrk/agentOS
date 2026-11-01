package radio

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/radio/confine"
)

// REQ: NET-6, NET-2

// exited is the process of a stack served inside the test's own process:
// there is nothing to kill.
type exited struct{}

func (exited) Stop() error { return nil }

// device is the radio as the stand-in stacks act on it: it keeps what
// reached it, and drops what a stack whose process is gone would send.
type device struct {
	mu   sync.Mutex
	acts []string
}

func (d *device) act(from *standIn, what string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if from.dead {
		return
	}
	d.acts = append(d.acts, what)
}

// standIn is a stack's process that stays alive after its link ends: Stop
// is the launcher's kill, and returns once the test lets the reap finish.
type standIn struct {
	dev     *device
	stopped chan struct{} // closed at the first Stop
	reap    chan struct{} // closed by the test: the process can exit
	once    sync.Once
	dead    bool // under dev.mu
}

func newStandIn(dev *device) *standIn {
	return &standIn{dev: dev, stopped: make(chan struct{}), reap: make(chan struct{})}
}

func (p *standIn) Stop() error {
	p.once.Do(func() { close(p.stopped) })
	<-p.reap
	p.dev.mu.Lock()
	p.dead = true
	p.dev.mu.Unlock()
	return nil
}

// TestReplacedStackGoneBeforeNewLink (ENF-k-11; NET-6 "the lock relocks
// automatically", NET-2 Confined radio stacks): an unlock that timed out
// sits unread in the old stack's process when its link ends, after a
// fault or because a restart replaces it. The host kills that process,
// and Attach of the replacement does not return, nor does the stack have
// a link, until it has been reaped; so the relock on the new link is the
// last thing the lock hears. Catches an Attach that lets the old process
// act on the radio after the relock (#4311).
func TestReplacedStackGoneBeforeNewLink(t *testing.T) {
	for _, fault := range []bool{true, false} {
		name := map[bool]string{true: "after a fault", false: "while its link is up"}[fault]
		t.Run(name, func(t *testing.T) {
			h, err := NewHost(Config{Devices: []Device{door}, Notify: func(Notification) {}, Log: func(string) {},
				Timeout: 50 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			dev := &device{}
			old := newStandIn(dev)
			apply := make(chan struct{})
			oldDone := make(chan struct{})
			host, stack := net.Pipe()
			t.Cleanup(func() { host.Close(); stack.Close() })
			go func() {
				// The old stack takes the unlock into its process and acts on
				// it late, if it is still alive.
				defer close(oldDone)
				var r Request
				if read(stack, &r) != nil {
					return
				}
				if fault {
					write(stack, Up{ID: r.ID + 100, Device: r.Device, Code: CodeOK})
				}
				<-apply
				dev.act(old, string(r.Data))
			}()
			if err := h.Attach(StackBLE, old, host); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if _, err := h.Send(ctx, Request{Op: OpWrite, Device: "door", Char: "cmd", Data: []byte("unlock")}); err == nil {
				t.Fatal("the unlock was answered")
			}
			if fault {
				select {
				case <-old.stopped:
				case <-time.After(5 * time.Second):
					t.Fatal("the host left a failed link's process running")
				}
			}

			next := newStandIn(dev)
			close(next.reap)
			nhost, nstack := net.Pipe()
			t.Cleanup(func() { nhost.Close(); nstack.Close() })
			go NewServer(StackBLE, nstack).Serve(func(r Request) ([]byte, Code) {
				dev.act(next, string(r.Data))
				return nil, CodeOK
			})
			attached := make(chan error, 1)
			go func() { attached <- h.Attach(StackBLE, next, nhost) }()
			select {
			case <-old.stopped:
			case <-time.After(5 * time.Second):
				t.Fatal("Attach left the replaced process running")
			}
			select {
			case <-attached:
				t.Fatal("Attach returned while the replaced process was alive")
			case <-time.After(100 * time.Millisecond):
			}
			if _, err := h.Call(Request{Op: OpWrite, Device: "door", Char: "cmd", Data: []byte("early")}); !errors.Is(err, ErrNoStack) {
				t.Fatalf("a send while the replaced process was alive: %v, want ErrNoStack", err)
			}
			close(old.reap)
			if err := <-attached; err != nil {
				t.Fatal(err)
			}
			if _, err := h.Call(Request{Op: OpWrite, Device: "door", Char: "cmd", Data: []byte("relock")}); err != nil {
				t.Fatalf("the relock: %v", err)
			}
			close(apply)
			<-oldDone
			dev.mu.Lock()
			defer dev.mu.Unlock()
			if !slices.Equal(dev.acts, []string{"relock"}) {
				t.Fatalf("the lock heard %q, want only the relock", dev.acts)
			}
		})
	}
}

// TestAttachNeedsProcessAndLink (ENF-k-11): a link without the process
// whose end it is cannot be attached, nor a process without a link.
func TestAttachNeedsProcessAndLink(t *testing.T) {
	h, err := NewHost(Config{Devices: []Device{door}, Notify: func(Notification) {}, Log: func(string) {}})
	if err != nil {
		t.Fatal(err)
	}
	host, stack := net.Pipe()
	defer host.Close()
	defer stack.Close()
	if err := h.Attach(StackBLE, nil, host); err == nil {
		t.Error("attached a link with no process")
	}
	if err := h.Attach(StackBLE, exited{}, nil); err == nil {
		t.Error("attached a process with no link")
	}
	if _, err := h.State("door"); !errors.Is(err, ErrNoStack) {
		t.Errorf("after refused attaches: %v, want ErrNoStack", err)
	}
}

// faultArg makes this test binary a stack that starts a child holding its
// stderr, sends the host an answer to nothing, and stays alive.
const faultArg = "radio-probe-fault"

// sleepArg makes this test binary a process that only sleeps: the fault
// stack's child.
const sleepArg = "radio-probe-sleep"

// childStarted is what the fault stack writes once its child runs.
const childStarted = "child started\n"

func faultStack() {
	child := exec.Command("/proc/self/exe", sleepArg)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stderr, os.Stderr
	if err := child.Start(); err != nil {
		os.Exit(2)
	}
	os.Stderr.WriteString(childStarted)
	write(os.NewFile(3, "interface"), Up{ID: 99, Device: "scale", Code: CodeOK})
	time.Sleep(time.Hour)
}

// TestReplacedStackReapedWithItsChildren (ENF-k-11, NET-2 Confined radio
// stacks): a confined stack that faults its link and stays alive, with a
// child of its own holding its stderr, is killed by the host, and Attach
// of its replacement returns only once it is reaped and its child is
// gone too (the stack is its PID namespace's init). Catches a launcher
// that leaves the old process, or a process it started, running beside
// the new link.
func TestReplacedStackReapedWithItsChildren(t *testing.T) {
	if !asRoot(t) {
		return
	}
	dir, err := os.MkdirTemp("", "radio")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	os.Chmod(dir, 0o755)
	bin := filepath.Join(dir, "radio.test")
	copyFile(t, os.Args[0], bin)
	faulted := make(chan struct{})
	var once sync.Once
	h, err := NewHost(Config{Devices: []Device{scale}, Timeout: 20 * time.Second,
		Notify: func(Notification) {}, Log: func(s string) {
			if strings.HasSuffix(s, "answer to no outstanding request") {
				once.Do(func() { close(faulted) })
			}
		}})
	if err != nil {
		t.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	old, conn, err := confine.Start(confine.Spec{Profile: bleProbe(4242), Self: bin, Path: bin,
		Args: []string{faultArg}, Stderr: w})
	w.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer old.Stop()
	pid := old.Pid()
	if err := h.Attach(StackBLE, old, conn); err != nil {
		t.Fatal(err)
	}
	r.SetReadDeadline(time.Now().Add(20 * time.Second))
	line := make([]byte, len(childStarted))
	if _, err := io.ReadFull(r, line); err != nil || string(line) != childStarted {
		t.Fatalf("the fault stack's child: %q, %v", line, err)
	}
	select {
	case <-faulted:
	case <-time.After(20 * time.Second):
		t.Fatal("the fault stack's answer to nothing did not end its link")
	}

	next, nconn, err := confine.Start(confine.Spec{Profile: bleProbe(4242), Self: bin, Path: bin,
		Args: []string{probeArg, filepath.Join(dir, "none"), filepath.Join(dir, "none.sock")}, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	defer next.Stop()
	if err := h.Attach(StackBLE, next, nconn); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Errorf("the replaced stack after Attach: kill 0 = %v, want ESRCH (reaped)", err)
	}
	r.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.Copy(io.Discard, r); err != nil {
		t.Errorf("the replaced stack's child still holds its stderr after Attach: %v", err)
	}
	if _, err := h.State(scale.Name); err != nil {
		t.Errorf("the replacement: %v", err)
	}
}
