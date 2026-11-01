package radio

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/radio/confine"
)

// REQ: NET-2

// probeArg makes this test binary the probe stack: it serves the BLE
// interface on fd 3 and, asked to read, reports what it could reach.
const probeArg = "radio-probe-stack"

// idleArg makes this test binary a process that waits for its stdin to
// close: the probe's ptrace target.
const idleArg = "radio-probe-idle"

const nestedEnv = "AGENTOS_RADIO_USERNS"

// leakedFD is a descriptor the enforcer holds without close-on-exec when
// it starts the stack; the stack must not have it.
const leakedFD = 100

func TestMain(m *testing.M) {
	confine.Trampoline()
	if len(os.Args) == 4 && os.Args[1] == probeArg {
		probeStack(os.Args[2], os.Args[3])
		return
	}
	if len(os.Args) == 5 && os.Args[1] == netProbeArg {
		probeNet(os.Args[2], os.Args[3], os.Args[4])
		return
	}
	if len(os.Args) == 2 && os.Args[1] == idleArg {
		io.Copy(io.Discard, os.Stdin)
		return
	}
	os.Exit(m.Run())
}

// probeStack is a stack that tries what an exploited radio process would:
// the rules, the page, the network, a new namespace, root.
func probeStack(policy, page string) {
	// The answer is bounded by MaxData, so it carries a verdict per check;
	// the reasons go to stderr, which the test logs.
	try := func(err error) string {
		if err != nil {
			fmt.Fprintf(os.Stderr, "refused: %v\n", err)
			return "refused"
		}
		return "allowed"
	}
	sock := func(family int) error {
		fd, err := syscall.Socket(family, syscall.SOCK_DGRAM, 0)
		if err == nil {
			syscall.Close(fd)
		}
		return err
	}
	out := map[string]string{}
	_, err := os.ReadFile(policy)
	out["read the policy"] = try(err)
	out["write the policy store"] = try(os.WriteFile(filepath.Join(filepath.Dir(policy), "next.json"), []byte("{}"), 0o600))
	c, err := net.DialTimeout("unix", page, time.Second)
	if err == nil {
		c.Close()
	}
	out["dial the page"] = try(err)
	out["AF_INET socket"] = try(sock(syscall.AF_INET))
	out["AF_INET6 socket"] = try(sock(syscall.AF_INET6))
	out["AF_NETLINK socket"] = try(sock(syscall.AF_NETLINK))
	out["AF_PACKET socket"] = try(sock(syscall.AF_PACKET))
	out["AF_BLUETOOTH socket"] = try(sock(31))
	out["unshare a user namespace"] = try(syscall.Unshare(syscall.CLONE_NEWUSER))
	out["setuid 0"] = try(syscall.Setuid(0))
	out["ptrace"] = ptraceChild(try)
	out["AF_UNIX socket (the system bus)"] = try(sock(syscall.AF_UNIX))
	var st syscall.Stat_t
	out["inherited fd 100"] = try(syscall.Fstat(leakedFD, &st))
	b, _ := os.ReadFile("/proc/net/dev")
	var ifs []string
	for _, l := range strings.Split(string(b), "\n")[2:] {
		if i := strings.Index(l, ":"); i > 0 {
			ifs = append(ifs, strings.TrimSpace(l[:i]))
		}
	}
	out["interfaces"] = strings.Join(ifs, " ")
	report, _ := json.Marshal(out)
	NewServer(StackBLE, os.NewFile(3, "interface")).Serve(func(r Request) ([]byte, Code) {
		return report, CodeOK
	})
}

// ptraceChild seizes a child the probe started, so the probe never touches
// a process it did not start: attaching to pid 1 stopped the runner's init
// (#4091). PTRACE_SEIZE runs PTRACE_ATTACH's permission checks without
// stopping the tracee.
//
// A refused seize alone does not show the filter: the kernel also answers
// EPERM under Yama's ptrace_scope 2, and ESRCH for a child that has gone
// (#4116). So the probe first sends a malformed seize, with a nonzero addr,
// which the kernel answers EIO before it checks any permission or the
// target's state (ptrace_attach), or ESRCH when no such pid exists. Only a
// filter in front of the call turns it into EPERM, so a confined "refused" needs both seizes to read EPERM,
// and the unconfined control needs the seize to succeed and the malformed
// one to read EIO. Anything else is no verdict. It takes the probes' try
// for their shared call, but no single error is a verdict here.
func ptraceChild(func(error) string) string {
	cmd := exec.Command("/proc/self/exe", idleArg)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard // pipes: a view has no /dev/null
	stdin, err := cmd.StdinPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		return fmt.Sprintf("untested: no target: %v", err)
	}
	defer func() {
		cmd.Process.Kill()
		stdin.Close()
		cmd.Wait()
	}()
	seize := func(addr uintptr) syscall.Errno {
		_, _, e := syscall.RawSyscall(syscall.SYS_PTRACE, 0x4206 /* PTRACE_SEIZE */, uintptr(cmd.Process.Pid), addr)
		return e
	}
	malformed := seize(1)
	e := seize(0)
	fmt.Fprintf(os.Stderr, "ptrace: malformed seize: %d (%v), seize: %d (%v)\n", malformed, malformed, e, e)
	switch {
	case malformed == syscall.EPERM && e == syscall.EPERM:
		return "refused"
	case malformed == syscall.EIO && e == 0:
		return "allowed"
	}
	return fmt.Sprintf("untested: malformed seize %d, seize %d", malformed, e)
}

// loader is what this test binary needs to run in a view: it links cgo
// (net), so it is dynamic, while the enforcer's binary is static
// (image/build.sh). A path the host lacks is left out of the view.
var loader = []string{"/lib", "/lib64", "/usr/lib", "/usr/lib64"}

// bleProbe is the BLE profile with its view widened by the loader, and by
// /proc, which probeStack reads for its interfaces and execs itself from
// for its ptrace target. The policy and the page stay outside the view.
func bleProbe(uid uint32) confine.Profile {
	p := confine.BLE(uid, uid)
	p.View = slices.Concat(p.View, loader, []string{"/proc"})
	return p
}

// asRoot runs the calling test as root: directly when it is, otherwise
// again as root of a user namespace that maps the runner's subordinate ids
// (CI's "Subordinate ids" step), so the stack can drop to another user.
// It reports whether this process should run the test.
func asRoot(t *testing.T) bool {
	t.Helper()
	if os.Geteuid() == 0 {
		return true
	}
	required := os.Getenv("CI") != "" || os.Getenv("AGENTOS_REQUIRE_NETNS") == "1"
	if _, err := exec.LookPath("newuidmap"); err != nil {
		if required {
			t.Fatalf("newuidmap missing: %v", err)
		}
		t.Skip("needs root or subordinate ids (newuidmap)")
	}
	cmd := exec.Command("unshare", "--map-root-user", "--map-auto", "--",
		os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), nestedEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("as root of a user namespace:\n%s", out)
	if err != nil {
		t.Fatalf("user namespace run failed: %v", err)
	}
	return false
}

// TestRadioCannotChangeRule (NET-2 Confined radio stacks): a radio stack
// started by the host, running as its own user, cannot open the policy
// store or the page's socket, nor reach a network, a raw radio socket, a
// new namespace or root; it can still answer on its command interface. The
// same probe run unconfined reaches the policy and the page, so the test
// can see a missing confinement. Catches a radio exploit reaching the
// rules.
func TestRadioCannotChangeRule(t *testing.T) {
	if !asRoot(t) {
		return
	}
	// The enforcer's state: the policy store and the page's socket, each
	// in a directory only the enforcer's user opens.
	state, err := os.MkdirTemp("", "radio")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(state)
	policy := filepath.Join(state, "policy", "policy.json")
	page := filepath.Join(state, "page", "page.sock")
	for _, d := range []string{filepath.Dir(policy), filepath.Dir(page)} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(policy, []byte(`{"canary":"synthetic"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", page)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if err := os.Chmod(state, 0o755); err != nil {
		t.Fatal(err)
	}
	// The binary the stack's user runs, where it can run it.
	bin := filepath.Join(state, "radio.test")
	copyFile(t, os.Args[0], bin)

	read := func(t *testing.T, conn Conn) map[string]string {
		// The host's read loop outlives the subtest (its link ends when the
		// deferred Stop runs), so its log goes to a sink, not to t.
		h, err := NewHost(Config{Devices: []Device{scale}, Timeout: 20 * time.Second,
			Notify: func(Notification) {}, Log: func(string) {}})
		if err != nil {
			t.Fatal(err)
		}
		h.Attach(StackBLE, conn)
		b, err := h.State(scale.Name)
		if err != nil {
			t.Fatalf("read through the interface: %v", err)
		}
		got := map[string]string{}
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	confinedProbe := func(t *testing.T, p confine.Profile) {
		f, err := syscall.Open(policy, syscall.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Dup2(f, leakedFD); err != nil {
			t.Fatal(err)
		}
		syscall.Close(f)
		defer syscall.Close(leakedFD)
		proc, conn, err := confine.Start(confine.Spec{Profile: p, Self: bin, Path: bin,
			Args: []string{probeArg, policy, page}, Stderr: testWriter{t}})
		if err != nil {
			t.Fatal(err)
		}
		defer proc.Stop()
		got := read(t, conn)
		for k, v := range got {
			t.Logf("%-32s %s", k, v)
		}
		for _, k := range []string{"read the policy", "write the policy store", "dial the page",
			"AF_INET socket", "AF_INET6 socket", "AF_NETLINK socket", "AF_PACKET socket",
			"AF_BLUETOOTH socket", "unshare a user namespace", "setuid 0", "ptrace", "inherited fd 100"} {
			if !strings.HasPrefix(got[k], "refused") {
				t.Errorf("confined stack: %s %s", k, got[k])
			}
		}
		if got["AF_UNIX socket (the system bus)"] != "allowed" {
			t.Errorf("the stack cannot open its bus socket: %s", got["AF_UNIX socket (the system bus)"])
		}
		if got["interfaces"] != "lo" {
			t.Errorf("the stack sees interfaces %q, want lo only", got["interfaces"])
		}
	}
	// The view alone hides the policy and the page (ENOENT), so the
	// stack's user is checked as a barrier of its own, without a view,
	// as the stacks that have none (#4369) rely on it.
	userOnly := confine.BLE(4242, 4242)
	userOnly.View = nil
	for _, c := range []struct {
		name string
		p    confine.Profile
	}{{"confined", bleProbe(4242)}, {"confined by its user alone", userOnly}} {
		t.Run(c.name, func(t *testing.T) { confinedProbe(t, c.p) })
	}

	t.Run("unconfined control", func(t *testing.T) {
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		syscall.SetNonblock(fds[0], true)
		ours, theirs := os.NewFile(uintptr(fds[0]), "ours"), os.NewFile(uintptr(fds[1]), "theirs")
		cmd := exec.Command(bin, probeArg, policy, page)
		cmd.ExtraFiles = []*os.File{theirs}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		theirs.Close()
		defer func() { cmd.Process.Kill(); cmd.Wait() }()
		got := read(t, ours)
		for _, k := range []string{"read the policy", "dial the page", "AF_INET socket", "ptrace"} {
			if got[k] != "allowed" {
				t.Errorf("unconfined probe: %s %s; the probe cannot see a missing confinement", k, got[k])
			}
		}
	})

	t.Run("no socket families", func(t *testing.T) {
		p := bleProbe(4242)
		p.Families = nil
		proc, conn, err := confine.Start(confine.Spec{Profile: p, Self: bin, Path: bin,
			Args: []string{probeArg, policy, page}, Stderr: testWriter{t}})
		if err != nil {
			t.Fatal(err)
		}
		defer proc.Stop()
		if got := read(t, conn); got["AF_UNIX socket (the system bus)"] != "refused" {
			t.Errorf("a profile with no families opened a socket: %v", got)
		}
	})

	t.Run("never root", func(t *testing.T) {
		for _, p := range []confine.Profile{confine.BLE(0, 4242), confine.BLE(4242, 0)} {
			if _, _, err := confine.Start(confine.Spec{Profile: p, Self: bin, Path: bin}); err != confine.ErrRoot {
				t.Errorf("%+v: %v", p, err)
			}
		}
	})
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(b []byte) (int, error) {
	w.t.Logf("stack: %s", b)
	return len(b), nil
}
