package radio

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/ghbmrk/agentos/broker/enforcer/radio/confine"
)

// REQ: NET-2

// netProbeArg makes this test binary a probe in the Thread or Matter
// profile: it tries what an exploited ot-daemon or Matter controller
// would, and serves its findings on fd 3.
const netProbeArg = "radio-probe-net"

// The probes' own users: Thread's, and the Matter controller's.
const (
	threadUID = 4243
	matterUID = 4244
)

// probeNet is a stack in the Thread profile (it creates wpan0 as ot-daemon
// does, and holds it while it serves) or in the Matter profile, joined to
// the Thread probe's network namespace.
func probeNet(kind, policy, page string) {
	try := func(err error) string {
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s refused: %v\n", kind, err)
			return "refused"
		}
		return "allowed"
	}
	sock := func(family, typ, proto int) error {
		fd, err := syscall.Socket(family, typ, proto)
		if err == nil {
			syscall.Close(fd)
		}
		return err
	}
	raw := func(nr uintptr, args ...uintptr) error {
		var a [3]uintptr
		copy(a[:], args)
		r, _, e := syscall.Syscall(nr, a[0], a[1], a[2])
		if e != 0 {
			return e
		}
		syscall.Close(int(r))
		return nil
	}
	out := map[string]string{}
	_, err := os.ReadFile(policy)
	out["policy-r"] = try(err)
	out["policy-w"] = try(os.WriteFile(filepath.Join(filepath.Dir(policy), "next.json"), []byte("{}"), 0o600))
	c, err := net.DialTimeout("unix", page, time.Second)
	if err == nil {
		c.Close()
	}
	out["page"] = try(err)
	out["packet"] = try(sock(syscall.AF_PACKET, syscall.SOCK_RAW, 0))
	out["bt"] = try(sock(31, syscall.SOCK_RAW, 1))
	out["inet"] = try(sock(syscall.AF_INET, syscall.SOCK_DGRAM, 0))
	out["netlink"] = try(sock(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE))
	if err := sock(syscall.AF_INET6, syscall.SOCK_DGRAM, 0); err == syscall.EAFNOSUPPORT {
		out["inet6"] = "no-ipv6"
	} else {
		out["inet6"] = try(err)
	}
	out["unshare-user"] = try(syscall.Unshare(syscall.CLONE_NEWUSER))
	out["unshare-mnt"] = try(syscall.Unshare(syscall.CLONE_NEWNS))
	out["clone-net"] = try(cloneNewNet())
	if f, err := os.Open("/proc/self/ns/net"); err == nil {
		_, _, e := syscall.RawSyscall(308 /* setns */, f.Fd(), syscall.CLONE_NEWNET, 0)
		f.Close()
		if e != 0 {
			out["setns"] = try(e)
		} else {
			out["setns"] = "allowed"
		}
	}
	out["mount"] = try(syscall.Mount("none", "/tmp", "tmpfs", 0, ""))
	tmpfs := []byte("tmpfs\x00")
	out["fsopen"] = try(raw(430, uintptr(unsafe.Pointer(&tmpfs[0])), 0))
	out["setuid0"] = try(syscall.Setuid(0))
	out["ptrace"] = ptraceChild(try)
	if kind == "thread" {
		// ot-daemon's own first step: a tun link named wpan0, held open.
		out["wpan0"] = try(createTun("wpan0"))
	} else {
		out["tun"] = try(createTun("rogue0"))
	}
	ifs, err := net.Interfaces()
	var names []string
	for _, i := range ifs {
		names = append(names, i.Name)
	}
	sort.Strings(names)
	out["ifs"] = strings.Join(names, " ")
	status, _ := os.ReadFile("/proc/self/status")
	for _, l := range strings.Split(string(status), "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok {
			switch k {
			case "Uid", "Gid", "Groups", "CapEff", "CapPrm", "NoNewPrivs", "Seccomp":
				if f := strings.Fields(v); len(f) == 4 && k != "Groups" && f[0] == f[1] && f[1] == f[2] && f[2] == f[3] {
					out[k] = f[0] // real, effective, saved and file-system ids all one
				} else {
					out[k] = strings.Join(f, " ")
				}
			}
		}
	}
	report, _ := json.Marshal(out)
	NewServer(StackThread, os.NewFile(3, "interface")).Serve(func(r Request) ([]byte, Code) {
		return report, CodeOK
	})
}

// held keeps the probe's tun descriptor open while it serves.
var held int

// createTun is TUNSETIFF on /dev/net/tun, which needs CAP_NET_ADMIN in
// the network namespace's user namespace.
func createTun(name string) error {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	var ifr [40]byte
	copy(ifr[:], name)
	*(*uint16)(unsafe.Pointer(&ifr[16])) = 0x0001 | 0x1000 // IFF_TUN | IFF_NO_PI
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x400454ca /* TUNSETIFF */, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		syscall.Close(fd)
		return e
	}
	held = fd
	return nil
}

// cloneNewNet is a raw clone(CLONE_NEWNET) whose child exits at once.
func cloneNewNet() error {
	pid, _, e := syscall.RawSyscall6(syscall.SYS_CLONE, syscall.CLONE_NEWNET|uintptr(syscall.SIGCHLD), 0, 0, 0, 0, 0)
	if e != 0 {
		return e
	}
	if pid == 0 {
		syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 0, 0, 0)
	}
	var ws syscall.WaitStatus
	syscall.Wait4(int(pid), &ws, 0, nil)
	return nil
}

// TestStacksConfined (NET-2 Confined radio stacks): the Thread stack runs
// as its own user in a user and network namespace the enforcer created as
// root, holding only CAP_NET_ADMIN and CAP_NET_RAW there; it can create
// wpan0 but sees only lo, wpan0 and infra0, cannot read or write the
// policy store or reach the page, cannot enter a new namespace or mount,
// and runs with no-new-privileges under the seccomp filter. The Matter
// controller, joined to that namespace as another user, sees the same
// links with no capability at all. Catches a stack run unconfined.
func TestStacksConfined(t *testing.T) {
	if !asRoot(t) {
		return
	}
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
	if err := os.Chmod(state, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(state, "radio.test")
	copyFile(t, os.Args[0], bin)

	read := func(t *testing.T, conn Conn) map[string]string {
		h, err := NewHost(Config{Devices: []Device{{Name: "probe", Stack: StackThread}}, Timeout: 20 * time.Second,
			Notify: func(Notification) {}, Log: func(string) {}})
		if err != nil {
			t.Fatal(err)
		}
		h.Attach(StackThread, conn)
		b, err := h.State("probe")
		if err != nil {
			t.Fatalf("read through the interface: %v", err)
		}
		got := map[string]string{}
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		for k, v := range got {
			t.Logf("%-28s %s", k, v)
		}
		return got
	}
	refused := []string{"policy-r", "policy-w", "page", "packet",
		"bt", "unshare-user", "unshare-mnt", "clone-net",
		"setns", "mount", "fsopen", "setuid0", "ptrace"}
	confined := func(t *testing.T, got map[string]string, uid int, capEff string) {
		t.Helper()
		for _, k := range refused {
			if !strings.HasPrefix(got[k], "refused") {
				t.Errorf("%s: %q, want refused", k, got[k])
			}
		}
		for _, k := range []string{"inet", "netlink"} {
			if got[k] != "allowed" {
				t.Errorf("%s: %q, want allowed", k, got[k])
			}
		}
		if v := got["inet6"]; v != "allowed" && v != "no-ipv6" {
			t.Errorf("AF_INET6 socket: %q", v)
		}
		id := fmt.Sprint(uid)
		if got["Uid"] != id || got["Gid"] != id || got["Groups"] != "" {
			t.Errorf("ids: uid %q gid %q groups %q, want %d and no groups", got["Uid"], got["Gid"], got["Groups"], uid)
		}
		if got["NoNewPrivs"] != "1" || got["Seccomp"] != "2" {
			t.Errorf("no-new-privileges %q, seccomp mode %q: want 1 and 2 (filter)", got["NoNewPrivs"], got["Seccomp"])
		}
		if got["CapEff"] != capEff || got["CapPrm"] != capEff {
			t.Errorf("capabilities: effective %q, permitted %q; want %s", got["CapEff"], got["CapPrm"], capEff)
		}
	}

	thread, conn, err := confine.Start(confine.Spec{Profile: confine.Thread(threadUID, threadUID), Self: bin,
		Path: bin, Args: []string{netProbeArg, "thread", policy, page}, Stderr: testWriter{t}})
	if err != nil {
		t.Fatal(err)
	}
	defer thread.Stop()
	t.Run("thread", func(t *testing.T) {
		got := read(t, conn)
		// CAP_NET_ADMIN (12) and CAP_NET_RAW (13), in its own user namespace.
		confined(t, got, threadUID, "0000000000003000")
		if got["wpan0"] != "allowed" {
			t.Errorf("the Thread stack cannot create wpan0: %s", got["wpan0"])
		}
		if got["ifs"] != "infra0 lo wpan0" {
			t.Errorf("the Thread stack sees %q, want infra0 lo wpan0", got["ifs"])
		}
	})
	t.Run("matter", func(t *testing.T) {
		matter, conn, err := confine.Start(confine.Spec{Profile: confine.Matter(matterUID, matterUID), Net: thread,
			Self: bin, Path: bin, Args: []string{netProbeArg, "matter", policy, page}, Stderr: testWriter{t}})
		if err != nil {
			t.Fatal(err)
		}
		defer matter.Stop()
		got := read(t, conn)
		confined(t, got, matterUID, "0000000000000000")
		if !strings.HasPrefix(got["tun"], "refused") {
			t.Errorf("the Matter controller created a link: %s", got["tun"])
		}
		if got["ifs"] != "infra0 lo wpan0" {
			t.Errorf("the Matter controller sees %q, want Thread's infra0 lo wpan0", got["ifs"])
		}
	})
	t.Run("the enforcer's own namespace is unchanged", func(t *testing.T) {
		ifs, _ := net.Interfaces()
		for _, i := range ifs {
			if i.Name == "infra0" || i.Name == "wpan0" {
				t.Errorf("%s appeared in the enforcer's own namespace", i.Name)
			}
		}
	})
	t.Run("a joining stack gets no capability or link", func(t *testing.T) {
		for _, p := range []confine.Profile{confine.Thread(matterUID, matterUID), func() confine.Profile {
			p := confine.Matter(matterUID, matterUID)
			p.Links = []string{"rogue0"}
			return p
		}()} {
			if _, _, err := confine.Start(confine.Spec{Profile: p, Net: thread, Self: bin, Path: bin}); err != confine.ErrJoin {
				t.Errorf("%s joined with %v", p.Name, err)
			}
		}
	})
}

// TestStackOutlivesEndedThreads (NET-2 Confined radio stacks): a stack's
// Pdeathsig is tied to the OS thread that forked it, and the runtime ends
// any thread whose goroutine exits locked to it (as the enforcer's own
// namespace work does), so a stack forked from a shared thread is killed
// at random. Many such goroutines run after the start; the stack still
// answers. Catches a stack forked from a thread other code can end.
func TestStackOutlivesEndedThreads(t *testing.T) {
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
	proc, conn, err := confine.Start(confine.Spec{Profile: confine.BLE(4242, 4242), Self: bin, Path: bin,
		Args: []string{probeArg, filepath.Join(dir, "none"), filepath.Join(dir, "none.sock")}, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Stop()
	var wg sync.WaitGroup
	for range 256 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread() // never unlocked: this thread ends
		}()
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)
	h, err := NewHost(Config{Devices: []Device{scale}, Timeout: 20 * time.Second,
		Notify: func(Notification) {}, Log: func(string) {}})
	if err != nil {
		t.Fatal(err)
	}
	h.Attach(StackBLE, conn)
	if _, err := h.State(scale.Name); err != nil {
		t.Fatalf("the stack after threads ended: %v", err)
	}
}
