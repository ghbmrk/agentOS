package radio

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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
	out := map[string]string{}
	var keep [][]byte // the C strings the calls below point at
	defer runtime.KeepAlive(&keep)
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
	// nf_tables, which CAP_NET_ADMIN in the stack's own namespace would reach.
	out["nfnl"] = try(sock(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER))
	if err := sock(syscall.AF_INET6, syscall.SOCK_DGRAM, 0); err == syscall.EAFNOSUPPORT {
		out["inet6"] = "no-ipv6"
	} else {
		out["inet6"] = try(err)
	}
	// The namespace, mount and process calls, each on an OS thread of
	// its own that is then discarded (threadCall), since a stack cannot
	// fork a single-threaded child for them (#4521). A threaded caller
	// gets EINVAL for unshare(CLONE_NEWUSER) and CLONE_NEWNS whatever the
	// filter says, so only EPERM counts as refused. This profile lacks the
	// capability for most of them, so its EPERM may be the kernel's;
	// confine's TestFilterRefusesLive shows each is the filter's, in a
	// process the kernel would let make them (#4233).
	nsCall := func(nr uintptr, a ...uintptr) string {
		var v [6]uintptr
		copy(v[:], a)
		e := threadCall(nr, v)
		switch {
		case e == syscall.EPERM:
			return try(e)
		case e == 0:
			return "allowed"
		}
		fmt.Fprintf(os.Stderr, "%s: %v\n", kind, e)
		return "untested: " + e.Error()
	}
	cstr := func(s string) uintptr {
		b := append([]byte(s), 0)
		keep = append(keep, b)
		return uintptr(unsafe.Pointer(&b[0]))
	}
	out["unshare-user"] = nsCall(syscall.SYS_UNSHARE, syscall.CLONE_NEWUSER)
	out["unshare-mnt"] = nsCall(syscall.SYS_UNSHARE, syscall.CLONE_NEWNS)
	out["clone-net"] = nsCall(syscall.SYS_CLONE, syscall.CLONE_NEWNET|uintptr(syscall.SIGCHLD))
	out["clone-process"] = nsCall(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD))
	out["fork"] = nsCall(syscall.SYS_FORK)
	if f, err := os.Open("/proc/self/ns/net"); err == nil {
		out["setns"] = nsCall(308 /* setns */, f.Fd(), syscall.CLONE_NEWNET)
		f.Close()
	}
	out["mount"] = nsCall(syscall.SYS_MOUNT, cstr("none"), cstr("/tmp"), cstr("tmpfs"), 0, cstr(""))
	out["fsopen"] = nsCall(430 /* fsopen */, cstr("tmpfs"), 0)
	out["setuid0"] = try(syscall.Setuid(0))
	out["ptrace"] = ptraceSelf(try)
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
	// The report is served in two halves, one per probe device, since an
	// answer is bounded by MaxData.
	halves := [2]map[string]string{{}, {}}
	keys := slices.Sorted(maps.Keys(out))
	for i, k := range keys {
		halves[i*2/len(keys)][k] = out[k]
	}
	var reports [2][]byte
	for i := range halves {
		reports[i], _ = json.Marshal(halves[i])
	}
	NewServer(StackThread, os.NewFile(3, "interface")).Serve(func(r Request) ([]byte, Code) {
		if r.Device == probeDevices[1] {
			return reports[1], CodeOK
		}
		return reports[0], CodeOK
	})
}

// probeDevices name the two halves of a net probe's report.
var probeDevices = [2]string{"probe", "probe2"}

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

// threadCall makes one call on a fresh locked OS thread, which exits with
// its goroutine, so a namespace the call entered ends with it. It returns
// the call's errno, 0 for success.
func threadCall(nr uintptr, a [6]uintptr) syscall.Errno {
	c := make(chan syscall.Errno, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread exits with this goroutine
		c <- rawCall(nr, a)
	}()
	return <-c
}

// rawCall makes the call; a process it made (fork or clone let through;
// never vfork, whose child would run on this thread's stack) exits at once, running only raw system calls with no stack
// check, as the runtime's own fork does.
//
//go:nosplit
func rawCall(nr uintptr, a [6]uintptr) syscall.Errno {
	r, _, e := syscall.RawSyscall6(nr, a[0], a[1], a[2], a[3], a[4], a[5])
	if e == 0 && r == 0 && (nr == syscall.SYS_CLONE || nr == syscall.SYS_FORK) {
		syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 0, 0, 0)
	}
	return e
}

// TestStacksConfined (NET-2 Confined radio stacks; #4369): the Thread stack
// runs as its own user in a user and network namespace the enforcer created
// as root, holding only CAP_NET_ADMIN and CAP_NET_RAW there with its view
// (CAP_SYS_ADMIN, which built the view, dropped); it can create wpan0
// through the tun device its view shows but sees only lo, wpan0 and
// infra0, cannot read or write the policy store or reach the page, opens no netlink but route netlink (so
// not nf_tables), cannot enter a new namespace or mount, starts no
// process (#4521), and runs with no-new-privileges under the seccomp filter. The Matter
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
	// The stacks' own directories, which their views show them; the
	// radio is a stand-in character device.
	own := func(name string, uid int) string {
		d := filepath.Join(state, name)
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(d, uid, uid); err != nil {
			t.Fatal(err)
		}
		return d
	}
	threadSpec, err := confine.Thread(threadUID, threadUID, own("thread-state", threadUID), own("thread-run", threadUID),
		"/dev/null", "", func(string, string) ([]string, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	threadProfile := probeView(threadSpec.Profile)
	matterProfile := probeView(confine.Matter(matterUID, matterUID, own("matter", matterUID)))

	read := func(t *testing.T, p Proc, conn Conn) map[string]string {
		h, err := NewHost(Config{Devices: []Device{{Name: probeDevices[0], Stack: StackThread}, {Name: probeDevices[1], Stack: StackThread}},
			Timeout: 20 * time.Second, Notify: func(Notification) {}, Log: func(string) {}})
		if err != nil {
			t.Fatal(err)
		}
		h.Attach(StackThread, p, conn)
		got := map[string]string{}
		for _, d := range probeDevices {
			b, err := h.State(d)
			if err != nil {
				t.Fatalf("read %s through the interface: %v", d, err)
			}
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatal(err)
			}
		}
		for k, v := range got {
			t.Logf("%-28s %s", k, v)
		}
		return got
	}
	refused := []string{"policy-r", "policy-w", "page", "packet", "nfnl",
		"bt", "unshare-user", "unshare-mnt", "clone-net", "clone-process", "fork",
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

	thread, conn, err := confine.Start(confine.Spec{Profile: threadProfile, Self: bin,
		Path: bin, Args: []string{netProbeArg, "thread", policy, page}, Stderr: testWriter{t}})
	if err != nil {
		t.Fatal(err)
	}
	defer thread.Stop()
	t.Run("thread", func(t *testing.T) {
		got := read(t, thread, conn)
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
		matter, conn, err := confine.Start(confine.Spec{Profile: matterProfile, Net: thread,
			Self: bin, Path: bin, Args: []string{netProbeArg, "matter", policy, page}, Stderr: testWriter{t}})
		if err != nil {
			t.Fatal(err)
		}
		defer matter.Stop()
		got := read(t, matter, conn)
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
		for _, p := range []confine.Profile{threadProfile, func() confine.Profile {
			p := matterProfile
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
	proc, conn, err := confine.Start(confine.Spec{Profile: bleProbe(4242), Self: bin, Path: bin,
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
	h.Attach(StackBLE, proc, conn)
	if _, err := h.State(scale.Name); err != nil {
		t.Fatalf("the stack after threads ended: %v", err)
	}
}
