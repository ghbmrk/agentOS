package confine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// REQ: NET-2

// viewArg makes this test binary the view probe, started by Start as a
// confined stack.
const viewArg = "confine-view-probe"

// viewUID is the probe stack's user: never root.
const viewUID = 4251

// The view probe's layout under the test's directory: two sockets any
// user may connect to, a state directory the stack writes, a shared
// mount the host mounts under after the start, and a symlink to the
// state directory.
const (
	vBus, vOther, vState, vShared, vLate, vLink = "bus", "other", "state", "shared", "shared/late", "link"
	vSub                                        = "shared/sub"
	devNull                                     = "/dev/null"
)

// stFlags are the statfs flags the probe reports: ST_RDONLY, ST_NOSUID,
// ST_NODEV and ST_NOEXEC.
const (
	stRdonly = 1
	stNosuid = 2
	stNodev  = 4
	stNoexec = 8
)

// viewReport is what the view probe found, written to its command
// interface: each dial's errno (0: connected), every path under its root
// but /proc ("full" variant only), what it could do there, and its
// capabilities.
type viewReport struct {
	Bus, Other int
	Tree       []string
	Create     int               // creating a file in the view's root
	Write      int               // creating one in its state directory
	Null       int               // opening and writing the device
	Wd         string            // its working directory
	Link       string            // the symlink's target, and whether it resolves
	Flags      map[string]uint64 // statfs flags of each entry, masked to stFlags
	Roots      []string          // the file system of each mount at "/" in mountinfo
	Late       bool              // the host's mount after the start is a mount here
	Caps       [3]uint32         // effective, permitted, inheritable (low words)
	Ambient    int               // PR_CAP_AMBIENT_IS_SET for CAP_SYS_ADMIN
}

// viewProbe is a stack an exploit has taken: it dials the bus and another
// socket the enforcer's host holds and, in the "full" variant, walks and
// writes its root, opens its device, reads its mounts, and then tells the
// enforcer it is ready and waits for one byte before looking for a mount
// the host made meanwhile.
func viewProbe(variant, dir string) int {
	errno := func(err error) int {
		if e := syscall.Errno(0); errors.As(err, &e) {
			return int(e)
		}
		if err != nil {
			return -1
		}
		return 0
	}
	dial := func(p string) int {
		fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			return errno(err)
		}
		defer syscall.Close(fd)
		return errno(syscall.Connect(fd, &syscall.SockaddrUnix{Name: p}))
	}
	at := func(n string) string { return filepath.Join(dir, n) }
	iface := os.NewFile(3, "interface")
	r := viewReport{Bus: dial(at(vBus)), Other: dial(at(vOther))}
	if variant == "full" {
		filepath.WalkDir("/", func(p string, _ fs.DirEntry, err error) error {
			if p == "/proc" {
				r.Tree = append(r.Tree, p)
				return fs.SkipDir
			}
			if err != nil {
				r.Tree = append(r.Tree, p+": "+err.Error())
				return nil
			}
			r.Tree = append(r.Tree, p)
			return nil
		})
		create := func(p string) int {
			fd, err := syscall.Open(p, syscall.O_CREAT|syscall.O_WRONLY|syscall.O_CLOEXEC, 0o600)
			if err == nil {
				syscall.Close(fd)
			}
			return errno(err)
		}
		r.Create = create("/written")
		r.Write = create(at(vState) + "/written")
		if fd, err := syscall.Open(devNull, syscall.O_RDWR|syscall.O_CLOEXEC, 0); err != nil {
			r.Null = errno(err)
		} else {
			_, err := syscall.Write(fd, []byte{0})
			r.Null = errno(err)
			syscall.Close(fd)
		}
		r.Wd, _ = syscall.Getwd()
		target, err := os.Readlink(at(vLink))
		_, serr := os.Stat(at(vLink) + "/.")
		r.Link = target + " " + errString(err) + " " + errString(serr)
		r.Flags = map[string]uint64{}
		for _, p := range []string{at(vBus), at(vState), at(vShared), at(vSub), devNull, "/proc", "/"} {
			var st syscall.Statfs_t
			if err := syscall.Statfs(p, &st); err != nil {
				r.Flags[p] = 1 << 63
				continue
			}
			r.Flags[p] = uint64(st.Flags) & (stRdonly | stNosuid | stNodev | stNoexec)
		}
		if b, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
			for l := range strings.SplitSeq(strings.TrimSpace(string(b)), "\n") {
				// id parent major:minor root mountpoint options ... - fstype source options
				f := strings.Fields(l)
				if len(f) > 4 && f[4] == "/" {
					i := slices.Index(f, "-")
					if i > 0 && i+1 < len(f) {
						r.Roots = append(r.Roots, f[i+1])
					}
				}
			}
		}
		var b [1]byte
		if _, err := iface.Write([]byte{'r'}); err != nil {
			return 1
		}
		if n, _ := iface.Read(b[:]); n != 1 {
			return 1
		}
		var sh, late syscall.Stat_t
		if syscall.Stat(at(vShared), &sh) == nil && syscall.Stat(at(vLate), &late) == nil {
			r.Late = sh.Dev != late.Dev
		}
	}
	hdr := struct{ version, pid uint32 }{capV3, 0}
	var data [6]uint32
	syscall.RawSyscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0)
	r.Caps = [3]uint32{data[0], data[1], data[2]}
	set, _, _ := syscall.RawSyscall6(syscall.SYS_PRCTL, 47 /* PR_CAP_AMBIENT */, 1 /* PR_CAP_AMBIENT_IS_SET */, capSysAdmin, 0, 0, 0)
	r.Ambient = int(set)
	b, _ := json.Marshal(r)
	if _, err := iface.Write(b); err != nil {
		return 1
	}
	return 0
}

func errString(err error) string {
	if err != nil {
		return "error"
	}
	return "ok"
}

// listen serves a Unix socket at p that any user may connect to, as the
// sockets an exploited stack would look for are. Its connections queue
// unaccepted. The test binary links no net package, so no cgo: it is
// static, as the enforcer's binary is, and runs in a view with no loader.
func listen(t *testing.T, p string) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: p}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Listen(fd, 8); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o777); err != nil {
		t.Fatal(err)
	}
}

// viewDir makes the probe's layout in a fresh directory, with a copy of
// this test binary the probe's user can execute, and returns both. The
// directory is its real path, since a view entry is never reached
// through a symlink.
func viewDir(t *testing.T) (dir, bin string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "view")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin = filepath.Join(dir, "confine.test")
	b, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, b, 0o755); err != nil {
		t.Fatal(err)
	}
	listen(t, filepath.Join(dir, vBus))
	listen(t, filepath.Join(dir, vOther))
	if err := os.Mkdir(filepath.Join(dir, vState), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Join(dir, vState), viewUID, viewUID); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(vState, filepath.Join(dir, vLink)); err != nil {
		t.Fatal(err)
	}
	return dir, bin
}

// startProbe starts the view probe under BLE's profile with view (nil:
// none), its working directory dir/state. stderr collects Trampoline's
// refusals.
func startProbe(t *testing.T, bin, dir, variant string, view []Entry, stderr io.Writer) (*Proc, *os.File) {
	t.Helper()
	p := BLE(viewUID, viewUID)
	p.View = view
	proc, conn, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{viewArg, variant, dir},
		Dir: filepath.Join(dir, vState), Stderr: stderr})
	if err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	return proc, conn
}

// readReport reads the probe's report and reaps it.
func readReport(t *testing.T, proc *Proc, conn *os.File) viewReport {
	t.Helper()
	defer conn.Close()
	out, err := io.ReadAll(conn)
	if werr := proc.Wait(); werr != nil {
		t.Fatalf("probe: %v", werr)
	}
	var r viewReport
	if err != nil || json.Unmarshal(out, &r) != nil {
		t.Fatalf("probe: %v: %q", err, out)
	}
	t.Logf("%+v", r)
	return r
}

// sharedMount mounts a tmpfs at dir/shared, shared, with dir/shared/late
// in it for the host's later mount, and unmounts both at the end.
func sharedMount(t *testing.T, dir string) {
	t.Helper()
	sh := filepath.Join(dir, vShared)
	if err := os.Mkdir(sh, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount("tmpfs", sh, "tmpfs", 0, "mode=0755,size=64k"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Unmount(sh, syscall.MNT_DETACH) })
	if err := syscall.Mount("", sh, "", syscall.MS_SHARED, ""); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, vLate), 0o755); err != nil {
		t.Fatal(err)
	}
	// A submount there before the start, writable, suid and dev as the
	// host has it, which the view must clone with the entry's attributes.
	sub := filepath.Join(dir, vSub)
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount("tmpfs", sub, "tmpfs", 0, "size=4k"); err != nil {
		t.Fatal(err)
	}
}

// TestViewOnlyItsEntries (NET-2 Confined radio stacks; #4215, #4369,
// #4385): a stack started under a profile with a view connects to its
// socket entry and not to another Unix socket that exists on the host,
// which any user may connect to; its root holds its entries' paths and
// nothing else (a listed path that does not exist is left out), and is
// read-only; its state directory is writable, nosuid, nodev and noexec,
// and is its working directory; its device opens, with nodev off on that
// entry alone; a symlink entry keeps its target; the stack holds no
// capability; the enforcer's own mount table is unchanged. It also holds
// the view's three hardening steps: a mount the host makes under a shared
// entry after the start does not reach the stack (its namespace is made
// private first), the old root is gone from its mount table (detached
// after the pivot), and each entry's mount has its attributes, a submount
// the host made under a directory entry included (cloned recursively,
// set recursively). The same
// probe under the same profile without a view connects to both sockets,
// so the refusal is the view's. Catches an exploited radio stack
// connecting outside its interface to another Unix socket its user can
// open (journald, a resolver, a radio peer), or reaching a file its view
// leaves out.
func TestViewOnlyItsEntries(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a confined stack as another user")
	}
	dir, bin := viewDir(t)
	sharedMount(t, dir)
	at := func(n string) string { return filepath.Join(dir, n) }
	view := []Entry{{Path: at(vBus), Kind: Socket}, {Path: at("missing"), Kind: Socket},
		{Path: at(vState), Kind: Dir, Write: true}, {Path: at(vShared), Kind: Dir}, {Path: at(vLink), Kind: Link},
		{Path: devNull, Kind: Device}, {Path: "/proc", Kind: Dir}}

	mounts := func() string {
		b, err := os.ReadFile("/proc/self/mountinfo")
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	before := mounts()
	proc, conn := startProbe(t, bin, dir, "full", view, testWriter{t})
	var b [1]byte
	if n, err := conn.Read(b[:]); n != 1 {
		t.Fatalf("the probe did not get ready: %v", err)
	}
	if after := mounts(); after != before {
		t.Errorf("the view changed the enforcer's mounts:\n%s\nwas\n%s", after, before)
	}
	if err := syscall.Mount("tmpfs", at(vLate), "tmpfs", 0, "size=4k"); err != nil {
		t.Fatal(err)
	}
	defer syscall.Unmount(at(vLate), syscall.MNT_DETACH)
	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	got := readReport(t, proc, conn)

	if got.Bus != 0 {
		t.Errorf("in the view, dialling its socket: %v, want connected", syscall.Errno(got.Bus))
	}
	if got.Other != int(syscall.ENOENT) {
		t.Errorf("in the view, dialling another socket: %v, want ENOENT", syscall.Errno(got.Other))
	}
	want := []string{"/proc", at(vLate), at(vSub)}
	for _, p := range []string{at(vBus), at(vState), at(vShared), at(vLink), devNull} {
		for ; p != "/"; p = filepath.Dir(p) {
			want = append(want, p)
		}
	}
	want = append(want, "/")
	for i := range want {
		want[i] = filepath.Clean(want[i])
	}
	slices.Sort(want)
	want = slices.Compact(want)
	if !slices.Equal(got.Tree, want) {
		t.Errorf("the view's tree %q, want %q", got.Tree, want)
	}
	if got.Create != int(syscall.EROFS) {
		t.Errorf("creating a file in the view's root: %v, want EROFS", syscall.Errno(got.Create))
	}
	if got.Write != 0 {
		t.Errorf("creating a file in its state directory: %v", syscall.Errno(got.Write))
	} else if _, err := os.Stat(at("state/written")); err != nil {
		t.Errorf("the stack's state file is not on the host: %v", err)
	}
	if got.Null != 0 {
		t.Errorf("opening and writing its device: %v", syscall.Errno(got.Null))
	}
	if got.Wd != at(vState) {
		t.Errorf("working directory %q, want %q", got.Wd, at(vState))
	}
	if got.Link != vState+" ok ok" {
		t.Errorf("the symlink entry: %q, want its target, resolving", got.Link)
	}
	// Each entry's flags are exactly its own, a submount's included.
	for p, f := range map[string]uint64{
		at(vBus):    stRdonly | stNosuid | stNodev | stNoexec,
		at(vState):  stNosuid | stNodev | stNoexec,
		at(vShared): stRdonly | stNosuid | stNodev | stNoexec,
		at(vSub):    stRdonly | stNosuid | stNodev | stNoexec,
		devNull:     stRdonly | stNosuid | stNoexec,
		"/proc":     stRdonly | stNosuid | stNodev | stNoexec,
		"/":         stRdonly | stNosuid | stNodev | stNoexec,
	} {
		if g := got.Flags[p]; g != f {
			t.Errorf("%s: mount flags %#x, want %#x", p, g, f)
		}
	}
	if !slices.Equal(got.Roots, []string{"tmpfs"}) {
		t.Errorf("mounts at / in the stack's table: %q, want the view's tmpfs alone (the old root detached)", got.Roots)
	}
	if got.Late {
		t.Error("a mount the host made after the start reached the stack's view")
	}
	if got.Caps != [3]uint32{} || got.Ambient != 0 {
		t.Errorf("the stack holds capabilities %x, ambient CAP_SYS_ADMIN %d", got.Caps, got.Ambient)
	}

	cproc, cconn := startProbe(t, bin, dir, "dial", nil, testWriter{t})
	control := readReport(t, cproc, cconn)
	if control.Bus != 0 || control.Other != 0 {
		t.Errorf("without a view, dials: bus %v, other %v; the probe cannot see a missing view",
			syscall.Errno(control.Bus), syscall.Errno(control.Other))
	}
	if control.Caps != [3]uint32{} || control.Ambient != 0 {
		t.Errorf("without a view, the stack holds capabilities %x, ambient CAP_SYS_ADMIN %d", control.Caps, control.Ambient)
	}
}

// TestViewRefusesSwappedEntry (NET-2; #4384): a view entry whose path is a
// symlink, is reached through one, or is a file of another kind than the
// profile declares fails the start before the stack runs (Trampoline
// exits 126 and the stack sends nothing), so swapping the bus socket for
// a symlink or a directory cannot widen the view to its target. The
// probe's plain entry runs under the same view otherwise (the control).
// Catches open_tree following a symlink at, or under, a view path, or
// binding a file whatever its type.
func TestViewRefusesSwappedEntry(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a confined stack as another user")
	}
	dir, bin := viewDir(t)
	at := func(n string) string { return filepath.Join(dir, n) }
	if err := os.Symlink(vBus, at("bus-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".", at("via")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(at("d"), 0o755); err != nil {
		t.Fatal(err)
	}
	state := Entry{Path: at(vState), Kind: Dir}
	for _, c := range []struct {
		name  string
		entry Entry
		why   string
	}{
		{"a symlink where the socket was", Entry{Path: at("bus-link"), Kind: Socket}, "not a s"},
		{"a symlink above the socket", Entry{Path: at("via/" + vBus), Kind: Socket}, syscall.ELOOP.Error()},
		{"a directory where the socket was", Entry{Path: at("d"), Kind: Socket}, "not a s"},
		{"a socket where the device was", Entry{Path: at(vBus), Kind: Device}, "not a c"},
		{"a directory declared a symlink", Entry{Path: at("d"), Kind: Link}, "not a l"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var log lockedBuffer
			p := BLE(viewUID, viewUID)
			p.View = []Entry{state, c.entry}
			proc, conn, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{viewArg, "dial", dir},
				Dir: state.Path, Stderr: &log})
			// A refused stack may exit before Start opens its network
			// namespace, which fails the start: refused as well.
			if err == nil {
				conn.SetReadDeadline(time.Now().Add(30 * time.Second))
				out, _ := io.ReadAll(conn)
				conn.Close()
				err := proc.Wait()
				var ee *exec.ExitError
				if !errors.As(err, &ee) || ee.ExitCode() != 126 || len(out) != 0 {
					t.Errorf("the stack ran: exit %v, sent %q", err, out)
				}
			}
			if l := log.String(); !strings.Contains(l, "confine: view: "+c.entry.Path+": ") || !strings.Contains(l, c.why) {
				t.Errorf("refusal %q, want %q for %s", l, c.why, c.entry.Path)
			}
		})
	}
	t.Run("control", func(t *testing.T) {
		proc, conn := startProbe(t, bin, dir, "dial", []Entry{state, {Path: at(vBus), Kind: Socket}}, testWriter{t})
		r := readReport(t, proc, conn)
		if r.Bus != 0 || r.Other != int(syscall.ENOENT) {
			t.Errorf("dials: bus %v, other %v", syscall.Errno(r.Bus), syscall.Errno(r.Other))
		}
	})
}

// TestThreadViewKeepsNetAdmin (NET-2; #4369): a stack under a NetAdmin
// profile with a view, as Thread's is, keeps CAP_NET_ADMIN and
// CAP_NET_RAW and nothing else once Trampoline drops CAP_SYS_ADMIN, and
// sees only its entries. Catches a view that clears Thread's capabilities
// (ot-daemon could not make wpan0) or leaves it CAP_SYS_ADMIN.
func TestThreadViewKeepsNetAdmin(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a confined stack as another user")
	}
	dir, bin := viewDir(t)
	at := func(n string) string { return filepath.Join(dir, n) }
	if err := os.Mkdir(at("run"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := Thread(viewUID, viewUID, at(vState), at("run"), devNull)
	p.View = append(p.View, Entry{Path: at(vBus), Kind: Socket})
	p.Links = nil // the enforcer's links need CONFIG_DUMMY; this test is about the view
	proc, conn, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{viewArg, "dial", dir},
		Dir: at(vState), Stderr: testWriter{t}})
	if err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	r := readReport(t, proc, conn)
	const netAdminRaw = 1<<capNetAdmin | 1<<capNetRaw
	if r.Caps != [3]uint32{netAdminRaw, netAdminRaw, netAdminRaw} || r.Ambient != 0 {
		t.Errorf("capabilities %x, ambient CAP_SYS_ADMIN %d; want CAP_NET_ADMIN and CAP_NET_RAW alone", r.Caps, r.Ambient)
	}
	if r.Bus != 0 || r.Other != int(syscall.ENOENT) {
		t.Errorf("dials: bus %v, other %v", syscall.Errno(r.Bus), syscall.Errno(r.Other))
	}
}

// lockedBuffer collects a stack's stderr.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestStackWithoutArguments (NET-2): a stack started with no arguments of
// its own still runs (Trampoline's argument count). Catches Trampoline
// refusing, or skipping, a start whose only arguments are its own.
func TestStackWithoutArguments(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a confined stack as another user")
	}
	_, bin := viewDir(t)
	truth, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no true(1)")
	}
	proc, conn, err := Start(Spec{Profile: Profile{Name: "noargs", UID: viewUID, GID: viewUID}, Self: bin, Path: truth,
		Stderr: testWriter{t}})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err := proc.Wait(); err != nil {
		t.Errorf("a stack with no arguments: %v", err)
	}
}

// TestShippedViews (NET-2; #4215, #4369): each shipped profile's view is
// what its stack needs and nothing else: BLE the system bus socket;
// Thread its state and run directories, writable, its radio, the tun
// device and /dev/urandom; its adapter the run directory, read-only,
// which holds ot-daemon's command socket and not the network's keys; the
// Matter controller its storage directory.
func TestShippedViews(t *testing.T) {
	for _, c := range []struct {
		p    Profile
		want []Entry
	}{
		{BLE(1, 1), []Entry{{Path: "/run/dbus/system_bus_socket", Kind: Socket}}},
		{Thread(1, 1, "/var/lib/thread", "/run/thread", "/dev/ttyACM0"), []Entry{
			{Path: "/var/lib/thread", Kind: Dir, Write: true}, {Path: "/run/thread", Kind: Dir, Write: true},
			{Path: "/dev/ttyACM0", Kind: Device}, {Path: "/dev/net/tun", Kind: Device}, {Path: "/dev/urandom", Kind: Device}}},
		{ThreadAdapter(1, 1, "/run/thread"), []Entry{{Path: "/run/thread", Kind: Dir}}},
		{Matter(1, 1, "/var/lib/matter"), []Entry{{Path: "/var/lib/matter", Kind: Dir, Write: true}}},
	} {
		if !slices.Equal(c.p.View, c.want) {
			t.Errorf("%s view %+v, want %+v", c.p.Name, c.p.View, c.want)
		}
	}
}

// TestStartRefusesBadView (NET-2): Start refuses, before it forks, a view
// entry Trampoline could not rebuild from its argument, that would
// replace the whole root, of no known kind, that writes and is not a
// directory, that execs and is not a read-only directory, or that is
// another entry's path or above or under it;
// Trampoline's decoding refuses the same.
func TestStartRefusesBadView(t *testing.T) {
	bad := []Entry{{Path: "", Kind: Socket}, {Path: "run/x", Kind: Socket}, {Path: "/", Kind: Dir},
		{Path: "/run/../etc", Kind: Dir}, {Path: "/run/", Kind: Dir}, {Path: "/run/x\n/etc", Kind: Socket},
		{Path: "/run/x", Kind: 'f'}, {Path: "/run/x", Kind: 0}, {Path: "/run/x", Kind: Socket, Write: true},
		{Path: "/dev/x", Kind: Device, Write: true}, {Path: "/x", Kind: Link, Write: true},
		{Path: "/run/x", Kind: Socket, Exec: true}, {Path: "/dev/x", Kind: Device, Exec: true},
		{Path: "/x", Kind: Link, Exec: true}, {Path: "/x", Kind: Dir, Write: true, Exec: true},
		{Path: SystemBus, Kind: Socket}, {Path: SystemBus + "/x", Kind: Socket}, {Path: "/run/dbus", Kind: Dir}}
	for _, e := range bad {
		p := BLE(1, 1)
		p.View = append(p.View, e)
		if _, _, err := Start(Spec{Profile: p, Path: "/nonexistent"}); err != ErrView {
			t.Errorf("entry %+v: %v", e, err)
		}
		if e.Write && e.Exec {
			continue // the encoding has no form for both; Start refused it above
		}
		if _, err := decodeView(encodeView(p.View)); err != ErrView {
			t.Errorf("entry %+v decoded: %v", e, err)
		}
	}
	for _, s := range []string{"", "s", "sr", "sx/run/x", "s\n"} {
		if _, err := decodeView(s); err != ErrView {
			t.Errorf("decoding %q: %v", s, err)
		}
	}
	// A good view is no view error, NetAdmin's included (the start may
	// still fail off root, or exec nothing as root), and survives its
	// encoding.
	loader := BLE(1, 1)
	loader.View = append(loader.View, Entry{Path: "/usr/lib", Kind: Dir, Exec: true}, Entry{Path: "/lib", Kind: Link})
	for _, p := range []Profile{BLE(1, 1), Thread(1, 1, "/a", "/b", "/dev/c"), Matter(1, 1, "/m"), ThreadAdapter(1, 1, "/b"), loader} {
		if got, err := decodeView(encodeView(p.View)); err != nil || !slices.Equal(got, p.View) {
			t.Errorf("%s: decoded %+v, %v", p.Name, got, err)
		}
		if proc, _, err := Start(Spec{Profile: p, Path: "/nonexistent"}); err == ErrView {
			t.Errorf("%s: view refused", p.Name)
		} else if err == nil {
			proc.Stop()
		}
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(b []byte) (int, error) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		w.t.Logf("%s", sc.Text())
	}
	return len(b), nil
}

// TestProcAttr (NET-2): the fork gives a View profile its own user and
// mount namespace with CAP_SYS_ADMIN there (which Trampoline drops),
// gives NetAdmin its user namespace with CAP_NET_ADMIN and CAP_NET_RAW,
// both to Thread, which has both, gives a profile with neither no user or
// mount namespace and no capability, and a fresh network namespace unless
// the stack joins one. It runs without root, where the root-gated tests
// skip.
func TestProcAttr(t *testing.T) {
	const userMnt = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS
	plain := BLE(1, 1)
	plain.View = nil
	netAdmin := Thread(1, 1, "/s", "/r", "/d")
	netAdmin.View = nil
	for _, c := range []struct {
		name    string
		p       Profile
		net     *Proc
		flags   uintptr
		ambient []uintptr
	}{
		{"ble", BLE(1, 1), nil, syscall.CLONE_NEWIPC | syscall.CLONE_NEWNET | userMnt, []uintptr{capSysAdmin}},
		{"no view", plain, nil, syscall.CLONE_NEWIPC | syscall.CLONE_NEWNET, nil},
		{"thread", Thread(1, 1, "/s", "/r", "/d"), nil, syscall.CLONE_NEWIPC | syscall.CLONE_NEWNET | userMnt,
			[]uintptr{capNetAdmin, capNetRaw, capSysAdmin}},
		{"net admin, no view", netAdmin, nil, syscall.CLONE_NEWIPC | syscall.CLONE_NEWNET | syscall.CLONE_NEWUSER,
			[]uintptr{capNetAdmin, capNetRaw}},
		{"matter joined", Matter(1, 1, "/m"), &Proc{}, syscall.CLONE_NEWIPC | userMnt, []uintptr{capSysAdmin}},
	} {
		a := procAttr(Spec{Profile: c.p, Net: c.net})
		if a.Cloneflags != c.flags || !slices.Equal(a.AmbientCaps, c.ambient) {
			t.Errorf("%s: clone flags %#x, ambient %v; want %#x, %v", c.name, a.Cloneflags, a.AmbientCaps, c.flags, c.ambient)
		}
		if mapped := len(a.UidMappings) == 1 && a.UidMappings[0].HostID == 1 && a.UidMappings[0].Size == 1; mapped != (c.flags&syscall.CLONE_NEWUSER != 0) {
			t.Errorf("%s: uid mappings %+v", c.name, a.UidMappings)
		}
	}
}
