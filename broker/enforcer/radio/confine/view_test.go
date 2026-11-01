package confine

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

// viewReport is what the view probe found, written to its command
// interface: each dial's errno (0: connected), every path under its root
// ("tree" variant only), creating a file in its root, and its
// capabilities.
type viewReport struct {
	Bus, Other int
	Tree       []string
	Create     int
	Caps       [3]uint32 // effective, permitted, inheritable (low words)
	Ambient    int       // PR_CAP_AMBIENT_IS_SET for CAP_SYS_ADMIN
}

// viewProbe is a stack an exploit has taken: it dials the bus and another
// socket the enforcer's host holds, and, asked for the tree, lists and
// writes its root.
func viewProbe(variant, bus, other string) int {
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
	r := viewReport{Bus: dial(bus), Other: dial(other)}
	if variant == "tree" {
		filepath.WalkDir("/", func(p string, _ fs.DirEntry, err error) error {
			if err != nil {
				r.Tree = append(r.Tree, p+": "+err.Error())
				return nil
			}
			r.Tree = append(r.Tree, p)
			return nil
		})
		fd, err := syscall.Open("/written", syscall.O_CREAT|syscall.O_WRONLY|syscall.O_CLOEXEC, 0o600)
		if err == nil {
			syscall.Close(fd)
		}
		r.Create = errno(err)
	}
	hdr := struct{ version, pid uint32 }{capV3, 0}
	var data [6]uint32
	syscall.RawSyscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0)
	r.Caps = [3]uint32{data[0], data[1], data[2]}
	set, _, _ := syscall.RawSyscall6(syscall.SYS_PRCTL, prCapAmbient, 1 /* PR_CAP_AMBIENT_IS_SET */, capSysAdmin, 0, 0, 0)
	r.Ambient = int(set)
	b, _ := json.Marshal(r)
	if _, err := os.NewFile(3, "interface").Write(b); err != nil {
		return 1
	}
	return 0
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

// TestViewOnlyBusSocket (NET-2 Confined radio stacks; #4215): a stack
// started under a profile whose view is the bus socket, as BLE's is,
// connects to the bus and not to another Unix socket that exists on the
// host, which any user may connect to; its root holds the bus socket's
// path and nothing else (a listed path that does not exist is left out),
// is read-only, the stack holds no capability, and the enforcer's own
// mount table is unchanged. The same probe under
// the same profile without a view connects to both, so the refusal is
// the view's. Catches an exploited BLE stack connecting outside D-Bus to
// another Unix socket its user can open (journald, a resolver, a radio
// peer), which the bus policy cannot bound.
func TestViewOnlyBusSocket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a confined stack as another user")
	}
	dir, err := os.MkdirTemp("", "view")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "confine.test")
	b, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, b, 0o755); err != nil {
		t.Fatal(err)
	}
	bus, other := filepath.Join(dir, "bus"), filepath.Join(dir, "other")
	listen(t, bus)
	listen(t, other)

	run := func(variant string, view []string) viewReport {
		t.Helper()
		p := BLE(viewUID, viewUID)
		p.View = view
		proc, conn, err := Start(Spec{Profile: p, Self: bin, Path: bin, Args: []string{viewArg, variant, bus, other},
			Stderr: testWriter{t}})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		out, err := io.ReadAll(conn)
		if werr := proc.Wait(); werr != nil {
			t.Fatalf("probe %s: %v", variant, werr)
		}
		var r viewReport
		if err != nil || json.Unmarshal(out, &r) != nil {
			t.Fatalf("probe %s: %v: %q", variant, err, out)
		}
		t.Logf("%s: %+v", variant, r)
		return r
	}

	mounts := func() string {
		b, err := os.ReadFile("/proc/self/mountinfo")
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	before := mounts()
	got := run("tree", []string{bus, filepath.Join(dir, "missing")})
	if after := mounts(); after != before {
		t.Errorf("the view changed the enforcer's mounts:\n%s\nwas\n%s", after, before)
	}
	if got.Bus != 0 {
		t.Errorf("in the view, dialling the bus: %v, want connected", syscall.Errno(got.Bus))
	}
	if got.Other != int(syscall.ENOENT) {
		t.Errorf("in the view, dialling another socket: %v, want ENOENT", syscall.Errno(got.Other))
	}
	var want []string
	for p := bus; ; p = filepath.Dir(p) {
		want = append(want, p)
		if p == "/" {
			break
		}
	}
	slices.Sort(want)
	if !slices.Equal(got.Tree, want) {
		t.Errorf("the view's tree %q, want %q", got.Tree, want)
	}
	if got.Create != int(syscall.EROFS) {
		t.Errorf("creating a file in the view's root: %v, want EROFS", syscall.Errno(got.Create))
	}
	if got.Caps != [3]uint32{} || got.Ambient != 0 {
		t.Errorf("the stack holds capabilities %x, ambient CAP_SYS_ADMIN %d", got.Caps, got.Ambient)
	}

	if control := run("dial", nil); control.Bus != 0 || control.Other != 0 {
		t.Errorf("without a view, dials: bus %v, other %v; the probe cannot see a missing view",
			syscall.Errno(control.Bus), syscall.Errno(control.Other))
	}
}

// TestBLEViewIsTheBus (NET-2): the shipped BLE profile's view is the
// system bus socket and nothing else.
func TestBLEViewIsTheBus(t *testing.T) {
	if v := BLE(1, 1).View; !slices.Equal(v, []string{"/run/dbus/system_bus_socket"}) {
		t.Errorf("BLE view %q", v)
	}
}

// TestStartRefusesBadView (NET-2): Start refuses, before it forks, a view
// path Trampoline could not rebuild or that would replace the whole root,
// and a view on a NetAdmin profile, whose user namespace keeps its
// capabilities.
func TestStartRefusesBadView(t *testing.T) {
	for _, v := range []string{"", "run/x", "/", "/run/../etc", "/run/", "/run/x\n/etc"} {
		p := BLE(1, 1)
		p.View = []string{SystemBus, v}
		if _, _, err := Start(Spec{Profile: p, Path: "/nonexistent"}); err != ErrView {
			t.Errorf("view %q: %v", v, err)
		}
	}
	th := Thread(1, 1)
	th.View = []string{SystemBus}
	if _, _, err := Start(Spec{Profile: th, Path: "/nonexistent"}); err != ErrView {
		t.Errorf("NetAdmin with a view: %v", err)
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(b []byte) (int, error) {
	w.t.Logf("%s", strings.TrimRight(string(b), "\n"))
	return len(b), nil
}
