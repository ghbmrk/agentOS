package proc

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// A clerk's key hand-off (MAIL-keys, Mark's option A on #2682 comment
// 6428111900). The kernel's unit has no network and cannot change uid, so
// it is no clerk's parent. Instead each clerk's unit names the clerk's key
// socket in OpenFile=, so at every start and restart of that unit the
// service manager, as root and already in the unit's cgroup, connects, and
// the clerk's main gets the connection as descriptor 3 (clerkkey.FD). The
// kernel writes the clerk's key, derived from the clerk root key the unlock
// step handed it (clerkkey.Derive), and closes. It admits only uid 0, so a
// process under the clerk's uid has no way to ask for the key, and only a
// process in the clerk's own unit's cgroup, matched by its whole path, so
// another root process that is not deliberately subverting the check,
// agentosd among them, is not handed one either (ASSUMPTIONS MAIL-keys-4).

// KeyClerk is a clerk the kernel hands a key to: its key socket and its
// unit's whole cgroup path, such as
// /agentos-keeper.slice/agentos-keeper-mail.service, the only cgroup the
// kernel hands that key to. The whole path, not the unit's name alone: a
// unit with Delegate=yes (agentosd) may make a group of any name under its
// own (#3554 L3 1). A template's path, such as
// /agentos.slice/agentos-drivers.slice/agentos-driver-scale@.service, is
// each of its instances in that same parent: a socket unit with Accept=yes
// names each connection's instance itself (DEVSLOT-drivers b2b-2, #3590).
type KeyClerk struct {
	Socket string
	Cgroup string
}

// unitName is a systemd service unit's name, a template instance's too, and
// cgroupElem one element of a cgroup path.
var (
	unitName   = regexp.MustCompile(`^[A-Za-z0-9:_.\-]+(@[A-Za-z0-9:_.\-]*)?\.service$`)
	cgroupElem = regexp.MustCompile(`^[-A-Za-z0-9:_.@\\]+$`) // systemd escapes a slice name's "-" as \x2d
)

// ValidCgroup reports whether c can be a clerk unit's cgroup: an absolute,
// clean path whose last element is a service unit's name.
func ValidCgroup(c string) bool {
	if len(c) > 1024 || !strings.HasPrefix(c, "/") || path.Clean(c) != c || !unitName.MatchString(path.Base(c)) {
		return false
	}
	for _, e := range strings.Split(c[1:], "/") {
		if e == "." || e == ".." || !cgroupElem.MatchString(e) {
			return false
		}
	}
	return true
}

// ErrKeyPeer: the connection is not the service manager starting the
// clerk's unit. It is closed unanswered.
var ErrKeyPeer = errors.New("run: a clerk's key goes only to the service manager starting that clerk's unit")

// ListenClerkKey opens a clerk's key socket at path for uid 0 alone.
func ListenClerkKey(path string) (net.Listener, error) { return sockets.ListenPeers(path, 0) }

// keyWait bounds the hand-off's write, so a peer that never reads holds the
// socket no longer.
const keyWait = 2 * time.Second

// ServeClerkKey hands name's key under root to each connection on ln from
// a process in the cgroup at path cgroup, one at a time, until ln closes.
// Serving one at a time, it returns only once no hand-off still reads
// root, and the caller may then clear it.
func ServeClerkKey(ln net.Listener, name, cgroup string, root *[clerkkey.Len]byte) error {
	return serveClerkKey(ln, name, cgroup, root, procCgroup)
}

func serveClerkKey(ln net.Listener, name, cgroup string, root *[clerkkey.Len]byte, cgroupOf func(pid int32) (string, error)) error {
	if !clerkkey.ValidName(name) || !ValidCgroup(cgroup) || *root == ([clerkkey.Len]byte{}) {
		return fmt.Errorf("run: clerk %q's key: no clerk root key or no unit", name)
	}
	return ServeConns(ln, 1, func(conn net.Conn) {
		defer conn.Close()
		if err := handKey(conn, name, cgroup, root, cgroupOf); err != nil {
			fmt.Fprintf(os.Stderr, "run: clerk %s's key: %v\n", name, err)
		}
	})
}

func handKey(conn net.Conn, name, cgroup string, root *[clerkkey.Len]byte, cgroupOf func(pid int32) (string, error)) error {
	pid, ok := peerPID(conn)
	if !ok {
		return ErrKeyPeer
	}
	if c, err := cgroupOf(pid); err != nil || !unitCgroup(c, cgroup) {
		return ErrKeyPeer
	}
	k, err := clerkkey.Derive(root, name)
	if err != nil {
		return err
	}
	defer k.Wipe()
	b, err := clerkkey.Marshal(k)
	if err != nil {
		return err
	}
	defer clear(b)
	conn.SetWriteDeadline(time.Now().Add(keyWait))
	_, err = conn.Write(b)
	return err
}

// unitCgroup reports whether c, a peer's whole cgroup path, is the clerk's
// unit at cgroup: the same path, or, for a template's path (an empty
// instance), an instance of that template, named by a non-empty instance,
// in the same parent. Nothing nested under an instance matches: its path
// has another element.
func unitCgroup(c, cgroup string) bool {
	tmpl, ok := strings.CutSuffix(cgroup, "@.service")
	if !ok {
		return c == cgroup
	}
	inst, ok := strings.CutPrefix(c, tmpl+"@")
	inst, ok2 := strings.CutSuffix(inst, ".service")
	return ok && ok2 && inst != "" && !strings.ContainsAny(inst, "/@") && ValidCgroup(c)
}

// peerPID is the pid of the process that connected (SO_PEERCRED).
func peerPID(c net.Conn) (int32, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || cerr != nil || cred.Pid <= 0 {
		return 0, false
	}
	return cred.Pid, true
}

// procCgroup is the cgroup pid is in, read from /proc.
func procCgroup(pid int32) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", err
	}
	return cgroupPath(b)
}

// cgroupPath reads the unified (cgroup v2) line of a /proc/<pid>/cgroup
// file and returns its whole path. No unified line, or two, or a path that
// is no unit's cgroup, is an error.
func cgroupPath(b []byte) (string, error) {
	var c string
	n := 0
	for _, l := range bytes.Split(b, []byte("\n")) {
		if p, ok := bytes.CutPrefix(l, []byte("0::")); ok {
			c, n = string(p), n+1
		}
	}
	if n != 1 || !ValidCgroup(c) {
		return "", ErrKeyPeer
	}
	return c, nil
}
