package main

// REQ: CLK-1, NET-2, RES-2

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/camera"
	"github.com/ghbmrk/agentos/broker/clerk/camera/decodehost"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
	"golang.org/x/sys/unix"
)

// TestDecoderStartsInItsUnit runs as one session of the image's own
// agentos-camdecode@.service, started by the image's agentos-camdecode.socket
// under the image's own systemd on a connection from the clerk's user, with
// only ExecStart= and its output replaced (CI's camera decoder step,
// tools/camdecode_unit.py). Its user is neither root nor the clerk's and it
// tells the step its uid on the connection, so the step can see that two
// sessions at once have two. It cannot write the clerk's runtime directory,
// see the clerk's state, or open a session of its own; and a decoder
// sandbox starts under runsc beside its leaf of the unit's delegated group,
// held to its memory cap, with no network, and is gone after its stop.
func TestDecoderStartsInItsUnit(t *testing.T) {
	bin, root, state, clerkUser := os.Getenv("AGENTOS_RUNSC"), os.Getenv("AGENTOS_DECODE_ROOT"),
		os.Getenv("AGENTOS_RUNSC_ROOT"), os.Getenv("AGENTOS_CLERK_USER")
	if bin == "" || root == "" || state == "" || clerkUser == "" {
		t.Skip("set AGENTOS_RUNSC, AGENTOS_DECODE_ROOT, AGENTOS_RUNSC_ROOT and AGENTOS_CLERK_USER, and run in the decoder unit (CI)")
	}
	clerk, err := user.Lookup(clerkUser)
	if err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	if uid == 0 || strconv.Itoa(uid) == clerk.Uid || os.Geteuid() != uid {
		t.Fatalf("the session runs as uid %d (euid %d); the clerk's is %s", uid, os.Geteuid(), clerk.Uid)
	}
	// A pid namespace of its own (PrivatePIDs=, systemd 257), where it is
	// PID 1, so it sees and signals no other session; and an empty /run,
	// so none of the box's path sockets (#4392).
	if pid := os.Getpid(); pid != 1 {
		t.Errorf("the session is pid %d, not 1 in a pid namespace of its own", pid)
	}
	runHolds(t, "/run")
	conn, err := net.FileConn(os.Stdin)
	if err != nil {
		t.Fatalf("standard input is not the session's connection: %v", err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "uid %d\n", uid); err != nil {
		t.Fatal(err)
	}

	// None of the clerk's: its owner socket's directory, its state, its
	// decoder socket.
	if f, err := os.CreateTemp("/run/agentos-camera", "escape"); err == nil {
		f.Close()
		os.Remove(f.Name())
		t.Error("the session wrote the clerk's runtime directory")
	}
	if _, err := os.ReadDir("/var/lib/agentos-camera"); err == nil {
		t.Error("the session reads the clerk's state directory")
	}
	if f, err := os.CreateTemp("/var/lib/agentos-camera", "escape"); err == nil {
		f.Close()
		os.Remove(f.Name())
		t.Error("the session wrote the clerk's state directory")
	}
	if c, err := net.Dial("unix", "/run/agentos-camdecode/conn.sock"); err == nil {
		c.Close()
		t.Error("the session opened a session of its own")
	}

	cg, err := decodehost.OwnCgroup("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cg, "agentos-camdecode@") {
		t.Fatalf("the session runs in %s", cg)
	}
	if err := decodehost.Leave(cg); err != nil {
		t.Fatal(err)
	}
	if got, _ := decodehost.OwnCgroup("/proc/self/cgroup"); got != filepath.Join(cg, "host") {
		t.Fatalf("after the join the session runs in %s", got)
	}
	start := decodehost.GVisor(runtime(config{runsc: bin, runscRoot: state, decodeRoot: root}))
	s := gvisor.Stream{Name: "camdecode", Root: root, Argv: []string{"/oneshot", "echo"},
		MemBytes: camera.DefaultDecodeMem, Cgroup: cg}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p, err := start(ctx, s)
	if err != nil {
		t.Fatalf("decoder sandbox: %v", err)
	}
	group := filepath.Join(cg, "stream-"+s.Name)
	if b, err := os.ReadFile(filepath.Join(group, "memory.max")); err != nil || strings.TrimSpace(string(b)) != strconv.Itoa(camera.DefaultDecodeMem) {
		t.Errorf("the sandbox's memory.max = %q, %v", b, err)
	}
	if _, err := p.In().Write([]byte("frame\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(p.Out()).ReadString('\n')
	if err != nil || line != "frame\n" {
		p.Stop()
		<-p.Done()
		t.Fatalf("decoder answered %q, %v; %s", line, err, why(p, state))
	}
	p.Stop()
	<-p.Done()
	if _, err := os.Stat(group); !os.IsNotExist(err) {
		t.Errorf("the sandbox's group is left: %v", err)
	}

	// No network in the sandbox.
	s.Argv = []string{"/oneshot", "net", "192.168.1.1:80"}
	p, err = start(ctx, s)
	if err != nil {
		t.Fatalf("decoder sandbox: %v", err)
	}
	p.In().(io.Closer).Close()
	out, _ := io.ReadAll(p.Out())
	<-p.Done()
	if !strings.Contains(string(out), "dial failed") {
		t.Errorf("the decoder dialled out: %q", out)
	}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(l, "iface ") && l != "iface lo" {
			t.Errorf("the decoder sees %q", l)
		}
	}
}

// why is what ended a sandbox early: its run's error and runsc's own
// lines, which the runtime keeps in its exec log.
func why(p camera.Proc, state string) string {
	out := ""
	if e, ok := p.(interface{ Err() error }); ok {
		out = fmt.Sprintf("the run ended: %v", e.Err())
	}
	if b, err := os.ReadFile(filepath.Join(state, "exec.log")); err == nil {
		out += "\n-- runsc\n" + string(b)
	}
	return out
}

// runHolds fails t unless the session's /run holds nothing but
// directories (the mount points systemd leaves under the empty tmpfs), so
// no socket or file of the box's is there to open. Each entry is logged
// with its mode. A directory the walk cannot list counts only if the
// session cannot search it either: a socket in a directory it can search
// but not list is still open to it by name.
// logger is what runHolds reports to: a *testing.T.
type logger interface {
	Errorf(string, ...any)
	Logf(string, ...any)
}

func runHolds(t logger, run string) {
	err := filepath.WalkDir(run, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() && errors.Is(err, fs.ErrPermission) && errors.Is(unix.Faccessat(unix.AT_FDCWD, p, unix.X_OK, unix.AT_EACCESS), unix.EACCES) {
				t.Logf("/run: %s cannot be listed or searched", p)
				return fs.SkipDir
			}
			t.Errorf("the session's /run: %s: %v", p, err)
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			t.Errorf("the session's /run: %s: %v", p, ierr)
			return nil
		}
		t.Logf("/run holds %s %v", p, info.Mode())
		if !d.IsDir() {
			t.Errorf("the session's /run holds %s (%v); want only directories", p, info.Mode())
		}
		return nil
	})
	if err != nil {
		t.Errorf("the session's /run: %v", err)
	}
}
