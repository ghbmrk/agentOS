package peers

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestListenNeedsAPeer(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.sock")
	ln, err := Listen(p)
	if err == nil || ln != nil || !strings.Contains(err.Error(), "at least one peer uid") {
		t.Fatalf("Listen with no uid = %v, %v; want the no-peer error", ln, err)
	}
	if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Listen with no uid made %s: %v", p, err)
	}
}

// accept runs one Accept on ln and hands on what it returns.
func accept(ln net.Listener) (<-chan net.Conn, <-chan error) {
	conns, errs := make(chan net.Conn, 1), make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errs <- err
			return
		}
		conns <- c
	}()
	return conns, errs
}

func TestListenAdmitsOnlyItsUIDs(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.sock")
	// A stale file at the path is replaced.
	if err := os.WriteFile(p, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(p, os.Getuid()+1, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(p)
	if err != nil || fi.Mode().Type() != os.ModeSocket || fi.Mode().Perm() != 0o666 {
		t.Fatalf("socket file = %v, %v; want a socket of mode 0666", fi, err)
	}
	conns, errs := accept(ln)
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case s := <-conns:
		defer s.Close()
		if uid, ok := UID(s); !ok || uid != os.Getuid() {
			t.Fatalf("UID of the accepted conn = %d, %v; want %d", uid, ok, os.Getuid())
		}
		if uid, ok := UID(c); !ok || uid != os.Getuid() {
			t.Fatalf("UID of the dialled conn = %d, %v; want %d", uid, ok, os.Getuid())
		}
	case err := <-errs:
		t.Fatalf("Accept: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("a listed uid was not admitted")
	}
	ln.Close()
	if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the socket file outlived its listener: %v", err)
	}
}

func TestListenClosesOtherUIDsUnread(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.sock")
	ln, err := Listen(p, os.Getuid()+1)
	if err != nil {
		t.Fatal(err)
	}
	conns, errs := accept(ln)
	for i := 0; i < 2; i++ { // Accept keeps refusing: it does not return on the first refusal
		c, err := net.Dial("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		if n, err := c.Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Fatalf("dial %d by an unlisted uid read %d, %v; want the connection closed", i, n, err)
		}
		c.Close()
	}
	select {
	case c := <-conns:
		c.Close()
		t.Fatal("an unlisted uid was admitted")
	case err := <-errs:
		t.Fatalf("Accept ended early: %v", err)
	default:
	}
	ln.Close()
	select {
	case err := <-errs:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close = %v; want net.ErrClosed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Accept did not end when the listener closed")
	}
}

func TestListenFailures(t *testing.T) {
	dir := t.TempDir()
	// A path that cannot be removed: a directory with a file in it.
	full := filepath.Join(dir, "full")
	if err := os.MkdirAll(filepath.Join(full, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if ln, err := Listen(full, os.Getuid()); err == nil {
		ln.Close()
		t.Fatal("Listen replaced a directory")
	}
	if _, err := os.Stat(filepath.Join(full, "x")); err != nil {
		t.Fatalf("Listen touched the directory: %v", err)
	}
	// A path whose directory does not exist: Remove reads it as absent, Listen fails.
	if ln, err := Listen(filepath.Join(dir, "none", "s.sock"), os.Getuid()); err == nil {
		ln.Close()
		t.Fatal("Listen made a socket in a missing directory")
	}
}

func TestUIDOfANonUnixConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if uid, ok := UID(a); ok || uid != 0 {
		t.Fatalf("UID of a pipe = %d, %v; want 0, false", uid, ok)
	}
	// A closed unix conn has no peer to read.
	p := filepath.Join(t.TempDir(), "s.sock")
	ln, err := Listen(p, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if uid, ok := UID(c); ok || uid != 0 {
		t.Fatalf("UID of a closed conn = %d, %v; want 0, false", uid, ok)
	}
}
