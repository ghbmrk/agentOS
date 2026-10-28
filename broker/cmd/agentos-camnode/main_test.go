package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camnode"
	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/camwire/camwiretest"
)

// REQ: NET-2, DEV-3, A16

// memElement is a secure element in memory: a synthetic device key and two
// counters that only rise.
type memElement struct {
	mu              sync.Mutex
	key             *ecdsa.PrivateKey
	settings, image uint64
	record          [32]byte
}

func (e *memElement) Public() ([camwire.PointLen]byte, error) {
	return camwiretest.Point(&e.key.PublicKey), nil
}
func (e *memElement) Sign(d []byte) ([]byte, error) { return ecdsa.SignASN1(rand.Reader, e.key, d) }
func (e *memElement) Settings() (uint64, [32]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.settings, e.record, nil
}
func (e *memElement) CommitBundle(c uint64, d [32]byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c <= e.settings {
		return errors.New("would not rise")
	}
	e.settings, e.record = c, d
	return nil
}
func (e *memElement) ClearBundle() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.record = [32]byte{}
	return nil
}
func (e *memElement) Image() (uint64, error) { return e.image, nil }
func (e *memElement) RaiseImage(c uint64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c <= e.image {
		return errors.New("would not rise")
	}
	e.image = c
	return nil
}

// genSource is generated video.
type genSource struct{}

func (genSource) Apply(camwire.Settings) error { return nil }
func (genSource) Read() (camwire.Frame, error) {
	time.Sleep(5 * time.Millisecond)
	return camwire.Frame{Type: camwire.TypeVideo, Payload: []byte{0, 0, 0, 1, 0x65, 0x88}}, nil
}

// TestMain runs the socket test's child when CAMNODE_CHILD is set: the
// binary's serve path on the listener passed as fd 3, in a network
// namespace of its own.
func TestMain(m *testing.M) {
	if os.Getenv("CAMNODE_CHILD") == "1" {
		os.Exit(child())
	}
	os.Exit(m.Run())
}

func child() int {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	el := &memElement{key: key}
	dir, err := os.MkdirTemp("", "camnode-child-")
	if err != nil {
		return 2
	}
	defer os.RemoveAll(dir)
	rel, _ := base64.StdEncoding.DecodeString(os.Getenv("CAMNODE_RELEASE"))
	os.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	ln, err := listener("")
	if err != nil {
		fmt.Println("listener:", err)
		return 2
	}
	ns, _ := os.Readlink("/proc/self/ns/net")
	pt, _ := el.Public()
	fmt.Printf("node %s %s\n", hex.EncodeToString(pt[:]), ns)
	go serve(ln, camnode.Config{
		Element: el, Store: camnode.FileStore{Dir: dir}, Source: genSource{}, Button: true, Release: rel,
		Ranges: camnode.Ranges{Resolutions: []camnode.Resolution{{Width: 1280, Height: 720}}, MaxFPS: 30, MinKbps: 500, MaxKbps: 8000},
	})
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		if in.Text() == "check" {
			fmt.Printf("sockets %d\n", sockets())
			return 0
		}
	}
	return 3
}

// sockets counts every socket in this network namespace: the rows of each
// /proc/self/net table but its header.
func sockets() int {
	n := 0
	for _, t := range []string{"tcp", "tcp6", "udp", "udp6", "raw", "raw6", "unix", "packet", "netlink"} {
		b, err := os.ReadFile("/proc/self/net/" + t)
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		if t == "netlink" {
			// The kernel's own netlink sockets are listed with port 0; a
			// process's have its port id.
			for _, l := range lines[1:] {
				if f := strings.Fields(l); len(f) > 2 && f[2] != "0" {
					n++
				}
			}
			continue
		}
		n += len(lines) - 1
	}
	return n
}

// TestNoOutboundDial (the binary's socket half; camnode's link half and
// capture's TestCaptureOpensNoSocket cover the libraries): the binary's
// serve path runs in a network namespace of its own on a listener passed
// as fd 3, so the listener and its connections live outside that
// namespace; after the node is provisioned, streams to the core and serves
// the enforcer, the namespace holds no socket at all. Revert mutant: a
// net.Dial or net.ListenPacket anywhere on the serve path.
func TestNoOutboundDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	lf, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "CAMNODE_CHILD=1", "LISTEN_FDS=1", "CAMNODE_RELEASE="+base64.StdEncoding.EncodeToString(pub))
	cmd.ExtraFiles = []*os.File{lf}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("no user and network namespace in CI: %v", err)
		}
		t.Skipf("no user and network namespace here: %v", err)
	}
	lf.Close()
	defer cmd.Process.Kill()
	out := bufio.NewScanner(stdout)
	if !out.Scan() {
		t.Fatal("child said nothing")
	}
	f := strings.Fields(out.Text())
	if len(f) != 3 || f[0] != "node" {
		t.Fatalf("child: %q", out.Text())
	}
	if own, _ := os.Readlink("/proc/self/ns/net"); own == f[2] {
		t.Fatal("child shares this network namespace")
	}
	raw, err := hex.DecodeString(f[1])
	if err != nil || len(raw) != camwire.PointLen {
		t.Fatalf("node point %q", f[1])
	}
	var node [camwire.PointLen]byte
	copy(node[:], raw)

	owner := camwiretest.NewPasskey(t)
	core, enforcer := camwiretest.NewKey(t), camwiretest.NewKey(t)
	dial := func(k *ecdsa.PrivateKey) *tls.Conn {
		cfg, err := camnode.ClientConfig(k, node)
		if err != nil {
			t.Fatal(err)
		}
		c, err := tls.Dial("tcp", ln.Addr().String(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(10 * time.Second))
		return c
	}
	b := camwire.Bundle{
		Node: camwire.Fingerprint(node), Counter: 1, Owner: owner.Owner(),
		Core: camwiretest.Point(&core.PublicKey), Enforcer: camwiretest.Point(&enforcer.PublicKey),
		Settings: camwire.Settings{Width: 1280, Height: 720, FPS: 25, BitrateKbps: 2000, Stream: true},
	}
	ec := dial(enforcer)
	if err := camwire.WriteFrame(ec, camwire.FromEnforcer, camwire.Shape{}, camwire.Frame{Type: camwire.TypeBundle, Payload: owner.SignBundle(t, b)}); err != nil {
		t.Fatal(err)
	}
	if _, err := camwire.ReadFrame(ec, camwire.ToEnforcer, camwire.Shape{}); err != nil {
		t.Fatalf("first bundle: %v", err)
	}
	cc := dial(core)
	for range 3 {
		if _, err := camwire.ReadFrame(cc, camwire.ToCore, camwire.Shape{}); err != nil {
			t.Fatalf("stream: %v", err)
		}
	}
	fmt.Fprintln(stdin, "check")
	if !out.Scan() {
		t.Fatal("child did not report")
	}
	if got := out.Text(); got != "sockets 0" {
		t.Fatalf("child's namespace: %s, want sockets 0", got)
	}
}

// TestBinaryImportsNoDialer (link half for the binary): no source file
// here imports a client package or calls a dialer; its one socket is the
// listener.
func TestBinaryImportsNoDialer(t *testing.T) {
	banned := map[string]bool{"net/http": true, "net/rpc": true, "net/smtp": true, "net/mail": true, "os/exec": true}
	dialers := map[string]bool{
		"Dial": true, "DialContext": true, "DialTCP": true, "DialUDP": true, "DialIP": true, "DialUnix": true,
		"DialTimeout": true, "Dialer": true, "ListenPacket": true, "ListenUDP": true, "ListenMulticastUDP": true, "ListenUnix": true,
	}
	files, _ := filepath.Glob("*.go")
	fs := token.NewFileSet()
	seen := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fs, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		seen++
		for _, im := range f.Imports {
			if p, _ := strconv.Unquote(im.Path.Value); banned[p] {
				t.Errorf("%s imports %s", name, p)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if s, ok := n.(*ast.SelectorExpr); ok && dialers[s.Sel.Name] {
				t.Errorf("%s: uses %s", fs.Position(s.Pos()), s.Sel.Name)
			}
			return true
		})
	}
	if seen == 0 {
		t.Fatal("no source files read")
	}
}
