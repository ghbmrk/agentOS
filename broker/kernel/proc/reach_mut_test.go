package proc

// REQ: KRN-7, LOG-4, BAK-1
//
// MUT-kill-6305-proc (#6367): the clerk key hand-off, the clerk and kernel
// sockets' refusals, the log's open, a restore's item frames and the
// content store's bound, each checked by what they return or leave.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/kernel"
)

const testUnit = "/a.slice/mail.service"

// unixPair is a connected pair of unix sockets in this process.
func unixPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out [2]*net.UnixConn
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "pair")
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[i] = c.(*net.UnixConn)
		t.Cleanup(func() { c.Close() })
	}
	return out[0], out[1]
}

func inUnit(int32) (string, error) { return testUnit, nil }

// A key goes only over a unix socket; one the peer never reads is given up
// after keyWait; a refused peer is said on stderr; a closed socket has no
// peer.
func TestAKeyHandOffRefusesAndGivesUp(t *testing.T) {
	root := [clerkkey.Len]byte{1}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := handKey(a, "mail", testUnit, &root, inUnit); !errors.Is(err, ErrKeyPeer) {
		t.Fatalf("a hand-off over a pipe: %v, want ErrKeyPeer", err)
	}
	srv, _ := unixPair(t)
	for {
		srv.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
		if _, err := srv.Write(make([]byte, 4096)); err != nil {
			break
		}
	}
	srv.SetWriteDeadline(time.Time{})
	done := make(chan error, 1)
	go func() { done <- handKey(srv, "mail", testUnit, &root, inUnit) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a key went to a peer that reads nothing")
		}
	case <-time.After(keyWait + 3*time.Second):
		t.Fatal("the hand-off waits on a peer that never reads")
	}
	c, _ := unixPair(t)
	c.Close()
	if _, ok := peerPID(c); ok {
		t.Fatal("a closed socket has a peer")
	}
	p := filepath.Join(t.TempDir(), "key.sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	said := stderrOf(t, func() {
		served := make(chan error, 1)
		go func() {
			served <- serveClerkKey(ln, "mail", testUnit, &root, func(int32) (string, error) { return "/other.service", nil })
		}()
		conn, err := net.Dial("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := io.ReadAll(conn); len(got) != 0 {
			t.Errorf("a refused peer read %d bytes", len(got))
		}
		conn.Close()
		ln.Close()
		<-served
	})
	if !strings.Contains(said, "run: clerk mail's key: "+ErrKeyPeer.Error()) {
		t.Fatalf("a refused peer is not said: %q", said)
	}
}

// procCgroup reads this process's cgroup and keeps no descriptor; a pid
// that is gone has none.
func TestProcCgroupReadsAndCloses(t *testing.T) {
	if _, err := procCgroup(1 << 30); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the cgroup of a pid that is gone: %v", err)
	}
	p := filepath.Join("/proc", itoa(uint64(os.Getpid())), "cgroup")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want, werr := cgroupPath(b)
	for range 3 {
		got, err := procCgroup(int32(os.Getpid()))
		if got != want || (err == nil) != (werr == nil) {
			t.Fatalf("procCgroup %q %v, want %q %v", got, err, want, werr)
		}
		if n := openFDsTo(t, p); n != 0 {
			t.Fatalf("%d descriptors to the cgroup file stay open", n)
		}
	}
}

// countClerk counts the calls it takes.
type countClerk struct{ n *atomic.Int32 }

func (c countClerk) Do(kernel.Request, kernel.View) kernel.Result {
	c.n.Add(1)
	return kernel.Result{Outcome: "ok"}
}

func (c countClerk) Probe(kernel.Request, kernel.View) kernel.Result {
	c.n.Add(1)
	return kernel.Result{Outcome: "done"}
}

// A call the clerk or the kernel cannot decode is closed unanswered, even
// one whose op decoded before the error.
func TestACallThatDoesNotDecodeIsNeverServed(t *testing.T) {
	n := new(atomic.Int32)
	a, b := net.Pipe()
	go serve(b, countClerk{n}, nil)
	a.Write([]byte(`{"op":"probe","req":5}` + "\n"))
	if got, _ := io.ReadAll(a); len(got) != 0 || n.Load() != 0 {
		t.Fatalf("a clerk answered %q to a call it could not decode, %d calls", got, n.Load())
	}
	a, b = net.Pipe()
	go ServeOne(b, func(string, json.RawMessage) (json.RawMessage, error) { n.Add(1); return nil, nil })
	a.Write([]byte(`{"op":5}` + "\n"))
	if got, _ := io.ReadAll(a); len(got) != 0 || n.Load() != 0 {
		t.Fatalf("the kernel answered %q to a call it could not decode, %d calls", got, n.Load())
	}
}

// A clerk that closes without an answer gives none, its call sent; a Remote
// carries the anchors it is given.
func TestAClerkThatClosesGivesNoAnswer(t *testing.T) {
	p := filepath.Join(t.TempDir(), "clerk.sock")
	ln, err := net.Listen("unix", p)
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
			io.ReadFull(c, make([]byte, 1))
			c.Close()
		}
	}()
	r := Remote{Socket: p, UID: os.Getuid()}.Clerk(anchors).(remote)
	if got := r.keys(); len(got) != len(anchors) || len(got) == 0 || got[0] != anchors[0] {
		t.Fatalf("the Remote's anchors: %v", got)
	}
	if a, sent, big := r.call(opProbe, kernel.Request{}, snapshot{}); a != nil || !sent || big {
		t.Fatalf("a clerk that closes: %+v sent %v big %v, want no answer, sent", a, sent, big)
	}
}

// The log refuses a file open to other uids and one another kernel holds,
// keeping no descriptor of its own to either.
func TestTheLogRefusesAndReleases(t *testing.T) {
	p := filepath.Join(t.TempDir(), "log")
	s, err := OpenFileStore(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(p); !errors.Is(err, ErrLogInUse) || openFDsTo(t, p) != 1 {
		t.Fatalf("a second open: %v, %d descriptors, want ErrLogInUse and the first's one", err, openFDsTo(t, p))
	}
	s.Close()
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(p); err == nil || !strings.Contains(err.Error(), "open to other uids") || openFDsTo(t, p) != 0 {
		t.Fatalf("a log open to other uids: %v, %d descriptors", err, openFDsTo(t, p))
	}
}

// frameOf is n as an item frame's length after hash h, then body.
func frameOf(h [32]byte, n uint32, body []byte) []byte {
	return append(binary.BigEndian.AppendUint32(h[:], n), body...)
}

// A restore refuses a frame cut in its header or its body, even where the
// zeros a cut leaves would match the hash.
func TestARestoreRefusesACutFrame(t *testing.T) {
	empty, tenZeros := sha256.Sum256(nil), sha256.Sum256(make([]byte, 10))
	for name, sec := range map[string][]byte{
		"a cut header": frameOf(empty, 0, nil)[:itemFrame-1],
		"a cut body":   frameOf(tenZeros, 10, make([]byte, 5)),
		"no body":      frameOf(tenZeros, 10, nil),
	} {
		dir := filepath.Join(t.TempDir(), "s")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := restoreItems(bytes.NewReader(sec), dir, nil); !errors.Is(err, ErrContentSection) {
			t.Fatalf("%s: %v, want ErrContentSection", name, err)
		}
	}
}

// A store refuses an item over maxSealed and writes nothing.
func TestAStoreRefusesAnItemOverItsBound(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mail")
	f, _, err := openFileContent(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Put(kernel.Hash{1}, make([]byte, maxSealed+1)); !errors.Is(err, kernel.ErrItem) {
		t.Fatalf("a put over maxSealed: %v, want ErrItem", err)
	}
	if n := names(t, dir); len(n) != 0 {
		t.Fatalf("the store holds %q", n)
	}
}

// A start whose content stores do not open says so and releases the log.
func TestAStartWhoseStoresDoNotOpenReleasesTheLog(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists any directory; CI runs these as a plain user")
	}
	dir := t.TempDir()
	content := filepath.Join(dir, "content")
	if err := os.Mkdir(content, 0o300); err != nil {
		t.Fatal(err)
	}
	cfg := KernelConfig{Log: filepath.Join(dir, "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7}, Pub: headPub, Sign: headPriv,
		Anchors: anchors, KeyDir: filepath.Join(dir, "keys"), ContentDir: content}
	if _, err := OpenKernel(cfg, 1_000_000); err == nil || !strings.Contains(err.Error(), "the content stores") {
		t.Fatalf("a start whose stores do not open: %v", err)
	}
	s, err := OpenFileStore(cfg.Log)
	if err != nil {
		t.Fatalf("the refused start kept the log: %v", err)
	}
	s.Close()
}
