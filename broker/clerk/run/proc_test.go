package run

// The helper processes the tests start: this test binary re-run with
// AGENTOS_RUN_ROLE set. The provider and the clerk run apart from the test
// process, which plays the kernel's process, so the clerk's secret never
// enters the test's memory: the clerk makes it up, and the test learns only
// its hash.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernelproc"
	"github.com/ghbmrk/agentos/broker/netguard"
)

const roleEnv = "AGENTOS_RUN_ROLE"

func TestMain(m *testing.M) {
	switch os.Getenv(roleEnv) {
	case "":
		os.Exit(m.Run())
	case "provider":
		provider()
	case "clerk":
		clerkProc()
	case "writer":
		writer()
	}
	os.Exit(3)
}

// testKey is the software sealer's key in every test: STO-2 has not landed,
// so no real store key exists.
var testKey = bytes.Repeat([]byte{0x5a}, 32)

func testSealer() clerk.Sealer {
	s, err := clerk.NewAESSealer(testKey)
	if err != nil {
		panic(err)
	}
	return s
}

func gen(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	p := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	return p.Public().(ed25519.PublicKey), p
}

// The owner's two hardware keys (D-146), the clerk key's holder and the
// log's head key.
var (
	ownerPub, ownerPriv   = gen(1)
	holderPub, holderPriv = gen(2)
	headPub, headPriv     = gen(3)
	sparePub, sparePriv   = gen(4)
	anchors               = []ed25519.PublicKey{ownerPub, sparePub}
)

// The one op the test clerk declares: a post to a recipient, with the secret
// as a bearer token.
func ops(base string) []clerk.Op {
	return []clerk.Op{{Verb: key.Post, Method: "POST", URL: base + "/v1/msg/{to}", Slot: "web", Prefix: "Bearer ", Type: clerk.TypeForm, Body: map[string]string{"msg": "msg"}, Content: "text", Labels: []string{"public"}}}
}

// guard resolves every name to a public address, then reaches addr.
func guard(addr string) *netguard.Policy {
	return netguard.New(netguard.Config{Resolver: resolver{}, Connect: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}})
}

type resolver struct{}

func (resolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

// provider is the fake remote. It writes its address and certificate to
// RUN_DIR, then logs each request's recipient and whether its bearer token
// hashes to RUN_SECRET_HASH's contents, synced, one line each. A request to
// "hang" never gets an answer.
func provider() {
	dir := os.Getenv("RUN_DIR")
	hits, err := os.OpenFile(filepath.Join(dir, "hits"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	fail(err)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want, _ := os.ReadFile(os.Getenv("RUN_SECRET_HASH"))
		got := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
		auth := "auth-bad"
		if hex.EncodeToString(got[:]) == strings.TrimSpace(string(want)) {
			auth = "auth-ok"
		}
		to := strings.TrimPrefix(r.URL.Path, "/v1/msg/")
		fmt.Fprintf(hits, "%s %s\n", to, auth)
		hits.Sync()
		if to == "hang" {
			select {}
		}
		w.WriteHeader(200)
	}))
	srv.StartTLS()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	fail(os.WriteFile(filepath.Join(dir, "cert.pem"), cert, 0o600))
	fail(os.WriteFile(filepath.Join(dir, "addr.tmp"), []byte(srv.Listener.Addr().String()), 0o600))
	fail(os.Rename(filepath.Join(dir, "addr.tmp"), filepath.Join(dir, "addr")))
	select {}
}

// clerkProc is the exit clerk's process: it seals a secret it makes up into
// its own Secrets file the first time (writing only the secret's hash for
// the test), then serves the exit on RUN_SOCK to the kernel's uid.
func clerkProc() {
	dir, pdir := os.Getenv("RUN_DIR"), os.Getenv("RUN_PROVIDER")
	sec, err := OpenSecrets(dir, testSealer())
	fail(err)
	if !sec.Has("web") {
		b := make([]byte, 16)
		rand.Read(b)
		secret := []byte("canary-" + hex.EncodeToString(b))
		h := sha256.Sum256(secret)
		fail(sec.Put("web", clerk.KindStatic, secret))
		clear(secret)
		fail(os.WriteFile(os.Getenv("RUN_SECRET_HASH"), []byte(hex.EncodeToString(h[:])), 0o600))
	}
	addr, err := os.ReadFile(filepath.Join(pdir, "addr"))
	fail(err)
	pemb, err := os.ReadFile(filepath.Join(pdir, "cert.pem"))
	fail(err)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemb)
	port := string(addr[bytes.LastIndexByte(addr, ':')+1:])
	d := clerk.Declaration{Name: "web", Ops: ops("https://example.com:" + port), Guard: guard(string(addr))}
	x, err := OpenExit(dir, testSealer(), d, anchors, roots)
	fail(err)
	uid, err := strconv.Atoi(os.Getenv("RUN_KERNEL_UID"))
	fail(err)
	ln, err := kernelproc.ListenClerk(os.Getenv("RUN_SOCK"), uid)
	fail(err)
	fail(kernelproc.ServeClerk(ln, x, anchors))
}

// writer puts a new secret into RUN_DIR's store, over and over, until killed.
func writer() {
	sec, err := OpenSecrets(os.Getenv("RUN_DIR"), testSealer())
	fail(err)
	for i := 0; ; i++ {
		fail(sec.Put("web", clerk.KindStatic, []byte(fmt.Sprintf("value-%08d-%s", i, strings.Repeat("x", i%4096)))))
	}
}

// start runs this test binary as role, killed when the test ends.
func start(t *testing.T, role string, env ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(append(os.Environ(), roleEnv+"="+role), env...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd
}

// waitFor polls ok for up to ten seconds.
func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// world is a provider process and the paths a clerk process uses.
type world struct {
	pdir, cdir, sock, hash string
	clerk                  *exec.Cmd
}

func newWorld(t *testing.T) *world {
	t.Helper()
	root := shortDir(t)
	w := &world{pdir: filepath.Join(root, "provider"), cdir: filepath.Join(root, "clerk"), sock: filepath.Join(root, "web.sock"), hash: filepath.Join(root, "secret.sha256")}
	for _, d := range []string{w.pdir, w.cdir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	start(t, "provider", "RUN_DIR="+w.pdir, "RUN_SECRET_HASH="+w.hash)
	waitFor(t, "the provider", func() bool { _, err := os.Stat(filepath.Join(w.pdir, "addr")); return err == nil })
	w.startClerk(t)
	return w
}

// startClerk starts the clerk process and waits until its socket answers.
func (w *world) startClerk(t *testing.T) {
	t.Helper()
	os.Remove(w.sock)
	w.clerk = start(t, "clerk", "RUN_DIR="+w.cdir, "RUN_PROVIDER="+w.pdir, "RUN_SOCK="+w.sock,
		"RUN_SECRET_HASH="+w.hash, "RUN_KERNEL_UID="+strconv.Itoa(os.Getuid()))
	waitFor(t, "the clerk's socket", func() bool {
		c, err := net.Dial("unix", w.sock)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
}

// kill ends the clerk process at once, as a crash does.
func (w *world) kill(t *testing.T) {
	t.Helper()
	w.clerk.Process.Signal(syscall.SIGKILL)
	w.clerk.Wait()
}

// hits is what the provider logged, one "recipient auth" line each.
func (w *world) hits(t *testing.T) []string {
	t.Helper()
	f, err := os.Open(filepath.Join(w.pdir, "hits"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	for s := bufio.NewScanner(f); s.Scan(); {
		out = append(out, s.Text())
	}
	return out
}

// secretHash is the hash the clerk process wrote of its secret.
func (w *world) secretHash(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(w.hash)
	if err != nil {
		t.Fatal(err)
	}
	h, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// findSecret reports whether r holds "canary-" and 32 hex digits hashing to h.
func findSecret(r io.Reader, h []byte) (bool, error) {
	const tag, n = "canary-", len("canary-") + 32
	b, err := io.ReadAll(r)
	if err != nil {
		return false, err
	}
	for i := bytes.Index(b, []byte(tag)); i >= 0; {
		if i+n <= len(b) {
			if s := sha256.Sum256(b[i : i+n]); bytes.Equal(s[:], h) {
				return true, nil
			}
		}
		j := bytes.Index(b[i+1:], []byte(tag))
		if j < 0 {
			break
		}
		i += 1 + j
	}
	return false, nil
}

// shortDir is a temporary directory with a short path: a socket's path must
// fit in 108 bytes, which a test's own TempDir under a long name may not.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "run")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}
