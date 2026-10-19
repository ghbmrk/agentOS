package holder

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-1, CRED-7

// The process split, end to end (SIM-split): a "world" process stands in
// for the unlock step and the provider, a holder process keeps the login,
// and this test process is egress. Egress serves a guest request through
// the holder, never holds the login (its memory is scanned for it), and
// the holder gets its login back from the keeper after a restart.

const roleEnv = "AGENTOS_HOLDER_TEST_ROLE"

func TestMain(m *testing.M) {
	switch os.Getenv(roleEnv) {
	case "world":
		world(os.Getenv("AGENTOS_HOLDER_TEST_DIR"))
		return
	case "holder":
		holderChild(os.Getenv("AGENTOS_HOLDER_TEST_DIR"))
		return
	}
	os.Exit(m.Run())
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func freshCanary(prefix string) []byte {
	return []byte(prefix + strconv.FormatInt(time.Now().UnixNano(), 36) + fmt.Sprintf("%x", os.Getpid()) + "q7Zr0vWm3Lk9")
}

// world runs the provider and the keeper. The login is made here and
// leaves only to the holder, over the hand socket.
func world(dir string) {
	login := freshCanary("sk-canary-")
	control := freshCanary("sk-control-")
	prov := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+string(login) {
			http.Error(w, "bad login", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"echo":"%s"}`, login)
	}))
	prov.StartTLS()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: prov.Certificate().Raw})
	// Egress redacts every vault value; the scan uses one probe for the
	// login and one for the control.
	files := map[string][]byte{
		"provider": []byte(prov.Listener.Addr().String()),
		"cert.pem": cert,
		"control":  control,
	}
	for name, vals := range map[string][][]byte{
		"redactor":      {login, control},
		"probe-login":   {login},
		"probe-control": {control},
	} {
		r, err := vault.NewHashRedactor(vals)
		if err != nil {
			fail(err)
		}
		files[name], _ = r.MarshalBinary()
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			fail(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "ready"), nil, 0o600); err != nil {
		fail(err)
	}
	k := &Keeper{Socket: filepath.Join(dir, HandSocket), Secret: func() ([]byte, error) {
		return append([]byte(nil), login...), nil
	}, Every: 20 * time.Millisecond}
	k.Run(context.Background())
}

// holderChild is the holder process: it trusts the world's provider and
// dials it for the adapter's host.
func holderChild(dir string) {
	addr, err := os.ReadFile(filepath.Join(dir, "provider"))
	if err != nil {
		fail(err)
	}
	cert, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if err != nil {
		fail(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cert)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", string(addr))
		},
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"},
	}
	h, err := New(Config{Adapters: []egress.Adapter{egress.OpenAI("openai-key")}, Transport: tr})
	if err != nil {
		fail(err)
	}
	reqs, err := Listen(filepath.Join(dir, RequestSocket), os.Getuid())
	if err != nil {
		fail(err)
	}
	hand, err := Listen(filepath.Join(dir, HandSocket), os.Getuid())
	if err != nil {
		fail(err)
	}
	fail(h.Serve(reqs, hand))
}

func start(t *testing.T, role, dir string) *exec.Cmd {
	t.Helper()
	c := exec.Command(os.Args[0], "-test.run=^$")
	c.Env = append(os.Environ(), roleEnv+"="+role, "AGENTOS_HOLDER_TEST_DIR="+dir)
	c.Stderr = os.Stderr
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Process.Kill(); c.Wait() })
	return c
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type journal struct{ events []egress.Event }

func (j *journal) Egress(e egress.Event) { j.events = append(j.events, e) }

func TestEgressHoldsNoLoginAcrossProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	dir := socketDir(t)
	start(t, "world", dir)
	waitFor(t, "the world", func() bool { _, err := os.Stat(filepath.Join(dir, "ready")); return err == nil })
	holder := start(t, "holder", dir)

	red := loadRedactor(t, dir, "redactor")
	p, err := egress.New(egress.Config{
		Adapters:  []egress.Adapter{egress.OpenAI("openai-key")},
		Grants:    map[string][]string{"m1": {"openai"}},
		Redaction: func() (egress.Redactor, error) { return red, nil },
		Holders:   map[string]http.RoundTripper{"openai-key": Client(filepath.Join(dir, RequestSocket))},
		Audit:     &journal{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ask := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(`{"model":"m","messages":[]}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer placeholder")
		w := httptest.NewRecorder()
		p.Handler("m1").ServeHTTP(w, r)
		return w
	}
	var w *httptest.ResponseRecorder
	waitFor(t, "the first answer", func() bool { w = ask(); return w.Code == 200 })
	if !strings.Contains(w.Body.String(), vault.Placeholder) {
		t.Fatalf("answer %s", w.Body)
	}

	// Egress's memory, after serving, holds no form of the login. The scan
	// is a hashed redactor over the login alone: a match adds a
	// placeholder. Its control is the same scan for a value this process
	// did read.
	control, err := os.ReadFile(filepath.Join(dir, "control"))
	if err != nil {
		t.Fatal(err)
	}
	if n := scanSelf(t, loadRedactor(t, dir, "probe-control")); n == 0 {
		t.Fatal("control: the memory scan missed a value this process holds")
	}
	if n := scanSelf(t, loadRedactor(t, dir, "probe-login")); n != 0 {
		t.Fatalf("egress memory holds the login: %d matches", n)
	}

	// A holder that dies takes the route down; one that restarts gets its
	// login from the keeper, not from egress.
	holder.Process.Kill()
	holder.Wait()
	if w := ask(); w.Code == 200 {
		t.Fatalf("answered with the holder down: %s", w.Body)
	}
	start(t, "holder", dir)
	waitFor(t, "the restarted holder", func() bool { return ask().Code == 200 })
	// The control must stay reachable until its scan is done: `_ =
	// control[0]` needs only the length, so the collector could free and
	// reuse its bytes first, and the control then missed (the old flake).
	runtime.KeepAlive(control)
}

func loadRedactor(t *testing.T, dir, name string) *vault.HashRedactor {
	t.Helper()
	enc, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	var r vault.HashRedactor
	if err := r.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	return &r
}

// scanSelf reads every writable mapping of this process and returns how
// many spans r redacts in it.
func scanSelf(t *testing.T, r *vault.HashRedactor) int {
	t.Helper()
	maps, err := os.Open("/proc/self/maps")
	if err != nil {
		t.Skip("no /proc/self/maps")
	}
	defer maps.Close()
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		t.Skip("no /proc/self/mem")
	}
	defer mem.Close()
	const chunk = 1 << 20
	over := r.MaxLen()
	buf := make([]byte, chunk+over)
	ph := []byte(vault.Placeholder)
	found := 0
	sc := bufio.NewScanner(maps)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || !strings.HasPrefix(f[1], "rw") {
			continue
		}
		if len(f) >= 6 && (f[5] == "[vvar]" || f[5] == "[vsyscall]") {
			continue
		}
		var lo, hi uint64
		if _, err := fmt.Sscanf(f[0], "%x-%x", &lo, &hi); err != nil {
			continue
		}
		for at := lo; at < hi; at += chunk {
			n := uint64(len(buf))
			if at+n > hi {
				n = hi - at
			}
			got, err := mem.ReadAt(buf[:n], int64(at))
			if got == 0 && err != nil {
				break
			}
			b := buf[:got]
			if allZero(b) {
				continue
			}
			if d := bytes.Count(r.Redact(b), ph) - bytes.Count(b, ph); d > 0 {
				found += d
			}
		}
	}
	return found
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
