package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: CRED-5, CRED-1, A14, A3, DEV-2, RES-5

// planLogins is a stand-in for the vault's plan logins: one real token per
// worker, resolved only for the placeholder that worker holds.
type planLogins struct {
	real map[string]string // worker -> real access token
}

func (p planLogins) Resolve(provider, worker, ph string) (string, bool) {
	real, ok := p.real[worker]
	if !ok || provider != "codex" || ph != "ph-access-"+worker {
		return "", false
	}
	return real, true
}

func (planLogins) ForWorker(string, string) egress.Swapper { return nil }
func (planLogins) ForSignIn(string, string) egress.Swapper { return nil }

type upstream struct {
	mu   sync.Mutex
	seen []*http.Request
}

func (u *upstream) RoundTrip(r *http.Request) (*http.Response, error) {
	u.mu.Lock()
	u.seen = append(u.seen, r)
	u.mu.Unlock()
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "text/event-stream")
	io.WriteString(rec, "data: {\"type\":\"response.completed\"}\n\n")
	return rec.Result(), nil
}

type nopAudit struct {
	mu sync.Mutex
	ev []egress.Event
}

func (a *nopAudit) Egress(e egress.Event) {
	a.mu.Lock()
	a.ev = append(a.ev, e)
	a.mu.Unlock()
}

type workerRig struct {
	p       *workerRoutes
	ctl     http.Handler
	up      *upstream
	audit   *nopAudit
	real    map[string]string
	forgot  []string
	locked  bool
	dir     string
	forgetM sync.Mutex
}

func newWorkerRig(t *testing.T) *workerRig {
	t.Helper()
	// Unix socket paths are short; t.TempDir can exceed the limit.
	dir, err := os.MkdirTemp("", "rt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	r := &workerRig{
		up: &upstream{}, audit: &nopAudit{}, dir: dir,
		real: map[string]string{
			"pw-a": synthetic(t, "canary-access-a-"),
			"pw-b": synthetic(t, "canary-access-b-"),
		},
	}
	r.p = newWorkerRoutes(dir, func(worker string) (egress.WorkerRouteConfig, error) {
		if r.locked {
			return egress.WorkerRouteConfig{}, errors.New("vault locked")
		}
		return egress.WorkerRouteConfig{
			Route: egress.Codex(), Worker: worker, Logins: planLogins{r.real},
			Transport: r.up, Audit: r.audit,
		}, nil
	}, func(worker string) {
		r.forgetM.Lock()
		r.forgot = append(r.forgot, worker)
		r.forgetM.Unlock()
	})
	r.ctl = r.p.handler()
	t.Cleanup(r.p.closeAll)
	return r
}

func (r *workerRig) call(verb, machine string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/"+verb+"?machine="+machine, nil)
	w := httptest.NewRecorder()
	r.ctl.ServeHTTP(w, req)
	return w
}

func (r *workerRig) open(t *testing.T, machine string) string {
	t.Helper()
	w := r.call("open", machine)
	if w.Code != http.StatusOK {
		t.Fatalf("open %s: %d %s", machine, w.Code, w.Body)
	}
	var out struct{ Dir string }
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Dir == "" {
		t.Fatalf("open %s: bad reply %q", machine, w.Body)
	}
	return out.Dir
}

// through sends the pinned CLI's responses request over a route socket.
func through(t *testing.T, sock, placeholder string, extra http.Header) (*http.Response, error) {
	t.Helper()
	cl := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
	body := `{"model":"gpt-x","stream":true,"tool_choice":"auto","include":["reasoning.encrypted_content"],` +
		`"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}`
	req, _ := http.NewRequest("POST", "http://127.0.0.1:18432/backend-api/codex/responses", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+placeholder)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range extra {
		req.Header[k] = v
	}
	return cl.Do(req)
}

// The prefix the control socket accepts is the VM manager's provider
// prefix: one word, pinned here so the two cannot drift.
func TestA14ProviderPrefixIsTheManagers(t *testing.T) {
	if providerPrefix != vm.ProviderPrefix {
		t.Fatalf("egress accepts %q, the manager names provider workers %q", providerPrefix, vm.ProviderPrefix)
	}
}

// A provider worker's route socket serves that worker's route: its
// placeholder becomes the real login at the declared endpoint, and nothing
// real comes back (CRED-5, A14).
func TestCRED5OpenServesTheWorkersRouteOnItsSocket(t *testing.T) {
	r := newWorkerRig(t)
	dir := r.open(t, "pw-a")
	resp, err := through(t, filepath.Join(dir, RouteSocket), "ph-access-pw-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d %s", resp.StatusCode, b)
	}
	if len(r.up.seen) != 1 || r.up.seen[0].URL.String() != "https://chatgpt.com/backend-api/codex/responses" {
		t.Fatalf("upstream saw %v", r.up.seen)
	}
	if got := r.up.seen[0].Header.Get("Authorization"); got != "Bearer "+r.real["pw-a"] {
		t.Fatalf("upstream authorization %q, want the real login", got)
	}
	if strings.Contains(string(b), r.real["pw-a"]) {
		t.Fatal("the real login reached the worker")
	}
	if len(r.audit.ev) == 0 || r.audit.ev[0].Machine != "pw-a" {
		t.Fatalf("audit %v, want an event for pw-a", r.audit.ev)
	}
}

// The worker's identity is the socket it holds, never a header: pw-b's
// socket with pw-a's placeholder resolves nothing, whatever the request
// claims (CRED-1).
func TestCRED1WorkerIdentityIsTheSocketNotTheRequest(t *testing.T) {
	r := newWorkerRig(t)
	r.open(t, "pw-a")
	dirB := r.open(t, "pw-b")
	claim := http.Header{"X-Agentos-Machine": {"pw-a"}, "X-Worker": {"pw-a"}}
	resp, err := through(t, filepath.Join(dirB, RouteSocket), "ph-access-pw-a", claim)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode < 400 {
		t.Fatalf("status %d: pw-a's placeholder was accepted on pw-b's socket", resp.StatusCode)
	}
	if len(r.up.seen) != 0 {
		t.Fatal("a refused request reached the provider")
	}
}

// Each worker gets its own directory holding only the route socket, so the
// directory a worker is given reaches no other worker's route (A3).
func TestA3EachWorkerDirectoryHoldsOnlyItsOwnRouteSocket(t *testing.T) {
	r := newWorkerRig(t)
	da, db := r.open(t, "pw-a"), r.open(t, "pw-b")
	if da == db {
		t.Fatalf("both workers got %s", da)
	}
	for _, d := range []string{da, db} {
		if !strings.HasPrefix(d, r.dir+string(filepath.Separator)) {
			t.Fatalf("directory %s is outside the route root %s", d, r.dir)
		}
		ents, err := os.ReadDir(d)
		if err != nil {
			t.Fatal(err)
		}
		if len(ents) != 1 || ents[0].Name() != RouteSocket {
			t.Fatalf("%s holds %v, want only %s", d, ents, RouteSocket)
		}
	}
}

// Only a provider worker gets a route: plain workers, other machines and
// malformed names get none, and no directory appears (A14).
func TestA14OnlyProviderWorkersGetARoute(t *testing.T) {
	r := newWorkerRig(t)
	for _, m := range []string{"wk-1", "m1", "pw-", "pw-../x", "pw-A", "", "pw-a/b", "pw-" + strings.Repeat("a", 60)} {
		if w := r.call("open", m); w.Code != http.StatusBadRequest {
			t.Errorf("open %q: status %d, want 400", m, w.Code)
		}
	}
	ents, _ := os.ReadDir(r.dir)
	if len(ents) != 0 {
		t.Fatalf("refused opens left %v", ents)
	}
}

// With the vault locked there is no login to swap in, so no route opens
// and the machine does not start (fails closed).
func TestCRED5LockedVaultOpensNoRoute(t *testing.T) {
	r := newWorkerRig(t)
	r.locked = true
	if w := r.call("open", "pw-a"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", w.Code)
	}
	if ents, _ := os.ReadDir(r.dir); len(ents) != 0 {
		t.Fatalf("a locked open left %v", ents)
	}
}

// Close takes the socket and directory away, drops the worker's
// placeholders, and a second close is harmless (RES-5).
func TestRES5CloseRemovesTheRouteAndForgetsThePlaceholders(t *testing.T) {
	r := newWorkerRig(t)
	dir := r.open(t, "pw-a")
	if w := r.call("close", "pw-a"); w.Code != http.StatusOK {
		t.Fatalf("close: %d %s", w.Code, w.Body)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("directory survived close: %v", err)
	}
	if _, err := through(t, filepath.Join(dir, RouteSocket), "ph-access-pw-a", nil); err == nil {
		t.Fatal("route still answers after close")
	}
	if len(r.forgot) != 1 || r.forgot[0] != "pw-a" {
		t.Fatalf("forgot %v, want [pw-a]", r.forgot)
	}
	if w := r.call("close", "pw-a"); w.Code != http.StatusOK {
		t.Fatalf("second close: %d", w.Code)
	}
}

// Opening a worker that is already open replaces its route (a restart),
// leaving one socket that serves.
func TestRES5ReopenReplacesTheRoute(t *testing.T) {
	r := newWorkerRig(t)
	d1 := r.open(t, "pw-a")
	d2 := r.open(t, "pw-a")
	if d1 != d2 {
		t.Fatalf("reopen moved the directory: %s then %s", d1, d2)
	}
	resp, err := through(t, filepath.Join(d2, RouteSocket), "ph-access-pw-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d after reopen", resp.StatusCode)
	}
}

// Shutdown closes every route and leaves no directory (RES-5).
func TestRES5CloseAllRemovesEveryRoute(t *testing.T) {
	r := newWorkerRig(t)
	r.open(t, "pw-a")
	r.open(t, "pw-b")
	r.p.closeAll()
	if ents, _ := os.ReadDir(r.dir); len(ents) != 0 {
		t.Fatalf("closeAll left %v", ents)
	}
}

// The control socket takes POST /open and /close only.
func TestA14ControlTakesOnlyOpenAndClose(t *testing.T) {
	r := newWorkerRig(t)
	for _, c := range []struct{ method, path string }{
		{"GET", "/open?machine=pw-a"}, {"POST", "/other?machine=pw-a"}, {"DELETE", "/close?machine=pw-a"},
	} {
		w := httptest.NewRecorder()
		r.ctl.ServeHTTP(w, httptest.NewRequest(c.method, c.path, nil))
		if w.Code < 400 {
			t.Errorf("%s %s: status %d", c.method, c.path, w.Code)
		}
	}
	if ents, _ := os.ReadDir(r.dir); len(ents) != 0 {
		t.Fatalf("refused calls left %v", ents)
	}
}

func controlCall(t *testing.T, sock, path string) (int, error) {
	t.Helper()
	cl := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
	resp, err := cl.Post("http://egress"+path, "text/plain", nil)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// The control socket admits the broker's uid only, and while the vault is
// locked an open is refused (A14, CRED-5).
func TestA14ControlSocketAdmitsOnlyTheBroker(t *testing.T) {
	run, err := os.MkdirTemp("", "rc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(run) })
	c := &custody{notify: func(string) {}}

	other, err := serveWorkerRoutes(filepath.Join(run, "o"), c, os.Getuid()+1)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if code, err := controlCall(t, filepath.Join(run, "o", ProviderSocket), "/open?machine=pw-a"); err == nil {
		t.Fatalf("a peer that is not the broker got status %d", code)
	}

	mine, err := serveWorkerRoutes(filepath.Join(run, "m"), c, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer mine.Close()
	code, err := controlCall(t, filepath.Join(run, "m", ProviderSocket), "/open?machine=pw-a")
	if err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("locked open: status %d, err %v; want 503", code, err)
	}
}
