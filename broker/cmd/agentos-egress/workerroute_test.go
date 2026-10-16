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
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/vault"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: CRED-5, CRED-1, A14, A3, DEV-2, RES-5

// planLogins is a stand-in for the vault's plan logins: one real token per
// worker, resolved only for the placeholder that worker holds. Forget drops
// a worker's placeholder as PlanLogins.Forget does, so a route that forgets
// on the wrong path fails here as it would on the box.
type planLogins struct {
	real map[string]string // worker -> real access token

	mu     sync.Mutex
	forgot map[string]bool
}

func (p *planLogins) Resolve(provider, worker, ph string) (string, bool) {
	p.mu.Lock()
	gone := p.forgot[worker]
	p.mu.Unlock()
	real, ok := p.real[worker]
	if gone || !ok || provider != "codex" || ph != "ph-access-"+worker {
		return "", false
	}
	return real, true
}

func (p *planLogins) Forget(worker string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.forgot[worker] = true
}

func (*planLogins) ForWorker(string, string) egress.Swapper { return nil }
func (*planLogins) ForSignIn(string, string) egress.Swapper { return nil }
func (*planLogins) ShareRefresh(_ context.Context, _ string, x func() (*egress.Exchanged, error)) (*egress.Exchanged, func(), error) {
	res, err := x()
	return res, func() {}, err
}

type upstream struct {
	mu    sync.Mutex
	seen  []*http.Request
	quota http.Header // headers the next replies carry
}

func (u *upstream) RoundTrip(r *http.Request) (*http.Response, error) {
	u.mu.Lock()
	u.seen = append(u.seen, r)
	quota := u.quota.Clone()
	u.mu.Unlock()
	rec := httptest.NewRecorder()
	for k, v := range quota {
		rec.Header()[k] = v
	}
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
	usage   egress.PlanUsage
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
	logins := &planLogins{real: r.real, forgot: map[string]bool{}}
	r.p = newWorkerRoutes(dir, func(worker string) (egress.WorkerRouteConfig, error) {
		if r.locked {
			return egress.WorkerRouteConfig{}, errors.New("vault locked")
		}
		return codexRouteConfig(worker, logins, r.up, nil, r.audit, &r.usage), nil
	}, func(worker string) {
		r.forgetM.Lock()
		r.forgot = append(r.forgot, worker)
		r.forgetM.Unlock()
		logins.Forget(worker)
	}, func(worker string) (map[string][]byte, error) {
		if r.locked {
			return nil, egress.ErrVaultLocked
		}
		return map[string][]byte{egress.CodexAuthFile: []byte("ph-access-" + worker)}, nil
	})
	r.p.usage = r.usage.Snapshot
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
// leaving one socket that serves. The worker keeps its placeholders: the
// auth.json already in its layer must still resolve (only /close and
// shutdown forget them).
func TestRES5ReopenReplacesTheRoute(t *testing.T) {
	r := newWorkerRig(t)
	d1 := r.open(t, "pw-a")
	d2 := r.open(t, "pw-a")
	if d1 != d2 {
		t.Fatalf("reopen moved the directory: %s then %s", d1, d2)
	}
	if len(r.forgot) != 0 {
		t.Fatalf("reopen forgot %v; a restarted worker's placeholders must survive", r.forgot)
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

// Shutdown closes every route, forgets every worker's placeholders and
// leaves no directory (RES-5).
func TestRES5CloseAllRemovesEveryRoute(t *testing.T) {
	r := newWorkerRig(t)
	r.open(t, "pw-a")
	r.open(t, "pw-b")
	r.p.closeAll()
	if ents, _ := os.ReadDir(r.dir); len(ents) != 0 {
		t.Fatalf("closeAll left %v", ents)
	}
	sort.Strings(r.forgot)
	if strings.Join(r.forgot, ",") != "pw-a,pw-b" {
		t.Fatalf("closeAll forgot %v, want [pw-a pw-b]", r.forgot)
	}
}

// The control socket takes POST /open, /close and /seed only.
func TestA14ControlTakesOnlyOpenCloseAndSeed(t *testing.T) {
	r := newWorkerRig(t)
	for _, c := range []struct{ method, path string }{
		{"GET", "/open?machine=pw-a"}, {"POST", "/other?machine=pw-a"}, {"DELETE", "/close?machine=pw-a"},
		{"GET", "/seed?machine=pw-a"}, {"POST", "/seed?machine=wk-1"},
		{"GET", "/usage?provider=codex"}, {"POST", "/usage?provider=Codex!"}, {"POST", "/usage"},
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
	resp, err := cl.Post("http://localhost"+path, "text/plain", nil)
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

// The route directory is 0700 and its socket 0600 whatever the umask, so no
// other host uid reaches a worker's route; only the egress uid, and runsc
// (root) through the worker's mount, do (A14, egress K28).
func TestA14RouteModesIgnoreTheUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	r := newWorkerRig(t)
	dir := r.open(t, "pw-a")
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m := fi.Mode().Perm(); m != 0o700 {
		t.Fatalf("route directory mode %o, want 700", m)
	}
	fi, err = os.Stat(filepath.Join(dir, RouteSocket))
	if err != nil {
		t.Fatal(err)
	}
	if m := fi.Mode().Perm(); m != 0o600 {
		t.Fatalf("route socket mode %o, want 600", m)
	}
}

// A directory left by a crashed vault process does not stop the worker from
// opening again (RES-5).
func TestRES5OpenOverACrashLeftover(t *testing.T) {
	r := newWorkerRig(t)
	stale := filepath.Join(r.dir, "pw-a")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, RouteSocket), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := r.open(t, "pw-a")
	resp, err := through(t, filepath.Join(dir, RouteSocket), "ph-access-pw-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d over a leftover directory", resp.StatusCode)
	}
}

// Starting the control socket clears route directories a crashed process
// left: their workers' mounts then point at nothing, which fails closed.
func TestRES5ServeClearsLeftoverRoutes(t *testing.T) {
	run, err := os.MkdirTemp("", "rl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(run) })
	stale := filepath.Join(run, workerRouteRoot, "pw-x")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	cl, err := serveWorkerRoutes(run, &custody{notify: func(string) {}}, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("leftover route directory survived the start: %v", err)
	}
}

// /seed hands agentosd the worker's placeholder files before the machine
// starts; a locked vault is a one-line 503 and a non-provider id 400
// (CRED-5, #1015).
func TestCRED5SeedServesTheWorkersPlaceholders(t *testing.T) {
	r := newWorkerRig(t)
	w := r.call("seed", "pw-a")
	if w.Code != http.StatusOK {
		t.Fatalf("seed: %d %s", w.Code, w.Body)
	}
	var got map[string][]byte
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || string(got[egress.CodexAuthFile]) != "ph-access-pw-a" {
		t.Fatalf("seed reply %q (%v)", w.Body, err)
	}
	if w := r.call("seed", "wk-1"); w.Code != http.StatusBadRequest {
		t.Fatalf("seed of a plain worker: %d", w.Code)
	}
	r.locked = true
	w = r.call("seed", "pw-a")
	if body := strings.TrimSpace(w.Body.String()); w.Code != http.StatusServiceUnavailable || strings.Contains(body, "\n") {
		t.Fatalf("locked seed: %d %q", w.Code, body)
	}
	if ents, _ := os.ReadDir(r.dir); len(ents) != 0 {
		t.Fatalf("seed made %v", ents)
	}
}

// A locked open answers with one line, which modelroute.RouteControl maps
// to modelroute.ErrVaultLocked (#1314 tells "unlock your box" from a fault).
func TestCRED5LockedOpenIsOneLine(t *testing.T) {
	r := newWorkerRig(t)
	r.locked = true
	w := r.call("open", "pw-a")
	if body := strings.TrimSpace(w.Body.String()); w.Code != http.StatusServiceUnavailable || strings.Contains(body, "\n") {
		t.Fatalf("locked open: %d %q", w.Code, body)
	}
}

// End to end over the real PlanLogins: the placeholder auth.json /seed
// returns before the machine starts resolves through the worker's own route
// socket after /open, also after a reopen, and the provider sees the real
// login (CRED-5, A3).
func TestCRED5SeededPlaceholderResolvesThroughTheRoute(t *testing.T) {
	dir, err := os.MkdirTemp("", "rs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	v, err := vault.Create(filepath.Join(dir, "v"), []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	realAccess := synthetic(t, "canary-access-")
	login, _ := json.Marshal(map[string]string{
		"access_token": realAccess, "refresh_token": synthetic(t, "canary-refresh-"),
		"id_token": "x.y.z", "account_id": "acct-synthetic",
	})
	if err := v.Put("plan-login-codex", egress.LoginKind, login); err != nil {
		t.Fatal(err)
	}
	logins := egress.NewPlanLogins(func() (egress.LoginStore, error) { return v, nil }, map[string]string{})
	up := &upstream{}
	p := newWorkerRoutes(filepath.Join(dir, "w"), func(worker string) (egress.WorkerRouteConfig, error) {
		return egress.WorkerRouteConfig{Route: egress.Codex(), Worker: worker, Logins: logins, Transport: up, Audit: &nopAudit{}}, nil
	}, logins.Forget, func(worker string) (map[string][]byte, error) { return logins.Seed("codex", worker) })
	t.Cleanup(p.closeAll)
	ctl := p.handler()
	call := func(verb string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		ctl.ServeHTTP(w, httptest.NewRequest("POST", "/"+verb+"?machine=pw-a", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", verb, w.Code, w.Body)
		}
		return w
	}
	var seed map[string][]byte
	if err := json.Unmarshal(call("seed").Body.Bytes(), &seed); err != nil {
		t.Fatal(err)
	}
	var auth struct{ Tokens map[string]string }
	if err := json.Unmarshal(seed[egress.CodexAuthFile], &auth); err != nil || auth.Tokens["access_token"] == "" {
		t.Fatalf("seeded auth.json %q (%v)", seed[egress.CodexAuthFile], err)
	}
	if strings.Contains(string(seed[egress.CodexAuthFile]), realAccess) {
		t.Fatal("the seed carries the real login")
	}
	var out struct{ Dir string }
	json.Unmarshal(call("open").Body.Bytes(), &out)
	call("open") // a restart keeps the seeded placeholders
	resp, err := through(t, filepath.Join(out.Dir, RouteSocket), auth.Tokens["access_token"], nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("seeded placeholder: status %d", resp.StatusCode)
	}
	if len(up.seen) != 1 || up.seen[0].Header.Get("Authorization") != "Bearer "+realAccess {
		t.Fatalf("provider saw %v", up.seen)
	}
}

// slowCall starts a responses request with the worker's placeholder whose
// body is held open until release is called.
func slowCall(t *testing.T, sock, placeholder string) (release func(), done chan int) {
	t.Helper()
	pr, pw := io.Pipe()
	done = make(chan int, 1)
	cl := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
	req, _ := http.NewRequest("POST", "http://127.0.0.1:18432/backend-api/codex/responses", pr)
	req.Header.Set("Authorization", "Bearer "+placeholder)
	req.Header.Set("Content-Type", "application/json")
	go func() {
		resp, err := cl.Do(req)
		if err != nil {
			done <- 0
			return
		}
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	go io.WriteString(pw, `{"model":`)
	return func() { pw.CloseWithError(io.ErrUnexpectedEOF) }, done
}

// Calls in flight across every worker route are capped process-wide: past
// the cap a call is refused with 503 instead of buffering another body, so
// no number of callers pushes the vault process past its memory ceiling
// (CRED-8, tests/test_egress_memory.py).
func TestCRED8RouteCallsAreCappedAcrossWorkers(t *testing.T) {
	r := newWorkerRig(t)
	r.p.calls = make(chan struct{}, 1)
	da, db := r.open(t, "pw-a"), r.open(t, "pw-b")
	release, held := slowCall(t, filepath.Join(da, RouteSocket), "ph-access-pw-a")
	deadline := time.Now().Add(5 * time.Second)
	for len(r.p.calls) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the held call never took a slot")
		}
		time.Sleep(5 * time.Millisecond)
	}
	resp, err := through(t, filepath.Join(db, RouteSocket), "ph-access-pw-b", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a call past the cap: status %d, want 503", resp.StatusCode)
	}
	release()
	<-held
	// The client gives up as soon as its body errors, which can be before
	// the server's handler has left bounded and freed the slot.
	deadline = time.Now().Add(5 * time.Second)
	for len(r.p.calls) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the held call never freed its slot")
		}
		time.Sleep(5 * time.Millisecond)
	}
	resp, err = through(t, filepath.Join(db, RouteSocket), "ph-access-pw-b", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("after the slot freed: status %d", resp.StatusCode)
	}
}

// Each route accepts a bounded number of connections; one more waits in the
// kernel's queue, costing the vault process nothing, until one closes.
func TestCRED8RouteConnectionsArePerWorkerBounded(t *testing.T) {
	r := newWorkerRig(t)
	r.p.conns = 2
	dir := r.open(t, "pw-a")
	sock := filepath.Join(dir, RouteSocket)
	var held []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	got := make(chan int, 1)
	go func() {
		resp, err := through(t, sock, "ph-access-pw-a", nil)
		if err != nil {
			got <- 0
			return
		}
		resp.Body.Close()
		got <- resp.StatusCode
	}()
	select {
	case code := <-got:
		t.Fatalf("a connection past the limit was served (%d)", code)
	case <-time.After(300 * time.Millisecond):
	}
	held[0].Close()
	select {
	case code := <-got:
		if code != http.StatusOK {
			t.Fatalf("queued call: status %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the queued connection was never served")
	}
	held[1].Close()
}

// RES-5: the broker reads a provider's pools over the control socket
// (/usage), aggregated across every worker's route: the newest reading of
// each pool, whichever worker's call carried it.
func TestRES5UsageAggregatesAcrossWorkers(t *testing.T) {
	r := newWorkerRig(t)
	call := func(machine, primary, secondary string) {
		t.Helper()
		r.up.mu.Lock()
		r.up.quota = http.Header{}
		r.up.quota.Set("X-Codex-Primary-Used-Percent", primary)
		if secondary != "" {
			r.up.quota.Set("X-Codex-Secondary-Used-Percent", secondary)
		}
		r.up.mu.Unlock()
		resp, err := through(t, filepath.Join(r.open(t, machine), RouteSocket), "ph-access-"+machine, nil)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	call("pw-a", "40", "5")
	time.Sleep(time.Millisecond) // readings are ordered by their time
	call("pw-b", "70", "")

	w := httptest.NewRecorder()
	r.ctl.ServeHTTP(w, httptest.NewRequest("POST", "/usage?provider=codex", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("usage: %d %s", w.Code, w.Body)
	}
	var got egress.UsageSnapshot
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Pools) != 2 || got.Pools[0].Pool != "primary" || got.Pools[0].UsedPercent != 70 || got.Pools[0].Worker != "pw-b" ||
		got.Pools[1].Pool != "secondary" || got.Pools[1].UsedPercent != 5 {
		t.Fatalf("usage %+v", got)
	}
	if strings.Contains(w.Body.String(), r.real["pw-a"]) || strings.Contains(w.Body.String(), r.real["pw-b"]) {
		t.Fatal("the usage reply carries a login")
	}
	w = httptest.NewRecorder()
	r.ctl.ServeHTTP(w, httptest.NewRequest("POST", "/usage?provider=unread", nil))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "primary") {
		t.Fatalf("an unread provider: %d %s", w.Code, w.Body)
	}
}

// The config the vault process serves feeds every reading and every refused
// login into the usage /usage serves, so admission sees them in the shipped
// binary and not only in the rig (RES-5, CRED-5; #1856 review B1).
func TestRES5ShippedRouteConfigFeedsUsage(t *testing.T) {
	var usage egress.PlanUsage
	cfg := codexRouteConfig("pw-a", &planLogins{forgot: map[string]bool{}}, &upstream{}, nil, &nopAudit{}, &usage)
	if cfg.Quota == nil || cfg.Signal == nil {
		t.Fatal("the shipped route config drops readings or signals")
	}
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	cfg.Quota(egress.QuotaReading{At: at, Provider: "codex", Worker: "pw-a", Pool: "primary", UsedPercent: 30})
	cfg.Signal(egress.PlanSignal{At: at, Provider: "codex", Worker: "pw-a", Kind: egress.SignalLoginRefused})
	got := usage.Snapshot("codex")
	if len(got.Pools) != 1 || got.Pools[0].UsedPercent != 30 || !got.LoginRefused.Equal(at) {
		t.Fatalf("usage after the shipped config's callbacks: %+v", got)
	}
}

// ctlPost posts path on the control socket and returns the status and body.
func ctlPost(t *testing.T, sock, path string) (int, []byte) {
	t.Helper()
	cl := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
	resp, err := cl.Post("http://localhost"+path, "text/plain", nil)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return resp.StatusCode, body
}

// The vault process as it ships: serveWorkerRoutes over an open custody.
// A reading on a worker's route reaches the /usage that same control socket
// serves, so the routes it builds feed the usage it serves (RES-5, CRED-5;
// #1856 security S1: a route config without Quota, or a usage other than
// the served one, fails here).
func TestRES5ServedRoutesFeedTheServedUsage(t *testing.T) {
	run, err := os.MkdirTemp("", "ru")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(run) })
	v, err := vault.Create(filepath.Join(run, "v"), []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	realAccess := synthetic(t, "canary-access-")
	login, _ := json.Marshal(map[string]string{
		"access_token": realAccess, "refresh_token": synthetic(t, "canary-refresh-"),
		"id_token": "x.y.z", "account_id": "acct-synthetic",
	})
	if err := v.Put("plan-login-codex", egress.LoginKind, login); err != nil {
		t.Fatal(err)
	}
	up := &upstream{quota: http.Header{}}
	up.quota.Set("X-Codex-Primary-Used-Percent", "37")
	c := &custody{notify: func(string) {}, modelTransport: up}
	c.ph, c.v = open, v

	cl, err := serveWorkerRoutes(filepath.Join(run, "r"), c, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	sock := filepath.Join(run, "r", ProviderSocket)

	code, body := ctlPost(t, sock, "/usage?provider=codex")
	if code != http.StatusOK || strings.Contains(string(body), "primary") {
		t.Fatalf("usage before any call: %d %s", code, body)
	}
	code, body = ctlPost(t, sock, "/seed?machine=pw-a")
	if code != http.StatusOK {
		t.Fatalf("seed: %d %s", code, body)
	}
	var seed map[string][]byte
	var auth struct{ Tokens map[string]string }
	if err := json.Unmarshal(body, &seed); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(seed[egress.CodexAuthFile], &auth); err != nil || auth.Tokens["access_token"] == "" {
		t.Fatalf("seeded auth.json %q (%v)", seed[egress.CodexAuthFile], err)
	}
	code, body = ctlPost(t, sock, "/open?machine=pw-a")
	var out struct{ Dir string }
	if err := json.Unmarshal(body, &out); code != http.StatusOK || err != nil || out.Dir == "" {
		t.Fatalf("open: %d %s (%v)", code, body, err)
	}
	resp, err := through(t, filepath.Join(out.Dir, RouteSocket), auth.Tokens["access_token"], nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("call through the served route: status %d", resp.StatusCode)
	}
	up.mu.Lock()
	n := len(up.seen)
	up.mu.Unlock()
	if n != 1 {
		t.Fatalf("the provider saw %d calls, want 1", n)
	}

	code, body = ctlPost(t, sock, "/usage?provider=codex")
	var got egress.UsageSnapshot
	if err := json.Unmarshal(body, &got); code != http.StatusOK || err != nil {
		t.Fatalf("usage: %d %s (%v)", code, body, err)
	}
	if len(got.Pools) != 1 || got.Pools[0].Pool != "primary" || got.Pools[0].UsedPercent != 37 || got.Pools[0].Worker != "pw-a" {
		t.Fatalf("the served /usage after a reading on the served route: %+v", got)
	}
	if strings.Contains(string(body), realAccess) {
		t.Fatal("the usage reply carries a login")
	}
}
