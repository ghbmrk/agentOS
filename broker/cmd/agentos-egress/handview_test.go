package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/holder"
)

// REQ: ARC-1, CRED-1, CRED-7

// Every change to the open vault reaches the proxy process before the
// change returns, not at the keeper's next round: a withdrawn
// private-data answer narrows at once (CRED-1), and a stored key's keyed
// hash redacts at once (CRED-7). The keeper's rounds here are an hour
// apart, so only the hand-off each change makes can pass this. The
// unlock reaches it by the keeper's poke, also inside the hour.
func TestVaultChangesReachTheProxyAtOnce(t *testing.T) {
	r := newSplitRig(t, grants{}, "agent", nil, time.Hour)
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the open view, poked", func() bool { return r.pv.storedGrant("agent", "openai") })

	if err := r.c.putPrivate("openai", true, r.next()); err != nil {
		t.Fatal(err)
	}
	if !r.pv.privateAllowed("openai") {
		t.Fatal("an allow had not reached the proxy when it returned")
	}
	if err := r.c.putPrivate("openai", false, ""); err != nil {
		t.Fatal(err)
	}
	if r.pv.privateAllowed("openai") {
		t.Fatal("a withdraw had not reached the proxy when it returned")
	}

	key := synthetic(t, "sk-ant-canary-")
	if err := r.c.put("anthropic", []byte(key)); err != nil {
		t.Fatal(err)
	}
	if !r.pv.storedGrant("agent", "anthropic") {
		t.Fatal("a stored key had not reached the proxy when it returned")
	}
	red, err := r.pv.redactor()
	if err != nil {
		t.Fatal(err)
	}
	if out := red.Redact([]byte("echo " + key + " back")); bytes.Contains(out, []byte(key)) {
		t.Fatal("the proxy's redactor missed a key stored a moment ago")
	}

	r.c.lock()
	if r.pv.model() != nil || r.pv.storedGrant("agent", "openai") {
		t.Fatal("the proxy reports open after the lock returned")
	}
}

// The lock's view differs from the open one even when nothing was
// written while open, so the keeper hands it and does not take the
// proxy's held view as current.
func TestTheLockMovesTheViewVersion(t *testing.T) {
	r := newSplitRig(t, grants{}, "agent", nil, time.Hour)
	locked := r.c.viewVersion()
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	opened := r.c.viewVersion()
	r.c.lock()
	if relocked := r.c.viewVersion(); opened == locked || relocked == opened || relocked == locked {
		t.Fatalf("view versions locked %x, open %x, locked again %x", locked, opened, relocked)
	}
}

// A view that says locked answers locked, whatever keys or answers it
// lists, and a view that does not parse locks a proxy that was open.
func TestALockedViewAnswersLocked(t *testing.T) {
	pv, err := newProxyView(grants{}, "agent", map[string]bool{"openai": true}, holderDirs{"openai": "/run/h/openai", "anthropic": "/run/h/anthropic"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pv.Hand([]byte(`{"open":false,"keys":["openai","anthropic"],"private":["openai"]}`))
	if pv.model() != nil || pv.storedGrant("agent", "openai") || pv.privateAllowed("openai") || pv.privateGrantedNow() {
		t.Fatalf("a locked view answered open: %s", answers(pv))
	}

	// An open view from a vault process, handed here and not to the
	// rig's own proxy, so no keeper round replaces it.
	r := newSplitRig(t, grants{}, "agent", nil, time.Hour)
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	b, err := r.c.viewSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	pv.Hand(b)
	if pv.model() == nil || !pv.storedGrant("agent", "openai") {
		t.Fatal("the open view did not open the proxy")
	}
	pv.Hand([]byte(`{"open":true,"keys":["openai"],"redactor":"bm90IGEgcmVkYWN0b3I="}`))
	if pv.model() != nil || pv.storedGrant("agent", "openai") {
		t.Fatal("a view that does not parse left an open proxy open")
	}
}

// The hand socket refuses a view over maxView and leaves the proxy as it
// was.
func TestTheHandSocketCapsTheView(t *testing.T) {
	pv, err := newProxyView(grants{}, "agent", nil, holderDirs{"openai": "/run/h/openai", "anthropic": "/run/h/anthropic"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var hand http.Handler
	for _, s := range proxySockets(pv, testRouter(t), nil, nil, 101, 202) {
		if s.name == holder.HandSocket {
			hand = s.h
		}
	}
	if hand == nil {
		t.Fatal("no hand socket")
	}
	w := httptest.NewRecorder()
	hand.ServeHTTP(w, httptest.NewRequest("PUT", "/secret", bytes.NewReader(make([]byte, maxView+1))))
	if w.Code == http.StatusNoContent || pv.Held() {
		t.Fatalf("an oversize view was taken: %d", w.Code)
	}
	w = httptest.NewRecorder()
	hand.ServeHTTP(w, httptest.NewRequest("PUT", "/secret", strings.NewReader(`{"open":false}`)))
	if w.Code != http.StatusNoContent || !pv.Held() {
		t.Fatalf("a small view was refused: %d", w.Code)
	}
}

// The proxy process admits agentosd on the model and routing sockets and
// the vault process alone on the hand socket.
func TestProxySocketsAdmitEachPeer(t *testing.T) {
	pv, err := newProxyView(grants{}, "agent", nil, holderDirs{"openai": "/run/h/openai", "anthropic": "/run/h/anthropic"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, s := range proxySockets(pv, testRouter(t), nil, nil, 101, 202) {
		got[s.name] = s.uid
	}
	want := map[string]int{ModelSocket: 101, RoutingSocket: 101, holder.HandSocket: 202}
	if len(got) != len(want) {
		t.Fatalf("sockets %v, want %v", got, want)
	}
	for n, uid := range want {
		if got[n] != uid {
			t.Fatalf("sockets %v, want %v", got, want)
		}
	}
}

// The proxy process refuses a peer uid that is its own or the other
// peer's, so no one process stands in for two.
func TestProxyUIDsAreDistinct(t *testing.T) {
	for _, tc := range []struct {
		self, broker, vault int
		ok                  bool
	}{
		{10, 20, 30, true},
		{10, -1, 30, false},
		{10, 10, 30, false},
		{10, 20, -1, false},
		{10, 20, 10, false},
		{10, 20, 20, false},
	} {
		if err := proxyUIDs(tc.self, tc.broker, tc.vault); (err == nil) != tc.ok {
			t.Errorf("proxyUIDs(%d, %d, %d) = %v", tc.self, tc.broker, tc.vault, err)
		}
	}
}

// serve's -proxy needs an absolute directory and the holders.
func TestProxyFlagNeedsHoldersAndAnAbsoluteDir(t *testing.T) {
	held := holderDirs{"openai": "/run/h/openai", "anthropic": "/run/h/anthropic"}
	for _, tc := range []struct {
		dir  string
		held holderDirs
		ok   bool
	}{
		{"", nil, true},
		{"/run/agentos-proxy", held, true},
		{"/run/agentos-proxy", nil, false},
		{"run/agentos-proxy", held, false},
	} {
		if err := proxyFlagOK(tc.dir, tc.held); (err == nil) != tc.ok {
			t.Errorf("proxyFlagOK(%q, %v) = %v", tc.dir, tc.held, err)
		}
	}
}

// With -proxy the vault process serves no model or routing socket: the
// proxy process does. Without it, it serves both.
func TestServeWithProxyOpensNoModelSocket(t *testing.T) {
	for _, tc := range []struct {
		name     string
		proxyDir string
	}{{"proxy", "/run/agentos-proxy-test"}, {"no proxy", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			r := newFastRig(t, true)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			rt := r.c.handTo(ctx, tc.proxyDir, testRouter(t))
			if (rt == nil) != (tc.proxyDir != "") || (r.c.view != nil) != (tc.proxyDir != "") {
				t.Fatalf("handTo(%q): router %v, view %v", tc.proxyDir, rt != nil, r.c.view != nil)
			}
			run := filepath.Join(t.TempDir(), "run")
			srvs, err := serve(run, r.c, rt, nil, &routing{rt: testRouter(t)}, os.Getuid(), os.Getuid())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				for _, s := range srvs {
					s.Close()
				}
			})
			for _, n := range []string{ModelSocket, RoutingSocket} {
				if _, err := os.Stat(filepath.Join(run, n)); (err == nil) != (tc.proxyDir == "") {
					t.Errorf("%s in the vault process's run dir: %v", n, err)
				}
			}
			if _, err := os.Stat(filepath.Join(run, VerifySocket)); err != nil {
				t.Errorf("no verify socket: %v", err)
			}
		})
	}
}

// Each adapter's calls go to its own holder's request socket: each
// socket here answers with its adapter's name.
func TestHolderTransportsMapEachAdapter(t *testing.T) {
	dirs := holderDirs{}
	for _, a := range adapters() {
		dir, err := os.MkdirTemp("", "ht")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		l, err := net.Listen("unix", filepath.Join(dir, holder.RequestSocket))
		if err != nil {
			t.Fatal(err)
		}
		name := a.Name
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, name) })}
		go srv.Serve(l)
		t.Cleanup(func() { srv.Close() })
		dirs[a.Name] = dir
	}
	rts := holderTransports(dirs)
	if len(rts) != len(adapters()) {
		t.Fatalf("%d transports for %d adapters", len(rts), len(adapters()))
	}
	for _, a := range adapters() {
		rt := rts[a.Credential]
		if rt == nil {
			t.Fatalf("no transport for %s", a.Credential)
		}
		req := httptest.NewRequest("GET", "http://holder/", nil)
		req.RequestURI = ""
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatalf("%s: %v", a.Name, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != a.Name {
			t.Fatalf("%s's calls reached %q's holder", a.Name, b)
		}
	}
}

// A withdraw whose hand to the proxy fails is told as not yet in effect,
// since the proxy keeps its last view until a later round reaches it
// (W-2); a withdraw the proxy took is told plainly.
func TestAWithdrawTheProxyMissedIsToldAsPending(t *testing.T) {
	r := newFastRig(t, true)
	pv, err := newProxyView(grants{}, "agent", nil, holderDirs{"openai": "/run/h/openai", "anthropic": "/run/h/anthropic"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var refuse atomic.Bool
	hand := holder.HandHandler(pv, maxView)
	dir, err := os.MkdirTemp("", "px")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	l, err := holder.Listen(filepath.Join(dir, holder.HandSocket), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if q.Method == "PUT" && refuse.Load() {
			http.Error(w, "busy", http.StatusInternalServerError)
			return
		}
		hand.ServeHTTP(w, q)
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	r.c.keepEvery = time.Hour
	r.c.holders = holderDirs{"openai": filepath.Join(dir, "down"), "anthropic": filepath.Join(dir, "down")}
	r.c.view = newViewKeeper(r.c, dir)
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}

	withdraw := func() string {
		t.Helper()
		if err := r.c.putPrivate("openai", true, r.next()); err != nil {
			t.Fatal(err)
		}
		r.notes = nil
		if err := r.c.putPrivate("openai", false, ""); err != nil {
			t.Fatal(err)
		}
		for _, n := range r.notes {
			if strings.HasPrefix(n, "private data withdrawn") {
				return n
			}
		}
		t.Fatalf("no withdraw notice in %q", r.notes)
		return ""
	}
	if n := withdraw(); strings.Contains(n, "not yet") {
		t.Fatalf("a withdraw the proxy took was told as pending: %q", n)
	}
	if pv.privateAllowed("openai") {
		t.Fatal("the proxy allows after a withdraw it took")
	}
	refuse.Store(true)
	if n := withdraw(); !strings.Contains(n, "not yet in effect") {
		t.Fatalf("a withdraw the proxy missed was told as done: %q", n)
	}
}
