package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/holder"
)

// REQ: ARC-1, CRED-1, CRED-7
// With -proxy the proxy runs keyless in its own process (proxyview_test.go,
// a5_test.go); here it runs in the vault process, over the same holders.

// heldAt serves a holder for adapter a in a fresh socket directory, its
// provider reached over tr, and returns the directory and the holder.
func heldAt(t *testing.T, a egress.Adapter, tr http.RoundTripper) (string, *holder.Holder) {
	t.Helper()
	dir, err := os.MkdirTemp("", "hd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h, err := holder.New(holder.Config{Adapters: []egress.Adapter{a}, Transport: tr})
	if err != nil {
		t.Fatal(err)
	}
	reqs, err := holder.Listen(filepath.Join(dir, holder.RequestSocket), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	hand, err := holder.Listen(filepath.Join(dir, holder.HandSocket), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	go h.Serve(reqs, hand)
	t.Cleanup(func() { reqs.Close(); hand.Close() })
	return dir, h
}

// noDial fails any call the proxy would send to a provider itself: with
// holders, the key is added in the holder and nowhere else.
type noDial struct{ t *testing.T }

func (n noDial) RoundTrip(r *http.Request) (*http.Response, error) {
	n.t.Errorf("egress dialed %s itself", r.URL.Host)
	return nil, errors.New("no dial")
}

func waitUntil(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// SIM-split-wire: with -holder, the unlock step hands each API key to its
// own holder, which adds it and opens TLS; the proxy sends the request to
// the holder and never dials the provider. A replaced key reaches the
// holder, and a lock takes every key back out of the holders.
func TestHoldersAddTheKeyAndLockTakesItBack(t *testing.T) {
	tr, got := reflecting(t, true)
	openaiDir, oh := heldAt(t, egress.OpenAI("openai"), tr)
	anthDir, ah := heldAt(t, egress.Anthropic("anthropic"), tr)
	r := newFastRig(t, true) // its vault holds an OpenAI key
	r.c.holders = holderDirs{"openai": openaiDir, "anthropic": anthDir}
	r.c.keepEvery = 5 * time.Millisecond
	r.c.modelTransport = noDial{t}
	withGrants(r.c, grants{"agent": {"openai"}}, "")

	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	r.c.mu.Lock()
	s, _ := r.c.v.Secret("openai")
	key := s.Reveal()
	// The call carries another vault value, which the provider echoes
	// back: only egress's keyed-hash redaction can know it (CRED-7).
	seed, _ := r.c.v.Secret(SeedName)
	other := seed.Reveal()
	r.c.mu.Unlock()
	waitUntil(t, "the openai holder's key", oh.Held)
	if ah.Held() {
		t.Fatal("a holder whose key the vault lacks was handed one")
	}
	ask := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(`{"model":"gpt-test","messages":[{"role":"user","content":"`+other+`"}]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer placeholder")
		r.c.model().HandlerFor("agent", "private", noAudit{}).ServeHTTP(w, req)
		return w
	}
	w := ask()
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "hello ") {
		t.Fatalf("held call: %d %s", w.Code, w.Body)
	}
	if b := w.Body.String(); strings.Contains(b, key) || strings.Contains(b, other) {
		t.Fatal("a vault value came back unredacted")
	}
	if k := got(); len(k) != 1 || k[0] != key {
		t.Fatalf("provider got %d keys, want the vault's", len(k))
	}

	rotated := synthetic(t, "sk-canary-rotated-")
	if err := r.c.put("openai", []byte(rotated)); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the rotated key", func() bool {
		ask()
		k := got()
		return k[len(k)-1] == rotated
	})

	r.c.lock()
	if oh.Held() || ah.Held() {
		t.Fatal("a holder kept its key after the lock")
	}
	if r.c.keys.Load() != nil {
		t.Fatal("the keepers' vault outlived the lock")
	}
	time.Sleep(30 * time.Millisecond) // several keeper rounds
	if oh.Held() {
		t.Fatal("a keeper handed a key after the lock")
	}
}

// -holder names a built-in adapter and an absolute directory, once each;
// set at all, it names every adapter, so no key stays behind in egress.
func TestHolderFlag(t *testing.T) {
	h := holderDirs{}
	for _, bad := range []string{"openai", "nobody=/run/h", "openai=run/h", "openai=", "=/run/h"} {
		if h.Set(bad) == nil {
			t.Errorf("accepted -holder %q", bad)
		}
	}
	if err := h.Set("openai=/run/agentos-holder/openai"); err != nil {
		t.Fatal(err)
	}
	if h.Set("openai=/run/other") == nil {
		t.Error("accepted openai twice")
	}
	if h.check() == nil {
		t.Error("accepted holders for some adapters only")
	}
	if err := h.Set("anthropic=/run/agentos-holder/anthropic"); err != nil {
		t.Fatal(err)
	}
	if err := h.check(); err != nil {
		t.Fatal(err)
	}
	if err := (holderDirs{}).check(); err != nil {
		t.Fatalf("no holders: %v", err)
	}
}

// slowHand is a holder's hand socket whose PUT takes slow to land, as a
// hand in flight does, and whose DELETE answers dropStatus. It records
// whether it holds a key and the order of the hands and drops.
type slowHand struct {
	mu         sync.Mutex
	held       bool
	log        []string
	slow       time.Duration
	dropStatus int
	putting    chan struct{}
}

func (s *slowHand) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s.mu.Lock()
		held := s.held
		s.mu.Unlock()
		fmt.Fprintf(w, `{"held":%t}`, held)
	case "PUT":
		io.ReadAll(r.Body)
		select {
		case s.putting <- struct{}{}:
		default:
		}
		time.Sleep(s.slow) // lands whether or not the caller still waits
		s.mu.Lock()
		s.held = true
		s.log = append(s.log, "put")
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case "DELETE":
		s.mu.Lock()
		s.held = false
		s.log = append(s.log, "delete")
		s.mu.Unlock()
		w.WriteHeader(s.dropStatus)
	}
}

func (s *slowHand) state() (bool, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.held, append([]string(nil), s.log...)
}

// slowHolders serves h as the openai holder's hand socket; the anthropic
// holder is not running.
func slowHolders(t *testing.T, h *slowHand) holderDirs {
	t.Helper()
	dir, err := os.MkdirTemp("", "hd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	l, err := holder.Listen(filepath.Join(dir, holder.HandSocket), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return holderDirs{"openai": dir, "anthropic": filepath.Join(dir, "down")}
}

// A lock that lands while a hand is in flight waits for it, then drops:
// the holder ends up holding no key, and the hand never lands after the
// drop (CRED-1; Security S1 on #2449).
func TestLockWaitsForAHandInFlight(t *testing.T) {
	h := &slowHand{slow: 300 * time.Millisecond, dropStatus: http.StatusNoContent, putting: make(chan struct{}, 1)}
	r := newFastRig(t, true)
	r.c.holders = slowHolders(t, h)
	r.c.keepEvery = 5 * time.Millisecond
	withGrants(r.c, grants{"agent": {"openai"}}, "")
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.putting:
	case <-time.After(5 * time.Second):
		t.Fatal("no hand began")
	}
	r.c.lock()
	time.Sleep(2 * h.slow) // past when a hand cut loose would land
	held, log := h.state()
	if held || len(log) == 0 || log[len(log)-1] != "delete" {
		t.Fatalf("after the lock the holder holds a key: held=%t, %v", held, log)
	}
}

// A drop the holder refuses is told to the owner; a holder that is not
// running is not (Security S4 on #2449).
func TestFailedDropIsTold(t *testing.T) {
	h := &slowHand{dropStatus: http.StatusInternalServerError, putting: make(chan struct{}, 1)}
	r := newFastRig(t, true)
	r.c.holders = slowHolders(t, h)
	r.c.keepEvery = 5 * time.Millisecond
	withGrants(r.c, grants{"agent": {"openai"}}, "")
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the hand", func() bool { held, _ := h.state(); return held })
	r.notes = nil
	r.c.lock()
	var told []string
	for _, n := range r.notes {
		if strings.Contains(n, "not taken back") {
			told = append(told, n)
		}
	}
	if len(told) != 1 || !strings.Contains(told[0], "status 500") {
		t.Fatalf("notices %q, want one for the refused drop only", r.notes)
	}
}
