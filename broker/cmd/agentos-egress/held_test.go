package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/holder"
)

// REQ: ARC-1, CRED-1, CRED-5, CRED-7

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
	tr, got := reflector(t)
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
	r.c.mu.Unlock()
	key := s.Reveal()
	waitUntil(t, "the openai holder's key", oh.Held)
	if ah.Held() {
		t.Fatal("a holder whose key the vault lacks was handed one")
	}
	ask := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(`{"model":"gpt-test","messages":[]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer placeholder")
		r.c.model().HandlerFor("agent", "private", noAudit{}).ServeHTTP(w, req)
		return w
	}
	if w := ask(); w.Code != http.StatusOK || strings.Contains(w.Body.String(), key) {
		t.Fatalf("held call: %d %s", w.Code, w.Body)
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
