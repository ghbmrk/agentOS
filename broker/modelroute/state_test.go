package modelroute

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// REQ: OP-9, CRED-5, CRED-1, ARC-2

// The vault process answers the broker's state request with two yes-or-no
// facts; the probe adds that it answered at all.
func TestStateProbeReadsTheVaultProcessAnswer(t *testing.T) {
	for _, want := range []ModelState{
		{Reachable: true},
		{Reachable: true, Granted: true},
		{Reachable: true, Granted: true, Open: true},
	} {
		fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.Header.Get(HeaderState) == "" {
				http.Error(w, "not a state request", http.StatusBadRequest)
				return
			}
			fmt.Fprintf(w, `{"granted":%t,"open":%t}`, want.Granted, want.Open)
		}}
		got := NewStateProbe(serveUnix(t, fe))(context.Background())
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	}
}

// A stale state never reads as granted: a socket with nothing behind it,
// a process that never answers, a refusal, or a malformed answer all read
// as not reachable, and say nothing granted or open.
func TestStateProbeFailsClosed(t *testing.T) {
	answer := func(status int, body string) func(t *testing.T) string {
		return func(t *testing.T) string {
			return serveUnix(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				io.WriteString(w, body)
			}))
		}
	}
	for _, c := range []struct {
		name string
		sock func(t *testing.T) string
	}{
		{"absent socket", func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.sock") }},
		{"stale socket file", staleSocket},
		{"no answer", silentSocket},
		{"refused", answer(http.StatusServiceUnavailable, `{"granted":true,"open":true}`)},
		{"not JSON", answer(http.StatusOK, `granted`)},
		{"too long", answer(http.StatusOK, `{"granted":true,"open":true,"pad":"`+strings.Repeat("x", 2<<10)+`"}`)},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			start := time.Now()
			if got := NewStateProbe(c.sock(t))(ctx); got != (ModelState{}) {
				t.Fatalf("got %+v", got)
			}
			if d := time.Since(start); d > 3*time.Second {
				t.Fatalf("took %v", d)
			}
		})
	}
}

// staleSocket is a socket file left by a process that stopped serving:
// the file is there, nothing answers.
func staleSocket(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "model.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	return path
}

// silentSocket accepts and never answers.
func silentSocket(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "model.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	return path
}

// CRED-1: the state carries no secret. Whatever else the vault process's
// answer holds, the probe keeps only the yes-or-no facts.
func TestStateCarriesNoSecret(t *testing.T) {
	const canary = "sk-canary-state-5f3a"
	sock := serveUnix(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"granted":true,"open":true,"key":%q,"provider":%q}`, canary, canary)
	}))
	got := NewStateProbe(sock)(context.Background())
	if !got.Reachable || !got.Granted || !got.Open {
		t.Fatalf("got %+v", got)
	}
	if s := fmt.Sprintf("%+v %#v", got, got); strings.Contains(s, canary) {
		t.Fatalf("state holds the canary: %s", s)
	}
}

// A guest cannot ask for the state, or make the vault process read one of
// its calls as a state request: Forward drops the guest's HeaderState
// like every Agentos- header.
func TestForwardDropsAGuestStateRequest(t *testing.T) {
	fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderState) != "" {
			io.WriteString(w, `{"granted":true,"open":true}`)
			return
		}
		io.WriteString(w, `{"ok":true}`)
	}}
	fwd := Forward(Config{Socket: serveUnix(t, fe), Label: func(string) string { return "private" }, Denied: func(string, Denial) {}})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(HeaderState, "1")
	w := httptest.NewRecorder()
	fwd("m1").ServeHTTP(w, r)
	if w.Body.String() != `{"ok":true}` {
		t.Fatalf("guest got %q", w.Body.String())
	}
	if len(fe.seen) != 1 || fe.seen[0].Header.Get(HeaderState) != "" {
		t.Fatalf("vault process saw the guest's state header")
	}
}
