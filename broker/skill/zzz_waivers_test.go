package skill

// REQ: CAP-5

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// find refuses an agent-chosen name that leaves the namespace without
// opening it: a FIFO at Dir/evil.json would block the open forever.
func TestFindDoesNotOpenATraversalName(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, SkillsNS), 0o755)
	fifo := filepath.Join(dir, "evil.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan *Skill, 1)
	go func() { done <- (&Server{Dir: dir}).find("../evil") }()
	select {
	case sk := <-done:
		if sk != nil {
			t.Fatalf("a traversal name found %+v", sk)
		}
	case <-time.After(2 * time.Second):
		// Release each blocked open (find tries both namespaces) so the
		// goroutine ends.
		for {
			if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				w.Close()
			}
			select {
			case <-done:
				t.Fatal("find opened a file outside the skill namespace")
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
}

// load closes the file it read; with GC off no finalizer can close it.
func TestLoadClosesTheSkillFile(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	dir := t.TempDir()
	sk := report()
	os.MkdirAll(filepath.Join(dir, SkillsNS), 0o755)
	p := filepath.Join(dir, sk.Path())
	os.WriteFile(p, sk.Encode(), 0o644)
	if (&Server{Dir: dir}).load(SkillsNS, sk.ID) == nil {
		t.Fatal("skill not loaded")
	}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	for _, fd := range fds {
		if l, _ := os.Readlink(filepath.Join("/proc/self/fd", fd.Name())); l == p {
			t.Fatalf("fd %s still open on %s", fd.Name(), p)
		}
	}
}

// probeRT answers every request itself, recording its context and whether
// the caller closed the body.
type probeRT struct {
	mu     sync.Mutex
	ctx    context.Context
	closed bool
}

type probeBody struct {
	io.Reader
	rt *probeRT
}

func (b *probeBody) Close() error {
	b.rt.mu.Lock()
	b.rt.closed = true
	b.rt.mu.Unlock()
	return nil
}

func (rt *probeRT) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.ctx = r.Context()
	rt.mu.Unlock()
	ans := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"state\":\"succeeded\"}"}]}}`
	return &http.Response{StatusCode: 200, Header: http.Header{}, Request: r,
		Body: &probeBody{Reader: strings.NewReader(ans), rt: rt}}, nil
}

// Request closes the answer's body and cancels the step context on return,
// whatever RoundTripper the client uses.
func TestMCPEffectsReleasesBodyAndContext(t *testing.T) {
	rt := &probeRT{}
	m := &MCPEffects{Client: &http.Client{Transport: rt}, URL: "http://broker.localhost/mcp"}
	if _, err := m.Request(context.Background(), Effect{}); err != nil {
		t.Fatal(err)
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if !rt.closed {
		t.Error("answer body not closed")
	}
	if rt.ctx == nil || rt.ctx.Err() == nil {
		t.Error("step context still live after Request returned")
	}
}

// ctxFX records the context a run's steps get.
type ctxFX struct {
	mu  sync.Mutex
	ctx context.Context
}

func (f *ctxFX) Request(ctx context.Context, _ Effect) (State, error) {
	f.mu.Lock()
	f.ctx = ctx
	f.mu.Unlock()
	return State{State: "succeeded"}, nil
}

// ServeHTTP cancels the run context on return even when the caller never
// cancels the request's own context.
func TestServeHTTPCancelsTheRunContext(t *testing.T) {
	dir := t.TempDir()
	sk := report()
	os.MkdirAll(filepath.Join(dir, SkillsNS), 0o755)
	os.WriteFile(filepath.Join(dir, sk.Path()), sk.Encode(), 0o644)
	fx := &ctxFX{}
	s := &Server{Dir: dir, Effects: fx}
	params, _ := json.Marshal(map[string]any{"name": ToolPrefix + sk.ID,
		"arguments": map[string]any{"run_id": "r1", "to": "bo@example.test", "week": 7}})
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": json.RawMessage(params)})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(httptest.NewRecorder(), req)
	fx.mu.Lock()
	defer fx.mu.Unlock()
	if fx.ctx == nil {
		t.Fatal("no step ran")
	}
	if fx.ctx.Err() == nil {
		t.Error("run context still live after ServeHTTP returned")
	}
}
