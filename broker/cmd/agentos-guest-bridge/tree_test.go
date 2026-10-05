package main

// REQ: CAP-5, REV-5

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// fakeTree is a broker socket whose /mcp answers managed_tree.
type fakeTree struct {
	mu    sync.Mutex
	ans   treeAnswer
	err   string // a tool error, as for a public machine
	rpc   bool   // a JSON-RPC error, as a broker with no such tool gives
	asked []string
}

func (f *fakeTree) serve(t *testing.T) *http.Client {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "b.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		var a struct{ Version string }
		json.Unmarshal(req.Params.Arguments, &a)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.asked = append(f.asked, a.Version)
		switch {
		case f.rpc || req.Params.Name != "managed_tree":
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "no such tool"}})
		case f.err != "":
			json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"isError": true, "content": []any{map[string]any{"text": f.err}}}})
		default:
			ans := f.ans
			if a.Version == ans.Version {
				ans = treeAnswer{Version: ans.Version, Unchanged: true}
			}
			b, _ := json.Marshal(ans)
			json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"content": []any{map[string]any{"text": string(b)}}}})
		}
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return "<none>"
	}
	return string(b)
}

// W4: the bridge keeps its tree directory a copy of the broker's tree:
// new files written, gone ones removed, nothing outside the tree's
// namespaces touched; an unchanged version writes nothing.
func TestBridgeMirrorsTheManagedTree(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "skills"), 0o755)
	os.WriteFile(filepath.Join(dir, "skills", "old.json"), []byte("old"), 0o644)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine"), 0o644)
	f := &fakeTree{ans: treeAnswer{Version: "v1", Files: map[string][]byte{
		"skills/greet.json": []byte("greet"), "procedures/p.json": []byte("p"), "context/a/b.md": []byte("b")}}}
	c := f.serve(t)
	v, err := syncOnce(context.Background(), c, dir, "")
	if err != nil || v != "v1" {
		t.Fatalf("sync: %q %v", v, err)
	}
	for p, want := range map[string]string{"skills/greet.json": "greet", "procedures/p.json": "p", "context/a/b.md": "b",
		"skills/old.json": "<none>", "notes.txt": "mine"} {
		if got := read(t, filepath.Join(dir, p)); got != want {
			t.Errorf("%s = %q, want %q", p, got, want)
		}
	}
	if fi, _ := os.Stat(filepath.Join(dir, "skills/greet.json")); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	os.WriteFile(filepath.Join(dir, "skills", "greet.json"), []byte("edited"), 0o644)
	if v, err := syncOnce(context.Background(), c, dir, v); err != nil || v != "v1" || read(t, filepath.Join(dir, "skills/greet.json")) != "edited" {
		t.Fatalf("unchanged version rewrote the tree: %q %v", v, err)
	}
	f.mu.Lock()
	f.ans = treeAnswer{Version: "v2", Files: map[string][]byte{"skills/greet.json": []byte("greet2")}}
	f.mu.Unlock()
	if v, err := syncOnce(context.Background(), c, dir, v); err != nil || v != "v2" {
		t.Fatalf("v2: %q %v", v, err)
	}
	if read(t, filepath.Join(dir, "skills/greet.json")) != "greet2" || read(t, filepath.Join(dir, "procedures/p.json")) != "<none>" {
		t.Fatal("v2 not mirrored")
	}
}

// A refusal (a public machine), a broker with no managed_tree (a replay
// machine, whose seed is the tree under test), or an answer with a path
// outside the tree's namespaces changes nothing.
func TestBridgeKeepsItsTreeWhenTheBrokerDoesNotSendOne(t *testing.T) {
	for name, f := range map[string]*fakeTree{
		"public": {err: "the managed tree reaches only private machines"},
		"replay": {rpc: true},
		"escape": {ans: treeAnswer{Version: "v1", Files: map[string][]byte{"skills/a.json": []byte("a"), "../../etc/passwd": []byte("x")}}},
		"grants": {ans: treeAnswer{Version: "v1", Files: map[string][]byte{"grants/g.json": []byte("g")}}},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			os.MkdirAll(filepath.Join(dir, "skills"), 0o755)
			os.WriteFile(filepath.Join(dir, "skills", "seeded.json"), []byte("seed"), 0o644)
			v, err := syncOnce(context.Background(), f.serve(t), dir, "")
			if err == nil || v != "" {
				t.Fatalf("sync: %q %v", v, err)
			}
			if read(t, filepath.Join(dir, "skills/seeded.json")) != "seed" || read(t, filepath.Join(dir, "skills/a.json")) != "<none>" {
				t.Fatal("the tree changed")
			}
		})
	}
}
