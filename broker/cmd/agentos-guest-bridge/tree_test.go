package main

// REQ: CAP-5, REV-5, CHG-6

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/guest"
)

// fakeTree is a broker socket whose /mcp answers managed_tree.
type fakeTree struct {
	mu    sync.Mutex
	ans   treeAnswer
	err   string // a tool error, as for a public machine
	rpc   bool   // a JSON-RPC error, as a broker with no such tool gives
	text  string // a result text sent as it is, not a tree
	asked []string
	// script, when set, is the tree for each call in turn, its last for
	// every call after; done closes at the call that reaches the last.
	script []treeAnswer
	done   chan struct{}
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
		if f.done != nil && len(f.asked) == len(f.script) {
			close(f.done)
		}
		switch {
		case f.rpc || req.Params.Name != "managed_tree":
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "no such tool"}})
		case f.err != "":
			json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"isError": true, "content": []any{map[string]any{"text": f.err}}}})
		case f.text != "":
			json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"content": []any{map[string]any{"text": f.text}}}})
		default:
			ans := f.ans
			if len(f.script) > 0 {
				ans = f.script[min(len(f.asked), len(f.script))-1]
			}
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
// outside the tree's namespaces changes nothing. A failure before the
// mirror keeps the version held (TREE-undo-invalidate); a path the mirror
// refuses drops it, as any mirror failure does.
func TestBridgeKeepsItsTreeWhenTheBrokerDoesNotSendOne(t *testing.T) {
	for name, c := range map[string]struct {
		f    *fakeTree
		held string // the version held after
	}{
		"public":     {&fakeTree{err: "the managed tree reaches only private machines"}, "v0"},
		"replay":     {&fakeTree{rpc: true}, "v0"},
		"escape":     {&fakeTree{ans: treeAnswer{Version: "v1", Files: map[string][]byte{"skills/a.json": []byte("a"), "../../etc/passwd": []byte("x")}}}, ""},
		"grants":     {&fakeTree{ans: treeAnswer{Version: "v1", Files: map[string][]byte{"grants/g.json": []byte("g")}}}, ""},
		"dotdot":     {&fakeTree{ans: treeAnswer{Version: "v1", Files: map[string][]byte{"skills/../../x": []byte("x")}}}, ""},
		"absolute":   {&fakeTree{ans: treeAnswer{Version: "v1", Files: map[string][]byte{"/skills/x.json": []byte("x")}}}, ""},
		"file + dir": {&fakeTree{ans: treeAnswer{Version: "v1", Files: map[string][]byte{"skills/a.json": []byte("a"), "skills/a.json/b": []byte("b")}}}, ""},
		"oversize":   {&fakeTree{ans: treeAnswer{Version: "v1", Files: map[string][]byte{"skills/big.json": make([]byte, guest.MaxTreeAnswer)}}}, "v0"},
		"not a tree": {&fakeTree{text: "not json"}, "v0"},
		"no version": {&fakeTree{ans: treeAnswer{Files: map[string][]byte{"skills/a.json": []byte("a")}}}, "v0"},
		"unchanged":  {&fakeTree{ans: treeAnswer{Version: "v9", Unchanged: true}}, "v0"},
		"not ready":  {&fakeTree{err: "the managed tree is not ready; keep the one you have"}, "v0"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			os.MkdirAll(filepath.Join(dir, "skills"), 0o755)
			os.WriteFile(filepath.Join(dir, "skills", "seeded.json"), []byte("seed"), 0o644)
			v, err := syncOnce(context.Background(), c.f.serve(t), dir, "v0")
			if err == nil || v != c.held {
				t.Fatalf("sync: %q %v, want %q held", v, err, c.held)
			}
			if read(t, filepath.Join(dir, "skills/seeded.json")) != "seed" || read(t, filepath.Join(dir, "skills/a.json")) != "<none>" {
				t.Fatal("the tree changed")
			}
		})
	}
}

// L3 on #120: a symlink in the tree directory cannot send a write, or a
// removal, outside it.
func TestBridgeMirrorStaysInsideTheTree(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(outside, "keep.json"), []byte("outside"), 0o644)
	if err := os.Symlink(outside, filepath.Join(dir, "skills")); err != nil {
		t.Fatal(err)
	}
	f := &fakeTree{ans: treeAnswer{Version: "v1", Files: map[string][]byte{"skills/a.json": []byte("a")}}}
	if _, err := syncOnce(context.Background(), f.serve(t), dir, ""); err == nil {
		t.Fatal("wrote through a symlink")
	}
	if read(t, filepath.Join(outside, "a.json")) != "<none>" || read(t, filepath.Join(outside, "keep.json")) != "outside" {
		t.Fatal("the mirror reached outside the tree")
	}
}

// TREE-answer-bound (#1487): the guest plane sends a managed_tree answer
// of up to guest.MaxTreeAnswer bytes on the wire, newline included, and
// the bridge reads one of exactly that size whole.
func TestBridgeReadsATreeAnswerOfTheBoundWhole(t *testing.T) {
	answer := func(pad int) []byte {
		tree, _ := json.Marshal(treeAnswer{Version: "v" + strings.Repeat("a", pad),
			Files: map[string][]byte{"skills/a.json": []byte("a")}})
		var b strings.Builder
		json.NewEncoder(&b).Encode(map[string]any{"jsonrpc": "2.0", "id": 1,
			"result": map[string]any{"content": []any{map[string]any{"type": "text", "text": string(tree)}}}})
		return []byte(b.String())
	}
	body := answer(guest.MaxTreeAnswer - len(answer(0)))
	if len(body) != guest.MaxTreeAnswer {
		t.Fatalf("answer is %d bytes, not %d", len(body), guest.MaxTreeAnswer)
	}
	sock := filepath.Join(t.TempDir(), "b.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) })}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	dir := t.TempDir()
	v, err := syncOnce(context.Background(), c, dir, "")
	if err != nil || len(v) != guest.MaxTreeAnswer-len(answer(0))+1 || read(t, filepath.Join(dir, "skills/a.json")) != "a" {
		t.Fatalf("an answer of exactly the bound: version of %d bytes, %v", len(v), err)
	}
}

// undoTrees are A and a B whose write to context fails, through a
// symlink planted there that leads outside the tree, after it may have
// written some of its skills.
func undoTrees(t *testing.T, dir string, skills int) (a, b treeAnswer, outside string) {
	t.Helper()
	outside = t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "context")); err != nil {
		t.Fatal(err)
	}
	a = treeAnswer{Version: "vA", Files: map[string][]byte{"skills/x": []byte("a")}}
	b = treeAnswer{Version: "vB", Files: map[string][]byte{"context/y.md": []byte("y")}}
	for i := 0; i < skills; i++ {
		b.Files[fmt.Sprintf("skills/b%d.json", i)] = []byte("b")
	}
	return a, b, outside
}

// undone reports whether dir holds A again and nothing reached outside.
func undone(t *testing.T, dir, outside string) {
	t.Helper()
	if ents, _ := os.ReadDir(filepath.Join(dir, "skills")); len(ents) != 1 || read(t, filepath.Join(dir, "skills/x")) != "a" {
		t.Fatalf("UNDO left %d entries in skills, skills/x = %q", len(ents), read(t, filepath.Join(dir, "skills/x")))
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatal("the mirror reached outside the tree")
	}
}

// TREE-undo-invalidate (#1562, CHG-6): a mirror that fails part way has
// already written some of B's files, so the bridge holds no version; an
// UNDO to A is then fetched whole and removes them, not answered
// Unchanged. B's failing write lands wherever map order puts it, so the
// sequence repeats until it lands after a good file.
func TestBridgeUndoAfterAPartialMirrorRestoresTheOldTree(t *testing.T) {
	for try := 0; ; try++ {
		if try == 100 {
			t.Fatal("no partial mirror in 100 tries")
		}
		dir := t.TempDir()
		treeA, treeB, outside := undoTrees(t, dir, 20)
		f := &fakeTree{ans: treeA}
		c := f.serve(t)
		v, err := syncOnce(context.Background(), c, dir, "")
		if err != nil || v != "vA" {
			t.Fatalf("A: %q %v", v, err)
		}
		f.mu.Lock()
		f.ans = treeB
		f.mu.Unlock()
		if v, err = syncOnce(context.Background(), c, dir, v); err == nil {
			t.Fatal("B was written through a symlink")
		}
		if ents, _ := os.ReadDir(filepath.Join(dir, "skills")); len(ents) < 2 {
			continue // the failing path came first: nothing of B landed
		}
		f.mu.Lock()
		f.ans = treeA // the owner's UNDO to A
		f.mu.Unlock()
		if v, err = syncOnce(context.Background(), c, dir, v); err != nil || v != "vA" {
			t.Fatalf("UNDO: %q %v", v, err)
		}
		undone(t, dir, outside)
		return
	}
}

// TREE-undo-invalidate (#1562, CHG-6): the polling loop takes the version
// a failed sync returns, so after a failed B it asks for the whole tree,
// and an UNDO to A is answered whole rather than Unchanged.
func TestBridgePollAfterAFailedMirrorAsksForTheWholeTree(t *testing.T) {
	dir := t.TempDir()
	treeA, treeB, outside := undoTrees(t, dir, 1)
	// A whole, A unchanged, B failing, then the owner's UNDO to A.
	f := &fakeTree{script: []treeAnswer{treeA, treeA, treeB, treeA, treeA}, done: make(chan struct{})}
	c := f.serve(t)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { syncTree(ctx, c, dir, time.Millisecond); close(stopped) }()
	<-f.done
	cancel()
	<-stopped
	f.mu.Lock()
	asked := strings.Join(f.asked, ",")
	f.mu.Unlock()
	if want := ",vA,vA,,vA"; asked != want {
		t.Fatalf("asked for versions %q, want %q", asked, want)
	}
	undone(t, dir, outside)
}

// Security R1 on #1572: a tree that swaps a file for a directory of the
// same name, and an UNDO that swaps it back, each mirror whole; the old
// tree's file or directory does not stay in the way.
func TestBridgeUndoAcrossAFileToDirectorySwap(t *testing.T) {
	dir := t.TempDir()
	treeA := treeAnswer{Version: "vA", Files: map[string][]byte{"skills/x": []byte("a")}}
	treeB := treeAnswer{Version: "vB", Files: map[string][]byte{"skills/x/y.json": []byte("y")}}
	f := &fakeTree{ans: treeA}
	c := f.serve(t)
	v, err := syncOnce(context.Background(), c, dir, "")
	if err != nil || v != "vA" {
		t.Fatalf("A: %q %v", v, err)
	}
	f.mu.Lock()
	f.ans = treeB
	f.mu.Unlock()
	if v, err = syncOnce(context.Background(), c, dir, v); err != nil || v != "vB" || read(t, filepath.Join(dir, "skills/x/y.json")) != "y" {
		t.Fatalf("B: %q %v", v, err)
	}
	f.mu.Lock()
	f.ans = treeA // the owner's UNDO to A
	f.mu.Unlock()
	if v, err = syncOnce(context.Background(), c, dir, v); err != nil || v != "vA" {
		t.Fatalf("UNDO: %q %v", v, err)
	}
	if fi, err := os.Lstat(filepath.Join(dir, "skills/x")); err != nil || !fi.Mode().IsRegular() || read(t, filepath.Join(dir, "skills/x")) != "a" {
		t.Fatalf("UNDO left skills/x as %v, %q", fi, read(t, filepath.Join(dir, "skills/x")))
	}
}
