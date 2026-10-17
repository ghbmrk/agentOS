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

// undoTrees are A and a B whose write to context fails, because the file
// name is longer than the file system allows, after it may have written
// some of its skills.
func undoTrees(t *testing.T, dir string, skills int) (a, b treeAnswer) {
	t.Helper()
	a = treeAnswer{Version: "vA", Files: map[string][]byte{"skills/x": []byte("a")}}
	b = treeAnswer{Version: "vB", Files: map[string][]byte{"context/" + strings.Repeat("y", 300): []byte("y")}}
	for i := 0; i < skills; i++ {
		b.Files[fmt.Sprintf("skills/b%d.json", i)] = []byte("b")
	}
	return a, b
}

// undone reports whether dir holds A again.
func undone(t *testing.T, dir string) {
	t.Helper()
	if ents, _ := os.ReadDir(filepath.Join(dir, "skills")); len(ents) != 1 || read(t, filepath.Join(dir, "skills/x")) != "a" {
		t.Fatalf("UNDO left %d entries in skills, skills/x = %q", len(ents), read(t, filepath.Join(dir, "skills/x")))
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
		treeA, treeB := undoTrees(t, dir, 20)
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
			t.Fatal("B was written with a name too long")
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
		undone(t, dir)
		return
	}
}

// TREE-undo-invalidate (#1562, CHG-6): the polling loop takes the version
// a failed sync returns, so after a failed B it asks for the whole tree,
// and an UNDO to A is answered whole rather than Unchanged.
func TestBridgePollAfterAFailedMirrorAsksForTheWholeTree(t *testing.T) {
	dir := t.TempDir()
	treeA, treeB := undoTrees(t, dir, 1)
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
	undone(t, dir)
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

// TREE-clearway-symlink (#1630, #1572 Security S-1; CHG-6, ARC-7): a
// symlink anywhere on a file's path, the namespace and the file itself
// included, is refused and left. One that stays inside the tree directory
// is no exception: it must not let a sync remove or write a directory
// outside skills, procedures and context.
func TestBridgeRefusesASymlinkOnTheWayOfAFile(t *testing.T) {
	for _, tc := range []struct{ name, link, file string }{
		{"ancestor", "skills/l", "skills/l/keep"},
		{"deep ancestor", "skills/d/l", "skills/d/l/keep"},
		{"namespace", "skills", "skills/keep"},
		{"the file itself", "skills/keep", "skills/keep"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			// other is inside the tree directory but outside every namespace.
			other := filepath.Join(dir, "other")
			os.MkdirAll(filepath.Join(other, "keep"), 0o755)
			os.WriteFile(filepath.Join(other, "keep", "f"), []byte("mine"), 0o644)
			if tc.link != "skills" {
				os.MkdirAll(filepath.Join(dir, "skills/d"), 0o755)
			}
			target, _ := filepath.Rel(filepath.Dir(filepath.Join(dir, tc.link)), other)
			if err := os.Symlink(target, filepath.Join(dir, tc.link)); err != nil {
				t.Fatal(err)
			}
			f := &fakeTree{ans: treeAnswer{Version: "v1", Files: map[string][]byte{tc.file: []byte("new")}}}
			v, err := syncOnce(context.Background(), f.serve(t), dir, "")
			if err == nil || v != "" {
				t.Fatalf("synced through a symlink: %q %v", v, err)
			}
			if fi, err := os.Lstat(filepath.Join(dir, tc.link)); err != nil || fi.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("the symlink %s was not left: %v", tc.link, err)
			}
			if read(t, filepath.Join(other, "keep", "f")) != "mine" {
				t.Fatal("the sync removed a directory outside the namespaces")
			}
			if ents, _ := os.ReadDir(other); len(ents) != 1 {
				t.Fatalf("the sync wrote outside the namespaces: %d entries", len(ents))
			}
		})
	}
}

// A symlink on the path of a file whose content is already right is refused
// too: the tree directory must be a copy of the tree, and a link there is
// not.
func TestBridgeRefusesASymlinkEvenWhenTheContentMatches(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "other"), 0o755)
	os.WriteFile(filepath.Join(dir, "other", "keep"), []byte("same"), 0o644)
	os.MkdirAll(filepath.Join(dir, "skills"), 0o755)
	if err := os.Symlink("../other", filepath.Join(dir, "skills", "l")); err != nil {
		t.Fatal(err)
	}
	f := &fakeTree{ans: treeAnswer{Version: "v1", Files: map[string][]byte{"skills/l/keep": []byte("same")}}}
	if _, err := syncOnce(context.Background(), f.serve(t), dir, ""); err == nil {
		t.Fatal("accepted a symlink on the path")
	}
}

// TREE-clearway-symlink (#1630, reviews of #1728): a namespace that is
// itself a symlink is refused before anything is written or removed, even
// when the tree holds no file in it, or no file at all: the removal walk
// would otherwise follow it and delete the files of another directory.
func TestBridgeRefusesASymlinkedNamespaceWithNoFileInIt(t *testing.T) {
	for _, tc := range []struct {
		name, link string
		files      map[string][]byte
	}{
		{"empty tree", "skills", map[string][]byte{}},
		{"tree of another namespace", "context", map[string][]byte{"skills/x": []byte("x")}},
		{"procedures", "procedures", map[string][]byte{"skills/x": []byte("x")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			other := filepath.Join(dir, "other")
			os.MkdirAll(other, 0o755)
			os.WriteFile(filepath.Join(other, "keep"), []byte("mine"), 0o644)
			if err := os.Symlink("other", filepath.Join(dir, tc.link)); err != nil {
				t.Fatal(err)
			}
			f := &fakeTree{ans: treeAnswer{Version: "v1", Files: tc.files}}
			v, err := syncOnce(context.Background(), f.serve(t), dir, "")
			if err == nil || v != "" {
				t.Fatalf("synced past a symlinked namespace: %q %v", v, err)
			}
			if read(t, filepath.Join(other, "keep")) != "mine" {
				t.Fatal("the sync removed a file outside the namespaces")
			}
			if _, err := os.Lstat(filepath.Join(dir, "skills", "x")); err == nil && tc.link != "skills" {
				t.Fatal("the sync wrote before refusing")
			}
		})
	}
}

// The refusal names the tree directory, the link and the remedy, and not
// the file being written: mirror visits files in map order, so a message
// that named one would differ between polls and defeat syncTree's
// once-per-message log.
func TestBridgeSymlinkRefusalIsTheSameForEveryFile(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "other"), 0o755)
	os.MkdirAll(filepath.Join(dir, "skills"), 0o755)
	if err := os.Symlink("../other", filepath.Join(dir, "skills", "l")); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for i := 0; i < 20; i++ {
		files[fmt.Sprintf("skills/l/f%d", i)] = []byte("x")
	}
	f := &fakeTree{ans: treeAnswer{Version: "v1", Files: files}}
	c := f.serve(t)
	msgs := map[string]bool{}
	for i := 0; i < 20; i++ {
		_, err := syncOnce(context.Background(), c, dir, "")
		if err == nil {
			t.Fatal("synced through a symlink")
		}
		msgs[err.Error()] = true
	}
	if len(msgs) != 1 {
		t.Fatalf("%d distinct messages: %v", len(msgs), msgs)
	}
	for m := range msgs {
		if !strings.Contains(m, dir) || !strings.Contains(m, "skills/l") || !strings.Contains(m, "remove") || strings.Contains(m, "/f") {
			t.Fatalf("message %q should name the directory, the link and the remedy, not a file", m)
		}
	}
}

// #1462: the console line for a refused answer says what was refused and
// that the tree held stays; "nothing changed" read as "the tree did not
// change upstream".
func TestBridgeNoVersionRefusalSaysTheTreeWasKept(t *testing.T) {
	f := &fakeTree{ans: treeAnswer{Files: map[string][]byte{"skills/a.json": []byte("a")}}}
	_, err := syncOnce(context.Background(), f.serve(t), t.TempDir(), "v0")
	const want = "refused a managed_tree answer with no version; kept the current tree"
	if err == nil || err.Error() != want {
		t.Fatalf("sync error %v, want %q", err, want)
	}
}
