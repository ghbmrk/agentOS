package main

// REQ: CAP-5, ARC-2

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

	"github.com/ghbmrk/agentos/broker/fold"
	"github.com/ghbmrk/agentos/broker/guest"
)

// planeMachines is the least a guest.Plane needs: the tree tests submit no
// plans, so the plane has no kernel.
type planeMachines struct{}

func (planeMachines) Step(context.Context, string) error { return nil }
func (planeMachines) RaisePrivate(string) error          { return nil }
func (planeMachines) Lineage(id string) (string, error)  { return id, nil }

// treeTool serves managed_tree as agentosd's liveTree answers it, or a
// fixed text in its place, and the agent's own tool "big", whose every
// answer is over fold.Max and so is held as a fold record.
type treeTool struct {
	mu   sync.Mutex
	ans  treeAnswer
	text string
	n    int
}

func (*treeTool) List() []map[string]any {
	return []map[string]any{{"name": "managed_tree"}, {"name": "big"}}
}

func (f *treeTool) Call(_ context.Context, _, _, name string, args json.RawMessage) (string, bool, error) {
	if name == "big" {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.n++
		return fmt.Sprintf("%d:%s", f.n, strings.Repeat("x", 64<<10)), true, nil
	}
	if name != "managed_tree" {
		return "", false, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.text != "" {
		return f.text, true, nil
	}
	var a struct{ Version string }
	json.Unmarshal(args, &a)
	ans := f.ans
	if a.Version == ans.Version {
		ans = treeAnswer{Version: ans.Version, Unchanged: true}
	}
	b, err := json.Marshal(ans)
	return string(b), true, err
}

// planeClient opens machine m1 on a real guest plane, which folds every
// tool result over fold.Max, and returns a client on its socket.
func planeClient(t *testing.T, tool *treeTool) *http.Client {
	t.Helper()
	p, err := guest.New(guest.Config{Dir: t.TempDir(), Machines: planeMachines{}, Tools: tool})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Shutdown)
	dir, err := p.Open("m1")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, guest.Socket)
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
}

// bigTree is a tree whose managed_tree answer is well over fold.Max.
func bigTree() map[string][]byte {
	files := map[string][]byte{"skills/seeded.json": []byte("seed")}
	for i := range 4 {
		files[fmt.Sprintf("skills/s%d.json", i)] = []byte(strings.Repeat(fmt.Sprintf("step %d;", i), 400))
	}
	files["procedures/p.json"] = []byte("p")
	files["context/c.md"] = []byte("c")
	return files
}

// TREE-fold-wipe (#1437), TREE-fold-evict (#1461): a managed tree over
// 8 KiB reaches the bridge whole and is applied; the seeded file stays,
// and the next poll is unchanged.
func TestBridgeAppliesATreeOverFoldMax(t *testing.T) {
	files := bigTree()
	b, _ := json.Marshal(treeAnswer{Version: "v1", Files: files})
	if len(b) <= fold.Max {
		t.Fatalf("tree answer is %d bytes, not over fold.Max", len(b))
	}
	tool := &treeTool{ans: treeAnswer{Version: "v1", Files: files}}
	c := planeClient(t, tool)
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "skills"), 0o755)
	os.WriteFile(filepath.Join(dir, "skills", "seeded.json"), []byte("seed"), 0o644)

	v, err := syncOnce(context.Background(), c, dir, "")
	if err != nil || v != "v1" {
		t.Fatalf("sync: %q %v", v, err)
	}
	for p, want := range files {
		if got := read(t, filepath.Join(dir, p)); got != string(want) {
			t.Errorf("%s: %d bytes, want %d", p, len(got), len(want))
		}
	}
	if v, err := syncOnce(context.Background(), c, dir, v); err != nil || v != "v1" {
		t.Fatalf("second poll: %q %v", v, err)
	}
	if read(t, filepath.Join(dir, "skills/seeded.json")) != "seed" {
		t.Fatal("seeded skill lost on the second poll")
	}
}

// agentFold calls the agent's tool "big" and returns its fold record's ID.
func agentFold(t *testing.T, c *http.Client) string {
	t.Helper()
	text, err := callTool(context.Background(), c, "big", map[string]string{})
	var in fold.StandIn
	if err != nil || json.Unmarshal([]byte(text), &in) != nil || !in.Folded || in.ID == "" {
		t.Fatalf("agent fold: %.80s %v", text, err)
	}
	return in.ID
}

// agentReads reports whether the agent can still read fold record id.
func agentReads(c *http.Client, id string) bool {
	text, err := callTool(context.Background(), c, "result_read", map[string]string{"id": id})
	return err == nil && strings.Contains(text, strings.Repeat("x", 64<<10))
}

// TREE-fold-evict (#1461, Security S1 and Potency P-1 on #1449): a sync
// that keeps failing refetches the whole tree on every poll. Over 40
// polls, an agent fold recorded before them stays readable.
func TestAFailingTreeSyncKeepsTheAgentsFolds(t *testing.T) {
	tool := &treeTool{ans: treeAnswer{Version: "v1", Files: bigTree()}}
	c := planeClient(t, tool)
	id := agentFold(t, c)
	// The tree directory is a regular file, so every mirror fails.
	dir := filepath.Join(t.TempDir(), "tree")
	os.WriteFile(dir, []byte("not a directory"), 0o644)
	for i := range 40 {
		if v, err := syncOnce(context.Background(), c, dir, ""); err == nil || v != "" {
			t.Fatalf("poll %d: %q %v", i, v, err)
		}
	}
	if !agentReads(c, id) {
		t.Fatal("40 failing tree polls evicted the agent's folded result")
	}
}

// TREE-fold-evict (#1461, Potency P-2 on #1449): with the agent's fold
// store full (32 records, 2 MiB), a 2 MiB tree change keeps every one of
// the agent's records readable.
func TestALargeTreeChangeKeepsTheAgentsFolds(t *testing.T) {
	files := map[string][]byte{"skills/big.json": []byte(strings.Repeat("s", 2<<20))}
	tool := &treeTool{ans: treeAnswer{Version: "v2", Files: files}}
	c := planeClient(t, tool)
	var ids []string
	for range 32 {
		ids = append(ids, agentFold(t, c))
	}
	dir := t.TempDir()
	if v, err := syncOnce(context.Background(), c, dir, "v1"); err != nil || v != "v2" {
		t.Fatalf("sync: %q %v", v, err)
	}
	if got := read(t, filepath.Join(dir, "skills/big.json")); len(got) != 2<<20 {
		t.Fatalf("tree file: %d bytes", len(got))
	}
	for i, id := range ids {
		if !agentReads(c, id) {
			t.Fatalf("agent record %d of 32 evicted by the tree change", i)
		}
	}
}

// An answer with no version is not a tree, whether a fold stand-in or
// anything else, and is refused: nothing is deleted.
func TestBridgeRefusesATreeAnswerWithNoVersion(t *testing.T) {
	for name, text := range map[string]string{
		"fold stand-in": `{"folded":true,"id":"gone","bytes":20000,"sha256":"00","head":"{"}`,
		"no version":    `{"files":{}}`,
		"empty":         `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			c := planeClient(t, &treeTool{text: text})
			dir := t.TempDir()
			os.MkdirAll(filepath.Join(dir, "skills"), 0o755)
			os.WriteFile(filepath.Join(dir, "skills", "seeded.json"), []byte("seed"), 0o644)
			v, err := syncOnce(context.Background(), c, dir, "")
			if err == nil || v != "" {
				t.Fatalf("sync: %q %v", v, err)
			}
			if read(t, filepath.Join(dir, "skills/seeded.json")) != "seed" {
				t.Fatal("the tree was wiped")
			}
		})
	}
}
