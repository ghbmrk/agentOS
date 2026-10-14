package main

// REQ: CAP-5, ARC-2

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/ghbmrk/agentos/broker/journal"
)

// planeMachines and noEffects are the least a guest.Plane needs: the
// tree tests call no effect tools.
type planeMachines struct{}

func (planeMachines) Step(context.Context, string) error { return nil }
func (planeMachines) RaisePrivate(string) error          { return nil }
func (planeMachines) Lineage(id string) (string, error)  { return id, nil }

type noEffects struct{}

func (noEffects) Submit(journal.Intent) (journal.Status, error) {
	return journal.Status{}, errors.New("no effects")
}
func (noEffects) Authorize(context.Context, string) (journal.Status, error) {
	return journal.Status{}, errors.New("no effects")
}
func (noEffects) Dispatch(context.Context, string) (journal.Status, error) {
	return journal.Status{}, errors.New("no effects")
}
func (noEffects) Get(string) (journal.Status, error) {
	return journal.Status{}, errors.New("no effects")
}

// treeTool serves managed_tree as agentosd's liveTree answers it, or a
// fixed text in its place.
type treeTool struct {
	mu   sync.Mutex
	ans  treeAnswer
	text string
}

func (*treeTool) List() []map[string]any { return []map[string]any{{"name": "managed_tree"}} }

func (f *treeTool) Call(_ context.Context, _, _, name string, args json.RawMessage) (string, bool, error) {
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
	p, err := guest.New(guest.Config{Dir: t.TempDir(), Machines: planeMachines{}, Effects: noEffects{}, Tools: tool})
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

// TREE-fold-wipe (#1437): a managed tree over 8 KiB reaches the bridge
// folded. The bridge reads the full answer back with result_read and
// applies it; the seeded file stays, and the next poll is unchanged.
func TestBridgeAppliesATreeTheBrokerFolded(t *testing.T) {
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

// An answer with no version that is not a readable fold (its record
// evicted, or not a tree at all) is refused: nothing is deleted.
func TestBridgeRefusesATreeAnswerWithNoVersion(t *testing.T) {
	for name, text := range map[string]string{
		"evicted fold": `{"folded":true,"id":"gone","bytes":20000,"sha256":"00","head":"{"}`,
		"no version":   `{"files":{}}`,
		"empty":        `{}`,
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
