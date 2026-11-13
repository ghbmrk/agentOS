package guest

// REQ: CAP-5, ARC-6

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// treeText is a broker tool set whose managed_tree answer is text, as
// agentosd's liveTree would give it.
type treeText struct{ text string }

func (treeText) List() []map[string]any { return nil }

func (t *treeText) Call(_ context.Context, _, _, name string, _ json.RawMessage) (string, bool, error) {
	if name != TreeTool {
		return "", false, nil
	}
	return t.text, true, nil
}

// treeCall is one managed_tree call as the bridge makes it: its raw
// answer on the wire, and that answer's first text and error flag.
func (r *rig) treeCall(id string) (wire int, text string, isErr bool) {
	r.t.Helper()
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": TreeTool, "arguments": map[string]any{"version": ""}}})
	code, body := r.do(id, "POST", "/mcp", string(b))
	if code != 200 {
		r.t.Fatalf("managed_tree: %d %.200s", code, body)
	}
	var out struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		r.t.Fatal(err)
	}
	if len(out.Result.Content) != 1 {
		r.t.Fatalf("managed_tree answer has %d content items", len(out.Result.Content))
	}
	return len(body), out.Result.Content[0].Text, out.Result.IsError
}

// TREE-answer-bound (#1487): the bound is on the answer as the bridge
// reads it, not on the tree's raw bytes. An answer of exactly
// MaxTreeAnswer bytes goes whole; one byte more is refused as too large
// and never sent cut short.
func TestTreeAnswerBoundIsOnTheWire(t *testing.T) {
	tt := &treeText{}
	r := newRig(t, func(c *Config) { c.Tools = tt })
	// Each plain character added to a path adds one byte on the wire.
	fill := func(n int) string {
		return `{"version":"v1","files":{"skills/` + strings.Repeat("a", n) + `":""}}`
	}
	tt.text = fill(0)
	base, _, _ := r.treeCall("m1")
	for _, over := range []int{0, 1} {
		tt.text = fill(MaxTreeAnswer - base + over)
		wire, text, isErr := r.treeCall("m1")
		if wire > MaxTreeAnswer {
			t.Fatalf("over %d: %d bytes on the wire, over %d", over, wire, MaxTreeAnswer)
		}
		switch over {
		case 0:
			if isErr || text != tt.text || wire != MaxTreeAnswer {
				t.Fatalf("an answer of exactly the bound was not sent whole: %d bytes, error %v", wire, isErr)
			}
		case 1:
			if !isErr || !strings.Contains(text, "too large") {
				t.Fatalf("an answer one byte over the bound: error %v, %.80q", isErr, text)
			}
		}
	}
}

// The security review's probe (#1484 S-L1): a tree under 4 MiB of path
// and file bytes, whose paths are made of characters JSON escapes, grows
// past 8 MiB once encoded twice. It is refused here as too large, not cut
// short at the bridge's read limit.
func TestTreeAnswerWithEscapedPathsIsRefusedWhole(t *testing.T) {
	files := map[string][]byte{}
	raw := 0
	for i := 0; raw+300 < 4<<20; i++ {
		p := fmt.Sprintf("skills/%d-%s.json", i, strings.Repeat("<&>", 80))
		files[p] = []byte("x")
		raw += len(p) + 1
	}
	b, err := json.Marshal(struct {
		Version string            `json:"version"`
		Files   map[string][]byte `json:"files"`
	}{"v1", files})
	if err != nil {
		t.Fatal(err)
	}
	var logged []string
	r := newRig(t, func(c *Config) {
		c.Tools = &treeText{string(b)}
		c.Logf = func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }
	})
	wire, text, isErr := r.treeCall("m1")
	if !isErr || !strings.Contains(text, "too large") || wire > MaxTreeAnswer {
		t.Fatalf("%d raw bytes: %d on the wire, error %v, %.80q", raw, wire, isErr, text)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "managed tree not sent") {
		t.Fatalf("logged %q", logged)
	}
}

// #1488 O-1: the bridge reads only a tree answer's first item, so the
// one-shot note about a failed step snapshot never rides on one. A tree
// poll leaves it for the agent's next tool result.
func TestATreePollLeavesTheStepNoteForTheAgent(t *testing.T) {
	r := newRig(t, func(c *Config) {
		c.StepInterval = time.Hour
		c.Tools = &treeText{`{"version":"v1"}`}
	})
	r.tool("m1", "plan", send("r1")) // snapshots at once, and succeeds
	r.ms.failSteps(fmt.Errorf("vm: %w", ErrStepNoRoom))
	r.tool("m1", "plan", send("r2"))
	r.intervalPasses("m1") // the trailing snapshot runs, and fails
	r.treeCall("m1")       // one content item: no note
	if got := r.notes("m1", "plan", map[string]any{"request_id": "r2"}); len(got) != 1 || got[0] != stepNoteNoRoom {
		t.Fatalf("the agent's next result's notes = %q", got)
	}
}
