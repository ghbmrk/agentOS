package guest

// REQ: ARC-6, CAP-3, FORGET-FOLDS-1, FORGET-FOLDS-2

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/fold"
)

type fakeTools struct{ calls []string }

func (f *fakeTools) List() []map[string]any {
	return []map[string]any{{"name": "recall_search", "inputSchema": map[string]any{"type": "object"}}}
}

func (f *fakeTools) Call(_ context.Context, machine, lineage, name string, args json.RawMessage) (string, bool, error) {
	if name != "recall_search" {
		return "", false, nil
	}
	f.calls = append(f.calls, machine+" "+lineage+" "+string(args))
	if strings.Contains(string(args), "fail") {
		return "", true, errors.New("fixed refusal")
	}
	return "results", true, nil
}

// Further broker tools are listed beside the effect tools and called with
// the machine and lineage the socket fixes, whatever the guest claims.
func TestARC6FurtherToolsTakeIdentityFromTheSocket(t *testing.T) {
	ft := &fakeTools{}
	r := newRig(t, func(c *Config) { c.Tools = ft })
	r.ms.lineage["fork-1"] = "root-7"
	var names []string
	for _, tl := range r.rpc("fork-1", "tools/list", nil)["tools"].([]any) {
		names = append(names, tl.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "effect_request,effect_status,result_read,recall_search" {
		t.Fatalf("tools %v", names)
	}
	res := r.rpc("fork-1", "tools/call", map[string]any{"name": "recall_search", "arguments": map[string]any{"query": "x"}}, "X-Machine", "m2")
	if text := res["content"].([]any)[0].(map[string]any)["text"]; text != "results" || res["isError"] == true {
		t.Fatalf("result %v", res)
	}
	if len(ft.calls) != 1 || !strings.HasPrefix(ft.calls[0], "fork-1 root-7 ") {
		t.Fatalf("identity: %v", ft.calls)
	}
	res = r.rpc("fork-1", "tools/call", map[string]any{"name": "recall_search", "arguments": map[string]any{"query": "fail"}})
	if res["isError"] != true {
		t.Fatalf("error not reported: %v", res)
	}
	// Names the extra tools do not serve still reach the effect tools, and
	// unknown names are refused.
	if _, errText := r.tool("fork-1", "nope", nil); !strings.Contains(errText, "no tool") {
		t.Fatalf("unknown tool: %s", errText)
	}
	if st, _ := r.tool("fork-1", "effect_request", send("r1")); st.State != "succeeded" {
		t.Fatalf("effect tools: %+v", st)
	}
}

type shadowTools struct{ fakeTools }

func (shadowTools) List() []map[string]any {
	return []map[string]any{{"name": "effect_status"}, {"name": "result_read"}, {"name": "recall_search"}}
}

// A further tool set cannot list a tool under an effect tool's or
// result_read's name: the broker's own names are served only by the plane
// (L3 N2 on #95, L3 on #670).
func TestFurtherToolsCannotShadowTheEffectTools(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Tools = &shadowTools{} })
	var names []string
	for _, tl := range r.rpc("m1", "tools/list", nil)["tools"].([]any) {
		names = append(names, tl.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "effect_request,effect_status,result_read,recall_search" {
		t.Fatalf("tools %v", names)
	}
}

// A JSON tool result loses insignificant whitespace and nothing else.
func TestAJSONToolResultLosesOnlyWhitespace(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Tools = prettyTools{} })
	res := r.rpc("m1", "tools/call", map[string]any{"name": "pretty", "arguments": map[string]any{}})
	text, _ := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if text != `{"note":"keep  spaces","n":1}` && text != `{"n":1,"note":"keep  spaces"}` {
		// key order is the tool's order, only spaces go
		if compactJSON(prettyBody) != text {
			t.Fatalf("result %q", text)
		}
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(text), &got); err != nil || got["note"] != "keep  spaces" {
		t.Fatalf("value %q %v", text, err)
	}
	if res["isError"] == true {
		t.Fatal("error")
	}
}

const prettyBody = "{\n  \"n\": 1,\n  \"note\": \"keep  spaces\"\n}\n"

type prettyTools struct{}

func (prettyTools) List() []map[string]any {
	return []map[string]any{{"name": "pretty", "inputSchema": map[string]any{"type": "object"}}}
}

func (prettyTools) Call(context.Context, string, string, string, json.RawMessage) (string, bool, error) {
	return prettyBody, true, nil
}

type bigTools struct{}

func (bigTools) List() []map[string]any {
	return []map[string]any{{"name": "big", "inputSchema": map[string]any{"type": "object"}}}
}

func (bigTools) Call(_ context.Context, _, _, name string, _ json.RawMessage) (string, bool, error) {
	if name != "big" && name != TreeTool {
		return "", false, nil
	}
	return strings.Repeat("x", fold.Max+32), true, nil
}

// An oversized tool result is handed back as a stand-in. Only the machine
// that received it can read the original, which is not folded a second time.
func TestAnOversizedToolResultIsReadBackWhole(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Tools = bigTools{} })
	res := r.rpc("m1", "tools/call", map[string]any{"name": "big", "arguments": map[string]any{}})
	text, _ := res["content"].([]any)[0].(map[string]any)["text"].(string)
	var in fold.StandIn
	if err := json.Unmarshal([]byte(text), &in); err != nil || !in.Folded || in.Bytes != fold.Max+32 {
		t.Fatalf("stand-in: %s %v", text, err)
	}
	got := r.rpc("m1", "tools/call", map[string]any{"name": "result_read", "arguments": map[string]any{"id": in.ID}})
	full, _ := got["content"].([]any)[0].(map[string]any)["text"].(string)
	if full != strings.Repeat("x", fold.Max+32) || got["isError"] == true {
		t.Fatalf("read back %d err %v", len(full), got["isError"])
	}
	other := r.rpc("m2", "tools/call", map[string]any{"name": "result_read", "arguments": map[string]any{"id": in.ID}})
	if other["isError"] != true {
		t.Fatalf("other machine: %v", other)
	}
}

// A machine created later under a destroyed machine's ID cannot read the
// results held for the destroyed one (L3 and Security on #670).
func TestAReusedMachineIDCannotReadTheOldMachinesResults(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Tools = bigTools{} })
	res := r.rpc("m1", "tools/call", map[string]any{"name": "big", "arguments": map[string]any{}})
	text, _ := res["content"].([]any)[0].(map[string]any)["text"].(string)
	var in fold.StandIn
	if err := json.Unmarshal([]byte(text), &in); err != nil || !in.Folded {
		t.Fatalf("stand-in: %.80s %v", text, err)
	}
	r.p.Close("m1")
	got := r.rpc("m1", "tools/call", map[string]any{"name": "result_read", "arguments": map[string]any{"id": in.ID}})
	if got["isError"] != true {
		t.Fatal("a reused ID read the destroyed machine's result")
	}
}

// TREE-fold-evict (#1461): the managed tree goes to the guest whole. The
// bridge reads it on every poll, and a failing sync polls it again and
// again; folding it would fill the machine's fold store and evict the
// agent's own held results, which it cannot safely fetch again.
func TestTheManagedTreeIsNeverFolded(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Tools = bigTools{} })
	res := r.rpc("m1", "tools/call", map[string]any{"name": "big", "arguments": map[string]any{}})
	text, _ := res["content"].([]any)[0].(map[string]any)["text"].(string)
	var in fold.StandIn
	if err := json.Unmarshal([]byte(text), &in); err != nil || !in.Folded {
		t.Fatalf("stand-in: %.80s %v", text, err)
	}
	for i := range 40 {
		got := r.rpc("m1", "tools/call", map[string]any{"name": TreeTool, "arguments": map[string]any{}})
		tree, _ := got["content"].([]any)[0].(map[string]any)["text"].(string)
		if tree != strings.Repeat("x", fold.Max+32) || got["isError"] == true {
			t.Fatalf("tree call %d: %d bytes, err %v", i, len(tree), got["isError"])
		}
	}
	got := r.rpc("m1", "tools/call", map[string]any{"name": "result_read", "arguments": map[string]any{"id": in.ID}})
	if got["isError"] == true {
		t.Fatal("the agent's held result was evicted by managed_tree answers")
	}
}

// FORGET-FOLDS-2 (CAP-3): a reset machine keeps its socket but not the
// results it held, so result_read fails after a forget. Another machine's
// held results stay.
func TestResultReadFailsAfterAForgetReset(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Tools = bigTools{} })
	held := func(id string) fold.StandIn {
		res := r.rpc(id, "tools/call", map[string]any{"name": "big", "arguments": map[string]any{}})
		text, _ := res["content"].([]any)[0].(map[string]any)["text"].(string)
		var in fold.StandIn
		if err := json.Unmarshal([]byte(text), &in); err != nil || !in.Folded {
			t.Fatalf("stand-in: %.80s %v", text, err)
		}
		return in
	}
	read := func(id string, in fold.StandIn) map[string]any {
		return r.rpc(id, "tools/call", map[string]any{"name": "result_read", "arguments": map[string]any{"id": in.ID}})
	}
	a, b := held("m1"), held("m2")
	if read("m1", a)["isError"] == true {
		t.Fatal("held result unreadable before the reset")
	}
	r.p.Reset("m1")
	if read("m1", a)["isError"] != true {
		t.Fatal("result_read still returns a held result after the reset")
	}
	if read("m2", b)["isError"] == true {
		t.Fatal("resetting m1 dropped m2's held result")
	}
	if again := held("m1"); read("m1", again)["isError"] == true {
		t.Fatal("m1's socket stopped serving after the reset")
	}
}
