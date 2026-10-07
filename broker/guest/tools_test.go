package guest

// REQ: ARC-6, CAP-3

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
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
	if strings.Join(names, ",") != "effect_request,effect_status,recall_search" {
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
	return []map[string]any{{"name": "effect_status"}, {"name": "recall_search"}}
}

// A further tool set cannot list a tool under an effect tool's name: the
// broker's own names are served only by the plane (L3 N2 on #95).
func TestFurtherToolsCannotShadowTheEffectTools(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Tools = &shadowTools{} })
	var names []string
	for _, tl := range r.rpc("m1", "tools/list", nil)["tools"].([]any) {
		names = append(names, tl.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "effect_request,effect_status,recall_search" {
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
