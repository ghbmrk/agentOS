package egress

// REQ: CRED-5, CAP-11

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// codeModeRequest is a responses request the pinned CLI (0.162.1) sent in
// code mode under the image's managed config (S8-W1 s6, #1503): its second
// turn, after one exec call. Ids are synthetic and the CLI's long prompt and
// tool descriptions are elided; the keys, types, names, schemas and the
// exec grammar are as the CLI sent them.
func codeModeRequest(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/codex-0.162.1-codemode.json")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	return body
}

// declaredTools is the additional_tools item's namespace list.
func declaredTools(t *testing.T, body map[string]any) []any {
	t.Helper()
	item := body["input"].([]any)[0].(map[string]any)
	if item["type"] != "additional_tools" {
		t.Fatalf("captured request's first item is %v", item["type"])
	}
	return item["tools"].([]any)
}

func namespaceTools(t *testing.T, body map[string]any, ns string) []any {
	t.Helper()
	for _, n := range declaredTools(t, body) {
		if n := n.(map[string]any); n["name"] == ns {
			return n["tools"].([]any)
		}
	}
	t.Fatalf("no namespace %s", ns)
	return nil
}

func setDeclared(body map[string]any, tools []any) {
	body["input"].([]any)[0].(map[string]any)["tools"] = tools
}

func setNamespace(body map[string]any, ns string, tools []any) {
	for _, n := range body["input"].([]any)[0].(map[string]any)["tools"].([]any) {
		if n := n.(map[string]any); n["name"] == ns {
			n["tools"] = tools
		}
	}
}

func encode(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestCodeModeRequestPasses: the pinned CLI's own code-mode request, every
// key it sends (client_metadata included) and every tool it declares, is
// forwarded.
func TestCodeModeRequestPasses(t *testing.T) {
	r := newWorkerRig(t, false)
	if w := r.do(responses(encode(t, codeModeRequest(t)))); w.Code != http.StatusOK {
		t.Fatalf("the pinned CLI's code-mode request: %d %s (%+v)", w.Code, w.Body, r.audit.last(t))
	}
	var sent map[string]any
	if err := json.Unmarshal(r.up.body[0], &sent); err != nil {
		t.Fatal(err)
	}
	if got, want := encode(t, sent["input"].([]any)[0]), encode(t, codeModeRequest(t)["input"].([]any)[0]); got != want {
		t.Fatalf("declared tools changed on the way: %s", got)
	}
}

// TestCodeModeHostedToolRefused: the same request with one tool the pinned
// CLI does not declare, hosted or not, is refused and never reaches the
// provider (#1503: a CLI update or a lower config layer enabling a tool
// OpenAI runs server-side).
func TestCodeModeHostedToolRefused(t *testing.T) {
	mutants := map[string]func(t *testing.T, b map[string]any){
		"hosted beside the namespaces": func(t *testing.T, b map[string]any) {
			setDeclared(b, append(declaredTools(t, b), map[string]any{"type": "web_search"}))
		},
		"hosted in a namespace": func(t *testing.T, b map[string]any) {
			setNamespace(b, "functions", append(namespaceTools(t, b, "functions"), map[string]any{"type": "web_search"}))
		},
		"hosted at the top level": func(t *testing.T, b map[string]any) {
			b["tools"] = []any{map[string]any{"type": "web_search"}}
		},
		"hosted image generation": func(t *testing.T, b map[string]any) {
			setDeclared(b, append(declaredTools(t, b), map[string]any{"type": "image_generation"}))
		},
		"hosted mcp": func(t *testing.T, b map[string]any) {
			setDeclared(b, append(declaredTools(t, b), map[string]any{"type": "mcp", "server_url": "https://mcp.example"}))
		},
		"undeclared function": func(t *testing.T, b map[string]any) {
			setNamespace(b, "functions", append(namespaceTools(t, b, "functions"),
				map[string]any{"type": "function", "name": "view_image", "parameters": map[string]any{}}))
		},
		"undeclared namespace": func(t *testing.T, b map[string]any) {
			setDeclared(b, append(declaredTools(t, b), map[string]any{"type": "namespace", "name": "mcp__remote",
				"tools": []any{map[string]any{"type": "function", "name": "fetch"}}}))
		},
		"declared name in another namespace": func(t *testing.T, b map[string]any) {
			setNamespace(b, "clock", append(namespaceTools(t, b, "clock"), map[string]any{"type": "custom", "name": "exec"}))
		},
		"declared name of another type": func(t *testing.T, b map[string]any) {
			setNamespace(b, "clock", []any{map[string]any{"type": "custom", "name": "sleep"}})
		},
		"namespace in a namespace": func(t *testing.T, b map[string]any) {
			setNamespace(b, "functions", append(namespaceTools(t, b, "functions"), map[string]any{"type": "namespace",
				"name": "clock", "tools": []any{map[string]any{"type": "function", "name": "sleep"}}}))
		},
		"tools under a function": func(t *testing.T, b map[string]any) {
			setNamespace(b, "clock", []any{map[string]any{"type": "function", "name": "sleep",
				"tools": []any{map[string]any{"type": "web_search"}}}})
		},
		"bare declared tool": func(t *testing.T, b map[string]any) {
			setDeclared(b, append(declaredTools(t, b), map[string]any{"type": "custom", "name": "exec"}))
		},
		"hosted tool_choice": func(t *testing.T, b map[string]any) {
			b["tool_choice"] = map[string]any{"type": "web_search"}
		},
		"client_metadata carries tools": func(t *testing.T, b map[string]any) {
			b["client_metadata"].(map[string]any)["x"] = map[string]any{"tools": []any{map[string]any{"type": "web_search"}}}
		},
		"client_metadata not text": func(t *testing.T, b map[string]any) {
			b["client_metadata"].(map[string]any)["x"] = 1
		},
		"client_metadata not an object": func(t *testing.T, b map[string]any) {
			b["client_metadata"] = "x"
		},
	}
	for name, mutate := range mutants {
		t.Run(name, func(t *testing.T) {
			b := codeModeRequest(t)
			mutate(t, b)
			r := newWorkerRig(t, false)
			if w := r.do(responses(encode(t, b))); w.Code != http.StatusForbidden {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if r.up.count() != 0 {
				t.Fatal("reached the provider")
			}
			if ev := r.audit.last(t); ev.Allowed || strings.Contains(ev.Reason, `"`) {
				t.Fatalf("journaled as %+v", ev)
			}
		})
	}
}

// TestPlanRouteDeclaresItsTools: a route declares the tools it allows, each
// of a client-side type, so none is allowed by default.
func TestPlanRouteDeclaresItsTools(t *testing.T) {
	for name, edit := range map[string]func(*PlanRoute){
		"no tools": func(p *PlanRoute) { p.Tools = nil },
		"hosted type": func(p *PlanRoute) {
			p.Tools = append(p.Tools, DeclaredTool{Namespace: "functions", Name: "s", Type: "web_search"})
		},
		"type not routed": func(p *PlanRoute) { p.ToolTypes = []string{"namespace", "function"} },
		"namespace type": func(p *PlanRoute) {
			p.Tools = append(p.Tools, DeclaredTool{Namespace: "functions", Name: "n", Type: "namespace"})
		},
		"unnamed":  func(p *PlanRoute) { p.Tools = append(p.Tools, DeclaredTool{Namespace: "functions", Type: "function"}) },
		"repeated": func(p *PlanRoute) { p.Tools = append(p.Tools, p.Tools[0]) },
	} {
		route := Codex()
		edit(&route)
		if err := route.validate(); err == nil || !strings.Contains(err.Error(), "tool") {
			t.Fatalf("%s: a route with this tool declaration validated: %v", name, err)
		}
	}
	if err := Codex().validate(); err != nil {
		t.Fatal(err)
	}
}
