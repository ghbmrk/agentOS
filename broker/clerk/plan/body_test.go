package plan_test

// REQ: PLN-5, CLK-7, LOG-7, RES-5

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/plan"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// capture is a request in the shape Codex CLI 0.162.1 sends in code mode
// (#809): the top-level keys it sets, its declared tools in an
// additional_tools item, developer and user messages, and a custom tool
// call with its output. The tools come from the Codex declaration, grouped
// by namespace; the text is synthetic.
func capture(t *testing.T) map[string]any {
	t.Helper()
	spaces := map[string][]any{}
	var order []string
	for _, tl := range plan.Codex(nil).Body.Tools {
		tool := map[string]any{"type": tl.Type, "name": tl.Name, "description": "d"}
		if tl.Type == "custom" {
			tool["format"] = map[string]any{"type": "grammar", "syntax": "lark", "definition": "start: /.+/"}
		} else {
			tool["parameters"] = map[string]any{"type": "object", "properties": map[string]any{"url": map[string]any{"type": "string"}}}
		}
		if _, ok := spaces[tl.Namespace]; !ok {
			order = append(order, tl.Namespace)
		}
		spaces[tl.Namespace] = append(spaces[tl.Namespace], tool)
	}
	var tools []any
	for _, ns := range order {
		tools = append(tools, map[string]any{"type": "namespace", "name": ns, "description": "", "tools": spaces[ns]})
	}
	text := func(s string) []any { return []any{map[string]any{"type": "input_text", "text": s}} }
	return map[string]any{
		"model": "gpt-m", "stream": true, "tool_choice": "auto", "parallel_tool_calls": false,
		"reasoning": map[string]any{"effort": "low", "context": "all_turns"}, "store": false,
		"include": []any{"reasoning.encrypted_content"}, "prompt_cache_key": "k", "text": map[string]any{"verbosity": "low"},
		"client_metadata": map[string]any{
			"x-codex-installation-id": "11111111-1111-4111-8111-111111111111",
			"session_id":              "22222222-2222-4222-8222-222222222222",
			"thread_id":               "22222222-2222-4222-8222-222222222222",
			"x-codex-window-id":       "22222222-2222-4222-8222-222222222222:1",
			"turn_id":                 "33333333-3333-4333-8333-333333333333",
			"x-codex-turn-metadata":   `{"request_kind":"turn","workspaces":{}}`,
		},
		"input": []any{
			map[string]any{"type": "additional_tools", "id": "at_1", "role": "developer", "tools": tools},
			map[string]any{"type": "message", "id": "m1", "role": "developer", "content": text("instructions")},
			map[string]any{"type": "message", "id": "m2", "role": "user", "content": text("brief")},
			map[string]any{"type": "custom_tool_call", "call_id": "c0", "name": "exec", "input": "print(1)"},
			map[string]any{"type": "custom_tool_call_output", "id": "o1", "call_id": "c0", "output": text("1")},
		},
	}
}

func callWith(p *plan.Login, guest, bearer, body string, m plan.Meter) (*http.Response, string) {
	h := map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + bearer}
	return p.Do(context.Background(), guest, req("POST", "/backend-api/codex/responses", body, h), m)
}

func encode(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A model call's body is held to the CLI's declared shape before anything
// is sent: the measured request passes as the clerk's own encoding with
// store forced off, and a hosted tool, a provider-held conversation, a
// remote content source or any undeclared shape is refused with nothing
// sent (PLN-5(a), CLK-7).
func TestPlanModelBodyHeldToDeclaredShape(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	ph := g.Tokens["access_token"]

	resp, d := callWith(p, "g", ph, encode(t, capture(t)), free)
	if d != "" {
		t.Fatalf("the measured request: %s", d)
	}
	read(t, resp)
	_, sent := f.last()
	var got map[string]any
	if err := json.Unmarshal([]byte(sent), &got); err != nil || got["store"] != false || len(got) != len(capture(t)) {
		t.Fatalf("upstream body: %v (%v)", got, err)
	}
	if b := encode(t, map[string]any{"model": "m", "stream": true}); true {
		if resp, d := callWith(p, "g", ph, b, free); d != "" {
			t.Fatalf("a minimal body: %s", d)
		} else {
			read(t, resp)
		}
		if _, sent := f.last(); sent != `{"model":"m","store":false,"stream":true}` {
			t.Fatalf("store is not forced off: %s", sent)
		}
	}

	mut := func(edit func(m map[string]any)) string {
		m := capture(t)
		edit(m)
		return encode(t, m)
	}
	item := func(m map[string]any, i int) map[string]any { return m["input"].([]any)[i].(map[string]any) }
	before := f.hits()
	for name, c := range map[string]struct{ body, rule string }{
		"not an object": {`[1]`, "json"},
		"trailing data": {`{"model":"m"} {}`, "json"},
		"store on":      {mut(func(m map[string]any) { m["store"] = true }), "store"},
		// The guest does not choose how its call is metered (#3128 Security 1).
		"stream off":     {mut(func(m map[string]any) { m["stream"] = false }), "stream"},
		"stream absent":  {mut(func(m map[string]any) { delete(m, "stream") }), "stream"},
		"stream as text": {mut(func(m map[string]any) { m["stream"] = "true" }), "stream"},
		"a url under parameters outside a tool": {mut(func(m map[string]any) {
			item(m, 1)["parameters"] = map[string]any{"image_url": "https://example.net/a.png"}
		}), "remote"},
		"background":            {mut(func(m map[string]any) { m["background"] = true }), "key"},
		"previous_response_id":  {mut(func(m map[string]any) { m["previous_response_id"] = "r" }), "key"},
		"conversation":          {mut(func(m map[string]any) { m["conversation"] = "c" }), "key"},
		"undeclared key":        {mut(func(m map[string]any) { m["metadata"] = map[string]any{} }), "key"},
		"hosted tool top level": {mut(func(m map[string]any) { m["tools"] = []any{map[string]any{"type": "web_search"}} }), "tool"},
		"undeclared function": {mut(func(m map[string]any) {
			m["tools"] = []any{map[string]any{"type": "function", "name": "shell"}}
		}), "tool"},
		"hosted tool in additional_tools": {mut(func(m map[string]any) {
			it := item(m, 0)
			it["tools"] = append(it["tools"].([]any), map[string]any{"type": "web_search_preview"})
		}), "tool"},
		"a namespace in a namespace": {mut(func(m map[string]any) {
			it := item(m, 0)
			ns := it["tools"].([]any)[0].(map[string]any)
			ns["tools"] = append(ns["tools"].([]any), map[string]any{"type": "namespace", "name": "functions", "tools": []any{}})
		}), "tool"},
		"undeclared namespace": {mut(func(m map[string]any) {
			it := item(m, 0)
			it["tools"] = append(it["tools"].([]any), map[string]any{"type": "namespace", "name": "web", "tools": []any{}})
		}), "tool"},
		"declared tool of another type": {mut(func(m map[string]any) {
			it := item(m, 0)
			it["tools"] = []any{map[string]any{"type": "namespace", "name": "functions", "tools": []any{map[string]any{"type": "function", "name": "exec"}}}}
		}), "tool"},
		"tools inside a message": {mut(func(m map[string]any) { item(m, 1)["tools"] = []any{} }), "tool"},
		"tools nested in reasoning": {mut(func(m map[string]any) {
			m["reasoning"] = map[string]any{"x": map[string]any{"tools": []any{}}}
		}), "tool"},
		"undeclared input type": {mut(func(m map[string]any) {
			m["input"] = append(m["input"].([]any), map[string]any{"type": "item_reference", "id": "x"})
		}), "input"},
		"undeclared content type": {mut(func(m map[string]any) {
			item(m, 1)["content"] = []any{map[string]any{"type": "input_file", "file_id": "f"}}
		}), "content"},
		"remote image": {mut(func(m map[string]any) {
			item(m, 1)["content"] = []any{map[string]any{"type": "input_image", "image_url": "https://example.net/a.png"}}
		}), "remote"},
		"metadata of numbers": {mut(func(m map[string]any) { m["client_metadata"] = map[string]any{"turn_id": 1} }), "meta"},
		"hosted tool_choice":  {mut(func(m map[string]any) { m["tool_choice"] = map[string]any{"type": "web_search"} }), "choice"},
		"tool_choice word":    {mut(func(m map[string]any) { m["tool_choice"] = "web" }), "choice"},
	} {
		admitted := false
		m := func([]byte) (func(plan.Used), string) { admitted = true; return func(plan.Used) {}, "" }
		if resp, d := callWith(p, "g", ph, c.body, m); resp != nil || d != plan.DBody+" "+c.rule {
			t.Errorf("%s: answered %v, detail %q, want %q", name, resp != nil, d, plan.DBody+" "+c.rule)
		}
		if admitted {
			t.Errorf("%s: the meter admitted a refused body", name)
		}
	}
	if f.hits() != before {
		t.Fatal("a refused body reached the provider")
	}
	// An inline image passes.
	inline := mut(func(m map[string]any) {
		item(m, 1)["content"] = []any{map[string]any{"type": "input_image", "image_url": "data:image/png;base64,AAAA"}}
	})
	if resp, d := callWith(p, "g", ph, inline, free); d != "" {
		t.Fatalf("an inline image: %s", d)
	} else {
		read(t, resp)
	}
}

// A declaration whose model body could have the provider act for the guest
// is refused at New, as is a model endpoint with no body shape.
func TestPlanDeclarationRefusesAHostedBody(t *testing.T) {
	f := newPlanFix(t)
	for name, edit := range map[string]func(d *plan.Declaration){
		"no body shape": func(d *plan.Declaration) { d.Body = plan.Body{} },
		"a stream with no stream key": func(d *plan.Declaration) {
			d.Body.Keys = []string{"model", "input", "store"}
		},
		"no store key": func(d *plan.Declaration) {
			d.Body.Keys = []string{"model", "input", "stream"}
		},
		"a hosted key":  func(d *plan.Declaration) { d.Body.Keys = append(d.Body.Keys, "mcp_servers") },
		"background":    func(d *plan.Declaration) { d.Body.Keys = append(d.Body.Keys, "background") },
		"a hosted type": func(d *plan.Declaration) { d.Body.ToolTypes = append(d.Body.ToolTypes, "web_search") },
		"a tool unallowed": func(d *plan.Declaration) {
			d.Body.Tools = append(d.Body.Tools, plan.Tool{Name: "x", Type: "web_search"})
		},
		"a namespace tool": func(d *plan.Declaration) {
			d.Body.Tools = append(d.Body.Tools, plan.Tool{Name: "x", Type: "namespace"})
		},
		"a namespace when namespaces are off": func(d *plan.Declaration) {
			d.Body.ToolTypes = []string{"function"}
			d.Body.Tools = []plan.Tool{{Namespace: "functions", Name: "wait", Type: "function"}}
		},
		"an answer header naming X-Forwarded-For": func(d *plan.Declaration) { d.ResponseHeaders = []string{"X-Forwarded-For"} },
		"an answer header naming a proxy header":  func(d *plan.Declaration) { d.ResponseHeaders = []string{"Proxy-Authorization"} },
		"client_metadata with no keys":            func(d *plan.Declaration) { d.Body.Meta = nil },
		"metadata keys with no client_metadata": func(d *plan.Declaration) {
			d.Body.Keys = []string{"model", "input", "store", "stream"}
		},
		"a metadata key with no cap": func(d *plan.Declaration) { d.Body.Meta = map[string]plan.Value{"turn_id": {Kind: plan.KindText}} },
		"an empty metadata key": func(d *plan.Declaration) {
			d.Body.Meta = map[string]plan.Value{"": {Kind: plan.KindText, Max: 8}}
		},
		"a metadata value that is not text": func(d *plan.Declaration) { d.Body.Meta = map[string]plan.Value{"n": {Kind: plan.KindInt}} },
		"a metadata value that may be null": func(d *plan.Declaration) {
			d.Body.Meta = map[string]plan.Value{"n": {Kind: plan.KindText, Max: 8, Null: true}}
		},
		"a JSON text holding nothing declared": func(d *plan.Declaration) {
			d.Body.Meta = map[string]plan.Value{"j": {Kind: plan.KindJSON, Max: 8}}
		},
		"an object with no fields": func(d *plan.Declaration) {
			d.Body.Meta = map[string]plan.Value{"j": {Kind: plan.KindJSON, Max: 8, Each: &plan.Value{Kind: plan.KindObject}}}
		},
		"an unknown kind": func(d *plan.Declaration) {
			d.Body.Meta = map[string]plan.Value{"j": {Kind: plan.KindJSON, Max: 8, Each: &plan.Value{Kind: "number"}}}
		},
		"a map with no key cap": func(d *plan.Declaration) {
			d.Body.Meta = map[string]plan.Value{"j": {Kind: plan.KindJSON, Max: 8, Each: &plan.Value{Kind: plan.KindMap, Each: &plan.Value{Kind: plan.KindBool}}}}
		},
		"a flag with a cap": func(d *plan.Declaration) {
			d.Body.Meta = map[string]plan.Value{"j": {Kind: plan.KindJSON, Max: 8, Each: &plan.Value{Kind: plan.KindOff, Max: 1}}}
		},
		"a JSON text below the top level": func(d *plan.Declaration) {
			d.Body.Meta = map[string]plan.Value{"j": {Kind: plan.KindJSON, Max: 8, Each: &plan.Value{Kind: plan.KindMap, Max: 8,
				Each: &plan.Value{Kind: plan.KindJSON, Max: 8, Each: &plan.Value{Kind: plan.KindBool}}}}}
		},
		"a number with a word list": func(d *plan.Declaration) {
			d.Body.Meta = map[string]plan.Value{"j": {Kind: plan.KindJSON, Max: 8, Each: &plan.Value{Kind: plan.KindInt, Only: []string{"1"}}}}
		},
		"an object with an invalid field": func(d *plan.Declaration) {
			d.Body.Meta = map[string]plan.Value{"j": {Kind: plan.KindJSON, Max: 8, Each: &plan.Value{Kind: plan.KindObject,
				Fields: map[string]plan.Value{"t": {Kind: plan.KindText}}}}}
		},
		"a required key not declared": func(d *plan.Declaration) {
			d.Body.Meta = map[string]plan.Value{"j": {Kind: plan.KindJSON, Max: 8, Each: &plan.Value{Kind: plan.KindObject,
				Fields: map[string]plan.Value{"b": {Kind: plan.KindBool}}, Required: []string{"kind"}}}}
		},
		"a required key outside an object": func(d *plan.Declaration) {
			d.Body.Meta = map[string]plan.Value{"j": {Kind: plan.KindJSON, Max: 8, Each: &plan.Value{Kind: plan.KindMap, Max: 8,
				Each: &plan.Value{Kind: plan.KindBool}, Required: []string{"kind"}}}}
		},
		"a shape that holds itself": func(d *plan.Declaration) {
			self := plan.Value{Kind: plan.KindMap, Max: 8}
			self.Each = &self
			d.Body.Meta = map[string]plan.Value{"j": {Kind: plan.KindJSON, Max: 8, Each: &self}}
		},
		"no mode":         func(d *plan.Declaration) { d.Mode = "" },
		"an unknown mode": func(d *plan.Declaration) { d.Mode = "allowed" },
	} {
		d := f.decl(t)
		edit(&d)
		if _, err := plan.New(d, plan.NewStore(sealer(t), nil), f.roots); err == nil {
			t.Errorf("%s: New took it", name)
		}
	}
}

// sse is a Responses stream that ends with usage.
func sse(in, out int) string {
	return "event: response.created\ndata: {\"type\":\"response.created\"}\n\n" +
		"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n" +
		"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":" +
		itoa(in) + ",\"output_tokens\":" + itoa(out) + ",\"output_tokens_details\":{\"reasoning_tokens\":3}}}}\n\n"
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// recorder is a meter that admits every call and keeps each settlement.
type recorder struct {
	mu     sync.Mutex
	bodies []string
	used   []plan.Used
	refuse string
}

func (r *recorder) meter(body []byte) (func(plan.Used), string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.refuse != "" {
		return nil, r.refuse
	}
	r.bodies = append(r.bodies, string(body))
	return func(u plan.Used) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.used = append(r.used, u)
	}, ""
}

func (r *recorder) settled() []plan.Used {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]plan.Used(nil), r.used...)
}

// A model call is admitted with its checked body before it is sent, and
// settled exactly once when it ends, with the usage the stream's last event
// reported and the pool reading from the answer's headers. A call the meter
// refuses, or one made with no meter, is never sent (LOG-7, RES-5).
func TestPlanModelCallIsMeteredOnce(t *testing.T) {
	f := newPlanFix(t)
	f.stream = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Codex-Primary-Used-Percent", "12.5")
		w.Header().Set("X-Codex-Primary-Reset-At", "1792000000")
		w.Header().Set("X-Codex-Secondary-Used-Percent", "40")
		w.Header().Set("X-Codex-Secondary-Reset-At", "1792500000")
		io.WriteString(w, sse(1200, 340))
	}
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	ph := g.Tokens["access_token"]

	rec := &recorder{}
	resp, d := callWith(p, "g", ph, `{"model":"m","stream":true}`, rec.meter)
	if d != "" {
		t.Fatalf("model call: %s", d)
	}
	if len(rec.settled()) != 0 {
		t.Fatal("settled before the answer was read")
	}
	if got := read(t, resp); got != sse(1200, 340) {
		t.Fatalf("the guest's stream changed: %q", got)
	}
	if rec.bodies[0] != `{"model":"m","store":false,"stream":true}` {
		t.Fatalf("the meter saw %q, not the checked body", rec.bodies[0])
	}
	u := rec.settled()
	if len(u) != 1 {
		t.Fatalf("settled %d times", len(u))
	}
	want := plan.Used{Sent: true, Done: true, Reported: true, In: 1200, Out: 340, Bytes: int64(len(sse(1200, 340))),
		Pool: rd(w5h(125, 1792000000*1000), w7d(400, 1792500000*1000))}
	if u[0].Pool == nil || !reflect.DeepEqual(*u[0].Pool, *want.Pool) {
		t.Fatalf("pool reading %+v, want %+v", u[0].Pool, want.Pool)
	}
	u[0].Pool, want.Pool = nil, nil
	if u[0] != want {
		t.Fatalf("settled %+v, want %+v", u[0], want)
	}

	before := f.hits()
	rec.refuse = "plan-refused spend-task"
	if resp, d := callWith(p, "g", ph, `{"model":"m","stream":true}`, rec.meter); resp != nil || d != rec.refuse {
		t.Fatalf("a refused admission: %v %q", resp != nil, d)
	}
	if resp, d := callWith(p, "g", ph, `{"model":"m","stream":true}`, nil); resp != nil || d != plan.DUnmetered {
		t.Fatalf("no meter: %v %q", resp != nil, d)
	}
	if f.hits() != before {
		t.Fatal("an unadmitted call reached the provider")
	}
}

// A call settles as it ended: cut off by the guest, answered with an error,
// with a stream that reports nothing or an event too long to read, or
// refused at the dial with nothing sent. Each settles once (LOG-7).
func TestPlanModelCallSettlesAsItEnded(t *testing.T) {
	f := newPlanFix(t)
	var mu sync.Mutex
	answer := sse(10, 20)
	status := 200
	f.stream = func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		a, s := answer, status
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(s)
		io.WriteString(w, a)
	}
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	ph := g.Tokens["access_token"]
	set := func(a string, s int) {
		mu.Lock()
		answer, status = a, s
		mu.Unlock()
	}
	one := func(name string, consume func(*http.Response)) plan.Used {
		t.Helper()
		rec := &recorder{}
		resp, d := callWith(p, "g", ph, `{"model":"m","stream":true}`, rec.meter)
		if d != "" {
			t.Fatalf("%s: %s", name, d)
		}
		consume(resp)
		resp.Body.Close()
		u := rec.settled()
		if len(u) != 1 {
			t.Fatalf("%s: settled %d times", name, len(u))
		}
		return u[0]
	}
	all := func(r *http.Response) { io.ReadAll(r.Body) }

	if u := one("closed unread", func(*http.Response) {}); !u.Sent || u.Done {
		t.Errorf("closed unread: %+v, want sent and not done", u)
	}
	set("data: {\"type\":\"response.output_text.delta\"}\n\n", 200)
	if u := one("no usage", all); !u.Done || u.Reported {
		t.Errorf("a stream with no usage: %+v, want done and unreported", u)
	}
	set(sse(10, 20), 500)
	if u := one("an error status", all); u.Done || !u.Reported {
		t.Errorf("a 500 that reported usage: %+v, want reported and not done", u)
	}
	long := "data: {\"type\":\"response.completed\",\"pad\":\"" + strings.Repeat("x", 5<<20) + "\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n"
	set(long, 200)
	if u := one("an event too long", all); u.Reported || !u.Done || u.Bytes != int64(len(long)) {
		t.Errorf("an event too long: reported %v done %v bytes %d", u.Reported, u.Done, u.Bytes)
	}
	for name, figures := range map[string]string{
		"negative": `"input_tokens":-1,"output_tokens":2`, "fractional": `"input_tokens":1,"output_tokens":2.5`,
		"too large": `"input_tokens":1,"output_tokens":2e12`, "missing": `"input_tokens":1`, "text": `"input_tokens":"1","output_tokens":2`,
	} {
		set("data: {\"type\":\"response.completed\",\"response\":{\"usage\":{"+figures+"}}}\n\n", 200)
		if u := one(name, all); u.Reported {
			t.Errorf("a %s figure was taken: %+v", name, u)
		}
	}
	set("data: {\"type\":\"response.output_text.done\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}}\n\n", 200)
	if u := one("usage on another event", all); u.Reported {
		t.Errorf("usage on a non-final event was taken: %+v", u)
	}

	set(strings.TrimSuffix(sse(7, 8), "\n\n"), 200)
	if u := one("a last line with no newline", all); !u.Reported || u.In != 7 || u.Out != 8 {
		t.Errorf("a last line with no newline: %+v", u)
	}

	// A 2xx answer that is not an event stream is not read for its usage,
	// so it is never done: it is metered at its worst case (#3128 Security 1).
	f.stream = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"usage":{"input_tokens":30,"output_tokens":40000}}`)
	}
	if u := one("a JSON answer", all); u.Done || u.Reported {
		t.Errorf("a JSON answer: %+v, want neither done nor reported", u)
	}

	// An encoded answer, which the clerk cannot read, is refused, and the
	// call was sent.
	f.stream = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("X-Codex-Primary-Used-Percent", "10")
		io.WriteString(w, "x")
	}
	rec := &recorder{}
	if resp, det := callWith(p, "g", ph, `{"model":"m","stream":true}`, rec.meter); resp != nil || det != plan.DEncoded {
		t.Fatalf("an encoded answer: %v %q", resp != nil, det)
	}
	if u := rec.settled(); len(u) != 1 || !u[0].Sent || u[0].Done || u[0].Pool == nil || !reflect.DeepEqual(*u[0].Pool, *rd(w5h(100, 0))) {
		t.Fatalf("an encoded answer settled %+v, want once, sent, with its reading", u)
	}
	// A dial the home-network policy refuses sends nothing.
	d := f.decl(t)
	d.Guard = netguard.New(netguard.Config{Resolver: resolver(netip.MustParseAddr("192.168.1.10")), Connect: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, f.srv.Listener.Addr().String())
	}})
	q, err := plan.New(d, f.sec, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	qg, _ := q.Guest("g")
	rec = &recorder{}
	if resp, det := callWith(q, "g", qg.Tokens["access_token"], `{"model":"m","stream":true}`, rec.meter); resp != nil || det == "" {
		t.Fatalf("a refused dial answered: %v %q", resp != nil, det)
	}
	if u := rec.settled(); len(u) != 1 || u[0].Sent {
		t.Fatalf("a refused dial settled %+v, want once, not sent", u)
	}
}

// A model call held by the home-network policy and cancelled by its caller
// before it connects sent nothing, so it settles as not sent; a call
// cancelled once it is on the provider's connection settles as sent (#5108).
func TestPlanHeldModelCallCancelledBeforeConnectIsNotSent(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	model := func(q *plan.Login, ctx context.Context, rec *recorder) (*http.Response, string) {
		g, _ := q.Guest("g")
		h := map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + g.Tokens["access_token"]}
		return q.Do(ctx, "g", req("POST", "/backend-api/codex/responses", `{"model":"m","stream":true}`, h), rec.meter)
	}

	// A quick read moves to a gateway with no external address read yet, and
	// its full read waits: every public destination is held.
	reading, release := make(chan struct{}, 1), make(chan struct{})
	var connects atomic.Int32
	d := f.decl(t)
	guard := netguard.New(netguard.Config{
		Resolver: resolver(netip.MustParseAddr("8.8.8.8")),
		Quick: func() (netguard.Network, error) {
			return netguard.Network{Gateway: netip.MustParseAddr("192.168.7.1")}, nil
		},
		Source: func() (netguard.Network, error) {
			select {
			case reading <- struct{}{}:
			default:
			}
			<-release
			return netguard.Network{}, errors.New("no read")
		},
		Connect: func(ctx context.Context, network, _ string) (net.Conn, error) {
			connects.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, f.srv.Listener.Addr().String())
		},
	})
	d.Guard = guard
	q, err := plan.New(d, f.sec, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	wctx, wstop := context.WithCancel(context.Background())
	events, watched := make(chan struct{}, 1), make(chan struct{})
	go func() { guard.Watch(wctx, events); close(watched) }()
	t.Cleanup(func() { close(release); wstop(); <-watched })
	events <- struct{}{}
	select { // the quick read has opened the hold
	case <-reading:
	case <-time.After(10 * time.Second):
		t.Fatal("the guard's full read never started: no hold to cancel in")
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	rec := &recorder{}
	if resp, det := model(q, ctx, rec); resp != nil || det == "" {
		t.Fatalf("a cancelled held call answered: %v %q", resp != nil, det)
	}
	if n := connects.Load(); n != 0 {
		t.Fatalf("a held call connected %d times", n)
	}
	if u := rec.settled(); len(u) != 1 || u[0].Sent {
		t.Fatalf("a held call cancelled before connect settled %+v, want once, not sent", u)
	}

	// The same cancel once the provider has the call: it was sent.
	arrived := make(chan struct{})
	f.stream = func(w http.ResponseWriter, r *http.Request) {
		close(arrived)
		<-r.Context().Done()
	}
	ctx, cancel = context.WithCancel(context.Background())
	go func() { <-arrived; cancel() }()
	rec = &recorder{}
	if resp, det := model(p, ctx, rec); resp != nil || det == "" {
		t.Fatalf("a call cancelled at the provider answered: %v %q", resp != nil, det)
	}
	if u := rec.settled(); len(u) != 1 || !u[0].Sent {
		t.Fatalf("a call cancelled at the provider settled %+v, want once, sent", u)
	}
}

// The pool reading is the window nearest its limit, per mille and in unix
// ms; a reached limit reads as full; a window with no readable use is no
// reading of it (RES-5).
func TestPlanPoolReading(t *testing.T) {
	f := newPlanFix(t)
	var mu sync.Mutex
	var hdr map[string]string
	f.stream = func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, sse(1, 1))
	}
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	for name, c := range map[string]struct {
		h    map[string]string
		want *plan.Reading
	}{
		"none":            {map[string]string{}, nil},
		"primary only":    {map[string]string{"X-Codex-Primary-Used-Percent": "0.01"}, rd(w5h(1, 0))},
		"over 100":        {map[string]string{"X-Codex-Primary-Used-Percent": "180", "X-Codex-Primary-Reset-At": "5"}, rd(w5h(1000, 5000))},
		"unreadable":      {map[string]string{"X-Codex-Primary-Used-Percent": "lots", "X-Codex-Primary-Reset-At": "5"}, nil},
		"negative":        {map[string]string{"X-Codex-Primary-Used-Percent": "-3"}, nil},
		"not a number":    {map[string]string{"X-Codex-Primary-Used-Percent": "NaN"}, nil},
		"none used":       {map[string]string{"X-Codex-Primary-Used-Percent": "0", "X-Codex-Primary-Reset-At": "1"}, rd(w5h(0, 1000))},
		"no reset":        {map[string]string{"X-Codex-Primary-Used-Percent": "10", "X-Codex-Primary-Reset-At": "0"}, rd(w5h(100, 0))},
		"negative reset":  {map[string]string{"X-Codex-Primary-Used-Percent": "10", "X-Codex-Primary-Reset-At": "-5"}, rd(w5h(100, 0))},
		"largest reset":   {map[string]string{"X-Codex-Primary-Used-Percent": "10", "X-Codex-Primary-Reset-At": "9223372036854775"}, rd(w5h(100, 9223372036854775000))},
		"reset too large": {map[string]string{"X-Codex-Primary-Used-Percent": "10", "X-Codex-Primary-Reset-At": "99999999999999999"}, rd(w5h(100, 0))},
		"each window on its own": {map[string]string{"X-Codex-Primary-Used-Percent": "90", "X-Codex-Primary-Reset-At": "10",
			"X-Codex-Secondary-Used-Percent": "30", "X-Codex-Secondary-Reset-At": "20"}, rd(w5h(900, 10000), w7d(300, 20000))},
		"an unreadable window is no reading of it": {map[string]string{"X-Codex-Primary-Used-Percent": "lots", "X-Codex-Primary-Reset-At": "10",
			"X-Codex-Secondary-Used-Percent": "50", "X-Codex-Secondary-Reset-At": "20"}, rd(w7d(500, 20000))},
		"limit reached": {map[string]string{"X-Codex-Rate-Limit-Reached-Type": "primary", "X-Codex-Primary-Used-Percent": "20", "X-Codex-Primary-Reset-At": "10",
			"X-Codex-Secondary-Used-Percent": "30", "X-Codex-Secondary-Reset-At": "20"}, rd(w5h(1000, 20000), w7d(1000, 20000))},
		"limit reached with no window": {map[string]string{"X-Codex-Rate-Limit-Reached-Type": "primary"}, rd(w5h(1000, 0), w7d(1000, 0))},
	} {
		mu.Lock()
		hdr = c.h
		mu.Unlock()
		rec := &recorder{}
		resp, d := callWith(p, "g", g.Tokens["access_token"], `{"model":"m","stream":true}`, rec.meter)
		if d != "" {
			t.Fatalf("%s: %s", name, d)
		}
		read(t, resp)
		got := rec.settled()[0].Pool
		if (got == nil) != (c.want == nil) || got != nil && !reflect.DeepEqual(*got, *c.want) {
			t.Errorf("%s: reading %+v, want %+v", name, got, c.want)
		}
	}
}

const (
	hourMS = 3600 * 1000
	weekMS = 7 * 24 * hourMS
)

func rd(ws ...plan.WindowUse) *plan.Reading { return &plan.Reading{Windows: ws} }
func w5h(used, reset int64) plan.WindowUse {
	return plan.WindowUse{Window: "5h", Used: used, ResetAt: reset, Every: 5 * hourMS}
}
func w7d(used, reset int64) plan.WindowUse {
	return plan.WindowUse{Window: "7d", Used: used, ResetAt: reset, Every: weekMS}
}

// The Codex pool is named as ChatGPT names it, and its windows as the
// headers #809 captured read them, so the owner's page invents no name or
// window (RES-5, CLK-7).
// REQ: RES-5, CLK-7
func TestTheCodexPoolIsNamedAsTheProviderNamesIt(t *testing.T) {
	d := plan.Codex(nil)
	want := plan.Pool{ID: "codex", Name: "ChatGPT Codex", Windows: []plan.Window{
		{ID: "5h", Prefix: "X-Codex-Primary-", Label: "5-hour limit", Every: 5 * hourMS},
		{ID: "7d", Prefix: "X-Codex-Secondary-", Label: "week", Every: weekMS},
	}, Reached: "X-Codex-Rate-Limit-Reached-Type"}
	if d.Title != "ChatGPT" || !reflect.DeepEqual(d.Pool, want) {
		t.Fatalf("declared %q %+v, want ChatGPT %+v", d.Title, d.Pool, want)
	}
	for name, mut := range map[string]func(*plan.Pool){
		"no name":        func(p *plan.Pool) { p.Name = "" },
		"no ID":          func(p *plan.Pool) { p.ID = "" },
		"a window twice": func(p *plan.Pool) { p.Windows[1].ID = "5h" },
		"no label":       func(p *plan.Pool) { p.Windows[0].Label = "" },
		"no prefix":      func(p *plan.Pool) { p.Windows[0].Prefix = "" },
		"no length":      func(p *plan.Pool) { p.Windows[1].Every = 0 },
	} {
		f := newPlanFix(t)
		d := f.decl(t)
		d.Pool.Windows = append([]plan.Window{}, d.Pool.Windows...)
		mut(&d.Pool)
		if _, err := plan.New(d, f.sec, f.roots); err == nil {
			t.Errorf("%s: a pool declaration that cannot name its windows is refused", name)
		}
	}
}

// variant is a whole value of a declared shape with one part changed, and
// whether the clerk must take it.
type variant struct {
	name string
	val  any
	ok   bool
}

// variants builds a value of shape v with every declared key present, and
// one variant per declared key and limit: each text and map key at its cap
// (taken) and one byte over it, in ASCII and in a two-byte character
// (refused), each value of the wrong kind, an unknown key, a flag that must
// be off turned on, and a JSON text that does not parse.
func variants(v plan.Value) (any, []variant) {
	over := func(n int) []variant {
		return []variant{
			{"one byte over its cap", strings.Repeat("a", n+1), false},
			{"one byte over its cap in two-byte characters", "a" + strings.Repeat("é", n/2), n%2 == 1},
		}
	}
	var good any
	var alts []variant
	switch v.Kind {
	case plan.KindText:
		if v.Only != nil {
			good = v.Only[0]
			for _, o := range v.Only {
				alts = append(alts, variant{"value " + o, o, true})
			}
			alts = append(alts, variant{"an undeclared value", "x" + v.Only[0], false})
		} else {
			good = "a"
			alts = append(alts, variant{"at its cap", strings.Repeat("a", v.Max), true})
			alts = append(alts, variant{"at its cap in two-byte characters", strings.Repeat("é", v.Max/2), true})
		}
		alts = append(alts, over(v.Max)...)
		alts = append(alts, variant{"a number", 1, false})
	case plan.KindInt:
		good = 1700000000000
		alts = []variant{{"negative", -1, true}, {"a fraction", 1.5, false}, {"text", "1", false}}
	case plan.KindBool:
		good = true
		alts = []variant{{"false", false, true}, {"text", "true", false}}
	case plan.KindOff:
		good = false
		alts = []variant{{"on", true, false}, {"text", "false", false}}
	case plan.KindObject:
		obj := map[string]any{}
		subs := map[string][]variant{}
		for k, f := range v.Fields {
			obj[k], subs[k] = variants(f)
		}
		with := func(k string, x any) map[string]any {
			c := map[string]any{}
			for kk, vv := range obj {
				c[kk] = vv
			}
			c[k] = x
			return c
		}
		good = obj
		for k, list := range subs {
			for _, a := range list {
				alts = append(alts, variant{k + ": " + a.name, with(k, a.val), a.ok})
			}
			alts = append(alts, variant{k + " in another case", with(strings.ToUpper(k), obj[k]), false})
		}
		alts = append(alts, variant{"an undeclared key", with("x-undeclared", "a"), false},
			variant{"not an object", []any{}, false})
	case plan.KindMap:
		each, list := variants(*v.Each)
		good = map[string]any{"k": each}
		for _, a := range list {
			alts = append(alts, variant{"entry: " + a.name, map[string]any{"k": a.val}, a.ok})
		}
		alts = append(alts, variant{"a key at its cap", map[string]any{strings.Repeat("k", v.Max): each}, true})
		for _, a := range over(v.Max) {
			alts = append(alts, variant{"a key " + a.name, map[string]any{a.val.(string): each}, a.ok})
		}
		alts = append(alts, variant{"not an object", "k", false})
	case plan.KindJSON:
		in, list := variants(*v.Each)
		text := func(x any) string { b, _ := json.Marshal(x); return string(b) }
		good = text(in)
		for _, a := range list {
			alts = append(alts, variant{"held: " + a.name, text(a.val), a.ok})
		}
		alts = append(alts, variant{"not JSON", "{", false}, variant{"trailing data", text(in) + " {}", false},
			variant{"over its cap", text(in) + strings.Repeat(" ", v.Max), false}, variant{"not text", in, false})
	case plan.KindDrop:
		// Taken in any shape, and dropped (TestPlanTurnMetadataSendsNoWorkspaces).
		good = map[string]any{"k": "v"}
		return good, []variant{{"text", "v", true}, {"a number", 1, true}, {"null", nil, true}}
	}
	if v.Null {
		alts = append(alts, variant{"null", nil, true})
	} else if v.Kind != plan.KindOff {
		alts = append(alts, variant{"null", nil, false})
	}
	return good, alts
}

// client_metadata, and the turn metadata blob inside it, hold only the
// keys the CLI sets, each value of its declared shape and within its cap:
// every declared key and limit is tried, and a refused one is never sent
// (#2117, #4580, CLK-7).
func TestPlanClientMetadataHeldToItsKeys(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	ph := g.Tokens["access_token"]
	with := func(meta any) string {
		m := capture(t)
		m["client_metadata"] = meta
		return encode(t, m)
	}
	good, alts := variants(plan.Value{Kind: plan.KindObject, Fields: plan.Codex(nil).Body.Meta})
	alts = append(alts, variant{"every declared key", good, true})
	took := 0
	for _, a := range alts {
		before := f.hits()
		resp, d := callWith(p, "g", ph, with(a.val), free)
		switch {
		case a.ok && d != "":
			t.Errorf("%s: refused %q", a.name, d)
		case a.ok:
			read(t, resp)
			took++
		case resp != nil || d != plan.DBody+" meta":
			t.Errorf("%s: answered %v, detail %q", a.name, resp != nil, d)
		case f.hits() != before:
			t.Errorf("%s: a refused client_metadata reached the provider", a.name)
		}
	}
	if took == 0 || took == len(alts) {
		t.Fatalf("took %d of %d", took, len(alts))
	}
}

// A JSON text is held to its cap as the clerk sends it too: a blob within
// its cap that the clerk's encoding would grow past it (U+2028 is sent
// escaped, three bytes as six) is refused (#4580).
func TestPlanTurnMetadataCapHoldsAfterEncoding(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	ph := g.Tokens["access_token"]
	// Each key is 42 raw U+2028, 126 bytes, within the 128-byte key cap;
	// 100 of them fit the cap raw and pass it escaped.
	k := strings.Repeat("\u2028", 42)
	var ns []string
	for i := 0; i < 100; i++ {
		ns = append(ns, `"`+string(rune('0'+i/10))+string(rune('0'+i%10))+k+`":{}`)
	}
	blob := `{"tool_namespaces_info":{` + strings.Join(ns, ",") + `}}`
	if len(blob) > 16<<10 {
		t.Fatalf("blob of %d bytes", len(blob))
	}
	m := capture(t)
	m["client_metadata"] = map[string]any{"x-codex-turn-metadata": blob}
	before := f.hits()
	if resp, d := callWith(p, "g", ph, encode(t, m), free); resp != nil || d != plan.DBody+" meta" {
		t.Fatalf("answered %v, detail %q", resp != nil, d)
	}
	if f.hits() != before {
		t.Fatal("sent")
	}
}

// The provider never sees the guest's workspaces: their paths, git remote
// URLs and latest commit can name a private project, and a turn needs none
// of them (#4632). The clerk drops the key from the blob it sends, whatever
// the key holds, and keeps the rest. CLI 0.162.1 itself omits the key when
// it finds no git repository (responses_metadata.rs non_empty_workspaces),
// so the provider already takes a blob without it.
func TestPlanTurnMetadataSendsNoWorkspaces(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	ph := g.Tokens["access_token"]
	ws := `{"/home/guest/secret-project":{"associated_remote_urls":{"origin":"https://git.example/secret-project.git"},` +
		`"latest_git_commit_hash":"0123456789abcdef0123456789abcdef01234567","has_changes":true}}`
	for _, blob := range []string{
		`{"request_kind":"turn","workspaces":` + ws + `}`,
		`{"request_kind":"turn","workspaces":{}}`,
		`{"request_kind":"turn","workspaces":"/home/guest/secret-project"}`,
		`{"request_kind":"turn","workspaces":null}`,
	} {
		m := capture(t)
		m["client_metadata"] = map[string]any{"x-codex-turn-metadata": blob}
		resp, d := callWith(p, "g", ph, encode(t, m), free)
		if d != "" {
			t.Fatalf("%s: %s", blob, d)
		}
		read(t, resp)
		_, sent := f.last()
		if strings.Contains(sent, "secret-project") || strings.Contains(sent, "0123456789abcdef") || strings.Contains(sent, "workspaces") {
			t.Errorf("%s: sent %s", blob, sent)
		}
		var got struct {
			Meta map[string]string `json:"client_metadata"`
		}
		if err := json.Unmarshal([]byte(sent), &got); err != nil {
			t.Fatal(err)
		}
		if b := got.Meta["x-codex-turn-metadata"]; b != `{"request_kind":"turn"}` {
			t.Errorf("%s: sent blob %s", blob, b)
		}
	}
}

// The security property, written from literals rather than from the
// declaration, so widening the declaration fails here: a guest cannot ask
// the provider to ingest history, turn analytics on, attribute a call to an
// MCP server, or draw guardian credits for the plan (#4585 Security 1). An
// MCP tool source is refused for its kind alone, with no server named, and
// MCP attribution inside the blob as well as beside it (#4595). A source
// that states no kind is refused too (#4652), and so is a function entry
// that carries no source at all (#4678).
func TestPlanGuestCannotAskTheProviderToKeepOrAct(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	ph := g.Tokens["access_token"]
	tool := func(source string) string {
		return `{"tool_namespaces_info":{"functions":{"name":"functions","functions":{"exec":` +
			`{"name":"exec","direct":true,"code_mode_name":null,"deferred":false,"source":` + source + `}}}}}`
	}
	for name, meta := range map[string]map[string]any{
		"history ingest":                 {"x-codex-turn-metadata": `{"history_ingest_requested":true}`},
		"analytics":                      {"x-codex-turn-metadata": `{"analytics_enabled":true}`},
		"an MCP tool source":             {"x-codex-turn-metadata": tool(`{"kind":"mcp","server_name":"s"}`)},
		"an MCP tool source alone":       {"x-codex-turn-metadata": tool(`{"kind":"mcp"}`)},
		"a tool source with no kind":     {"x-codex-turn-metadata": tool(`{}`)},
		"a tool source with a null kind": {"x-codex-turn-metadata": tool(`{"kind":null}`)},
		"a tool with no source": {"x-codex-turn-metadata": `{"tool_namespaces_info":{"functions":{"name":"functions","functions":` +
			`{"exec":{"name":"exec","direct":true,"code_mode_name":null,"deferred":false}}}}}`},
		"MCP attribution":                {"mcp_attribution": `{"status":"ok"}`},
		"MCP attribution in a blob":      {"x-codex-turn-metadata": `{"mcp_attribution":{"status":"ok"}}`},
		"MCP attribution text in a blob": {"x-codex-turn-metadata": `{"mcp_attribution":"{\"status\":\"ok\"}"}`},
		"guardian credits":               {"guardian_credits_requested": "true"},
		"guardian credits in a blob":     {"x-codex-turn-metadata": `{"guardian_credits_requested":"true"}`},
	} {
		m := capture(t)
		m["client_metadata"] = meta
		before := f.hits()
		if resp, d := callWith(p, "g", ph, encode(t, m), free); resp != nil || d != plan.DBody+" meta" {
			t.Errorf("%s: answered %v, detail %q", name, resp != nil, d)
		}
		if f.hits() != before {
			t.Errorf("%s: sent", name)
		}
	}
	m := capture(t)
	m["client_metadata"] = map[string]any{"x-codex-turn-metadata": tool(`{"kind":"harness"}`)}
	resp, d := callWith(p, "g", ph, encode(t, m), free)
	if d != "" {
		t.Fatalf("a harness tool source: %s", d)
	}
	read(t, resp)
}

// The top-level client_metadata keys and caps, as a fixed table rather than
// read from the declaration: each id takes 128 bytes and refuses 129, the
// blob refuses 16 KiB + 1, and no other key is taken (#4585 L3 1).
func TestPlanClientMetadataCapsAreFixed(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	ph := g.Tokens["access_token"]
	ids := []string{"x-codex-installation-id", "session_id", "thread_id", "x-codex-window-id", "turn_id",
		"x-openai-subagent", "x-codex-parent-thread-id", "parent_turn_id", "root_turn_id"}
	if got := len(plan.Codex(nil).Body.Meta); got != len(ids)+1 {
		t.Fatalf("the declaration has %d client_metadata keys, want %d", got, len(ids)+1)
	}
	call := func(meta map[string]any) string {
		m := capture(t)
		m["client_metadata"] = meta
		resp, d := callWith(p, "g", ph, encode(t, m), free)
		if resp != nil {
			read(t, resp)
		}
		return d
	}
	for _, k := range ids {
		if d := call(map[string]any{k: strings.Repeat("a", 128)}); d != "" {
			t.Errorf("%s at 128 bytes: %s", k, d)
		}
		if d := call(map[string]any{k: strings.Repeat("a", 129)}); d != plan.DBody+" meta" {
			t.Errorf("%s at 129 bytes: %q", k, d)
		}
	}
	if d := call(map[string]any{"x-codex-turn-metadata": "{}" + strings.Repeat(" ", 16<<10-1)}); d != plan.DBody+" meta" {
		t.Errorf("a blob of 16 KiB + 1: %q", d)
	}
}

// A provider-read flag cannot be smuggled past the check by repeating it:
// the clerk sends its own encoding of the blob it checked, so the provider
// sees one key, whichever of a repeated pair its parser keeps (#4580).
func TestPlanTurnMetadataIsSentAsChecked(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	ph := g.Tokens["access_token"]
	for _, blob := range []string{
		`{"history_ingest_requested":true,"history_ingest_requested":false}`,
		`{"analytics_enabled":true , "analytics_enabled":false}`,
	} {
		m := capture(t)
		m["client_metadata"] = map[string]any{"x-codex-turn-metadata": blob}
		resp, d := callWith(p, "g", ph, encode(t, m), free)
		if d != "" {
			t.Fatalf("%s: %s", blob, d)
		}
		read(t, resp)
		_, sent := f.last()
		var got struct {
			Meta map[string]string `json:"client_metadata"`
		}
		if err := json.Unmarshal([]byte(sent), &got); err != nil {
			t.Fatal(err)
		}
		if b := got.Meta["x-codex-turn-metadata"]; strings.Contains(b, "true") || strings.Count(b, `":false`) != 1 {
			t.Errorf("%s: sent %s", blob, b)
		}
	}
}

// The Codex body (its keys, tools and client_metadata) is measured on one
// CLI release, the one the image pins as CODEX_VERSION in
// guest/codex/build-rootfs.sh. The declaration's Version names it, so a
// CLI bump fails here until the same change requalifies the declaration,
// and a newly declared tool or key cannot reach the plan as a refusal on
// every turn unnoticed (#2115).
func TestCodexBodyIsMeasuredOnThePinnedCLI(t *testing.T) {
	raw, err := os.ReadFile("../../../guest/codex/build-rootfs.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^CODEX_VERSION=([0-9][0-9A-Za-z.+-]*)$`).FindAllSubmatch(raw, -1)
	if len(m) != 1 {
		t.Fatalf("build-rootfs.sh: %d CODEX_VERSION lines", len(m))
	}
	v := plan.Codex(nil).Version
	if !regexp.MustCompile(`^codex-` + regexp.QuoteMeta(string(m[0][1])) + `-[0-9]+$`).MatchString(v) {
		t.Fatalf("the Codex declaration is %q, measured on another CLI than the pinned %s", v, m[0][1])
	}
}
