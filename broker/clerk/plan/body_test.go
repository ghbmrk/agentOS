package plan_test

// REQ: PLN-5, CLK-7, LOG-7, RES-5

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"

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
		"client_metadata": map[string]any{"turn_id": "t1", "session_id": "s1", "thread_id": "th1"},
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
		"metadata of numbers": {mut(func(m map[string]any) { m["client_metadata"] = map[string]any{"a": 1} }), "meta"},
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
		"a prefix that could pass X-Forwarded-For": func(d *plan.Declaration) { d.ResponsePrefixes = []string{"X-Forwarded-Foo"} },
		"a prefix that could pass a proxy header":  func(d *plan.Declaration) { d.ResponsePrefixes = []string{"Proxy-Authorization-"} },
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
		Pool: &plan.Reading{Used: 400, ResetAt: 1792500000 * 1000}}
	if u[0].Pool == nil || *u[0].Pool != *want.Pool {
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
	if u := rec.settled(); len(u) != 1 || !u[0].Sent || u[0].Done || u[0].Pool == nil || u[0].Pool.Used != 100 {
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
		"primary only":    {map[string]string{"X-Codex-Primary-Used-Percent": "0.01"}, &plan.Reading{Used: 1}},
		"over 100":        {map[string]string{"X-Codex-Primary-Used-Percent": "180", "X-Codex-Primary-Reset-At": "5"}, &plan.Reading{Used: 1000, ResetAt: 5000}},
		"unreadable":      {map[string]string{"X-Codex-Primary-Used-Percent": "lots", "X-Codex-Primary-Reset-At": "5"}, nil},
		"negative":        {map[string]string{"X-Codex-Primary-Used-Percent": "-3"}, nil},
		"not a number":    {map[string]string{"X-Codex-Primary-Used-Percent": "NaN"}, nil},
		"reset too large": {map[string]string{"X-Codex-Primary-Used-Percent": "10", "X-Codex-Primary-Reset-At": "99999999999999999"}, &plan.Reading{Used: 100}},
		"the tighter window": {map[string]string{"X-Codex-Primary-Used-Percent": "90", "X-Codex-Primary-Reset-At": "10",
			"X-Codex-Secondary-Used-Percent": "30", "X-Codex-Secondary-Reset-At": "20"}, &plan.Reading{Used: 900, ResetAt: 10000}},
		"a tie takes the later reset": {map[string]string{"X-Codex-Primary-Used-Percent": "50", "X-Codex-Primary-Reset-At": "10",
			"X-Codex-Secondary-Used-Percent": "50", "X-Codex-Secondary-Reset-At": "20"}, &plan.Reading{Used: 500, ResetAt: 20000}},
		"limit reached": {map[string]string{"X-Codex-Rate-Limit-Reached-Type": "primary", "X-Codex-Primary-Used-Percent": "20", "X-Codex-Primary-Reset-At": "10",
			"X-Codex-Secondary-Used-Percent": "30", "X-Codex-Secondary-Reset-At": "20"}, &plan.Reading{Used: 1000, ResetAt: 20000}},
		"limit reached with no window": {map[string]string{"X-Codex-Rate-Limit-Reached-Type": "primary"}, &plan.Reading{Used: 1000}},
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
		if (got == nil) != (c.want == nil) || got != nil && *got != *c.want {
			t.Errorf("%s: reading %+v, want %+v", name, got, c.want)
		}
	}
}
