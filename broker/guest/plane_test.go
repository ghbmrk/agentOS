package guest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
)

// REQ: REV-1, REV-5, OP-1, ADP-10, CRED-1, ARC-3
// SPEC v0.12 IDs (PR #15; move into REQ when it merges): ARC-6, ARC-7, OP-8

// fakeMachines records steps and label changes.
type fakeMachines struct {
	mu      sync.Mutex
	steps   map[string]int
	private map[string]bool
	lineage map[string]string
	events  []string
}

func newMachines() *fakeMachines {
	return &fakeMachines{steps: map[string]int{}, private: map[string]bool{}, lineage: map[string]string{}}
}

func (f *fakeMachines) Step(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.steps[id]++
	f.events = append(f.events, "step "+id)
	return nil
}

func (f *fakeMachines) RaisePrivate(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.private[id] = true
	f.events = append(f.events, "private "+id)
	return nil
}

func (f *fakeMachines) Lineage(id string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l := f.lineage[id]; l != "" {
		return l, nil
	}
	return id, nil
}

func (f *fakeMachines) stepsOf(id string) int { f.mu.Lock(); defer f.mu.Unlock(); return f.steps[id] }

// allow authorizes everything; exec counts effects.
type allow struct{}

func (allow) Check(context.Context, journal.Phase, journal.Intent) error { return nil }

type exec struct {
	mu   sync.Mutex
	runs map[string]int
}

func (e *exec) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.runs[in.ID]++
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "sent"}
}

func (e *exec) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultUnknown}
}

type rig struct {
	t     *testing.T
	p     *Plane
	ms    *fakeMachines
	eng   *journal.Engine
	ex    *exec
	meter *meter.Meter
	model int
	mu    sync.Mutex
	reps  []string
}

func newRig(t *testing.T, mod func(*Config)) *rig {
	t.Helper()
	r := &rig{t: t, ms: newMachines(), ex: &exec{runs: map[string]int{}}}
	eng, err := journal.Open(&journal.MemStore{}, allow{}, map[string]journal.Executor{"mail": r.ex}, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	r.eng = eng
	m, err := meter.Open(meter.Config{
		Path:       filepath.Join(t.TempDir(), "meter.json"),
		MachineCap: meter.Limits{Calls: 2, Tokens: 1 << 20},
		OverallCap: meter.Limits{Calls: 100, Tokens: 1 << 30},
	})
	if err != nil {
		t.Fatal(err)
	}
	r.meter = m
	cfg := Config{
		Dir:      filepath.Join(t.TempDir(), "guests"),
		Machines: r.ms,
		Effects:  eng,
		Route: func(account string) (string, bool) {
			return "mail", account == "owner-mail"
		},
		Model: func(machine string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				r.mu.Lock()
				r.model++
				r.mu.Unlock()
				fmt.Fprintf(w, `{"machine":%q,"path":%q}`, machine, req.URL.Path)
			})
		},
		Meter: m,
		OwnerReply: func(machine, id, text string) {
			r.mu.Lock()
			r.reps = append(r.reps, machine+" "+id+" "+text)
			r.mu.Unlock()
		},
	}
	if mod != nil {
		mod(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.p = p
	t.Cleanup(p.Shutdown)
	return r
}

// client talks to machine id's socket as its guest would.
func (r *rig) client(id string) *http.Client {
	r.t.Helper()
	dir, err := r.p.Open(id)
	if err != nil {
		r.t.Fatal(err)
	}
	sock := filepath.Join(dir, Socket)
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
}

func (r *rig) do(id, method, path, body string, hdr ...string) (int, string) {
	r.t.Helper()
	req, _ := http.NewRequest(method, "http://broker"+path, strings.NewReader(body))
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := r.client(id).Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// rpc sends one JSON-RPC request and returns its result.
func (r *rig) rpc(id, method string, params any, hdr ...string) map[string]any {
	r.t.Helper()
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	code, body := r.do(id, "POST", "/mcp", string(b), hdr...)
	if code != 200 {
		r.t.Fatalf("%s: %d %s", method, code, body)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		r.t.Fatal(err)
	}
	if out["error"] != nil {
		r.t.Fatalf("%s: %v", method, out["error"])
	}
	return out["result"].(map[string]any)
}

// tool calls a broker tool and returns its decoded state, or the error text.
func (r *rig) tool(id, name string, args map[string]any, hdr ...string) (effectState, string) {
	r.t.Helper()
	res := r.rpc(id, "tools/call", map[string]any{"name": name, "arguments": args}, hdr...)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if res["isError"] == true {
		return effectState{}, text
	}
	var st effectState
	if err := json.Unmarshal([]byte(text), &st); err != nil {
		r.t.Fatalf("tool result %q: %v", text, err)
	}
	return st, ""
}

func send(reqID string) map[string]any {
	return map[string]any{"request_id": reqID, "account": "owner-mail", "action": "message.send",
		"params": map[string]any{"text": "hello"}, "recipients": []string{"a@example.test"}}
}

// TestARC6SocketServesOnlyTheGuestInterface: the socket answers the ARC-6
// services and nothing else.
func TestARC6SocketServesOnlyTheGuestInterface(t *testing.T) {
	r := newRig(t, nil)
	for _, c := range []struct{ method, path string }{
		{"GET", "/"}, {"GET", "/admin"}, {"POST", "/v1/chat/completions"}, {"GET", "/owner"},
		{"POST", "/sockets/owner"}, {"GET", "/../etc/passwd"},
	} {
		if code, _ := r.do("m1", c.method, c.path, ""); code != 404 && code != 405 && code != 301 {
			t.Errorf("%s %s answered %d", c.method, c.path, code)
		}
	}
	if code, _ := r.do("m1", "GET", "/mcp", ""); code != 405 {
		t.Errorf("GET /mcp: %d (no server stream)", code)
	}
	r2 := newRig(t, func(c *Config) { c.Model, c.Meter = nil, nil })
	if code, _ := r2.do("m1", "POST", "/model/openai/v1/chat/completions", "{}"); code != 503 {
		t.Errorf("model without egress: %d", code)
	}
}

// TestARC6MCPHandshakeAndToolList: the MCP subset S4 qualified with
// OpenClaw (initialize, notifications, tools/list, ping).
func TestARC6MCPHandshakeAndToolList(t *testing.T) {
	r := newRig(t, nil)
	res := r.rpc("m1", "initialize", map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}})
	if res["protocolVersion"] != "2025-03-26" {
		t.Fatalf("version %v", res["protocolVersion"])
	}
	if code, _ := r.do("m1", "POST", "/mcp", `{"jsonrpc":"2.0","method":"notifications/initialized"}`); code != 202 {
		t.Fatalf("notification: %d", code)
	}
	names := []string{}
	for _, tl := range r.rpc("m1", "tools/list", nil)["tools"].([]any) {
		names = append(names, tl.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "effect_request,effect_status" {
		t.Fatalf("tools %v", names)
	}
	r.rpc("m1", "ping", nil)
	if r.ms.stepsOf("m1") != 0 {
		t.Fatal("listing tools took a snapshot")
	}
	_, body := r.do("m1", "POST", "/mcp", `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`)
	if !strings.Contains(body, "-32600") {
		t.Fatalf("batch: %s", body)
	}
}

// TestARC6IdentityComesFromTheSocket: the intent's origin is the machine
// whose socket the call arrived on, whatever the request says, and another
// machine can neither see nor collide with it.
func TestARC6IdentityComesFromTheSocket(t *testing.T) {
	r := newRig(t, nil)
	st, errText := r.tool("m1", "effect_request", send("r1"), "X-Machine", "m2", "Authorization", "Bearer m2")
	if errText != "" || st.State != "succeeded" {
		t.Fatalf("effect_request: %+v %s", st, errText)
	}
	s, err := r.eng.Get("m1/r1")
	if err != nil || s.Intent.Origin != "guest:m1" {
		t.Fatalf("intent %+v %v", s.Intent, err)
	}
	if _, errText := r.tool("m2", "effect_status", map[string]any{"request_id": "r1"}); errText == "" {
		t.Fatal("m2 read m1's request")
	}
	st, _ = r.tool("m2", "effect_request", send("r1"))
	if st.State != "succeeded" || r.ex.runs["m1/r1"] != 1 || r.ex.runs["m2/r1"] != 1 {
		t.Fatalf("m2's r1 is not its own: %+v %v", st, r.ex.runs)
	}
}

// TestOP1RetriesAndForksRunAnEffectOnce: the same request_id from a machine
// or from a fork in its lineage is one intent and runs once; different
// arguments under it are refused.
func TestOP1RetriesAndForksRunAnEffectOnce(t *testing.T) {
	r := newRig(t, nil)
	r.ms.lineage["f1"] = "m1"
	for _, id := range []string{"m1", "m1", "f1"} {
		if st, e := r.tool(id, "effect_request", send("r1")); st.State != "succeeded" {
			t.Fatalf("%s: %+v %s", id, st, e)
		}
	}
	if n := r.ex.runs["m1/r1"]; n != 1 {
		t.Fatalf("effect ran %d times", n)
	}
	other := send("r1")
	other["params"] = map[string]any{"text": "different"}
	if _, e := r.tool("f1", "effect_request", other); !strings.Contains(e, "different arguments") {
		t.Fatalf("conflict not refused: %q", e)
	}
	if st, _ := r.tool("f1", "effect_status", map[string]any{"request_id": "r1"}); st.State != "succeeded" {
		t.Fatalf("fork cannot see its lineage's request: %+v", st)
	}
}

// TestADP10NoAdapterNoIntent: an effect on an account with no connected
// adapter is refused and nothing is journaled or run.
func TestADP10NoAdapterNoIntent(t *testing.T) {
	r := newRig(t, nil)
	a := send("r1")
	a["account"] = "bank"
	st, _ := r.tool("m1", "effect_request", a)
	if st.State != "refused" || len(r.eng.List()) != 0 {
		t.Fatalf("%+v, %d intents", st, len(r.eng.List()))
	}
	for _, bad := range []map[string]any{
		{"account": "owner-mail", "action": "x"},
		{"request_id": "a/b", "account": "owner-mail", "action": "x"},
		{"request_id": strings.Repeat("a", 65), "account": "owner-mail", "action": "x"},
	} {
		if _, e := r.tool("m1", "effect_request", bad); e == "" {
			t.Errorf("accepted %v", bad)
		}
	}
	if _, e := r.tool("m1", "intent", send("r2")); e == "" {
		t.Fatal("unknown tool accepted")
	}
}

// TestREV1StepAfterEveryToolCall: each broker tool call is a step, so the
// machine's files are snapshotted after it (vm V3).
func TestREV1StepAfterEveryToolCall(t *testing.T) {
	r := newRig(t, nil)
	r.tool("m1", "effect_request", send("r1"))
	r.tool("m1", "effect_status", map[string]any{"request_id": "r1"})
	r.tool("m1", "effect_request", map[string]any{})
	if n := r.ms.stepsOf("m1"); n != 3 {
		t.Fatalf("%d steps for 3 tool calls", n)
	}
}

// TestOP8ModelRouteIsMeteredByMachine: model calls go through the meter,
// charged to the socket's machine, and are refused once its cap is spent;
// a plane that would serve model egress unmetered is refused.
func TestOP8ModelRouteIsMeteredByMachine(t *testing.T) {
	r := newRig(t, nil)
	for i := 0; i < 2; i++ {
		code, body := r.do("m1", "POST", "/model/openai/v1/chat/completions", `{"messages":[]}`, "X-Machine", "m2")
		if code != 200 || !strings.Contains(body, `"machine":"m1"`) || !strings.Contains(body, `"path":"/openai/v1/chat/completions"`) {
			t.Fatalf("call %d: %d %s", i, code, body)
		}
	}
	if code, _ := r.do("m1", "POST", "/model/openai/v1/chat/completions", `{}`); code != 429 {
		t.Fatalf("over cap: %d", code)
	}
	if r.model != 2 {
		t.Fatalf("model egress called %d times", r.model)
	}
	if code, _ := r.do("m2", "POST", "/model/openai/v1/chat/completions", `{}`); code != 200 {
		t.Fatalf("m2 charged for m1: %d", code)
	}
	if _, err := New(Config{Dir: t.TempDir(), Machines: r.ms, Effects: r.eng, Model: func(string) http.Handler { return nil }}); err == nil {
		t.Fatal("model egress without a meter")
	}
}

// TestREV5OwnerMessageRaisesLabelFirst: an owner message makes the machine
// private before the guest can fetch it; the guest's reply reaches the
// owner channel hook; delivery is at least once.
func TestREV5OwnerMessageRaisesLabelFirst(t *testing.T) {
	pollWait = 200 * time.Millisecond
	t.Cleanup(func() { pollWait = 25 * time.Second })
	r := newRig(t, nil)
	r.client("m1")
	if code, _ := r.do("m1", "GET", "/owner/next", ""); code != 204 {
		t.Fatalf("empty inbox: %d", code)
	}
	id, err := r.p.DeliverOwner("m1", "what is on today?")
	if err != nil {
		t.Fatal(err)
	}
	if !r.ms.private["m1"] {
		t.Fatal("label not raised")
	}
	code, body := r.do("m1", "GET", "/owner/next", "")
	var msg struct{ ID, Text string }
	json.Unmarshal([]byte(body), &msg)
	if code != 200 || msg.ID != id || msg.Text != "what is on today?" {
		t.Fatalf("next: %d %s", code, body)
	}
	if code, _ := r.do("m2", "POST", "/owner/reply", fmt.Sprintf(`{"id":%q,"text":"x"}`, id)); code != 404 {
		t.Fatal("another machine answered m1's message")
	}
	if code, _ := r.do("m1", "POST", "/owner/reply", fmt.Sprintf(`{"id":%q,"text":"dentist at 3"}`, id)); code != 204 {
		t.Fatalf("reply: %d", code)
	}
	if len(r.reps) != 1 || r.reps[0] != "m1 "+id+" dentist at 3" {
		t.Fatalf("replies %v", r.reps)
	}
	if code, _ := r.do("m1", "POST", "/owner/reply", fmt.Sprintf(`{"id":%q,"text":"again"}`, id)); code != 404 {
		t.Fatal("answered twice")
	}

	// At least once: an unanswered message comes back after its lease.
	lease = 0
	t.Cleanup(func() { lease = 15 * time.Minute })
	id2, _ := r.p.DeliverOwner("m1", "second")
	for i := 0; i < 2; i++ {
		_, body := r.do("m1", "GET", "/owner/next", "")
		if !strings.Contains(body, id2) {
			t.Fatalf("delivery %d: %s", i, body)
		}
	}
	if _, err := r.p.DeliverOwner("nope", "x"); err == nil {
		t.Fatal("delivered to a machine with no socket")
	}
}

// TestOwnerNextWakesOnDelivery: a waiting fetch returns as soon as a
// message arrives.
func TestOwnerNextWakesOnDelivery(t *testing.T) {
	r := newRig(t, nil)
	r.client("m1")
	go func() {
		time.Sleep(100 * time.Millisecond)
		r.p.DeliverOwner("m1", "hi")
	}()
	t0 := time.Now()
	if code, _ := r.do("m1", "GET", "/owner/next", ""); code != 200 || time.Since(t0) > 5*time.Second {
		t.Fatalf("%d after %v", code, time.Since(t0))
	}
}

// TestARC6CloseRemovesTheSocket: a destroyed machine's socket is gone.
func TestARC6CloseRemovesTheSocket(t *testing.T) {
	r := newRig(t, nil)
	dir, _ := r.p.Open("m1")
	again, _ := r.p.Open("m1")
	if dir != again {
		t.Fatal("Open is not idempotent")
	}
	r.p.Close("m1")
	if _, err := net.Dial("unix", filepath.Join(dir, Socket)); err == nil {
		t.Fatal("socket still answers")
	}
	r.p.Close("m1")
	if _, err := r.p.Open("../x"); err == nil {
		t.Fatal("bad id accepted")
	}
}

// TestARC6PerMachineConcurrencyCap: one machine cannot hold more than
// MaxConns requests open.
func TestARC6PerMachineConcurrencyCap(t *testing.T) {
	r := newRig(t, func(c *Config) { c.MaxConns = 2 })
	r.client("m1")
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.do("m1", "GET", "/owner/next", "") }()
	}
	time.Sleep(200 * time.Millisecond)
	if code, _ := r.do("m1", "POST", "/mcp", `{}`); code != 429 {
		t.Fatalf("third request: %d", code)
	}
	if code, _ := r.do("m2", "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"ping"}`); code != 200 {
		t.Fatalf("another machine blocked: %d", code)
	}
	r.p.DeliverOwner("m1", "a")
	r.p.DeliverOwner("m1", "b")
	wg.Wait()
}

// TestOP8SpendNoteNamesTheTask: the journal note for an exhaustion says
// which limit and task stopped the machine.
func TestOP8SpendNoteNamesTheTask(t *testing.T) {
	if n := SpendNote(meter.Exhausted{Scope: meter.ScopeTask, Machine: "m1", Task: "t1"}); n.Machine != "m1" || !strings.Contains(n.Reason, "t1") {
		t.Fatalf("%+v", n)
	}
}
