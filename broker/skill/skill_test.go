package skill

// REQ: CAP-5

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func lit(v string) Node  { return Node{Lit: json.RawMessage(v)} }
func slot(n string) Node { return Node{Slot: n} }

// report is a two-step skill: draft a report to one address, then send it.
func report() *Skill {
	return &Skill{
		Version: Version, Kind: KindSkill, ID: "k0123456789ab", Runs: 3,
		Slots: []Slot{{Name: "to", Type: Email, Max: 64}, {Name: "week", Type: Number, Max: 1}},
		Steps: []Step{
			{Account: "mail", Action: "draft.create", Params: map[string]Node{
				"subject": lit(`"Weekly report"`),
				"meta":    {Obj: map[string]Node{"week": slot("week")}},
				"to":      slot("to"),
			}},
			{Account: "mail", Action: "message.send", Recipients: []Node{slot("to")}},
		},
	}
}

type fakeFX struct {
	mu    sync.Mutex
	got   []Effect
	state map[int]string // 1-based call -> state; default succeeded
	err   error
}

func (f *fakeFX) Request(_ context.Context, e Effect) (State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, e)
	if f.err != nil {
		return State{}, f.err
	}
	st := f.state[len(f.got)]
	if st == "" {
		st = Succeeded
	}
	return State{RequestID: e.RequestID, State: st}, nil
}

func args(kv ...string) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for i := 0; i < len(kv); i += 2 {
		out[kv[i]] = json.RawMessage(kv[i+1])
	}
	return out
}

// CAP-5: a compiled skill runs its fixed steps in order, each as an
// ordinary effect request with literals and bound inputs, and stable
// request IDs so a retried run repeats each request (OP-1).
func TestRunAllSteps(t *testing.T) {
	sk := report()
	if err := sk.Validate(); err != nil {
		t.Fatal(err)
	}
	fx := &fakeFX{}
	res := Run(context.Background(), sk, "r1", args("to", `"ann@example.test"`, "week", `41`), fx)
	if res.Status != "done" || len(res.Done) != 2 || res.Stopped != nil {
		t.Fatalf("result %+v", res)
	}
	if len(fx.got) != 2 {
		t.Fatalf("%d requests", len(fx.got))
	}
	e := fx.got[0]
	if e.RequestID != "skill-k0123456789ab-r1-1" || e.Account != "mail" || e.Action != "draft.create" {
		t.Fatalf("step 1 %+v", e)
	}
	if e.Params["subject"] != "Weekly report" || e.Params["to"] != "ann@example.test" {
		t.Fatalf("params %v", e.Params)
	}
	if m, _ := e.Params["meta"].(map[string]any); m["week"] != json.Number("41") {
		t.Fatalf("nested %v", e.Params["meta"])
	}
	if r := fx.got[1].Recipients; len(r) != 1 || r[0] != "ann@example.test" {
		t.Fatalf("recipients %v", r)
	}
	sid, rid, n, ok := ParseRequestID(fx.got[1].RequestID)
	if !ok || sid != sk.ID || rid != "r1" || n != 2 {
		t.Fatalf("parse %q", fx.got[1].RequestID)
	}
	again := &fakeFX{}
	Run(context.Background(), sk, "r1", args("to", `"ann@example.test"`, "week", `41`), again)
	if again.got[0].RequestID != fx.got[0].RequestID {
		t.Fatal("a retried run must repeat its request IDs")
	}
}

// CAP-5: inputs are assumptions checked before any effect. A wrong type, a
// missing or unknown input, or one longer than any past run hands the task
// back to the model with nothing requested.
func TestRunInputAssumptions(t *testing.T) {
	sk := report()
	for name, a := range map[string]map[string]json.RawMessage{
		"not an email": args("to", `"ann"`, "week", `41`),
		"not a number": args("to", `"ann@example.test"`, "week", `"41"`),
		"missing":      args("to", `"ann@example.test"`),
		"unknown":      args("to", `"ann@example.test"`, "week", `1`, "bcc", `"x@y.test"`),
		"too long":     args("to", `"`+strings.Repeat("a", 70)+`@example.test"`, "week", `1`),
	} {
		fx := &fakeFX{}
		res := Run(context.Background(), sk, "r2", a, fx)
		if res.Status != "stopped" || res.Stopped == nil || res.Stopped.Step != 0 || len(fx.got) != 0 {
			t.Errorf("%s: %+v, %d requests", name, res, len(fx.got))
		}
	}
	if res := Run(context.Background(), sk, "bad id!", args("to", `"a@b.test"`, "week", `1`), &fakeFX{}); res.Stopped == nil {
		t.Error("a bad run_id must stop the run")
	}
}

// CAP-5: a step that does not succeed (waiting for the owner, denied) stops
// the run; the model gets the remaining steps with their bound values. The
// skill never skips or retries a step.
func TestRunStopsWhereAssumptionFails(t *testing.T) {
	sk := report()
	sk.Steps = append(sk.Steps, Step{Account: "mail", Action: "label.add", Params: map[string]Node{"label": lit(`"sent-reports"`)}})
	fx := &fakeFX{state: map[int]string{2: "pending"}}
	res := Run(context.Background(), sk, "r3", args("to", `"ann@example.test"`, "week", `41`), fx)
	if res.Status != "stopped" || res.Stopped.Step != 2 || res.Stopped.State != "pending" || len(fx.got) != 2 {
		t.Fatalf("result %+v", res)
	}
	if len(res.Remaining) != 1 || res.Remaining[0].Action != "label.add" || res.Remaining[0].Params["label"] != "sent-reports" {
		t.Fatalf("remaining %+v", res.Remaining)
	}
	fx = &fakeFX{err: errors.New("down")}
	res = Run(context.Background(), sk, "r4", args("to", `"ann@example.test"`, "week", `41`), fx)
	if res.Stopped.Step != 1 || len(res.Remaining) != 3 {
		t.Fatalf("broker error: %+v", res)
	}
}

// CAP-5: the file format is strict, and a skill can never carry a
// broker-state change (OP-5) or a procedure a recorded value.
func TestDecodeRefuses(t *testing.T) {
	good := report().Encode()
	if _, err := Decode(good); err != nil {
		t.Fatal(err)
	}
	mut := func(f func(*Skill)) []byte {
		s := report()
		f(s)
		return s.Encode()
	}
	cases := map[string][]byte{
		"unknown field": bytes.Replace(good, []byte(`{"version"`), []byte(`{"x":1,"version"`), 1),
		"trailing":      append(append([]byte{}, good...), []byte(`{}`)...),
		"broker":        mut(func(s *Skill) { s.Steps[0].Account = "broker" }),
		"meta":          mut(func(s *Skill) { s.Steps[0].Action = "meta.grant" }),
		"upper":         mut(func(s *Skill) { s.Steps[0].Action = "Message.Send" }),
		"unused slot":   mut(func(s *Skill) { s.Slots = append(s.Slots, Slot{Name: "x", Type: Text, Max: 5}) }),
		"unknown slot":  mut(func(s *Skill) { s.Steps[1].Recipients = []Node{slot("cc")} }),
		"two kinds":     mut(func(s *Skill) { s.Steps[1].Recipients = []Node{{Slot: "to", Lit: json.RawMessage(`"a"`)}} }),
		"bad id":        mut(func(s *Skill) { s.ID = "x1" }),
		"kind/id":       mut(func(s *Skill) { s.ID = "p0123456789ab" }),
		"run_id slot":   mut(func(s *Skill) { s.Slots[1].Name = "run_id"; s.Steps[0].Params["meta"].Obj["week"] = slot("run_id") }),
		"no steps":      mut(func(s *Skill) { s.Steps = nil }),
		"procedure lit": mut(func(s *Skill) { s.Kind, s.ID = KindProcedure, "p0123456789ab" }),
	}
	for name, b := range cases {
		if _, err := Decode(b); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// broker is a stand-in for the broker's /mcp effect_request tool.
type broker struct {
	mu   sync.Mutex
	reqs []Effect
}

func (b *broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     json.RawMessage `json:"id"`
		Params struct {
			Name      string `json:"name"`
			Arguments Effect `json:"arguments"`
		} `json:"params"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	b.mu.Lock()
	b.reqs = append(b.reqs, req.Params.Arguments)
	b.mu.Unlock()
	st, _ := json.Marshal(State{RequestID: req.Params.Arguments.RequestID, State: Succeeded})
	json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID,
		"result": map[string]any{"content": []map[string]string{{"type": "text", "text": string(st)}}, "isError": false}})
}

func rpc(t *testing.T, url, method string, params any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: %s", method, raw)
	}
	return out
}

// CAP-5: inside the guest, each valid skill in the tree is one MCP tool;
// calling it runs the steps through the broker's own effect_request. A
// file that fails validation or whose name is not its ID is not offered.
func TestServerOffersAndRunsSkills(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, SkillsNS), 0o755)
	sk := report()
	os.WriteFile(filepath.Join(dir, sk.Path()), sk.Encode(), 0o644)
	bad := report()
	bad.Steps[0].Account = "broker"
	os.WriteFile(filepath.Join(dir, SkillsNS, "k111111111111.json"), bad.Encode(), 0o644)
	os.WriteFile(filepath.Join(dir, SkillsNS, "k222222222222.json"), sk.Encode(), 0o644) // name is not its ID

	b := &broker{}
	bs := httptest.NewServer(b)
	defer bs.Close()
	srv := httptest.NewServer(&Server{Dir: dir, Effects: &MCPEffects{URL: bs.URL}})
	defer srv.Close()

	list := rpc(t, srv.URL, "tools/list", map[string]any{})
	tools := list["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "skill_"+sk.ID {
		t.Fatalf("tools %v", tools)
	}
	call := rpc(t, srv.URL, "tools/call", map[string]any{"name": "skill_" + sk.ID,
		"arguments": map[string]any{"run_id": "r9", "to": "bo@example.test", "week": 7}})
	text := call["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	var res Result
	if err := json.Unmarshal([]byte(text), &res); err != nil || res.Status != "done" {
		t.Fatalf("%s", text)
	}
	if len(b.reqs) != 2 || b.reqs[1].Action != "message.send" || b.reqs[1].RequestID != "skill-"+sk.ID+"-r9-2" {
		t.Fatalf("broker saw %+v", b.reqs)
	}
	call = rpc(t, srv.URL, "tools/call", map[string]any{"name": "skill_k111111111111", "arguments": map[string]any{"run_id": "r1"}})
	if call["result"].(map[string]any)["isError"] != true {
		t.Fatal("an invalid skill must not run")
	}
}
