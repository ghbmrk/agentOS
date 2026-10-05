package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

// REQ: ARC-3, REV-1, REV-5, OP-1, CRED-1
// SPEC v0.12 IDs (PR #15; move into REQ when it merges): ARC-6, ARC-7, OP-8
//
// TestIntegrationOpenClawGuest runs OpenClaw 2026.9.8, unmodified (ARC-3),
// as an agent machine under gVisor, with the guest bridge as PID 1 and the
// machine's broker socket as its only way out. One owner message goes in
// through the guest plane's inbox (ARC-6 (c)); a scripted model behind the
// metered model route (ARC-6 (a), OP-8) has OpenClaw call the broker's
// effect_request tool over MCP (ARC-6 (b)); the journal runs the effect
// once; the machine is snapshotted after the call (REV-1); the answer comes
// back to the owner. The owner's message raises the machine to private
// (REV-5).
//
// It needs root, AGENTOS_RUNSC (a runsc binary), and AGENTOS_OPENCLAW_ROOTFS
// (a root built by guest/openclaw/build-rootfs.sh).

const placeholderKey = "placeholder-not-a-secret"

// managerRef lets the plane reach the manager, which needs the plane as its
// Services and so is opened after it.
type managerRef struct{ m atomic.Pointer[vm.Manager] }

func (r *managerRef) Step(ctx context.Context, id string) error {
	_, err := r.m.Load().Step(ctx, id)
	return err
}
func (r *managerRef) RaisePrivate(id string) error { return r.m.Load().RaiseLabel(id, vm.Private) }
func (r *managerRef) Lineage(id string) (string, error) {
	mc, err := r.m.Load().Get(id)
	return mc.Lineage, err
}

type allowAll struct{}

func (allowAll) Check(context.Context, journal.Phase, journal.Intent) error { return nil }

type mailer struct {
	mu   sync.Mutex
	runs []journal.Intent
}

func (m *mailer) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs = append(m.runs, in)
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "queued"}
}

func (m *mailer) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultUnknown}
}

// scriptedModel is an OpenAI-compatible model that, asked "SCENARIO:send",
// calls the broker's effect_request tool (directly, or through OpenClaw's
// tool_search and tool_call when the tool is deferred), then reports the
// tool's answer. It is the S4 stub's script, in Go.
type scriptedModel struct {
	mu    sync.Mutex
	calls int
	keys  map[string]int // Authorization header values seen
	tools [][]string
}

var effectArgs = map[string]any{
	"request_id": "oc-1", "account": "owner-mail", "action": "message.send",
	"params": map[string]any{"to": "owner", "text": "P1-7 hello"},
}

type chatMsg struct {
	Role      string          `json:"role"`
	Content   json.RawMessage `json:"content"`
	ToolCalls []struct {
		Function struct{ Name string } `json:"function"`
	} `json:"tool_calls"`
}

func text(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct{ Text string }
	json.Unmarshal(raw, &parts)
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(p.Text + " ")
	}
	return b.String()
}

func (m *scriptedModel) reply(msgs []chatMsg, names []string) map[string]any {
	call := func(name string, args any) map[string]any {
		a, _ := json.Marshal(args)
		return map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{map[string]any{
			"id": fmt.Sprintf("call_%d", len(msgs)), "type": "function",
			"function": map[string]any{"name": name, "arguments": string(a)},
		}}}
	}
	say := func(s string) map[string]any { return map[string]any{"role": "assistant", "content": s} }
	// Ignore trailing runtime-context blocks the guest appends as user turns.
	convo := msgs
	for len(convo) > 0 && convo[len(convo)-1].Role == "user" && !strings.Contains(text(convo[len(convo)-1].Content), "SCENARIO:") {
		convo = convo[:len(convo)-1]
	}
	if len(convo) == 0 {
		return say("nothing to do")
	}
	n := 0
	prev := ""
	for _, c := range convo {
		if len(c.ToolCalls) > 0 {
			n++
			prev = c.ToolCalls[len(c.ToolCalls)-1].Function.Name
		}
	}
	last := convo[len(convo)-1]
	if n >= 4 {
		return say("stopping: tool-call cap reached")
	}
	if last.Role == "tool" {
		if prev == "tool_search" {
			ids := regexp.MustCompile(`"id"\s*:\s*"([^"]*effect_request[^"]*)"`).FindStringSubmatch(text(last.Content))
			if ids != nil {
				return call("tool_call", map[string]any{"id": ids[1], "args": effectArgs})
			}
		}
		return say("done. broker said: " + text(last.Content))
	}
	if !strings.Contains(text(last.Content), "SCENARIO:send") {
		return say("no scenario")
	}
	for _, n := range names {
		if strings.Contains(n, "effect_request") {
			return call(n, effectArgs)
		}
	}
	for _, n := range names {
		if n == "tool_search" {
			return call("tool_search", map[string]any{"query": "effect_request"})
		}
	}
	return say("no broker tool offered: " + strings.Join(names, ","))
}

func (m *scriptedModel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.calls++
	m.keys[r.Header.Get("Authorization")]++
	m.mu.Unlock()
	if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
		if strings.HasSuffix(r.URL.Path, "/models") {
			fmt.Fprint(w, `{"object":"list","data":[{"id":"broker-default","object":"model"}]}`)
			return
		}
		http.NotFound(w, r)
		return
	}
	var body struct {
		Model    string    `json:"model"`
		Stream   bool      `json:"stream"`
		Messages []chatMsg `json:"messages"`
		Tools    []struct {
			Function struct{ Name string } `json:"function"`
		} `json:"tools"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var names []string
	for _, t := range body.Tools {
		names = append(names, t.Function.Name)
	}
	m.mu.Lock()
	m.tools = append(m.tools, names)
	m.mu.Unlock()
	msg := m.reply(body.Messages, names)
	finish := "stop"
	if msg["tool_calls"] != nil {
		finish = "tool_calls"
	}
	base := map[string]any{"id": "p17", "created": time.Now().Unix(), "model": body.Model}
	usage := map[string]int{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
	with := func(kv ...any) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			out[kv[i].(string)] = kv[i+1]
		}
		return out
	}
	if !body.Stream {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(with("object", "chat.completion", "usage", usage,
			"choices", []any{map[string]any{"index": 0, "message": msg, "finish_reason": finish}}))
		return
	}
	delta := map[string]any{"role": "assistant"}
	if c, ok := msg["content"].(string); ok {
		delta["content"] = c
	}
	if tc, ok := msg["tool_calls"].([]any); ok {
		c := tc[0].(map[string]any)
		c["index"] = 0
		delta["tool_calls"] = []any{c}
	}
	w.Header().Set("Content-Type", "text/event-stream")
	for _, c := range []map[string]any{
		with("object", "chat.completion.chunk", "choices", []any{map[string]any{"index": 0, "delta": delta, "finish_reason": nil}}),
		with("object", "chat.completion.chunk", "usage", usage, "choices", []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": finish}}),
	} {
		b, _ := json.Marshal(c)
		fmt.Fprintf(w, "data: %s\n\n", b)
	}
	io.WriteString(w, "data: [DONE]\n\n")
}

func TestIntegrationOpenClawGuest(t *testing.T) {
	runsc, rootfs := os.Getenv("AGENTOS_RUNSC"), os.Getenv("AGENTOS_OPENCLAW_ROOTFS")
	if runsc == "" || rootfs == "" || os.Geteuid() != 0 {
		t.Skip("set AGENTOS_RUNSC and AGENTOS_OPENCLAW_ROOTFS (guest/openclaw/build-rootfs.sh) and run as root")
	}
	var launch struct{ Argv, Env []string }
	b, err := os.ReadFile("../../guest/openclaw/launch.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &launch); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	ex := &mailer{}
	eng, err := journal.Open(&journal.MemStore{}, allowAll{}, map[string]journal.Executor{"mail": ex}, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	mtr, err := meter.Open(meter.Config{
		Path: filepath.Join(dir, "meter.json"), MachineCap: meter.DefaultMachineCap, OverallCap: meter.DefaultOverallCap,
	})
	if err != nil {
		t.Fatal(err)
	}
	model := &scriptedModel{keys: map[string]int{}}
	replies := make(chan string, 4)
	ref := &managerRef{}
	plane, err := guest.New(guest.Config{
		Dir:      filepath.Join(dir, "guests"),
		Machines: ref,
		Effects:  eng,
		Route:    func(account string) (string, bool) { return "mail", account == "owner-mail" },
		Label: func(id string) string {
			if l, err := ref.m.Load().Label(id); err == nil && l == vm.Public {
				return "public"
			}
			return "private"
		},
		// The guest names provider "openai"; the plane strips /model.
		Model:      func(string) http.Handler { return http.StripPrefix("/openai", model) },
		Meter:      mtr,
		OwnerReply: func(_, _, text string) { replies <- text },
		Logf:       t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer plane.Shutdown()

	ctx := context.Background()
	adm, err := admission.New(admission.Config{CapacityMB: 4096}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := vm.Open(ctx, vm.Config{
		StateDir:  filepath.Join(dir, "machines"),
		Images:    map[string]string{"openclaw": rootfs},
		Runtime:   &gvisor.Runtime{Bin: runsc, StateDir: filepath.Join(dir, "runsc")},
		Admit:     adm,
		NoCgroups: true,
		Services:  plane,
	})
	if err != nil {
		t.Fatal(err)
	}
	ref.m.Store(m)
	t.Cleanup(func() { syscall.Unmount(filepath.Join(dir, "runsc", "null-netns"), syscall.MNT_DETACH) })
	console := filepath.Join(dir, "machines", "machines", "agent", "console.log")
	defer func() {
		if t.Failed() {
			out, _ := os.ReadFile(console)
			t.Logf("console.log:\n%s", out)
		}
		m.Destroy(ctx, "agent")
	}()

	start := time.Now()
	if _, err := m.Create(ctx, "agent", vm.Spec{
		Image: "openclaw", Class: admission.Foreground, MemMB: 1536,
		Argv: launch.Argv, Env: launch.Env, Label: vm.Public,
	}); err != nil {
		t.Fatal(err)
	}
	created := time.Since(start)
	before := len(m.Snapshots("agent"))

	if _, err := plane.DeliverOwner("agent", "SCENARIO:send tell the owner hello", false); err != nil {
		t.Fatal(err)
	}
	if l, _ := m.Label("agent"); l != vm.Private {
		t.Fatalf("label after owner chat = %v, want private (REV-5)", l)
	}
	var answer string
	select {
	case answer = <-replies:
	case <-time.After(5 * time.Minute):
		t.Fatal("no answer from the guest")
	}
	answered := time.Since(start)
	t.Logf("machine started in %v; owner answer after %v: %q", created, answered, answer)

	if !strings.Contains(answer, "done.") || !strings.Contains(answer, "succeeded") {
		t.Fatalf("answer %q: want the broker's result for the effect", answer)
	}
	ex.mu.Lock()
	runs := ex.runs
	ex.mu.Unlock()
	// Owner chat raised the machine to private before the guest read it
	// (REV-5), so its requests live in the lineage's private namespace.
	if len(runs) != 1 || runs[0].ID != "agent/private/oc-1" || runs[0].Origin != "guest:agent" || runs[0].Action != "message.send" {
		t.Fatalf("effects run: %+v, want agent/private/oc-1 once", runs)
	}
	if after := len(m.Snapshots("agent")); after <= before {
		t.Fatalf("snapshots %d -> %d: want a Step after the tool call (REV-1)", before, after)
	}
	model.mu.Lock()
	keys, calls := model.keys, model.calls
	model.mu.Unlock()
	for k := range keys {
		if k != "Bearer "+placeholderKey {
			t.Fatalf("model saw Authorization %q: the guest should hold only the placeholder", k)
		}
	}
	if u := mtr.Usage("agent"); u.Calls < 2 || int(u.Calls) != calls {
		t.Fatalf("meter counted %+v, model saw %d calls (OP-8)", u, calls)
	}
	if st, err := eng.Get("agent/private/oc-1"); err != nil || st.State != journal.Succeeded {
		t.Fatalf("journal: %+v %v", st, err)
	}
}
