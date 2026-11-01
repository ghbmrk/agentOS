package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

// REQ: ARC-3, REV-1, REV-5, OP-1, CRED-1, ARC-6, ARC-7, OP-8
//
// TestIntegrationOpenClawGuest runs OpenClaw 2026.10.9, unmodified (ARC-3),
// as an agent machine under gVisor, with the guest bridge as PID 1 and the
// machine's broker socket as its only way out. One owner message goes in
// through the guest plane's inbox (ARC-6 (c)); a scripted model behind the
// metered model route (ARC-6 (a), OP-8) has OpenClaw call the broker's
// plan command over MCP (PLN-5 (b)); the plane signs the plan under the
// machine's key and the kernel's seam takes it once; the machine is
// snapshotted after the call (REV-1); the answer comes
// back to the owner. The owner's message raises the machine to private
// (REV-5). The gateway serves no Control UI (PLN-5, #4417).
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

// planKernel is the kernel's seam as the plane reaches it: it records every
// plan it takes and reads each as done.
type planKernel struct {
	mu    sync.Mutex
	plans []kernel.Plan
}

func (k *planKernel) Submit(_ context.Context, p kernel.Plan) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.plans = append(k.plans, p)
	return nil
}

func (k *planKernel) Plan(_ context.Context, id string) (kernel.PlanView, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, p := range k.plans {
		if p.ID == id {
			return kernel.PlanView{Status: kernel.SDone, Steps: []kernel.StepView{{Phase: kernel.PDone}}}, nil
		}
	}
	return kernel.PlanView{}, nil
}

// scriptedModel is an OpenAI-compatible model that, asked "SCENARIO:send",
// calls the broker's plan command (directly, or through OpenClaw's
// tool_search and tool_call when the tool is deferred), then reports the
// tool's answer. It is the S4 stub's script, in Go.
type scriptedModel struct {
	mu    sync.Mutex
	calls int
	keys  map[string]int // Authorization header values seen
	tools [][]string
}

var planArgs = map[string]any{
	"request_id": "oc-1", "steps": []map[string]any{
		{"verb": "send", "clerk": "owner-mail", "args": map[string]string{"to": "owner", "msg": "P1-7 hello"}}},
}

// planTool matches the broker's plan command as OpenClaw names an MCP
// tool: the bare name, or the server's prefix and a separator before it.
var planTool = regexp.MustCompile(`(^|[_.-])plan$`)

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
			ids := regexp.MustCompile(`"id"\s*:\s*"((?:[^"]*[_.-])?plan)"`).FindStringSubmatch(text(last.Content))
			if ids != nil {
				return call("tool_call", map[string]any{"id": ids[1], "args": planArgs})
			}
		}
		return say("done. broker said: " + text(last.Content))
	}
	if !strings.Contains(text(last.Content), "SCENARIO:send") {
		return say("no scenario")
	}
	for _, n := range names {
		if planTool.MatchString(n) {
			return call(n, planArgs)
		}
	}
	for _, n := range names {
		if n == "tool_search" {
			return call("tool_search", map[string]any{"query": "plan"})
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
	kern := &planKernel{}
	_, holder, err := ed25519.GenerateKey(nil)
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
		Kernel:   kern,
		Keys:     func(string) (key.Key, ed25519.PrivateKey, bool) { return key.Key{}, holder, true },
		Label: func(id string) string {
			if l, err := ref.m.Load().Label(id); err == nil && l == vm.Public {
				return "public"
			}
			return "private"
		},
		// The guest names provider "openai"; the plane strips /model.
		Model:      func(string) http.Handler { return http.StripPrefix("/openai", model) },
		Meter:      mtr,
		OwnerReply: func(_ string, rep guest.Reply) { replies <- rep.Text },
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
	rt := &gvisor.Runtime{Bin: runsc, StateDir: filepath.Join(dir, "runsc")}
	m, err := vm.Open(ctx, vm.Config{
		StateDir:  filepath.Join(dir, "machines"),
		Images:    map[string]string{"openclaw": rootfs},
		Runtime:   rt,
		Admit:     adm,
		NoCgroups: true,
		NoQuota:   true,
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

	if !strings.Contains(answer, "done.") || !strings.Contains(answer, "steps") {
		t.Fatalf("answer %q: want the broker's result for the plan", answer)
	}
	kern.mu.Lock()
	plans := kern.plans
	kern.mu.Unlock()
	// Owner chat raised the machine to private before the guest read it
	// (REV-5), so its plans live in the lineage's private namespace and
	// carry the private label (PLN-3).
	mc, _ := m.Get("agent")
	if len(plans) != 1 || plans[0].ID != mc.Lineage+"/private/oc-1" || len(plans[0].Steps) != 1 ||
		plans[0].Steps[0].Verb != key.Send || !slices.Contains(plans[0].Steps[0].Labels, "private") || len(plans[0].Sig) == 0 {
		t.Fatalf("plans taken: %+v, want %s/private/oc-1 once, signed", plans, mc.Lineage)
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
	noControlUI(t, rt, rootfs)
}

// controlUIProbe runs inside the guest. For each path it asks the gateway
// on 18789 and prints the status, the body's SHA-256, and whether the body
// carries the Control UI's build marker, as one JSON object.
const controlUIProbe = `
const crypto = require("crypto");
(async () => {
  const out = {};
  for (const p of process.argv.slice(1)) {
    const r = await fetch("http://127.0.0.1:18789" + p, { redirect: "manual" });
    const b = Buffer.from(await r.arrayBuffer());
    out[p] = { status: r.status, sha256: crypto.createHash("sha256").update(b).digest("hex"),
      marker: b.includes("data-openclaw-control-ui-build-id") };
  }
  console.log(JSON.stringify(out));
})().catch(e => { console.error(String(e)); process.exit(1); });
`

// controlUIProbePin is the OpenClaw version noControlUI was checked on. On
// it the Control UI is served at the gateway's root with no token, so a 404
// or 401 there means the UI is off. A later pin may move the UI under
// another base path or behind auth, where the same answers would pass with
// the UI on; TestControlUIProbePin fails until the probe is rechecked on the
// new pin (#4425).
const controlUIProbePin = "2026.10.9"

// TestControlUIProbePin fails when the guest's OpenClaw moves off the
// version noControlUI was checked on. npm ci installs the version in
// guest/openclaw/package-lock.json, so that is the one that counts;
// package.json and build-rootfs.sh's OPENCLAW_VERSION must agree with it.
// It needs no root, so the pin bump's own PR fails here, not only on the
// gVisor runner.
func TestControlUIProbePin(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile("../../guest/openclaw/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var lock struct {
		Packages map[string]struct{ Version string } `json:"packages"`
	}
	if err := json.Unmarshal(read("package-lock.json"), &lock); err != nil {
		t.Fatal(err)
	}
	var pkg struct{ Dependencies map[string]string }
	if err := json.Unmarshal(read("package.json"), &pkg); err != nil {
		t.Fatal(err)
	}
	script := "(none)"
	if m := regexp.MustCompile(`(?m)^OPENCLAW_VERSION=(\S+)$`).FindAllSubmatch(read("build-rootfs.sh"), -1); len(m) == 1 {
		script = string(m[0][1])
	}
	for _, v := range []struct{ where, got string }{
		{"package-lock.json node_modules/openclaw", lock.Packages["node_modules/openclaw"].Version},
		{"package.json dependencies", pkg.Dependencies["openclaw"]},
		{"build-rootfs.sh OPENCLAW_VERSION", script},
	} {
		if v.got != controlUIProbePin {
			t.Errorf("OpenClaw in %s is %q, but noControlUI was checked on %s: with gateway.controlUi.enabled true on the new pin, "+
				"find where the gateway serves the Control UI (base path, auth) and point the probe there, then set controlUIProbePin (#4425)",
				v.where, v.got, controlUIProbePin)
		}
	}
}

// noControlUI checks that the guest's gateway does not serve OpenClaw's
// Control UI (#4417, PLN-5): agentOS never uses it, and its assets inline
// the DOMPurify and KaTeX copies accepted under #4302. OpenClaw serves it by
// default whenever dist/control-ui is present, so only the profile's
// gateway.controlUi.enabled false keeps it off. The probe asks for the UI's
// root and for the two assets that hold those copies, and fails if any
// comes back as the file in the image or carries the UI's build marker. A
// gateway the probe cannot reach fails the test, so a dead gateway is no pass.
// The probe runs through the machine's own runtime, with its runsc flags
// and fixed environment.
func noControlUI(t *testing.T, rt *gvisor.Runtime, rootfs string) {
	t.Helper()
	ui := filepath.Join(rootfs, "opt/openclaw/node_modules/openclaw/dist/control-ui")
	paths, want := []string{"/"}, map[string]string{}
	for _, g := range []string{"markdown-runtime-*.js", "mermaid.min-*.js"} {
		files, _ := filepath.Glob(filepath.Join(ui, "assets", g))
		if len(files) != 1 {
			t.Fatalf("control-ui assets %s: %v, want one file (has the OpenClaw pin moved?)", g, files)
		}
		b, err := os.ReadFile(files[0])
		if err != nil {
			t.Fatal(err)
		}
		p := "/assets/" + filepath.Base(files[0])
		paths = append(paths, p)
		want[p] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := rt.Exec(ctx, "agent", vm.Command{
		Argv:      append([]string{"/usr/local/bin/node", "-e", controlUIProbe}, paths...),
		MaxOutput: 1 << 20,
	})
	if err != nil {
		// runsc's own messages go to the runtime's exec log, not to err;
		// its last 16 KiB are this probe's.
		log, _ := os.ReadFile(filepath.Join(rt.StateDir, "exec.log"))
		if len(log) > 16<<10 {
			log = log[len(log)-16<<10:]
		}
		t.Fatalf("control UI probe: %v\nstderr: %s\nexec.log (tail):\n%s", err, res.Stderr, log)
	}
	out := res.Stdout
	if res.ExitCode != 0 || res.Truncated {
		t.Fatalf("control UI probe: exit %d (truncated %v)\nstdout: %s\nstderr: %s", res.ExitCode, res.Truncated, out, res.Stderr)
	}
	var got map[string]struct {
		Status int
		Sha256 string
		Marker bool
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("control UI probe output %q: %v", out, err)
	}
	t.Logf("control UI probe: %s", strings.TrimSpace(string(out)))
	for _, p := range paths {
		r, ok := got[p]
		switch {
		case !ok || r.Status == 0:
			t.Errorf("control UI probe: no answer for %s", p)
		case r.Marker || (want[p] != "" && r.Sha256 == want[p]):
			t.Errorf("gateway serves the Control UI at %s (status %d): want gateway.controlUi.enabled false (#4417)", p, r.Status)
		}
	}
}
