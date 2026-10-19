package e2e

// REQ: CRED-5, CRED-1, A14

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/provagent"
	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

// containProbe is where the test puts codexprobe in its copy of the image:
// outside the workspace and CODEX_HOME, and readable by a tool.
const containProbe = "/usr/local/libexec/agentos-contain-probe"

// S8-W1-contain (#1720): the pinned Codex CLI from guest/codex/build-rootfs.sh
// runs in a gVisor provider worker exactly as provagent.Run starts it (the
// codex declaration's forwarder wrap, env and argv, its result file), holding
// only a placeholder login with a synthetic canary. A scripted Responses
// endpoint on the worker's route socket has it start codexprobe as a tool.
// The CLI itself must reach the endpoint with the placeholder, and the tool
// must reach none of the forwarder's port, the route socket or CODEX_HOME,
// and write nothing outside the workspace. The same probe run as the worker
// runs the CLI, minus the CLI's sandbox, reaches all three: so what stops the
// tool is the CLI's own sandbox (bwrap and seccomp, under gVisor), not the
// worker or a missing file.
func TestIntegrationCodexContainment(t *testing.T) {
	runsc, rootfs := os.Getenv("AGENTOS_RUNSC"), os.Getenv("AGENTOS_CODEX_ROOTFS")
	if runsc == "" || rootfs == "" || os.Geteuid() != 0 {
		t.Skip("set AGENTOS_RUNSC and AGENTOS_CODEX_ROOTFS (guest/codex/build-rootfs.sh) and run as root")
	}
	dir := t.TempDir()
	img := filepath.Join(dir, "image")
	if out, err := exec.Command("cp", "-a", rootfs, img).CombinedOutput(); err != nil {
		t.Fatalf("copy image: %v: %s", err, out)
	}
	build := exec.Command("go", "build", "-trimpath", "-o", filepath.Join(img, containProbe), "./testdata/codexprobe")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build probe: %v: %s", err, out)
	}

	canary := "agentos-synthetic-canary-" + randHex(t)
	account := "acct-" + randHex(t)
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	auth, _ := json.Marshal(map[string]any{
		"OPENAI_API_KEY": nil,
		"tokens": map[string]string{
			"id_token": enc(map[string]string{"alg": "none", "typ": "JWT"}) + "." +
				enc(map[string]any{"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": account}}) + "." + canary + "-id",
			"access_token":  canary + "-access",
			"refresh_token": canary + "-refresh",
			"account_id":    account,
		},
		"last_refresh": time.Now().UTC().Format(time.RFC3339),
	})

	ep := &containEndpoint{cmd: containProbe, bearer: "Bearer " + canary + "-access", account: account}
	routes := filepath.Join(dir, "routes")
	if err := os.Mkdir(routes, 0o755); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(routes, "route.sock"))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: ep}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	ctx := context.Background()
	adm, err := admission.New(admission.Config{CapacityMB: 4096}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := vm.Open(ctx, vm.Config{
		StateDir:       filepath.Join(dir, "machines"),
		Images:         map[string]string{"codex": img},
		Runtime:        &gvisor.Runtime{Bin: runsc, StateDir: filepath.Join(dir, "runsc")},
		Admit:          adm,
		NoCgroups:      true,
		NoQuota:        true,
		ProviderRoutes: fixedRoute(routes),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Unmount(filepath.Join(dir, "runsc", "null-netns"), syscall.MNT_DETACH) })

	d := provagent.Builtins()["codex"]
	const id = vm.ProviderPrefix + "contain"
	spec := vm.Spec{Image: d.Image, Class: admission.Accepted, MemMB: 2048, Label: vm.Private, Argv: d.Idle}
	if _, err := m.CreateProviderWorker(ctx, id, spec, map[string][]byte{egress.CodexAuthFile: auth}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Destroy(context.Background(), id) })

	// Control: the probe started as the worker starts the CLI (env -i, the
	// declaration's env and forwarder wrap), with no CLI and so no CLI
	// sandbox in between.
	argv := append([]string{"env", "-i"}, d.Env...)
	argv = append(append(argv, d.Wrap...), containProbe)
	cr, err := m.Exec(ctx, id, vm.Command{Argv: argv, MaxOutput: 1 << 20, As: vm.Private}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ctl := probeLine(string(cr.Stdout))
	t.Logf("control: %s", ctl)
	var c probeResult
	if err := json.Unmarshal([]byte(ctl), &c); err != nil {
		t.Fatalf("control probe: %v; stdout %q stderr %q", err, cr.Stdout, cr.Stderr)
	}
	if !c.TCP || !c.Unix || !c.Auth || !c.CodexHomeWrite || !c.WorkWrite {
		t.Fatalf("control: the worker itself must reach the forwarder, the route socket and CODEX_HOME: %s", ctl)
	}

	start := time.Now()
	res, err := m.Exec(ctx, id, provagent.Command(d, "Run the probe."), 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("codex exec: exit %d after %v", res.ExitCode, time.Since(start))
	out, err := m.Exec(ctx, id, vm.Command{Argv: []string{"cat", d.ResultPath}, MaxOutput: 4 << 20, As: vm.Private}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	stream := string(out.Stdout)

	calls, sawCanary := ep.seen()
	if calls == 0 || !sawCanary {
		t.Fatalf("the CLI never reached the endpoint with the placeholder login (%d calls); result %q", calls, tail(stream))
	}
	var line string
	sc := bufio.NewScanner(strings.NewReader(stream))
	sc.Buffer(nil, 4<<20)
	for sc.Scan() {
		var ev struct {
			Item struct {
				Type   string `json:"type"`
				Output string `json:"aggregated_output"`
			} `json:"item"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) == nil && ev.Item.Type == "command_execution" {
			if l := probeLine(ev.Item.Output); l != "" {
				line = l
			}
		}
	}
	t.Logf("tool: %s", line)
	t.Logf("tool output sent back: %s", tail(ep.toolOutput()))
	var p probeResult
	if err := json.Unmarshal([]byte(line), &p); err != nil {
		t.Fatalf("the probe never ran as a CLI tool: %v; result %q", err, tail(stream))
	}
	for name, reached := range map[string]bool{
		"the forwarder's loopback port": p.TCP,
		"the route socket":              p.Unix,
		"the placeholder auth.json":     p.Auth,
		"a write to /":                  p.RootWrite,
		"a write to CODEX_HOME":         p.CodexHomeWrite,
		"a write to /tmp":               p.SlashTmpWrite,
	} {
		if reached {
			t.Errorf("the tool reached %s", name)
		}
	}
	// Names under CODEX_HOME stay listable: the deny list covers its entries, not the directory
	// (guest/codex/requirements.toml, C12; ASSUMPTIONS E7). Logged, not asserted.
	t.Logf("CODEX_HOME listable from the tool: %v", p.CodexHomeList)
	if !p.WorkWrite {
		t.Errorf("the tool must still write its workspace")
	}
	if p.NoNewPrivs != "1" || p.Seccomp != "2" {
		t.Errorf("the tool is not under the CLI's seccomp filter: NoNewPrivs %q Seccomp %q", p.NoNewPrivs, p.Seccomp)
	}
	if p.NsNet == c.NsNet || p.NsMnt == c.NsMnt {
		t.Errorf("the tool shares the worker's namespaces (net %s, mnt %s): bwrap did not run", p.NsNet, p.NsMnt)
	}
	if strings.Contains(line, canary) {
		t.Errorf("the canary reached the tool")
	}
}

type probeResult struct {
	TCP            bool   `json:"tcp"`
	Unix           bool   `json:"unix"`
	Auth           bool   `json:"auth"`
	CodexHomeList  bool   `json:"codex_home_list"`
	RootWrite      bool   `json:"root_write"`
	CodexHomeWrite bool   `json:"codex_home_write"`
	SlashTmpWrite  bool   `json:"slash_tmp_write"`
	WorkWrite      bool   `json:"work_write"`
	Seccomp        string `json:"seccomp"`
	NoNewPrivs     string `json:"nonewprivs"`
	NsNet          string `json:"ns_net"`
	NsMnt          string `json:"ns_mnt"`
}

// probeLine is the last line of out that codexprobe printed.
func probeLine(out string) string {
	var line string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, `{"tcp"`) {
			line = l
		}
	}
	return line
}

// containEndpoint plays the Responses API on the route socket: the first
// turn asks for one code-mode tool call running cmd, every later one ends
// the turn. It records whether each request carried the placeholder login.
type containEndpoint struct {
	cmd, bearer, account string

	mu        sync.Mutex
	calls     int
	sawCanary bool
	second    []byte // the second request's body, which carries the tool's output
}

// toolOutput is the custom_tool_call_output the CLI sent back for the tool call.
func (e *containEndpoint) toolOutput() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var req struct {
		Input []json.RawMessage `json:"input"`
	}
	json.Unmarshal(e.second, &req)
	for _, in := range req.Input {
		if strings.Contains(string(in), `"custom_tool_call_output"`) {
			return string(in)
		}
	}
	return tail(string(e.second))
}

func (e *containEndpoint) seen() (int, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls, e.sawCanary
}

func (e *containEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/responses") {
		http.NotFound(w, r)
		return
	}
	e.mu.Lock()
	turn := e.calls
	e.calls++
	if turn == 1 {
		e.second = body
	}
	if r.Header.Get("Authorization") == e.bearer && r.Header.Get("Chatgpt-Account-Id") == e.account {
		e.sawCanary = true
	}
	e.mu.Unlock()
	rid := "r" + string(rune('0'+turn%10))
	var item map[string]any
	if turn == 0 {
		cmd, _ := json.Marshal(e.cmd)
		item = map[string]any{"type": "custom_tool_call", "name": "exec", "call_id": "c0", "id": "ct0",
			"input": "const r = await tools.exec_command({cmd: " + string(cmd) + ", yield_time_ms: 10000}); text(JSON.stringify(r));"}
	} else {
		item = map[string]any{"type": "message", "role": "assistant", "id": "m" + rid,
			"content": []any{map[string]string{"type": "output_text", "text": "done"}}}
	}
	var buf bytes.Buffer
	for _, ev := range []map[string]any{
		{"type": "response.created", "response": map[string]any{"id": rid}},
		{"type": "response.output_item.done", "item": item},
		{"type": "response.completed", "response": map[string]any{"id": rid, "usage": map[string]any{
			"input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
			"input_tokens_details": nil, "output_tokens_details": nil}}},
	} {
		b, _ := json.Marshal(ev)
		buf.WriteString("event: " + ev["type"].(string) + "\ndata: " + string(b) + "\n\n")
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Write(buf.Bytes())
}

// fixedRoute gives every provider worker the one route directory.
type fixedRoute string

func (f fixedRoute) Open(string) (string, error) { return string(f), nil }
func (fixedRoute) Close(string)                  {}

func randHex(t *testing.T) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func tail(s string) string {
	if len(s) > 2000 {
		return s[len(s)-2000:]
	}
	return s
}
