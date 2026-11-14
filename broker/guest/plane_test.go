package guest

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// REQ: REV-1, REV-5, OP-1, ADP-10, CRED-1, ARC-3, ARC-6, ARC-7, OP-8, PLN-5

// fakeMachines records steps and label changes.
type fakeMachines struct {
	mu      sync.Mutex
	steps   map[string]int
	private map[string]bool
	lineage map[string]string
	events  []string
	// locked mimics the manager holding its lock while it calls Open;
	// a Lineage call then would deadlock on the box.
	locked  bool
	misuse  int
	stepErr error           // what Step answers; nil succeeds
	gone    map[string]bool // machines the manager no longer knows
}

func newMachines() *fakeMachines {
	return &fakeMachines{steps: map[string]int{}, private: map[string]bool{}, lineage: map[string]string{}, gone: map[string]bool{}}
}

func (f *fakeMachines) Step(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.steps[id]++
	f.events = append(f.events, "step "+id)
	return f.stepErr
}

func (f *fakeMachines) failSteps(err error) { f.mu.Lock(); f.stepErr = err; f.mu.Unlock() }

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
	if f.locked {
		f.misuse++
	}
	if f.gone[id] {
		return "", errors.New("no such machine")
	}
	if l := f.lineage[id]; l != "" {
		return l, nil
	}
	return id, nil
}

func (f *fakeMachines) stepsOf(id string) int { f.mu.Lock(); defer f.mu.Unlock(); return f.steps[id] }

type rig struct {
	t     testing.TB
	p     *Plane
	ms    *fakeMachines
	kern  *testKernel
	model int
	goals []string // the goal each model call's context named
	mu    sync.Mutex
	reps  []string
}

func newRig(t testing.TB, mod func(*Config)) *rig {
	t.Helper()
	r := &rig{t: t, ms: newMachines(), kern: newTestKernel(t)}
	cfg := Config{
		Dir:      filepath.Join(t.TempDir(), "guests"),
		Machines: r.ms,
		Kernel:   r.kern,
		Keys:     r.kern.keys,
		Label:    func(string) string { return "public" },
		Model: func(machine string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				r.mu.Lock()
				r.model++
				g, _ := req.Context().Value(goalKey{}).(string)
				r.goals = append(r.goals, g)
				r.mu.Unlock()
				fmt.Fprintf(w, `{"machine":%q,"path":%q,"raw":%q}`, machine, req.URL.Path, req.URL.EscapedPath())
			})
		},
		Meter:    passMeter{},
		WithGoal: func(ctx context.Context, goal string) context.Context { return context.WithValue(ctx, goalKey{}, goal) },
		OwnerReply: func(machine string, rep Reply) {
			r.mu.Lock()
			r.reps = append(r.reps, machine+" "+rep.ID+" "+rep.Text+"|"+rep.Summary)
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

// passMeter meters nothing; the rig's WithGoal puts the goal under goalKey,
// where its model route reads it.
type passMeter struct{}

type goalKey struct{}

func (passMeter) Wrap(_ string, h http.Handler) http.Handler { return h }

// client talks to machine id's socket as its guest would.
func (r *rig) client(id string) *http.Client {
	r.t.Helper()
	dir := filepath.Join(r.p.cfg.Dir, id)
	if r.p.get(id) == nil {
		var err error
		if dir, err = r.p.Open(id); err != nil {
			r.t.Fatal(err)
		}
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
func (r *rig) tool(id, name string, args map[string]any, hdr ...string) (planState, string) {
	r.t.Helper()
	res := r.rpc(id, "tools/call", map[string]any{"name": name, "arguments": args}, hdr...)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if res["isError"] == true {
		return planState{}, text
	}
	var st planState
	if err := json.Unmarshal([]byte(text), &st); err != nil {
		r.t.Fatalf("tool result %q: %v", text, err)
	}
	return st, ""
}

// send is a one-step plan: organize a mail on the "mail" clerk, which the
// test kernel's key covers.
func send(reqID string) map[string]any {
	return map[string]any{"request_id": reqID, "steps": []map[string]any{
		{"verb": "organize", "clerk": "mail", "args": map[string]string{"target": "mail-1", "label": "done"}}}}
}

// TestARC6SocketServesOnlyTheGuestInterface: the socket answers the ARC-6
// services and nothing else.
func TestARC6SocketServesOnlyTheGuestInterface(t *testing.T) {
	r := newRig(t, nil)
	for _, c := range []struct{ method, path string }{
		{"GET", "/"}, {"GET", "/admin"}, {"POST", "/v1/chat/completions"}, {"GET", "/owner"},
		{"POST", "/sockets/owner"}, {"GET", "/../etc/passwd"},
	} {
		if code, _ := r.do("m1", c.method, c.path, ""); code != 404 && code != 405 {
			t.Errorf("%s %s answered %d", c.method, c.path, code)
		}
	}
	if code, _ := r.do("m1", "GET", "/mcp", ""); code != 405 {
		t.Errorf("GET /mcp: %d (no server stream)", code)
	}
	r2 := newRig(t, func(c *Config) { c.Model = nil })
	if code, _ := r2.do("m1", "POST", "/model/openai/v1/chat/completions", "{}"); code != 503 {
		t.Errorf("model without egress: %d", code)
	}
}

// TestADP10SocketNeverNormalizesAPath: the socket routes on the path the
// guest sent, byte for byte. A dot segment, an escaped separator, or an
// empty segment is never cleaned or redirected into a declared shape: on a
// model path it reaches the model chain as sent, whose shape check denies
// it (egress E1), and anywhere else it is 404. Go 1.26's ServeMux answers
// an unclean path with a 307 that keeps the method and body, so a guest
// that follows it lands on the clean path (security, ADP-10).
func TestADP10SocketNeverNormalizesAPath(t *testing.T) {
	r := newRig(t, nil)
	noFollow := func(id string) *http.Client {
		c := r.client(id)
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return c
	}
	send := func(id, method, path string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, "http://broker"+path, strings.NewReader("{}"))
		resp, err := noFollow(id).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	// Model paths reach the model chain unchanged, one machine each so
	// the meter's per-machine cap does not interfere.
	for i, p := range []string{
		"/model/openai/v1/../v1/chat/completions",
		"/model/openai/v1/chat%2Fcompletions",
		"/model/openai%2Fv1/chat/completions",
		"/model/openai/v1/%2e%2e/v1/chat/completions",
		"/model/openai/v1/./chat/completions",
		"/model/openai//v1/chat/completions",
		"/model/openai/v1/chat/completions/..",
		"/model/../model/openai/v1/chat/completions",
	} {
		id := fmt.Sprintf("n%d", i)
		code, body := send(id, "POST", p)
		want := fmt.Sprintf(`"raw":%q`, strings.TrimPrefix(p, "/model"))
		if code != 200 || !strings.Contains(body, want) {
			t.Errorf("POST %s: %d %s; want the model chain to see %s", p, code, body, want)
		}
	}
	// Everything else unclean is 404, never a redirect.
	for _, c := range []struct{ method, path string }{
		{"POST", "/mcp/../mcp"}, {"POST", "/./mcp"}, {"POST", "//mcp"}, {"POST", "/mcp/"},
		{"GET", "/owner%2Fnext"}, {"GET", "/owner/./next"}, {"POST", "/owner//reply"},
		{"GET", "/owner/next/.."}, {"POST", "/x/../model/openai/v1/chat/completions"},
		{"POST", "//model/openai/v1/chat/completions"}, {"POST", "/model"}, {"POST", "/%6dcp"},
	} {
		if code, body := send("m1", c.method, c.path); code != 404 {
			t.Errorf("%s %s answered %d %s; want 404", c.method, c.path, code, body)
		}
	}
	if r.model != 8 {
		t.Errorf("model chain saw %d calls, want 8", r.model)
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
	if strings.Join(names, ",") != "plan,result_read" {
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

// TestARC6IdentityComesFromTheSocket: a plan's ID is the lineage of the
// machine whose socket the call arrived on, whatever the request says, and
// another machine can neither see nor collide with it.
func TestARC6IdentityComesFromTheSocket(t *testing.T) {
	r := newRig(t, nil)
	st, errText := r.tool("m1", "plan", send("r1"), "X-Machine", "m2", "Authorization", "Bearer m2")
	if errText != "" || st.State != "done" || r.kern.ran("m1/r1") != 1 {
		t.Fatalf("plan: %+v %s", st, errText)
	}
	if _, errText := r.tool("m2", "plan", map[string]any{"request_id": "r1"}); errText == "" {
		t.Fatal("m2 read m1's plan")
	}
	st, _ = r.tool("m2", "plan", send("r1"))
	if st.State != "done" || r.kern.ran("m1/r1") != 1 || r.kern.ran("m2/r1") != 1 {
		t.Fatalf("m2's r1 is not its own: %+v %v", st, r.kern.runs)
	}
}

// TestOP1RetriesAndForksRunAPlanOnce: the same request_id from a machine
// or from a fork in its lineage is one plan and runs once; different steps
// under it submit nothing and say so.
func TestOP1RetriesAndForksRunAPlanOnce(t *testing.T) {
	r := newRig(t, nil)
	r.ms.lineage["f1"] = "m1"
	for _, id := range []string{"m1", "m1", "f1"} {
		if st, e := r.tool(id, "plan", send("r1")); st.State != "done" {
			t.Fatalf("%s: %+v %s", id, st, e)
		}
	}
	if n := r.kern.ran("m1/r1"); n != 1 {
		t.Fatalf("plan ran %d times", n)
	}
	other := send("r1")
	other["steps"].([]map[string]any)[0]["verb"] = "trash"
	if st, e := r.tool("f1", "plan", other); e != "" || !strings.Contains(st.Reason, reasonRepeat) || r.kern.plans() != 1 {
		t.Fatalf("a repeat with other steps: %+v %q, %d plans", st, e, r.kern.plans())
	}
	if st, _ := r.tool("f1", "plan", map[string]any{"request_id": "r1"}); st.State != "done" || st.Reason != "" {
		t.Fatalf("fork cannot read its lineage's plan: %+v", st)
	}
}

// TestPLN5NoKeyNoPlan: a machine with no key, or a plane with no kernel,
// has every plan refused in fixed words, and nothing reaches the kernel.
func TestPlaneMutNewNeedsMachines(t *testing.T) {
	// The TestPlaneMut tests each fail when one plane.go statement that
	// mutgate found unchecked is deleted (GUEST-mut-plane, #5748).
	if _, err := New(Config{Dir: filepath.Join(t.TempDir(), "guests")}); err == nil {
		t.Fatal("New took a Config with no Machines")
	}
}

func TestPlaneMutNewDefaults(t *testing.T) {
	p, err := New(Config{Dir: filepath.Join(t.TempDir(), "guests"), Machines: newMachines()})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Shutdown()
	if p.cfg.StepInterval != 2*time.Second || p.cfg.SubmitEvery != 3*time.Second {
		t.Fatalf("StepInterval %v, SubmitEvery %v; want the documented 2s and 3s", p.cfg.StepInterval, p.cfg.SubmitEvery)
	}
}

func TestPlaneMutNewTightensDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "guests")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{Dir: dir, Machines: newMachines()})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Shutdown()
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("an existing Dir kept mode %v; want 0700", fi.Mode().Perm())
	}
}

func TestPlaneMutNewRefusesABadInbox(t *testing.T) {
	tmp := t.TempDir()
	link := filepath.Join(tmp, "inbox.json")
	if err := os.Symlink(filepath.Join(tmp, "elsewhere"), link); err != nil {
		t.Fatal(err)
	}
	if p, err := New(Config{Dir: filepath.Join(tmp, "guests"), Machines: newMachines(), InboxPath: link}); err == nil {
		p.Shutdown()
		t.Fatal("New opened an inbox it cannot read (a symlink)")
	}
}

func TestPlaneMutOpenTwiceKeepsTheMachine(t *testing.T) {
	r := newRig(t, nil)
	dir, err := r.p.Open("m1")
	if err != nil {
		t.Fatal(err)
	}
	m := r.p.get("m1")
	again, err := r.p.Open("m1")
	if err != nil {
		t.Fatal(err)
	}
	if again != dir || r.p.get("m1") != m {
		t.Fatal("a second Open replaced the running machine")
	}
}

func TestPlaneMutOpenClearsAStaleDir(t *testing.T) {
	r := newRig(t, nil)
	stale := filepath.Join(r.p.cfg.Dir, "m1")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "left"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.p.Open("m1"); err != nil {
		t.Fatalf("Open over a stale directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stale, "left")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the stale file survived Open: %v", err)
	}
}

func TestPlaneMutOpenReportsAListenFailure(t *testing.T) {
	// A socket path past the kernel's limit (108 bytes) cannot be bound.
	dir := filepath.Join(t.TempDir(), strings.Repeat("d", 110))
	p, err := New(Config{Dir: dir, Machines: newMachines()})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Shutdown()
	if _, err := p.Open("m1"); err == nil {
		t.Fatal("Open succeeded with no socket to serve")
	}
	if p.get("m1") != nil {
		t.Fatal("a machine with no socket was recorded")
	}
}

func TestPlaneMutOpenCountsClosedConns(t *testing.T) {
	r := newRig(t, nil)
	c := r.client("m1")
	resp, err := c.Get("http://broker/nope")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	m := r.p.get("m1")
	if m.conns.Load() != 1 {
		t.Fatalf("%d open connections; want 1", m.conns.Load())
	}
	c.CloseIdleConnections()
	for deadline := time.Now().Add(5 * time.Second); m.conns.Load() != 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d connections still counted open after the guest closed its only one", m.conns.Load())
		}
	}
}

func TestPlaneMutCloseStopsServing(t *testing.T) {
	r := newRig(t, nil)
	c := r.client("m1")
	resp, err := c.Get("http://broker/nope")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	r.p.Close("m1")
	// The guest's kept-alive connection must end with its machine.
	if resp, err := c.Get("http://broker/nope"); err == nil {
		resp.Body.Close()
		t.Fatalf("a closed machine still answered %d", resp.StatusCode)
	}
}

func TestPlaneMutCloseStopsTheStepper(t *testing.T) {
	r := newRig(t, func(c *Config) { c.StepInterval = time.Hour })
	r.client("m1")
	r.client("m2")
	m1, m2 := r.p.get("m1"), r.p.get("m2")
	// m1: one snapshot taken, a trailing one armed for the interval.
	r.p.step(m1)
	r.p.step(m1)
	r.p.Close("m1")
	s := &m1.steps
	if !s.mu.TryLock() {
		t.Fatal("Close left the stepper locked")
	}
	timer := s.timer
	s.mu.Unlock()
	if timer == nil {
		t.Fatal("no trailing snapshot was armed")
	}
	if timer.Stop() {
		t.Fatal("Close left the trailing snapshot armed")
	}
	// m2: never snapshotted, so only stop keeps a late step from one.
	r.p.Close("m2")
	r.p.step(m2)
	if n := r.ms.stepsOf("m2"); n != 0 {
		t.Fatalf("a closed machine was snapshotted %d times", n)
	}
	if n := r.ms.stepsOf("m1"); n != 1 {
		t.Fatalf("m1 snapshotted %d times; want 1", n)
	}
}

func TestPlaneMutShutdownClosesEveryMachine(t *testing.T) {
	r := newRig(t, nil)
	r.client("m1")
	r.client("m2")
	r.p.Shutdown()
	if r.p.get("m1") != nil || r.p.get("m2") != nil {
		t.Fatal("Shutdown left a machine open")
	}
}

func TestPlaneMutHandlerBusyIsOnlyBusy(t *testing.T) {
	r := newRig(t, nil)
	r.client("m1")
	m := r.p.get("m1")
	for range cap(m.slot) {
		m.slot <- struct{}{}
	}
	code, body := r.do("m1", "GET", "/nope", "")
	for range cap(m.slot) {
		<-m.slot
	}
	if code != http.StatusTooManyRequests || body != "too many requests in flight\n" {
		t.Fatalf("a full machine answered %d %q; want 429 and nothing more", code, body)
	}
}

func TestPlaneMutHandlerEscapedPathIsOnlyNotFound(t *testing.T) {
	r := newRig(t, nil)
	code, body := r.do("m1", "GET", "/nope%41", "")
	if code != http.StatusNotFound || body != "404 page not found\n" {
		t.Fatalf("an escaped path answered %d %q; want one 404", code, body)
	}
}

func TestPlaneMutHandlerModelWithoutGoal(t *testing.T) {
	r := newRig(t, func(c *Config) { c.WithGoal = nil })
	code, body := r.do("m1", "GET", "/model/a/v1", "")
	if code != 200 || !strings.Contains(body, `"path":"/a/v1"`) {
		t.Fatalf("model call with no WithGoal: %d %q", code, body)
	}
}

func TestPlaneMutDeadlineHandlerSetIsKept(t *testing.T) {
	set := time.Now().Add(time.Minute)
	w := &deadlineWriter{d: time.Hour, set: set}
	if got := w.until(); !got.Equal(set) {
		t.Fatalf("until() = %v; want the handler's earlier deadline %v", got, set)
	}
	w.set = time.Now().Add(2 * time.Hour)
	if got := w.until(); !got.Before(w.set) {
		t.Fatalf("until() = %v; want now+d, before the handler's later deadline", got)
	}
}

func TestPlaneMutDeadlineRenewedOnHeaderAndFlush(t *testing.T) {
	// Each handler first expires the connection's write deadline behind
	// the writer's back, so a header or flush write it does not renew for
	// fails the reply.
	cases := map[string]func(w http.ResponseWriter){
		"header": func(w http.ResponseWriter) {
			w.(*deadlineWriter).rc.SetWriteDeadline(time.Now().Add(-time.Second))
			w.WriteHeader(http.StatusEarlyHints) // written at once
			w.WriteHeader(http.StatusTeapot)
		},
		"flush": func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusTeapot) // buffered: nothing written yet
			w.(*deadlineWriter).rc.SetWriteDeadline(time.Now().Add(-time.Second))
			w.(http.Flusher).Flush()
		},
	}
	for name, h := range cases {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: withWriteDeadline(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { h(w) }), time.Minute)}
		go srv.Serve(l)
		resp, err := http.Get("http://" + l.Addr().String() + "/")
		if err == nil {
			_, err = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		srv.Close()
		if err != nil || resp.StatusCode != http.StatusTeapot {
			t.Fatalf("%s: reply failed or lost its status: %v %v", name, resp, err)
		}
	}
}

func TestPlaneMutDeadlineFlushReachesTheGuest(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got, early := make(chan struct{}), make(chan bool, 1)
	srv := &http.Server{Handler: withWriteDeadline(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "a")
		w.(http.Flusher).Flush()
		select {
		case <-got:
			early <- true
		case <-time.After(5 * time.Second):
			early <- false
		}
	}), time.Minute)}
	go srv.Serve(l)
	defer srv.Close()
	resp, err := http.Get("http://" + l.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	close(got)
	resp.Body.Close()
	if !<-early {
		t.Fatal("Flush did not send the reply's start before the handler returned")
	}
}

func TestPlaneMutStepCoalescesWhileRunning(t *testing.T) {
	r := newRig(t, func(c *Config) { c.StepInterval = 20 * time.Millisecond })
	r.client("m1")
	m := r.p.get("m1")
	s := &m.steps
	r.ms.mu.Lock() // holds the first snapshot inside Step
	go r.p.step(m)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		s.mu.Lock()
		running := s.running
		s.mu.Unlock()
		if running {
			break
		}
		if time.Now().After(deadline) {
			r.ms.mu.Unlock()
			t.Fatal("a snapshot in progress is not marked running")
		}
	}
	done := make(chan struct{})
	go func() { r.p.step(m); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		r.ms.mu.Unlock()
		t.Fatal("a step during a snapshot started a second one")
	}
	r.ms.mu.Unlock()
	// The step it covered is owed: one trailing snapshot follows.
	for deadline := time.Now().Add(5 * time.Second); r.ms.stepsOf("m1") != 2; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d snapshots; want the first and one trailing", r.ms.stepsOf("m1"))
		}
	}
}

func TestPlaneMutStepTrailingNeedsAPendingStep(t *testing.T) {
	r := newRig(t, nil)
	r.client("m1")
	r.p.trailing(r.p.get("m1"))
	if n := r.ms.stepsOf("m1"); n != 0 {
		t.Fatalf("a trailing snapshot with nothing owed ran %d times", n)
	}
}

func TestPlaneMutStepFailureIsLogged(t *testing.T) {
	var logged atomic.Value
	r := newRig(t, func(c *Config) {
		c.Logf = func(format string, args ...any) { logged.Store(fmt.Sprintf(format, args...)) }
	})
	r.client("m1")
	r.ms.failSteps(errors.New("disk on fire"))
	r.p.step(r.p.get("m1"))
	if s, _ := logged.Load().(string); !strings.Contains(s, "step snapshot after tool call failed: disk on fire") {
		t.Fatalf("failed snapshot logged %q", s)
	}
}

func TestPlaneMutBucketRefills(t *testing.T) {
	b := bucket{last: time.Now().Add(-1500 * time.Millisecond)}
	if !b.take(5, time.Second) {
		t.Fatal("an empty bucket did not refill over 1.5 s at one token a second")
	}
	if b.take(5, time.Second) {
		t.Fatal("the same 1.5 s refilled the bucket twice")
	}
}

func TestPlaneMutLimitListenerClose(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newLimitListener(inner, 1)
	dial, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()
	held, err := l.Accept() // the only slot
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	within := func(what string, f func()) {
		t.Helper()
		done := make(chan struct{})
		go func() { f(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not return", what)
		}
	}
	within("Accept on a closed, full listener", func() {
		if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
			t.Errorf("Accept after Close: %v", err)
		}
	})
	within("closing the held connection", func() { held.Close() })
}

func TestPlaneMutLimitListenerFailedAcceptFreesItsSlot(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newLimitListener(inner, 1)
	inner.Close() // Accept fails, but the limit listener is not closed
	for i := range 3 {
		done := make(chan error, 1)
		go func() { _, err := l.Accept(); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("Accept on a closed socket succeeded")
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Accept %d blocked: a failed Accept kept its slot", i+1)
		}
	}
}

func TestPlaneMutInboxDropsAnsweredOnOpen(t *testing.T) {
	// Open and Close run these inbox statements too, so their mutgate
	// targets include them (GUEST-mut-plane, #5748).
	st, err := openStore("")
	if err != nil {
		t.Fatal(err)
	}
	st.msgs["m1"] = []storedMsg{{ID: "a", Text: "answered"}, {ID: "b", Text: "open"}}
	st.outbox = []PendingReply{{Machine: "m1", Reply: Reply{ID: "a"}}}
	b := newInbox("m1", st)
	if len(b.msgs) != 1 || b.msgs[0].ID != "b" {
		t.Fatalf("inbox holds %d messages; want only the unanswered one", len(b.msgs))
	}
	if left := st.load("m1"); len(left) != 1 || left[0].ID != "b" {
		t.Fatalf("store still holds %v; the answered message must leave it", left)
	}
}

func TestPlaneMutInboxWakesOnRequeueAndClose(t *testing.T) {
	st, err := openStore("")
	if err != nil {
		t.Fatal(err)
	}
	st.msgs["m1"] = []storedMsg{{ID: "a", Text: "x"}}
	b := newInbox("m1", st)
	woken := func(what string, w chan struct{}) {
		t.Helper()
		select {
		case <-w:
		default:
			t.Fatalf("%s did not wake the guest's waiting fetch", what)
		}
	}
	w := b.wake
	b.requeue()
	woken("requeue", w)
	w = b.wake
	b.close(true)
	woken("close", w)
	b.close(true) // idempotent: a second close must not close the channel again
	if left := st.load("m1"); len(left) != 0 {
		t.Fatalf("a forgetting close left %d stored messages", len(left))
	}
}

// Malformed calls are refused before anything is signed.
func TestPLN5NoKeyNoPlan(t *testing.T) {
	r := newRig(t, func(c *Config) {
		keys := c.Keys
		c.Keys = func(m string) (key.Key, ed25519.PrivateKey, bool) {
			switch m {
			case "m2":
				return key.Key{}, nil, false
			case "m3": // #3087: a short holder is refused, never signed with
				k, h, _ := keys(m)
				return k, h[:ed25519.SeedSize], true
			}
			return keys(m)
		}
	})
	if st, _ := r.tool("m2", "plan", send("r1")); st.State != "refused" || st.Reason != reasonNoKey || r.kern.plans() != 0 {
		t.Fatalf("%+v, %d plans", st, r.kern.plans())
	}
	if st, _ := r.tool("m3", "plan", send("r1")); st.State != "refused" || st.Reason != reasonNoKey || r.kern.plans() != 0 {
		t.Fatalf("short holder: %+v, %d plans", st, r.kern.plans())
	}
	nk := newRig(t, func(c *Config) { c.Kernel = nil })
	if st, _ := nk.tool("m1", "plan", send("r1")); st.State != "refused" || st.Reason != reasonNoKernel {
		t.Fatalf("no kernel: %+v", st)
	}
	step := func(verb, clerk string) map[string]any {
		return map[string]any{"verb": verb, "clerk": clerk, "args": map[string]string{"target": "t"}}
	}
	for _, bad := range []map[string]any{
		{"steps": []map[string]any{step("organize", "mail")}},
		{"request_id": "a/b", "steps": []map[string]any{step("organize", "mail")}},
		{"request_id": strings.Repeat("a", 65), "steps": []map[string]any{step("organize", "mail")}},
		{"request_id": "x1", "steps": []map[string]any{step("Organize", "mail")}},
		{"request_id": "x2", "steps": []map[string]any{step("organize", "")}},
		{"request_id": "x3", "steps": []map[string]any{step("organize", "m\u0430il")}}, // Cyrillic a
		{"request_id": "x4"}, // a first plan needs steps
	} {
		if _, e := r.tool("m1", "plan", bad); e == "" {
			t.Errorf("accepted %v", bad)
		}
	}
	if _, e := r.tool("m1", "effect_request", send("r2")); e == "" {
		t.Fatal("the journal's effect tool is still served")
	}
	if r.kern.plans() != 0 || r.ms.stepsOf("m1") != 0 {
		t.Fatalf("%d plans reached the kernel, %d steps", r.kern.plans(), r.ms.stepsOf("m1"))
	}
}

// TestREV1StepAfterEveryPlan: a plan sent to the kernel is a step, so the
// machine's files are snapshotted after it (vm V3). Status reads, refusals,
// and malformed calls are not steps, and a burst of plans shares one
// trailing snapshot, so a looping guest cannot flood the snapshot store
// (RES-4).
func TestREV1StepAfterEveryPlan(t *testing.T) {
	// The burst below must finish inside one interval; 1 s leaves room
	// for a loaded -race run.
	r := newRig(t, func(c *Config) { c.StepInterval = time.Second })
	r.tool("m1", "plan", send("r1"))
	if n := r.ms.stepsOf("m1"); n != 1 {
		t.Fatalf("%d steps after one plan", n)
	}
	r.tool("m1", "plan", map[string]any{"request_id": "r1"})
	r.tool("m1", "plan", map[string]any{})
	for i := 2; i < 12; i++ {
		r.tool("m1", "plan", send(fmt.Sprintf("r%d", i)))
	}
	if n := r.ms.stepsOf("m1"); n != 1 {
		t.Fatalf("%d steps inside the interval, want the first only", n)
	}
	r.stepsSettle("m1")
	if n := r.ms.stepsOf("m1"); n != 2 {
		t.Fatalf("%d steps after the burst, want one trailing snapshot", n)
	}
	r.tool("m1", "plan", send("r20"))
	if n := r.ms.stepsOf("m1"); n != 3 {
		t.Fatalf("%d steps: a plan after the interval snapshots at once", n)
	}
}

// stepsSettle waits until machine id's stepper owes nothing and a full
// StepInterval has passed since its last snapshot, so the next plan
// snapshots at once. It reads the stepper's state rather than sleeping a
// fixed time, which a late timer under load can outlast. A trailing
// snapshot is due within one interval; one not taken within three fails the
// test.
func (r *rig) stepsSettle(id string) {
	r.t.Helper()
	m := r.p.get(id)
	deadline := time.Now().Add(3 * r.p.cfg.StepInterval)
	for {
		s := &m.steps
		s.mu.Lock()
		idle := !s.running && !s.pending && s.timer == nil
		wait := r.p.cfg.StepInterval - time.Since(s.last)
		s.mu.Unlock()
		switch {
		case idle && wait <= 0:
			return
		case idle:
			time.Sleep(wait)
		case time.Now().After(deadline):
			r.t.Fatalf("stepper of %s still owes a snapshot after %v", id, 3*r.p.cfg.StepInterval)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// TestCH2PlansAreBoundedAndRateLimited: one plan's steps are bounded, and
// one machine's plans are rate-limited; excess is refused and never reaches
// the kernel.
func TestCH2PlansAreBoundedAndRateLimited(t *testing.T) {
	r := newRig(t, func(c *Config) { c.SubmitBurst, c.SubmitEvery = 3, time.Hour })
	huge := send("h1")
	huge["steps"].([]map[string]any)[0]["content"] = strings.Repeat("x", 17<<10)
	many := send("h2")
	steps := make([]map[string]any, maxSteps+1)
	for i := range steps {
		steps[i] = send("h2")["steps"].([]map[string]any)[0]
	}
	many["steps"] = steps
	labels := send("h3")
	labels["steps"].([]map[string]any)[0]["labels"] = []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}
	unnamed := []map[string]any{}
	for i, l := range []string{"Public", "a b", "privé", "x/y", "", strings.Repeat("l", 65)} {
		a := send(fmt.Sprintf("n%d", i))
		a["steps"].([]map[string]any)[0]["labels"] = []string{l}
		unnamed = append(unnamed, a)
	}
	for _, a := range append([]map[string]any{huge, many, labels}, unnamed...) {
		if _, e := r.tool("m1", "plan", a); e == "" {
			t.Fatalf("accepted %s", a["request_id"])
		}
	}
	if n := r.kern.plans(); n != 0 {
		t.Fatalf("%d refused plans reached the kernel", n)
	}
	for i := 0; i < 3; i++ {
		if st, e := r.tool("m1", "plan", send(fmt.Sprintf("ok%d", i))); st.State != "done" {
			t.Fatalf("plan %d: %+v %s", i, st, e)
		}
	}
	if _, e := r.tool("m1", "plan", send("ok3")); !strings.Contains(e, "too many") {
		t.Fatalf("burst not limited: %q", e)
	}
	if st, _ := r.tool("m2", "plan", send("ok0")); st.State != "done" {
		t.Fatal("another machine was limited")
	}
	if n := r.kern.plans(); n != 4 {
		t.Fatalf("%d plans reached the kernel, want 4", n)
	}
}

// TestServicesDirectoryHoldsOnlyTheBrokerSocket: the guest sees its
// services directory at vm.ServicesMount, and runsc --host-uds=open lets it
// connect to any socket there, so the plane puts its one socket there and
// nothing else, also on a reopen (ARC-6 "nothing else").
func TestServicesDirectoryHoldsOnlyTheBrokerSocket(t *testing.T) {
	r := newRig(t, nil)
	for range 2 {
		dir, err := r.p.Open("m1")
		if err != nil {
			t.Fatal(err)
		}
		es, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(es) != 1 || es[0].Name() != Socket || es[0].Type()&fs.ModeSocket == 0 {
			t.Fatalf("services directory holds %v, want only the socket %s", es, Socket)
		}
	}
}

// TestCH2GuestCannotExhaustBrokerConnections: a guest that opens thousands
// of connections holds at most MaxOpenConns of the broker's; the rest wait
// in the kernel, and another machine is still served.
func TestCH2GuestCannotExhaustBrokerConnections(t *testing.T) {
	r := newRig(t, func(c *Config) { c.MaxOpenConns = 16 })
	dir, _ := r.p.Open("m1")
	r.client("m2")
	var conns []net.Conn
	for i := 0; i < 2000; i++ {
		c, err := net.DialTimeout("unix", filepath.Join(dir, Socket), 50*time.Millisecond)
		if err != nil {
			continue // the kernel queue is full: also fine
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	time.Sleep(100 * time.Millisecond)
	if n := r.p.get("m1").conns.Load(); n > 16 || n < 1 {
		t.Fatalf("broker holds %d of m1's connections, cap 16", n)
	}
	if code, _ := r.do("m2", "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"ping"}`); code != 200 {
		t.Fatalf("m2 starved: %d", code)
	}
}

// TestG5OwnerMessagesSurviveABrokerRestart: unanswered owner messages are
// kept on disk and handed to the guest again after the broker restarts;
// a destroyed machine's are dropped.
func TestG5OwnerMessagesSurviveABrokerRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbox.json")
	r := newRig(t, func(c *Config) { c.InboxPath = path })
	r.client("m1")
	r.client("m2")
	id, err := r.p.DeliverOwner("m1", "book the dentist", false)
	if err != nil {
		t.Fatal(err)
	}
	r.p.DeliverOwner("m2", "to be dropped", false)
	r.do("m1", "GET", "/owner/next", "") // fetched, never answered
	r.p.Close("m2")                      // destroyed
	r.p.Shutdown()

	r2 := newRig(t, func(c *Config) { c.InboxPath = path; c.Dir = r.p.cfg.Dir })
	r2.client("m1")
	code, body := r2.do("m1", "GET", "/owner/next", "")
	if code != 200 || !strings.Contains(body, id) || !strings.Contains(body, "book the dentist") {
		t.Fatalf("after restart: %d %s", code, body)
	}
	if code, _ := r2.do("m1", "POST", "/owner/reply", fmt.Sprintf(`{"id":%q,"text":"done"}`, id)); code != 204 {
		t.Fatal("reply after restart")
	}
	pollWait = 100 * time.Millisecond
	t.Cleanup(func() { pollWait = 25 * time.Second })
	r2.client("m2")
	if code, body := r2.do("m2", "GET", "/owner/next", ""); code != 204 {
		t.Fatalf("a destroyed machine's message came back: %s", body)
	}
	r2.p.Shutdown()
	r3 := newRig(t, func(c *Config) { c.InboxPath = path; c.Dir = r.p.cfg.Dir })
	r3.client("m1")
	if code, body := r3.do("m1", "GET", "/owner/next", ""); code != 204 {
		t.Fatalf("an answered message came back: %s", body)
	}
}

// A failed inbox store must not hand the caller the path.
func TestAFailedInboxStoreDoesNotNameThePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing", "inbox.json")
	r := newRig(t, func(c *Config) { c.InboxPath = path })
	r.client("m1")
	_, err := r.p.DeliverOwner("m1", "book the dentist", true)
	if err == nil || strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), "missing") || strings.Contains(err.Error(), "/") {
		t.Fatalf("path leaked: %v", err)
	}
	if err.Error() != "guest: the message was not stored" {
		t.Fatalf("err %v", err)
	}
}

// TestREV5StoredOwnerMessagesRaiseTheMachine: the inbox store can outlive
// the machine record, so a machine created fresh (public) under an ID with
// stored owner messages is raised to private before the guest reads one,
// and a failed raise hands out nothing (security C1 on #56).
func TestREV5StoredOwnerMessagesRaiseTheMachine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbox.json")
	r := newRig(t, func(c *Config) { c.InboxPath = path })
	r.client("agent")
	if _, err := r.p.DeliverOwner("agent", "my bank details", false); err != nil {
		t.Fatal(err)
	}
	r.p.Shutdown()

	fail := &failRaise{fakeMachines: newMachines(), fail: true}
	r2 := newRig(t, func(c *Config) { c.InboxPath = path; c.Machines = fail })
	r2.client("agent")
	if code, body := r2.do("agent", "GET", "/owner/next", ""); code != 503 || strings.Contains(body, "bank") {
		t.Fatalf("raise failed, yet: %d %s", code, body)
	}
	fail.fail = false
	code, body := r2.do("agent", "GET", "/owner/next", "")
	if code != 200 || !strings.Contains(body, "bank") {
		t.Fatalf("after raise: %d %s", code, body)
	}
	if !fail.private["agent"] {
		t.Fatal("stored message handed out without raising the machine")
	}
}

type failRaise struct {
	*fakeMachines
	fail bool
}

func (f *failRaise) RaisePrivate(id string) error {
	if f.fail {
		return errors.New("label store down")
	}
	return f.fakeMachines.RaisePrivate(id)
}

// TestOP8ModelRouteIsTheMachines: model calls go through the meter to the
// route for the machine whose socket they came on, whatever the request
// says, and model egress is never served without a meter (OP-8).
func TestOP8ModelRouteIsTheMachines(t *testing.T) {
	r := newRig(t, nil)
	for i := 0; i < 2; i++ {
		code, body := r.do("m1", "POST", "/model/openai/v1/chat/completions", `{"messages":[]}`, "X-Machine", "m2")
		if code != 200 || !strings.Contains(body, `"machine":"m1"`) || !strings.Contains(body, `"path":"/openai/v1/chat/completions"`) {
			t.Fatalf("call %d: %d %s", i, code, body)
		}
	}
	if r.model != 2 {
		t.Fatalf("model route called %d times", r.model)
	}
	if _, err := New(Config{Dir: t.TempDir(), Machines: r.ms, Model: func(string) http.Handler { return nil }}); err == nil {
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
	id, err := r.p.DeliverOwner("m1", "what is on today?", false)
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
	if len(r.reps) != 1 || r.reps[0] != "m1 "+id+" dentist at 3|" {
		t.Fatalf("replies %v", r.reps)
	}
	// DEL-1c: a different second answer conflicts.
	if code, _ := r.do("m1", "POST", "/owner/reply", fmt.Sprintf(`{"id":%q,"text":"again"}`, id)); code != 409 || len(r.reps) != 1 {
		t.Fatal("answered twice")
	}

	// The reply may carry the agent's own one-line summary (CH-20): kept
	// as one line, cut to MaxSummary.
	idS, _ := r.p.DeliverOwner("m1", "and tomorrow?", false)
	r.do("m1", "GET", "/owner/next", "")
	long := strings.Repeat("s", MaxSummary+50)
	if code, _ := r.do("m1", "POST", "/owner/reply", fmt.Sprintf(`{"id":%q,"text":"full","summary":"Line one\nline two %s"}`, idS, long)); code != 204 {
		t.Fatalf("reply with summary: %d", code)
	}
	if got := r.reps[1]; !strings.HasPrefix(got, "m1 "+idS+" full|Line one line two sss") || len(got) != len("m1 "+idS+" full|")+MaxSummary {
		t.Fatalf("summary %q", got)
	}

	// A slow guest is not handed the message twice; a restart of the
	// machine (the vm manager opens its services again) is.
	pollWait = 100 * time.Millisecond
	t.Cleanup(func() { pollWait = 25 * time.Second })
	id2, _ := r.p.DeliverOwner("m1", "second", false)
	if _, body := r.do("m1", "GET", "/owner/next", ""); !strings.Contains(body, id2) {
		t.Fatalf("first delivery: %s", body)
	}
	if code, body := r.do("m1", "GET", "/owner/next", ""); code != 204 {
		t.Fatalf("handed out again to the same incarnation: %d %s", code, body)
	}
	if _, err := r.p.Open("m1"); err != nil {
		t.Fatal(err)
	}
	if _, body := r.do("m1", "GET", "/owner/next", ""); !strings.Contains(body, id2) {
		t.Fatalf("not redelivered after a restart: %s", body)
	}
	if _, err := r.p.DeliverOwner("nope", "x", false); err == nil {
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
		r.p.DeliverOwner("m1", "hi", false)
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
	r.p.DeliverOwner("m1", "a", false)
	r.p.DeliverOwner("m1", "b", false)
	wg.Wait()
}

// TestREV5PublicTaskKeepsTheLabel: a task the owner marked PUBLIC reaches
// the guest without raising its label; the agent adapter delivers to its
// one machine.
func TestREV5PublicTaskKeepsTheLabel(t *testing.T) {
	r := newRig(t, nil)
	r.client("m1")
	a := OwnerAgent{Plane: r.p, Machine: "m1"}
	if err := a.Deliver(context.Background(), "find bus times", true); err != nil {
		t.Fatal(err)
	}
	if r.ms.private["m1"] {
		t.Fatal("a PUBLIC task raised the label")
	}
	if err := a.Deliver(context.Background(), "read my mail", false); err != nil || !r.ms.private["m1"] {
		t.Fatalf("owner chat did not raise the label: %v", err)
	}
	if err := (OwnerAgent{Plane: r.p, Machine: "absent"}).Deliver(context.Background(), "x", false); err == nil {
		t.Fatal("delivered to a machine with no socket")
	}
}

// REQ: REV-5, OP-1

// TestIntentsRecordTheSubmittingMachineAndLabel: each intent records the
// machine and its data label, failing closed to private when the label is
// unknown, and a fork's repeat keeps the first submission's record.
func TestPlansCarryTheSubmittingMachinesLabel(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Label = nil })
	pub := send("r1")
	pub["steps"].([]map[string]any)[0]["labels"] = []string{"public"}
	if st, e := r.tool("m1", "plan", pub); st.State != "done" {
		t.Fatalf("%+v %s", st, e)
	}
	if l := strings.Join(r.kern.labels("m1/private/r1"), ","); l != "private,public" {
		t.Fatalf("an unlabelled machine's step carries %q", l)
	}
	pr := newRig(t, func(c *Config) {
		c.Label = func(id string) string {
			if id == "m1" {
				return "public"
			}
			return "bogus"
		}
	})
	pr.ms.lineage["f1"] = "m1"
	pr.tool("m1", "plan", send("r1"))
	pr.tool("f1", "plan", send("r2"))
	if l := strings.Join(pr.kern.labels("m1/r1"), ","); l != "public" {
		t.Fatalf("public machine's step carries %q", l)
	}
	if l := strings.Join(pr.kern.labels("m1/private/r2"), ","); l != "private" {
		t.Fatalf("unknown label's step carries %q", l)
	}
}

// REQ: REV-5, OP-1

// TestLabelsPartitionRequests: a private fork cannot pass anything to its
// public parent through request IDs, states, or reasons. Its own plans
// live apart; a repeat of a plan the lineage made while public reads it
// without driving it.
func TestLabelsPartitionRequests(t *testing.T) {
	labels := map[string]string{"m1": "public", "f1": "private"}
	r := newRig(t, func(c *Config) { c.Label = func(id string) string { return labels[id] } })
	r.ms.lineage["f1"] = "m1"

	// The private fork's own request is invisible to the public parent.
	if st, _ := r.tool("f1", "plan", send("p1")); st.State != "done" {
		t.Fatalf("fork request: %+v", st)
	}
	if _, e := r.tool("m1", "plan", map[string]any{"request_id": "p1"}); e == "" {
		t.Fatal("the public parent read the private fork's request")
	}
	if st, _ := r.tool("m1", "plan", send("p1")); st.State != "done" || r.kern.ran("m1/p1") != 1 {
		t.Fatalf("the parent's p1 is its own: %+v %v", st, r.kern.runs)
	}

	// A repeat of a public-era request reads it and runs nothing again.
	if st, e := r.tool("f1", "plan", map[string]any{"request_id": "p1"}); e != "" || st.State != "done" {
		t.Fatalf("fork status of its own p1: %+v %s", st, e)
	}
	r.tool("m1", "plan", send("q1"))
	n := r.kern.plans()
	if st, _ := r.tool("f1", "plan", send("q1")); st.State != "done" || !strings.Contains(st.Reason, reasonRepeat) ||
		r.kern.ran("m1/q1") != 1 || r.kern.ran("m1/private/q1") != 0 || r.kern.plans() != n {
		t.Fatalf("fork repeat of a public request: %+v %v", st, r.kern.runs)
	}
	// A private repeat of the machine's own private request reads that plan,
	// not a public one, and runs nothing again.
	r.tool("f1", "plan", send("p2"))
	n = r.kern.plans()
	if st, _ := r.tool("f1", "plan", send("p2")); st.State != "done" || !strings.Contains(st.Reason, reasonRepeat) ||
		r.kern.ran("m1/private/p2") != 1 || r.kern.plans() != n {
		t.Fatalf("private repeat of its own request: %+v %v", st, r.kern.runs)
	}
	if l := strings.Join(r.kern.labels("m1/q1"), ","); l != "public" {
		t.Fatalf("labels %q", l)
	}
}

// REQ: OP-8
//
// TestShutdownWaitsForCallsInFlight: a model call whose response the guest
// already has may still be settling the meter; Shutdown returns only once
// it has ended, so nothing writes the broker's files after shutdown.
func TestShutdownWaitsForCallsInFlight(t *testing.T) {
	var ended atomic.Bool
	r := newRig(t, func(c *Config) {
		c.Model = func(string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				io.WriteString(w, `{}`)
				w.(http.Flusher).Flush()
				time.Sleep(200 * time.Millisecond)
				ended.Store(true)
			})
		}
	})
	resp, err := r.client("m1").Post("http://broker/model/openai/v1/chat/completions", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(io.LimitReader(resp.Body, 2))
	resp.Body.Close()
	r.p.Shutdown()
	if !ended.Load() {
		t.Fatal("Shutdown returned with a call still in flight")
	}
}

// TestOwnerAgentReportsDeliveredTasks: W3 (potency PW3 on #90) keeps the
// owner's task text by goal ID for harvesting, so the agent adapter says
// which goal each delivered message starts; an undelivered one is not
// reported.
func TestOwnerAgentReportsDeliveredTasks(t *testing.T) {
	r := newRig(t, nil)
	r.client("m1")
	var got []string
	note := func(goal, text string, public bool) { got = append(got, fmt.Sprint(goal, "|", text, "|", public)) }
	if err := (OwnerAgent{Plane: r.p, Machine: "m1", Delivered: note}).Deliver(context.Background(), "find bus times", true); err != nil {
		t.Fatal(err)
	}
	_ = (OwnerAgent{Plane: r.p, Machine: "absent", Delivered: note}).Deliver(context.Background(), "x", false)
	if len(got) != 1 || !strings.HasPrefix(got[0], "owner:") || !strings.HasSuffix(got[0], "|find bus times|true") {
		t.Fatalf("reported %q", got)
	}
}
