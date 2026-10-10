package guest

import (
	"context"
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

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
)

// REQ: REV-1, REV-5, OP-1, ADP-10, CRED-1, ARC-3, ARC-6, ARC-7, OP-8

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
	stepErr error // what Step answers; nil succeeds
}

func newMachines() *fakeMachines {
	return &fakeMachines{steps: map[string]int{}, private: map[string]bool{}, lineage: map[string]string{}}
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
	t     testing.TB
	p     *Plane
	ms    *fakeMachines
	eng   *journal.Engine
	ex    *exec
	meter *meter.Meter
	model int
	mu    sync.Mutex
	reps  []string
}

func newRig(t testing.TB, mod func(*Config)) *rig {
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
		Label: func(string) string { return "public" },
		Model: func(machine string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				r.mu.Lock()
				r.model++
				r.mu.Unlock()
				fmt.Fprintf(w, `{"machine":%q,"path":%q,"raw":%q}`, machine, req.URL.Path, req.URL.EscapedPath())
			})
		},
		Meter: m,
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
		if code, _ := r.do("m1", c.method, c.path, ""); code != 404 && code != 405 {
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
	if strings.Join(names, ",") != "effect_request,effect_status,result_read" {
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

// TestREV1StepAfterEveryEffectRequest: an effect request the journal took
// is a step, so the machine's files are snapshotted after it (vm V3).
// Status reads, refusals, and malformed calls are not steps, and a burst
// of requests shares one trailing snapshot, so a looping guest cannot
// flood the snapshot store (RES-4).
func TestREV1StepAfterEveryEffectRequest(t *testing.T) {
	// The burst below must finish inside one interval; 1 s leaves room
	// for a loaded -race run.
	r := newRig(t, func(c *Config) { c.StepInterval = time.Second })
	r.tool("m1", "effect_request", send("r1"))
	if n := r.ms.stepsOf("m1"); n != 1 {
		t.Fatalf("%d steps after one effect request", n)
	}
	r.tool("m1", "effect_status", map[string]any{"request_id": "r1"})
	r.tool("m1", "effect_request", map[string]any{})
	bank := send("r9")
	bank["account"] = "bank"
	r.tool("m1", "effect_request", bank)
	for i := 2; i < 12; i++ {
		r.tool("m1", "effect_request", send(fmt.Sprintf("r%d", i)))
	}
	if n := r.ms.stepsOf("m1"); n != 1 {
		t.Fatalf("%d steps inside the interval, want the first only", n)
	}
	r.stepsSettle("m1")
	if n := r.ms.stepsOf("m1"); n != 2 {
		t.Fatalf("%d steps after the burst, want one trailing snapshot", n)
	}
	r.tool("m1", "effect_request", send("r20"))
	if n := r.ms.stepsOf("m1"); n != 3 {
		t.Fatalf("%d steps: a request after the interval snapshots at once", n)
	}
}

// stepsSettle waits until machine id's stepper owes nothing and a full
// StepInterval has passed since its last snapshot, so the next effect
// request snapshots at once. It reads the stepper's state rather than
// sleeping a fixed time, which a late timer under load can outlast. A
// trailing snapshot is due within one interval; one not taken within
// three fails the test.
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

// TestOP5GuestCannotRequestBrokerState: broker-state intents (account
// "broker", meta.* actions) are the owner's and the broker's. Some narrow
// and so pass STOP; a guest's request for one is refused before routing
// and nothing is journaled.
func TestOP5GuestCannotRequestBrokerState(t *testing.T) {
	r := newRig(t, func(c *Config) {
		c.Route = func(string) (string, bool) { return "mail", true } // every account routes
	})
	for i, a := range []map[string]string{
		{"account": "broker", "action": "meta.budget.lower"},
		{"account": "Broker", "action": "anything"},
		{"account": "owner-mail", "action": "META.grant.add"},
		// Look-alikes: names are strict lowercase ASCII, so none of these
		// reaches routing or the journal as a different name.
		{"account": " broker", "action": "send"},
		{"account": "broker ", "action": "send"},
		{"account": "bro\u200bker", "action": "send"},
		{"account": "br\u043e\u043aer", "action": "send"},          // Cyrillic o, k
		{"account": "owner-mail", "action": "meta\u2024grant.add"}, // one dot leader
		{"account": "owner-mail", "action": "\u200bmeta.grant.add"},
		{"account": "owner-mail", "action": "m\u0435ta.grant.add"}, // Cyrillic e
		{"account": "owner-mail", "action": "meta.grant.add\n"},
		{"account": "owner\uff0dmail", "action": "send"}, // fullwidth hyphen
	} {
		args := map[string]any{"request_id": fmt.Sprint("b", i), "account": a["account"], "action": a["action"]}
		st, e := r.tool("m1", "effect_request", args)
		if st.State != "refused" && e == "" {
			t.Fatalf("%q: %+v %s", args, st, e)
		}
	}
	if n := len(r.eng.List()); n != 0 || r.ms.stepsOf("m1") != 0 {
		t.Fatalf("%d intents journaled, %d steps", n, r.ms.stepsOf("m1"))
	}
}

// TestCH2EffectRequestsAreBoundedAndRateLimited: one request's params and
// recipients are bounded, and one machine's requests are rate-limited;
// excess is refused and not journaled.
func TestCH2EffectRequestsAreBoundedAndRateLimited(t *testing.T) {
	r := newRig(t, func(c *Config) { c.SubmitBurst, c.SubmitEvery = 3, time.Hour })
	huge := send("h1")
	huge["params"] = map[string]any{"text": strings.Repeat("x", 17<<10)}
	many := send("h2")
	rs := make([]string, 51)
	for i := range rs {
		rs[i] = fmt.Sprintf("r%d@example.test", i)
	}
	many["recipients"] = rs
	long := send("h3")
	long["recipients"] = []string{strings.Repeat("a", 400)}
	for _, a := range []map[string]any{huge, many, long} {
		if _, e := r.tool("m1", "effect_request", a); e == "" {
			t.Fatalf("accepted %s", a["request_id"])
		}
	}
	for i := 0; i < 3; i++ {
		if st, e := r.tool("m1", "effect_request", send(fmt.Sprintf("ok%d", i))); st.State != "succeeded" {
			t.Fatalf("request %d: %+v %s", i, st, e)
		}
	}
	if _, e := r.tool("m1", "effect_request", send("ok3")); !strings.Contains(e, "too many") {
		t.Fatalf("burst not limited: %q", e)
	}
	if st, _ := r.tool("m2", "effect_request", send("ok0")); st.State != "succeeded" {
		t.Fatal("another machine was limited")
	}
	if n := len(r.eng.List()); n != 4 {
		t.Fatalf("%d intents journaled, want 4", n)
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
	if code, _ := r.do("m1", "POST", "/owner/reply", fmt.Sprintf(`{"id":%q,"text":"again"}`, id)); code != 404 {
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

// TestOP8SpendNoteNamesTheTask: the journal note for an exhaustion says
// which limit and task stopped the machine.
func TestOP8SpendNoteNamesTheTask(t *testing.T) {
	if n := SpendNote(meter.Exhausted{Scope: meter.ScopeTask, Machine: "m1", Task: "t1"}); n.Machine != "m1" || !strings.Contains(n.Reason, "t1") {
		t.Fatalf("%+v", n)
	}
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
func TestIntentsRecordTheSubmittingMachineAndLabel(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Label = nil })
	if st, e := r.tool("m1", "effect_request", send("r1")); st.State != "succeeded" {
		t.Fatalf("%+v %s", st, e)
	}
	if s, _ := r.eng.Get("m1/private/r1"); s.Intent.Machine != "m1" || s.Intent.Label != "private" {
		t.Fatalf("no label source: %q %q", s.Intent.Machine, s.Intent.Label)
	}
	pub := newRig(t, func(c *Config) {
		c.Label = func(id string) string {
			if id == "m1" {
				return "public"
			}
			return "bogus"
		}
	})
	pub.ms.lineage["f1"] = "m1"
	pub.tool("m1", "effect_request", send("r1"))
	pub.tool("f1", "effect_request", send("r2"))
	if s, _ := pub.eng.Get("m1/r1"); s.Intent.Label != "public" {
		t.Fatalf("public machine recorded %q", s.Intent.Label)
	}
	if s, _ := pub.eng.Get("m1/private/r2"); s.Intent.Machine != "f1" || s.Intent.Label != "private" {
		t.Fatalf("unknown label recorded %q %q", s.Intent.Machine, s.Intent.Label)
	}
}

// REQ: REV-5, OP-1, OP-5

// TestLabelsPartitionRequests: a private fork cannot pass anything to its
// public parent through request IDs, states, or reasons. Its own requests
// live apart; a repeat of a request the lineage made while public reads
// that intent without driving it; broker actions are refused unjournaled.
func TestLabelsPartitionRequests(t *testing.T) {
	labels := map[string]string{"m1": "public", "f1": "private"}
	r := newRig(t, func(c *Config) { c.Label = func(id string) string { return labels[id] } })
	r.ms.lineage["f1"] = "m1"

	st, _ := r.tool("f1", "effect_request", map[string]any{"request_id": "x1", "account": "broker", "action": "meta.canary-7f3a"})
	if st.State != "refused" || strings.Contains(st.Reason, "canary") {
		t.Fatalf("broker action: %+v", st)
	}
	if len(r.eng.List()) != 0 {
		t.Fatal("a refused broker action was journaled")
	}

	// The private fork's own request is invisible to the public parent.
	if st, _ := r.tool("f1", "effect_request", send("p1")); st.State != "succeeded" {
		t.Fatalf("fork request: %+v", st)
	}
	if _, e := r.tool("m1", "effect_status", map[string]any{"request_id": "p1"}); e == "" {
		t.Fatal("the public parent read the private fork's request")
	}
	if st, _ := r.tool("m1", "effect_request", send("p1")); st.State != "succeeded" || r.ex.runs["m1/p1"] != 1 {
		t.Fatalf("the parent's p1 is its own: %+v %v", st, r.ex.runs)
	}

	// A repeat of a public-era request reads it and runs nothing again.
	if st, e := r.tool("f1", "effect_status", map[string]any{"request_id": "p1"}); e != "" || st.State != "succeeded" {
		t.Fatalf("fork status of its own p1: %+v %s", st, e)
	}
	r.tool("m1", "effect_request", send("q1"))
	if st, _ := r.tool("f1", "effect_request", send("q1")); st.State != "succeeded" || r.ex.runs["m1/q1"] != 1 {
		t.Fatalf("fork repeat of a public request: %+v %v", st, r.ex.runs)
	}
	if s, _ := r.eng.Get("m1/q1"); s.Intent.Label != "public" {
		t.Fatalf("label %q", s.Intent.Label)
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

// Security L1 on W5a: a guest cannot claim the broker's Loop 2 origin. An
// "origin" in its request, at the top or in params, is not the intent's
// origin, and a pause it asks for is refused before the journal.
func TestAGuestCannotClaimTheLoop2Origin(t *testing.T) {
	r := newRig(t, nil)
	a := send("o1")
	a["origin"] = "broker:loop2"
	a["params"] = map[string]any{"text": "hello", "origin": "broker:loop2"}
	if st, e := r.tool("m1", "effect_request", a); e != "" {
		t.Fatalf("%+v %s", st, e)
	}
	// The effect is journaled, and under the guest's own origin.
	if s, err := r.eng.Get("m1/o1"); err != nil || s.Intent.Origin != "guest:m1" {
		t.Fatalf("intent origin %q: %v", s.Intent.Origin, err)
	}
	p := map[string]any{"request_id": "o2", "account": "owner-mail", "action": "meta.grant.pause", "origin": "broker:loop2"}
	if st, e := r.tool("m1", "effect_request", p); st.State != "refused" || e != "" || !strings.Contains(st.Reason, "a guest cannot request them") {
		t.Fatalf("pause: %+v %s", st, e)
	}
	if _, err := r.eng.Get("m1/o2"); err == nil {
		t.Fatal("a guest's pause was journaled")
	}
}
