package replay

// REQ: LOOP-5, CHG-1, CHG-3

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/vm"
)

var _ change.Evaluator = (*Evaluator)(nil)

var bg = context.Background()

// script is a test guest: what it does with the owner's message, returning
// its reply. "" sends no reply.
type script func(g *client, input string) string

// machines is a fake vm.Manager: CreateSeeded opens the machine's services
// the way vm does and runs the script as the guest behind the socket.
type machines struct {
	t       *testing.T
	svc     vm.Services
	guest   script
	mu      sync.Mutex
	seeds   map[string]map[string][]byte
	live    map[string]bool
	created []string
	// createErr, if set, refuses every machine; states overrides a
	// machine's state (Running otherwise).
	createErr error
	states    map[string]vm.State
}

func (m *machines) Get(id string) (vm.Machine, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.live[id] {
		return vm.Machine{}, vm.ErrUnknown
	}
	st := vm.Running
	if s, ok := m.states[id]; ok {
		st = s
	}
	return vm.Machine{ID: id, State: st}, nil
}

func (m *machines) setState(id string, st vm.State) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.states == nil {
		m.states = map[string]vm.State{}
	}
	m.states[id] = st
}

func (m *machines) CreateSeeded(_ context.Context, id string, s vm.Spec, seed map[string][]byte) (vm.Machine, error) {
	m.mu.Lock()
	cerr := m.createErr
	m.mu.Unlock()
	if cerr != nil {
		return vm.Machine{}, cerr
	}
	dir, err := m.svc.Open(id)
	if err != nil {
		return vm.Machine{}, err
	}
	m.mu.Lock()
	m.seeds[id], m.live[id] = seed, true
	m.created = append(m.created, id)
	m.mu.Unlock()
	g := &client{t: m.t, sock: filepath.Join(dir, guest.Socket)}
	go g.serve(m.guest)
	return vm.Machine{ID: id, Spec: s, Label: s.Label}, nil
}

func (m *machines) Destroy(_ context.Context, id string) error {
	m.mu.Lock()
	delete(m.live, id)
	m.mu.Unlock()
	m.svc.Close(id)
	return nil
}

func (m *machines) Machines() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for id := range m.live {
		out = append(out, id)
	}
	return out
}

func (m *machines) running() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.live)
}

type client struct {
	t    *testing.T
	sock string
	hc   *http.Client
}

func (g *client) http() *http.Client {
	if g.hc == nil {
		g.hc = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", g.sock)
		}}}
	}
	return g.hc
}

func (g *client) do(method, path string, body any) (int, []byte, error) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, "http://broker"+path, bytes.NewReader(b))
	resp, err := g.http().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out, nil
}

// serve is the guest bridge: fetch the owner's message, act, reply.
func (g *client) serve(s script) {
	for {
		code, body, err := g.do("GET", "/owner/next", nil)
		if err != nil || code == http.StatusServiceUnavailable {
			return
		}
		if code != http.StatusOK {
			continue
		}
		var msg struct{ ID, Text string }
		json.Unmarshal(body, &msg)
		if out := s(g, msg.Text); out != "" {
			g.do("POST", "/owner/reply", map[string]string{"id": msg.ID, "text": out})
		}
		return
	}
}

// effect requests an effect and returns the state the broker reports, or
// the tool's error text.
func (g *client) effect(reqID, account, action string, params map[string]any) string {
	_, body, err := g.do("POST", "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "effect_request", "arguments": map[string]any{
			"request_id": reqID, "account": account, "action": action, "params": params}}})
	if err != nil {
		return err.Error()
	}
	var out struct {
		Result struct {
			Content []struct{ Text string }
			IsError bool
		}
	}
	json.Unmarshal(body, &out)
	if len(out.Result.Content) == 0 {
		return string(body)
	}
	text := out.Result.Content[0].Text
	if out.Result.IsError {
		return "error: " + text
	}
	var st struct{ State string }
	json.Unmarshal([]byte(text), &st)
	return st.State
}

type recs []journal.Status

func (r recs) Effects(string) ([]journal.Status, error) { return r, nil }

// active is the active tree's namespaces, as the pipeline's Files gives.
func active(ns string) change.Tree { return inNamespace(tree, ns) }

func sent(state journal.State) journal.Status {
	return journal.Status{State: state, Intent: journal.Intent{ID: "g.1/r1", Origin: "guest:g.1",
		Account: "owner-mail", Action: "message.send", Params: map[string]any{"text": "hello"}}}
}

type rig struct {
	e  *Evaluator
	ms *machines
}

func newRig(t *testing.T, r Recordings, s script, mod func(*Config)) *rig {
	t.Helper()
	dir, err := os.MkdirTemp("", "rp") // short: socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ms := &machines{t: t, guest: s, seeds: map[string]map[string][]byte{}, live: map[string]bool{}}
	cfg := Config{Machines: ms, Recordings: r, Active: active, Spec: vm.Spec{Image: "openclaw", MemMB: 512}, Dir: dir, Timeout: 5 * time.Second}
	if mod != nil {
		mod(&cfg)
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Shutdown)
	ms.svc = e
	return &rig{e: e, ms: ms}
}

var tree = change.Tree{
	"procedures/send.md": []byte("send the reply"),
	"config/guest.json":  []byte(`{"tools":"default"}`),
	"grants/mail.json":   []byte(`{"allow":"all"}`),
	"routing/rule.json":  []byte(`{"order":["b"]}`),
}

func TestLOOP5ReplayAnswersEffectsFromTheRecording(t *testing.T) {
	r := newRig(t, recs{sent(journal.Succeeded)}, func(g *client, in string) string {
		return in + ": " + g.effect("x", "owner-mail", "message.send", map[string]any{"text": "hello"})
	}, nil)
	out, err := r.e.Run(bg, tree, change.Probe{ID: "p1", Input: []byte("reply to Ann")})
	if err != nil || string(out) != "reply to Ann: succeeded" {
		t.Fatalf("run = %q, %v", out, err)
	}
	if r.ms.running() != 0 {
		t.Fatal("replay machine left running")
	}
	id := r.ms.created[0]
	if !strings.HasPrefix(id, Prefix) {
		t.Fatalf("machine %q lacks the replay prefix", id)
	}
	// The guest sees the guest-facing tree only; routing stays broker-side
	// and authority never reaches a guest.
	seed := r.ms.seeds[id]
	if string(seed[TreeDir+"/procedures/send.md"]) != "send the reply" || len(seed) != 1 {
		t.Fatalf("seed = %v", seed)
	}
}

func TestLOOP5UnrecordedEffectFailsClosed(t *testing.T) {
	r := newRig(t, recs{sent(journal.Succeeded)}, func(g *client, in string) string {
		g.effect("x", "owner-mail", "message.send", map[string]any{"text": "something else"})
		return "done anyway"
	}, nil)
	_, err := r.e.Run(bg, tree, change.Probe{ID: "p1", Input: []byte("go")})
	if !errors.Is(err, ErrUnrecorded) {
		t.Fatalf("unrecorded effect: %v", err)
	}
	if r.ms.running() != 0 {
		t.Fatal("replay machine left running")
	}
}

func TestLOOP5EachRecordingAnswersOnce(t *testing.T) {
	second := make(chan string, 1)
	r := newRig(t, recs{sent(journal.Succeeded)}, func(g *client, in string) string {
		g.effect("x", "owner-mail", "message.send", map[string]any{"text": "hello"})
		// The same request again is the same intent (OP-1), not a repeat.
		if s := g.effect("x", "owner-mail", "message.send", map[string]any{"text": "hello"}); s != "succeeded" {
			return "retry: " + s
		}
		second <- g.effect("y", "owner-mail", "message.send", map[string]any{"text": "hello"})
		return "sent twice"
	}, nil)
	_, err := r.e.Run(bg, tree, change.Probe{ID: "p1", Input: []byte("go")})
	// The run ends at the miss and its machine goes with it, so the guest
	// may see the refusal or a closed socket; never a second success.
	if s := <-second; !errors.Is(err, ErrUnrecorded) || s == "succeeded" {
		t.Fatalf("second send: %q, run %v", s, err)
	}
}

func TestLOOP5RecordedDenialIsReplayed(t *testing.T) {
	r := newRig(t, recs{sent(journal.Denied)}, func(g *client, in string) string {
		return g.effect("x", "owner-mail", "message.send", map[string]any{"text": "hello"})
	}, nil)
	out, err := r.e.Run(bg, tree, change.Probe{ID: "p1", Input: []byte("go")})
	if err != nil || string(out) != "denied" {
		t.Fatalf("run = %q, %v", out, err)
	}
}

func TestLOOP5SilentGuestTimesOut(t *testing.T) {
	r := newRig(t, recs{}, func(*client, string) string { return "" }, func(c *Config) { c.Timeout = 200 * time.Millisecond })
	if _, err := r.e.Run(bg, tree, change.Probe{ID: "p1", Input: []byte("go")}); !errors.Is(err, ErrNoReply) {
		t.Fatalf("silent guest: %v", err)
	}
	if r.ms.running() != 0 {
		t.Fatal("replay machine left running")
	}
}

func modelCall(g *client) string {
	code, body, err := g.do("POST", "/model/openai/v1/chat/completions", map[string]any{"model": "m", "messages": []any{}})
	if err != nil {
		return err.Error()
	}
	if code != http.StatusOK {
		return "status " + http.StatusText(code)
	}
	return string(body)
}

func TestLOOP5ModelAccessIsTheTreesAndMetered(t *testing.T) {
	r := newRig(t, recs{}, func(g *client, _ string) string { return modelCall(g) }, nil)
	// Without a model handler replay is offline: model calls fail.
	out, err := r.e.Run(bg, tree, change.Probe{ID: "p1", Input: []byte("go")})
	if err != nil || string(out) != "status Service Unavailable" {
		t.Fatalf("offline replay model call: %q, %v", out, err)
	}
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"), MachineCap: meter.DefaultMachineCap, OverallCap: meter.DefaultOverallCap})
	if err != nil {
		t.Fatal(err)
	}
	r = newRig(t, recs{}, func(g *client, _ string) string { return modelCall(g) }, func(c *Config) {
		c.Meter = mtr
		c.Model = func(_ string, t change.Tree) http.Handler {
			rule := t["routing/rule.json"]
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(rule) })
		}
	})
	out, err = r.e.Run(bg, tree, change.Probe{ID: "p1", Input: []byte("go")})
	if err != nil || string(out) != `{"order":["b"]}` {
		t.Fatalf("model call under the candidate's routing: %q, %v", out, err)
	}
	if u := mtr.Usage(r.ms.created[0]); u.Calls != 1 {
		t.Fatalf("replay model call not metered: %+v", u)
	}
}

func TestLOOP5ModelNeedsAMeter(t *testing.T) {
	_, err := New(Config{Machines: &machines{}, Recordings: recs{}, Active: active, Spec: vm.Spec{Image: "i"}, Dir: t.TempDir(),
		Model: func(string, change.Tree) http.Handler { return http.NotFoundHandler() }})
	if err == nil {
		t.Fatal("unmetered model access accepted")
	}
}

// liveServices records which machines reached the live plane.
type liveServices struct{ opened []string }

func (l *liveServices) Open(id string) (string, error) {
	l.opened = append(l.opened, id)
	return "/live/" + id, nil
}
func (l *liveServices) Close(string) {}

func TestLOOP5ReplayMachinesNeverReachTheLivePlane(t *testing.T) {
	r := newRig(t, recs{}, func(*client, string) string { return "" }, nil)
	live := &liveServices{}
	s := Services{Live: live, Replay: r.e}
	if dir, err := s.Open("main"); err != nil || dir != "/live/main" {
		t.Fatalf("live machine: %q %v", dir, err)
	}
	dir, err := s.Open(Prefix + "abc")
	if err != nil || strings.HasPrefix(dir, "/live/") || len(live.opened) != 1 {
		t.Fatalf("replay machine went live: %q %v %v", dir, err, live.opened)
	}
	s.Close(Prefix + "abc")
}

type fakeJournal []journal.Status

func (j fakeJournal) Get(id string) (journal.Status, error) {
	for _, s := range j {
		if s.Intent.ID == id {
			return s, nil
		}
	}
	return journal.Status{}, journal.ErrNotFound
}
func (j fakeJournal) List() []journal.Status { return j }

func st(id, goal, origin, account string) journal.Status {
	return journal.Status{Intent: journal.Intent{ID: id, GoalID: goal, Origin: origin, Account: account, Action: "a"}}
}

func TestLOOP5RecordingsAreTheTasksOwnIntents(t *testing.T) {
	j := fakeJournal{
		st("g/1", "goal-1", "guest:g", "mail"),
		st("g/2", "goal-1", "guest:g", "calendar"),
		st("g/3", "goal-2", "guest:g", "mail"),
		st("b/1", "goal-1", "owner", journal.BrokerAccount),
		st("h/1", "", "guest:h", "mail"),
		st("h/2", "", "guest:h", "mail"),
		st("k/1", "", "guest:k", "mail"),
	}
	tasks := map[string]string{"p-g": "g/1", "p-h": "h/2"}
	ids := func(probe string) string {
		got, err := JournalRecordings{J: j, Task: func(p string) (string, bool) { t, ok := tasks[p]; return t, ok }}.Effects(probe)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, s := range got {
			out = append(out, s.Intent.ID)
		}
		return strings.Join(out, ",")
	}
	if got := ids("p-g"); got != "g/1,g/2" {
		t.Fatalf("by goal: %s", got)
	}
	if got := ids("p-h"); got != "h/1,h/2" {
		t.Fatalf("by origin: %s", got)
	}
	// A probe with no task (a security fixture) has nothing recorded, so
	// any effect it asks for fails closed.
	if got := ids("p-fixture"); got != "" {
		t.Fatalf("security fixture: %s", got)
	}
}

// CHG-1, CHG-3: a tree that changes what replay cannot run (the image or
// the guest configuration) is not evaluated, never passed; the active tree
// itself, and changes elsewhere, still run.
func TestCHG1UntestableChangesAreNotEvaluated(t *testing.T) {
	r := newRig(t, recs{}, func(*client, string) string { return "ran" }, nil)
	for _, p := range []string{"config/guest.json", "guest-image/ref", "host-image/ref"} {
		cand := change.Tree{}
		for k, v := range tree {
			cand[k] = v
		}
		cand[p] = []byte("changed")
		if _, err := r.e.Run(bg, cand, change.Probe{ID: "p1", Input: []byte("go")}); !errors.Is(err, change.ErrNotEvaluated) {
			t.Fatalf("%s change: %v", p, err)
		}
	}
	if len(r.ms.created) != 0 {
		t.Fatal("an unevaluable tree started a machine")
	}
	removed := change.Tree{}
	for k, v := range tree {
		if k != "config/guest.json" {
			removed[k] = v
		}
	}
	if _, err := r.e.Run(bg, removed, change.Probe{ID: "p1", Input: []byte("go")}); !errors.Is(err, ErrNotEvaluated) {
		t.Fatalf("config removed: %v", err)
	}
	cand := change.Tree{"procedures/new.md": []byte("x")}
	for k, v := range tree {
		cand[k] = v
	}
	for _, tr := range []change.Tree{tree, cand} {
		if out, err := r.e.Run(bg, tr, change.Probe{ID: "p1", Input: []byte("go")}); err != nil || string(out) != "ran" {
			t.Fatalf("evaluable tree: %q %v", out, err)
		}
	}
}

// LOOP-5: replay machines a crashed broker left behind are destroyed when
// the evaluator starts; other machines are untouched.
func TestLOOP5LeftoverReplayMachinesAreDestroyed(t *testing.T) {
	dir, err := os.MkdirTemp("", "rp")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	ms := &machines{t: t, seeds: map[string]map[string][]byte{}, live: map[string]bool{Prefix + "old": true, "main": true}}
	ms.svc = &liveServices{}
	e, err := New(Config{Machines: ms, Recordings: recs{}, Active: active, Spec: vm.Spec{Image: "i"}, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Shutdown()
	if got := ms.Machines(); len(got) != 1 || got[0] != "main" {
		t.Fatalf("after start: %v", got)
	}
}

// CHG-1, LOOP-5: routing acts only through model access. Without it, a
// routing change gives both sides the same output, so it is not evaluated;
// with it, the candidate's rule is what the model handler gets.
func TestCHG1RoutingWithoutModelAccessIsNotEvaluated(t *testing.T) {
	cand := change.Tree{}
	for k, v := range tree {
		cand[k] = v
	}
	cand["routing/rule.json"] = []byte(`{"order":["a"]}`)
	r := newRig(t, recs{}, func(*client, string) string { return "ran" }, nil)
	if _, err := r.e.Run(bg, cand, change.Probe{ID: "p1", Input: []byte("go")}); !errors.Is(err, change.ErrNotEvaluated) {
		t.Fatalf("routing change, no model: %v", err)
	}
	if len(r.ms.created) != 0 {
		t.Fatal("an unevaluable routing change started a machine")
	}
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"), MachineCap: meter.DefaultMachineCap, OverallCap: meter.DefaultOverallCap})
	if err != nil {
		t.Fatal(err)
	}
	r = newRig(t, recs{}, func(g *client, _ string) string { return modelCall(g) }, func(c *Config) {
		c.Meter = mtr
		c.Model = func(_ string, t change.Tree) http.Handler {
			rule := t["routing/rule.json"]
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(rule) })
		}
	})
	if out, err := r.e.Run(bg, cand, change.Probe{ID: "p1", Input: []byte("go")}); err != nil || string(out) != `{"order":["a"]}` {
		t.Fatalf("routing change with model access: %q %v", out, err)
	}
}

func TestLOOP5NoTaskLookupRecordsNothing(t *testing.T) {
	got, err := JournalRecordings{J: fakeJournal{st("g/1", "", "guest:g", "mail")}}.Effects("p")
	if err != nil || len(got) != 0 {
		t.Fatalf("nil Task: %v %v", got, err)
	}
}

// Arbitrator on W3a: the verdict is a deterministic function of the replay
// machines' outputs; replay itself never calls a model. Its Model handle is
// built only for the run's own replay machine and is served only when that
// machine's guest makes a call. A guest that makes none causes no model
// call at all.
func TestCHG1ReplayNeverCallsAModelItself(t *testing.T) {
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"), MachineCap: meter.DefaultMachineCap, OverallCap: meter.DefaultOverallCap})
	if err != nil {
		t.Fatal(err)
	}
	var built []string
	var served int
	r := newRig(t, recs{}, func(*client, string) string { return "no model call" }, func(c *Config) {
		c.Meter = mtr
		c.Model = func(id string, _ change.Tree) http.Handler {
			built = append(built, id)
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { served++ })
		}
	})
	out, err := r.e.Run(bg, tree, change.Probe{ID: "p1", Input: []byte("go")})
	if err != nil || string(out) != "no model call" {
		t.Fatalf("run: %q %v", out, err)
	}
	if served != 0 || len(built) != 1 || built[0] != r.ms.created[0] || !strings.HasPrefix(built[0], Prefix) {
		t.Fatalf("model handle built for %q, served %d times; machine %q", built, served, r.ms.created)
	}
}

// The same, by source: replay's own code opens no outbound connection, so
// a model can only be reached through the guest plane's model route.
func TestCHG1ReplayOpensNoClient(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"http.Client", "http.Get", "http.Post", "DefaultClient", "DefaultTransport", "RoundTrip", "net.Dial", ".ServeHTTP("} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s uses %s", f, bad)
			}
		}
	}
}

// Replay's model access forwards the routing rule of the tree under
// evaluation, and only that file; a tree with none forwards no rule.
func TestLOOP5RuleModelCarriesOnlyTheTreesRule(t *testing.T) {
	type call struct{ id, rule string }
	var got []call
	model := RuleModel(func(id string, rule []byte) http.Handler {
		got = append(got, call{id, string(rule)})
		return http.NotFoundHandler()
	})
	model("eval-1", change.Tree{change.RoutingPath: []byte(`{"chat":[]}`), "skills/a.md": []byte("skill")})
	model("eval-2", change.Tree{"skills/a.md": []byte("x")})
	if len(got) != 2 || got[0] != (call{"eval-1", `{"chat":[]}`}) || got[1] != (call{"eval-2", ""}) {
		t.Fatalf("forwarded %+v", got)
	}
}

// Security C1 on #62: when the vault process refuses a replay's model call
// because the tree routes above the active price ceiling, the broker tells
// the evaluator, and the run is not evaluated, never a pass or a fail,
// even if the guest still replies.
func TestCHG1RouteOverThePriceCeilingIsNotEvaluated(t *testing.T) {
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"), MachineCap: meter.DefaultMachineCap, OverallCap: meter.DefaultOverallCap})
	if err != nil {
		t.Fatal(err)
	}
	var ev *Evaluator
	r := newRig(t, recs{}, func(g *client, _ string) string { modelCall(g); return "replied anyway" }, func(c *Config) {
		c.Meter = mtr
		c.Model = func(id string, _ change.Tree) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				ev.OverPriceCeiling(id)
				http.Error(w, "refused", http.StatusForbidden)
			})
		}
	})
	ev = r.e
	// Run reads the reply and the refusal from two channels; repeat so a
	// Run that let the reply win would fail here, not once in a while.
	for i := 0; i < 12; i++ {
		_, err = r.e.Run(bg, tree, change.Probe{ID: "p1", Input: []byte("go")})
		if !errors.Is(err, change.ErrNotEvaluated) || !errors.Is(err, ErrOverPriceCeiling) {
			t.Fatalf("run %d over the ceiling: %v", i, err)
		}
	}
	settled(t, mtr, r.ms.created)
	r.e.OverPriceCeiling("eval-none") // no run: ignored
}

// The same when the guest never replies: the run ends at once as not
// evaluated, never as a timeout (a failure on one side).
func TestCHG1RouteOverThePriceCeilingEndsASilentRun(t *testing.T) {
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"), MachineCap: meter.DefaultMachineCap, OverallCap: meter.DefaultOverallCap})
	if err != nil {
		t.Fatal(err)
	}
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	var ev *Evaluator
	r := newRig(t, recs{}, func(g *client, _ string) string { modelCall(g); <-hold; return "" }, func(c *Config) {
		c.Meter = mtr
		c.Timeout = 20 * time.Second
		c.Model = func(id string, _ change.Tree) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				ev.OverPriceCeiling(id)
				http.Error(w, "refused", http.StatusForbidden)
			})
		}
	})
	ev = r.e
	start := time.Now()
	_, err = r.e.Run(bg, tree, change.Probe{ID: "p1", Input: []byte("go")})
	if !errors.Is(err, ErrOverPriceCeiling) || errors.Is(err, ErrNoReply) || time.Since(start) > 10*time.Second {
		t.Fatalf("silent guest over the ceiling: %v after %v", err, time.Since(start))
	}
	settled(t, mtr, r.ms.created)
}

// The link from the vault process's ceiling refusal to the evaluator is
// structural: the evaluation route calls OverCeiling for the refused
// machine, so a 403 with modelroute.ReasonEvalCeiling ends the run as
// ErrOverPriceCeiling.
func TestCHG1CeilingDenialFromTheVaultProcessEndsTheRun(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "model.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(modelroute.Denial{Adapter: "router", Method: r.Method, Status: 403, Reason: modelroute.ReasonEvalCeiling})
		w.Header().Set(modelroute.HeaderDenial, string(b))
		http.Error(w, modelroute.ReasonEvalCeiling, http.StatusForbidden)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"), MachineCap: meter.DefaultMachineCap, OverallCap: meter.DefaultOverallCap})
	if err != nil {
		t.Fatal(err)
	}
	var ev *Evaluator
	r := newRig(t, recs{}, func(g *client, _ string) string { modelCall(g); return "replied anyway" }, func(c *Config) {
		c.Meter = mtr
		c.Model = RuleModel(modelroute.Evaluation(modelroute.Config{Socket: sock, Label: func(string) string { return "private" },
			Denied: func(string, modelroute.Denial) {}, OverCeiling: func(id string) { ev.OverPriceCeiling(id) }}))
	})
	ev = r.e
	if _, err := r.e.Run(bg, tree, change.Probe{ID: "p1", Input: []byte("go")}); !errors.Is(err, ErrOverPriceCeiling) {
		t.Fatalf("ceiling denial: %v", err)
	}
	settled(t, mtr, r.ms.created)
}

// settled waits until the meter has settled each machine's model call. A
// run over the price ceiling ends as soon as the refusal is recorded,
// while the metered call is still settling and saving the meter's state
// in the test's directory. Settling refunds the call's output reservation
// (route.DefaultMaxOutputTokens), so a settled machine shows less.
func settled(t *testing.T, mtr *meter.Meter, ids []string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for _, id := range ids {
		for mtr.Usage(id).Tokens >= 32000 {
			if time.Now().After(deadline) {
				t.Fatalf("model call of %s never settled: %+v", id, mtr.Usage(id))
			}
			time.Sleep(time.Millisecond)
		}
	}
}

// REQ: RES-1, CHG-1
// PE3: admission refusing a replay machine (memory pressure, no room, or
// admission withdrawn before it started) interrupts the run rather than
// failing it: the pipeline then gives no verdict (change C15). Any other
// start error is still a failure.
func TestRES1RefusedReplayMachineInterrupts(t *testing.T) {
	for _, cause := range []error{admission.ErrPressure, admission.ErrNoRoom, fmt.Errorf("%w: eval-x", vm.ErrRevoked)} {
		r := newRig(t, recs{}, func(*client, string) string { return "ok" }, nil)
		r.ms.createErr = cause
		_, err := r.e.Run(bg, tree, change.Probe{ID: "p1", Input: []byte("go")})
		if !errors.Is(err, ErrPreempted) || !errors.Is(err, change.ErrInterrupted) {
			t.Fatalf("%v: %v", cause, err)
		}
	}
	r := newRig(t, recs{}, func(*client, string) string { return "ok" }, nil)
	r.ms.createErr = errors.New("disk on fire")
	if _, err := r.e.Run(bg, tree, change.Probe{ID: "p1", Input: []byte("go")}); err == nil || errors.Is(err, change.ErrInterrupted) {
		t.Fatalf("another start error: %v", err)
	}
}

// REQ: RES-1, CHG-1
// PE3: a replay machine admission preempts mid-run ends the run at once as
// interrupted, not at the timeout and not as a failure, and the machine is
// destroyed.
func TestRES1PreemptedReplayMachineInterrupts(t *testing.T) {
	started := make(chan string, 1)
	r := newRig(t, recs{}, func(*client, string) string { return "" }, func(c *Config) {
		c.Timeout = 10 * time.Second
		c.PreemptPoll = 10 * time.Millisecond
	})
	r.ms.guest = func(*client, string) string {
		r.ms.mu.Lock()
		id := r.ms.created[len(r.ms.created)-1]
		r.ms.mu.Unlock()
		started <- id
		return ""
	}
	go func() { r.ms.setState(<-started, vm.Preempted) }()
	begin := time.Now()
	_, err := r.e.Run(bg, tree, change.Probe{ID: "p1", Input: []byte("go")})
	if !errors.Is(err, ErrPreempted) || !errors.Is(err, change.ErrInterrupted) {
		t.Fatalf("preempted run: %v", err)
	}
	if time.Since(begin) > 5*time.Second {
		t.Fatal("a preempted run waited for the timeout")
	}
	if r.ms.running() != 0 {
		t.Fatal("preempted replay machine not destroyed")
	}
}
