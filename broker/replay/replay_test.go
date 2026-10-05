package replay

// REQ: LOOP-5, CHG-1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
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
}

func (m *machines) CreateSeeded(_ context.Context, id string, s vm.Spec, seed map[string][]byte) (vm.Machine, error) {
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

func (r recs) Effects(change.Case) ([]journal.Status, error) { return r, nil }

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
	cfg := Config{Machines: ms, Recordings: r, Spec: vm.Spec{Image: "openclaw", MemMB: 512}, Dir: dir, Timeout: 5 * time.Second}
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
	"grants/mail.json":   []byte(`{"allow":"all"}`),
	"routing/rule.json":  []byte(`{"order":["b"]}`),
}

func TestLOOP5ReplayAnswersEffectsFromTheRecording(t *testing.T) {
	r := newRig(t, recs{sent(journal.Succeeded)}, func(g *client, in string) string {
		return in + ": " + g.effect("x", "owner-mail", "message.send", map[string]any{"text": "hello"})
	}, nil)
	out, err := r.e.Run(bg, tree, change.Case{ID: "c1", Input: []byte("reply to Ann")})
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
	_, err := r.e.Run(bg, tree, change.Case{ID: "c1", Input: []byte("go")})
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
	_, err := r.e.Run(bg, tree, change.Case{ID: "c1", Input: []byte("go")})
	if s := <-second; !errors.Is(err, ErrUnrecorded) || !strings.HasPrefix(s, "error:") {
		t.Fatalf("second send: %q, run %v", s, err)
	}
}

func TestLOOP5RecordedDenialIsReplayed(t *testing.T) {
	r := newRig(t, recs{sent(journal.Denied)}, func(g *client, in string) string {
		return g.effect("x", "owner-mail", "message.send", map[string]any{"text": "hello"})
	}, nil)
	out, err := r.e.Run(bg, tree, change.Case{ID: "c1", Input: []byte("go")})
	if err != nil || string(out) != "denied" {
		t.Fatalf("run = %q, %v", out, err)
	}
}

func TestLOOP5SilentGuestTimesOut(t *testing.T) {
	r := newRig(t, recs{}, func(*client, string) string { return "" }, func(c *Config) { c.Timeout = 200 * time.Millisecond })
	if _, err := r.e.Run(bg, tree, change.Case{ID: "c1", Input: []byte("go")}); !errors.Is(err, ErrNoReply) {
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
	out, err := r.e.Run(bg, tree, change.Case{ID: "c1", Input: []byte("go")})
	if err != nil || string(out) != "status Service Unavailable" {
		t.Fatalf("offline replay model call: %q, %v", out, err)
	}
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"), MachineCap: meter.DefaultMachineCap, OverallCap: meter.DefaultOverallCap})
	if err != nil {
		t.Fatal(err)
	}
	r = newRig(t, recs{}, func(g *client, _ string) string { return modelCall(g) }, func(c *Config) {
		c.Meter = mtr
		c.Model = func(t change.Tree) http.Handler {
			rule := t["routing/rule.json"]
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(rule) })
		}
	})
	out, err = r.e.Run(bg, tree, change.Case{ID: "c1", Input: []byte("go")})
	if err != nil || string(out) != `{"order":["b"]}` {
		t.Fatalf("model call under the candidate's routing: %q, %v", out, err)
	}
	if u := mtr.Usage(r.ms.created[0]); u.Calls != 1 {
		t.Fatalf("replay model call not metered: %+v", u)
	}
}

func TestLOOP5ModelNeedsAMeter(t *testing.T) {
	_, err := New(Config{Machines: &machines{}, Recordings: recs{}, Spec: vm.Spec{Image: "i"}, Dir: t.TempDir(),
		Model: func(change.Tree) http.Handler { return http.NotFoundHandler() }})
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
	ids := func(c change.Case) string {
		got, err := JournalRecordings{J: j}.Effects(c)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, s := range got {
			out = append(out, s.Intent.ID)
		}
		return strings.Join(out, ",")
	}
	if got := ids(change.Case{Task: "g/1"}); got != "g/1,g/2" {
		t.Fatalf("by goal: %s", got)
	}
	if got := ids(change.Case{Task: "h/2"}); got != "h/1,h/2" {
		t.Fatalf("by origin: %s", got)
	}
	if got := ids(change.Case{Security: true}); got != "" {
		t.Fatalf("security fixture: %s", got)
	}
}
