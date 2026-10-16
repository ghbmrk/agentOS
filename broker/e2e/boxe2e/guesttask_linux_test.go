package main

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/e2e/boxe2e/codexstub"
	"github.com/ghbmrk/agentos/broker/egress"
)

// REQ: HW-10, CRED-5, RES-5

// fakeGuest is the agent machine's guest plane as agentosd serves it on
// the machine's socket, with provider_run played by mode: "absent" offers
// no provider_run (#1721), "unqualified" refuses the route (#809), "answer"
// makes the worker's model call at the stub with the signed-in tokens and
// returns its text; the rest are the failures the driver must not pass.
type fakeGuest struct {
	f    *fakeBox
	mode string
}

func (g *fakeGuest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID     int    `json:"id"`
		Method string `json:"method"`
		Params struct {
			Name      string            `json:"name"`
			Arguments map[string]string `json:"arguments"`
		} `json:"params"`
	}
	if r.Method != "POST" || r.URL.Path != "/mcp" || json.NewDecoder(r.Body).Decode(&in) != nil {
		http.Error(w, "bad request", 400)
		return
	}
	reply := func(result any) {
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": in.ID, "result": result})
	}
	text := func(s string, isErr bool) {
		reply(map[string]any{"content": []any{map[string]string{"type": "text", "text": s}}, "isError": isErr})
	}
	switch in.Method {
	case "initialize":
		reply(map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}})
		return
	case "tools/list":
		tools := []any{map[string]string{"name": "provider_list"}}
		if g.mode != "absent" {
			tools = append(tools, map[string]string{"name": "provider_run"})
		}
		reply(map[string]any{"tools": tools})
		return
	case "tools/call":
	default:
		http.Error(w, "unknown method", 400)
		return
	}
	a := in.Params.Arguments
	if in.Params.Name != "provider_run" || a["provider"] != egress.Codex().Provider || a["brief"] != taskBrief || a["task_class"] != "code" {
		text("provider_run: bad arguments", true)
		return
	}
	switch g.mode {
	case "unqualified":
		text("provider_run: unqualified: this provider's route is not qualified yet; use another route", true)
	case "usedup":
		text("provider_run: used up: this provider's plan has no quota left until it resets; use another route", true)
	case "noCall":
		text(`{"result":"`+codexstub.Answer+`"}`, false)
	case "leak":
		text(`{"result":"`+g.f.stub.Tokens()[0]+`"}`, false)
	case "rpcError":
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": in.ID, "error": map[string]any{"code": -32603, "message": "internal error"}})
	case "garbage":
		w.Write([]byte("not json"))
	case "answer", "stray", "wrongText":
		if g.mode == "stray" {
			g.f.provider("GET", "/backend-api/undeclared", "application/json", "")
		}
		got := g.modelCall()
		if g.mode == "wrongText" {
			got = "something else"
		}
		b, _ := json.Marshal(map[string]string{"result": got})
		text(string(b), false)
	}
}

// modelCall is the worker's one call at the plan's responses endpoint, as
// the CLI makes it from the signed-in auth file; it returns the answer's
// text, or "" when the provider refused.
func (g *fakeGuest) modelCall() string {
	var ep egress.PlanEndpoint
	for _, e := range egress.Codex().Endpoints {
		if e.Name == "responses" {
			ep = e
		}
	}
	parts := strings.Split(g.f.tok["id_token"], ".")
	var claims map[string]map[string]string
	if len(parts) == 3 {
		b, _ := base64.RawURLEncoding.DecodeString(parts[1])
		json.Unmarshal(b, &claims)
	}
	r := httptest.NewRequest(ep.Method, "https://"+ep.Host+ep.Path, strings.NewReader(`{"stream":true}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+g.f.tok["access_token"])
	r.Header.Set("Chatgpt-Account-Id", claims["https://api.openai.com/auth"]["chatgpt_account_id"])
	w := httptest.NewRecorder()
	g.f.stub.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), codexstub.Answer) {
		return ""
	}
	return codexstub.Answer
}

// guestSock serves g on a fresh unix socket and returns its path.
func guestSock(t *testing.T, g *fakeGuest) string {
	dir, err := os.MkdirTemp("", "ge")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: g}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

// signedIn is a driver past step 7's sign-in, with the agent machine's
// guest plane played by a fakeGuest in mode.
func signedIn(t *testing.T, mode string) (*driver, *fakeBox) {
	f := &fakeBox{stub: codexstub.New(), offer: true, host: "auth.openai.com"}
	d := fakeDriver(f)
	d.guestSock = guestSock(t, &fakeGuest{f: f, mode: mode})
	return d, f
}

// The guest task runs one provider_run on the Codex route as the agent
// machine's guest: it passes only on the model's answer from a real call at
// the provider, with no token in the reply and no refused call. A box that
// offers no provider_run (#1721) or refuses the route as unqualified (#809,
// #1877) reads XFAIL; every other outcome reads FAIL.
func TestGuestTaskRunsOnTheCodexPlan(t *testing.T) {
	d, f := signedIn(t, "answer")
	if err := d.guestTask(); err != nil {
		t.Fatalf("answered: %v", err)
	}
	if f.stub.Hits()["responses"] != 1 || f.stub.Refused() != 0 {
		t.Fatalf("the task's model call: hits %v refused %d", f.stub.Hits(), f.stub.Refused())
	}

	for mode, says := range map[string]string{"absent": "#1721", "unqualified": "#809"} {
		d, _ := signedIn(t, mode)
		err := d.guestTask()
		if err == nil || !strings.HasPrefix(err.Error(), xfail["guest-task"].want) || !strings.Contains(err.Error(), says) {
			t.Errorf("%s: %v does not read XFAIL naming %s", mode, err, says)
		}
	}

	for mode, says := range map[string]string{
		"noCall":    "without a model call",
		"leak":      "carried a provider token",
		"usedup":    "provider_run refused: provider_run: used up",
		"rpcError":  "tools/call: error -32603",
		"garbage":   "tools/call: unreadable answer",
		"stray":     "the provider refused 1 calls",
		"wrongText": "not the model's",
	} {
		d, f := signedIn(t, mode)
		err := d.guestTask()
		if err == nil || strings.HasPrefix(err.Error(), notDriven) {
			t.Errorf("%s: %v reads XFAIL", mode, err)
		} else if !strings.Contains(err.Error(), says) {
			t.Errorf("%s: %v does not say %q", mode, err, says)
		}
		for _, tok := range f.stub.Tokens() {
			if err != nil && strings.Contains(err.Error(), tok) {
				t.Errorf("%s: the failure quotes an issued token", mode)
			}
		}
	}
}

// An agent machine that never gets its socket after setup reads FAIL.
func TestGuestTaskFailsWithoutTheAgentSocket(t *testing.T) {
	old := sockWait
	sockWait = 50 * time.Millisecond
	defer func() { sockWait = old }()
	f := &fakeBox{stub: codexstub.New(), offer: true, host: "auth.openai.com"}
	d := fakeDriver(f)
	d.guestSock = filepath.Join(t.TempDir(), "none")
	err := d.guestTask()
	if err == nil || strings.HasPrefix(err.Error(), notDriven) || !strings.Contains(err.Error(), "guest socket never appeared") {
		t.Fatalf("no socket: %v", err)
	}
}
