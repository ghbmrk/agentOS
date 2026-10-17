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
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/e2e/boxe2e/codexstub"
	"github.com/ghbmrk/agentos/broker/egress"
)

// REQ: HW-10, CRED-5

// fakeGuest is the agent machine's guest plane as agentosd serves it on
// the machine's socket, with provider_run played by mode: "absent" offers
// no provider_run (#1721), "unqualified" refuses the route (#809), "answer"
// makes the worker's model call at the stub with the signed-in tokens and
// returns its text; the rest are the failures the driver must not pass,
// "leakOld" among them: it refreshes, then leaks the id_token it replaced.
// It admits a run after the first only once a model call's response
// carried the plan's quota headers, as provagent admits only one probe
// while the plan has no usage reading; "noQuota" never reads them.
type fakeGuest struct {
	f     *fakeBox
	mode  string
	mu    sync.Mutex
	runs  int
	quota bool // a model call's response carried the plan's quota reading
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
	g.mu.Lock()
	defer g.mu.Unlock()
	g.runs++
	if g.runs > 1 && !g.quota {
		text("provider_run: pool-at-reserve: the plan is at the owner's reserve, or its usage is unread; use another route", true)
		return
	}
	if g.runs > 1 && g.mode == "unqualified2" {
		text("provider_run: unqualified: this provider's route is not qualified yet; use another route", true)
		return
	}
	answer := func() {
		b, _ := json.Marshal(map[string]string{"result": g.modelCall()})
		text(string(b), false)
	}
	switch g.mode {
	case "unqualified":
		text("provider_run: unqualified: this provider's route is not qualified yet; use another route", true)
	case "failed":
		text("provider_run: failed: the run failed, or its brief or result was over the size cap; shorten the brief, or use another route", true)
	case "usedup":
		text("provider_run: used up: this provider's plan has no quota left until it resets; use another route", true)
	case "noCall":
		text(`{"result":"`+codexstub.Answer+`"}`, false)
	case "leak":
		text(`{"result":"`+g.f.stub.Tokens()[0]+`"}`, false)
	case "leakID":
		g.modelCall()
		text(`{"result":"`+codexstub.Answer+` `+g.f.tok["id_token"]+`"}`, false)
	case "leakSecond":
		b, _ := json.Marshal(map[string]string{"result": g.modelCall()})
		reply(map[string]any{"content": []any{map[string]string{"type": "text", "text": string(b)},
			map[string]string{"type": "text", "text": g.f.tok["refresh_token"]}}, "isError": false})
	case "leakOld":
		// The CLI refreshes on its own, then the result carries the
		// id_token from before the refresh.
		g.f.mu.Lock()
		old := g.f.tok["id_token"]
		rb, _ := json.Marshal(map[string]string{"client_id": "app_synthetic", "grant_type": "refresh_token", "refresh_token": g.f.tok["refresh_token"]})
		if st, tok := g.f.provider("POST", "/oauth/token", "application/json", string(rb)); st == 200 {
			g.f.tok = tok
		}
		g.f.mu.Unlock()
		b, _ := json.Marshal(map[string]string{"result": g.modelCall() + " " + old})
		text(string(b), false)
	case "leakField":
		b, _ := json.Marshal(map[string]string{"result": g.modelCall()})
		reply(map[string]any{"content": []any{map[string]string{"type": "text", "text": string(b)}},
			"_meta": map[string]string{"auth": g.f.tok["id_token"]}, "isError": false})
	case "noQuota", "unqualified2":
		answer()
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
// text, or "" when the provider refused. g.mu is held.
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
	if g.mode != "noQuota" && w.Header().Get("X-Codex-Primary-Used-Percent") != "" {
		g.quota = true
	}
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

// The guest task runs provider_run twice on the Codex route as the agent
// machine's guest: it passes only on the model's answer from a real call at
// the provider each time, with no token anywhere in the result and no
// refused call, and the second run admitted only because the first run's
// quota reading landed. A box that offers no provider_run (#1721) or
// refuses the first run as unqualified (#809, #1877) reads XFAIL; every
// other outcome reads FAIL.
func TestGuestTaskRunsOnTheCodexPlan(t *testing.T) {
	d, f := signedIn(t, "answer")
	if err := d.guestTask(); err != nil {
		t.Fatalf("answered: %v", err)
	}
	if f.stub.Hits()["responses"] != 2 || f.stub.Refused() != 0 {
		t.Fatalf("the task's model calls: hits %v refused %d", f.stub.Hits(), f.stub.Refused())
	}

	for mode, says := range map[string]string{"absent": "#1721", "unqualified": "#809"} {
		d, _ := signedIn(t, mode)
		err := d.guestTask()
		if err == nil || !strings.HasPrefix(err.Error(), notDriven) || !strings.Contains(err.Error(), says) {
			t.Errorf("%s: %v does not say not driven, naming %s", mode, err, says)
		}
	}

	for mode, says := range map[string]string{
		"noCall":       "without a model call",
		"leak":         "carried a provider token",
		"leakID":       "carried a provider token",
		"leakSecond":   "carried a provider token",
		"leakField":    "carried a provider token",
		"leakOld":      "carried a provider token",
		"noQuota":      "usage reading never landed",
		"unqualified2": "provider_run 2 refused: provider_run: unqualified",
		"usedup":       "provider_run 1 refused: provider_run: used up",
		"rpcError":     "tools/call: error -32603",
		"garbage":      "tools/call: unreadable answer",
		"stray":        "the provider refused 1 calls",
		"wrongText":    "not the model's",
	} {
		d, f := signedIn(t, mode)
		err := d.guestTask()
		switch {
		case err == nil:
			t.Errorf("%s: passed", mode)
		case strings.HasPrefix(err.Error(), notDriven):
			t.Errorf("%s: %v reads XFAIL", mode, err)
		case !strings.Contains(err.Error(), says):
			t.Errorf("%s: %v does not say %q", mode, err, says)
		}
		for _, tok := range f.stub.Tokens() {
			if err != nil && strings.Contains(err.Error(), tok) {
				t.Errorf("%s: the failure quotes an issued token", mode)
			}
		}
	}
}

// The whole-result check finds a token in any content item or field, the
// id_token included, and passes the model's answer alone.
func TestLeaksScansTheWholeResult(t *testing.T) {
	toks := []string{"tok-access", "hdr.payload.sig"}
	for _, c := range []struct {
		raw  string
		leak bool
	}{
		{`{"content":[{"type":"text","text":"` + codexstub.Answer + `"}]}`, false},
		{`{"content":[{"type":"text","text":"ok"},{"type":"text","text":"tok-access"}]}`, true},
		{`{"content":[{"type":"text","text":"ok"}],"_meta":{"x":"hdr.payload.sig"}}`, true},
		{`{"content":[{"type":"text","text":"ok"}],"` + codexstub.Canary + `acct":1}`, true},
		{`{"content":[{"type":"text","text":"\u0074ok-access"}]}`, true},
	} {
		if got := leaks([]byte(c.raw), toks); got != c.leak {
			t.Errorf("%s: leaks %v", c.raw, got)
		}
	}
}

// An MCP error that quotes a token or canary is cut before it is printed.
func TestMCPErrorsAreRedacted(t *testing.T) {
	c := &mcpClient{tokens: func() []string { return []string{"tok-access"} }}
	got := c.redact("bad tok-access and " + codexstub.Canary + "acct-1")
	if strings.Contains(got, "tok-access") || strings.Contains(got, codexstub.Canary) {
		t.Fatalf("redact: %q", got)
	}
}

// agentosd's command line says whether the provider's image is registered.
func TestHasImageReadsAgentosdsCommandLine(t *testing.T) {
	show := "{ path=/usr/lib/agentos/with-uids ; argv[]=/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -owner x -runsc /usr/lib/agentos/runsc -image openclaw=/usr/lib/agentos/images/openclaw ; ignore_errors=no ; start_time=[n/a] }"
	argv, err := execArgv(show)
	if err != nil || argv[len(argv)-1] != "openclaw=/usr/lib/agentos/images/openclaw" {
		t.Fatalf("execArgv: %q %v", argv, err)
	}
	for _, c := range []struct {
		argv []string
		has  bool
	}{
		{argv, false},
		{append(argv, "-image", "codex=/usr/lib/agentos/images/codex"), true},
		{append(argv, "--image=codex=/x"), true},
		{append(argv, "-image", "codexx=/x"), false},
	} {
		d := &driver{agentosdArgv: func() ([]string, error) { return c.argv, nil }}
		if has, err := d.hasImage("codex"); err != nil || has != c.has {
			t.Errorf("%q: %v %v", c.argv, has, err)
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

// A provider_run refused as failed quotes why (#1701): the stub's calls,
// agentosd's setup and provagent lines, the end of runsc's exec log, and
// the end of what the run's CLI wrote to its result file, each with every
// issued token and canary cut out (ASSUMPTIONS E14).
func TestHW10AFailedRunQuotesItsOutput(t *testing.T) {
	d, f := signedIn(t, "failed")
	d.agentosdLog = func() string {
		return "agentosd: listening\nprovagent: destroy provider worker pw-2: busy\n"
	}
	d.runscLog = func() string { return "pw-2: runsc exec failed (exit status 1)\n" }
	d.runOut = func() string {
		return `{"type":"thread.started"}` + "\n" + strings.Repeat(`{"type":"noise"}`+"\n", 10) +
			`{"type":"error","message":"unexpected status 401 Unauthorized ` + f.stub.Tokens()[0] + `"}` + "\n" +
			`{"type":"turn.failed","error":{"message":"stream disconnected ` + codexstub.Canary + `"}}` + "\n"
	}
	err := d.guestTask()
	switch {
	case err == nil:
		t.Fatal("failed run: passed")
	case strings.HasPrefix(err.Error(), notDriven):
		t.Fatalf("failed run: %v reads XFAIL", err)
	case !strings.Contains(err.Error(), "provider_run 1 refused: provider_run: failed"):
		t.Errorf("failed run: %v does not name the refusal", err)
	case !strings.Contains(err.Error(), "stub map[") || !strings.Contains(err.Error(), "provagent: destroy provider worker pw-2") ||
		!strings.Contains(err.Error(), "runsc exec failed (exit status 1)"):
		t.Errorf("failed run: %v quotes no stub, provagent or runsc line", err)
	case !strings.Contains(err.Error(), "result: ") || !strings.Contains(err.Error(), "401 Unauthorized [redacted]") ||
		!strings.Contains(err.Error(), "stream disconnected [redacted]") || strings.Contains(err.Error(), "thread.started"):
		t.Errorf("failed run: %v does not quote the end of the result file", err)
	case strings.Contains(err.Error(), codexstub.Canary) || strings.Contains(err.Error(), "listening"):
		t.Errorf("failed run: %v quotes the canary or an unrelated line", err)
	}
	for _, tok := range f.stub.Tokens() {
		if err != nil && strings.Contains(err.Error(), tok) {
			t.Error("failed run: the failure quotes an issued token")
		}
	}
}
