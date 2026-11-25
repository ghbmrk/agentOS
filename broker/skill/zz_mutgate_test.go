package skill

// REQ: HLD-4

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
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

// answerBroker answers every plan with the raw body given.
func answerBroker(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}))
}

// A step whose request fails stops the run at that step with the broker's
// message, every step from it still remaining; a run that goes on records
// each step's number.
func TestRunRecordsDoneAndStopsOnRequestError(t *testing.T) {
	sk := report()
	a := args("to", `"bo@example.test"`, "week", `7`)
	res := Run(context.Background(), sk, "r1", a, &fakeFX{})
	if len(res.Done) != 2 || res.Done[0].Step != 1 || res.Done[1].Step != 2 {
		t.Fatalf("done %+v", res.Done)
	}
	res = Run(context.Background(), sk, "r2", a, &fakeFX{err: errors.New("boom")})
	if res.Stopped == nil || res.Stopped.Step != 1 || res.Stopped.State != "" ||
		res.Stopped.Why != "the broker did not take the request: boom" || len(res.Remaining) != 2 || res.Status != "stopped" {
		t.Fatalf("result %+v", res)
	}
}

// A skill file of exactly MaxFile bytes is offered; the read limit is one
// byte past it.
func TestLoadReadsAFileOfMaxFileBytes(t *testing.T) {
	mk := func(n int) *Skill {
		sk := report()
		sk.Steps[0].Params["pad"] = lit(`"` + strings.Repeat("a", n) + `"`)
		sk.ID = "k" + sk.Shape()
		return sk
	}
	n := MaxFile - len(mk(0).Encode())
	sk := mk(n)
	if got := len(sk.Encode()); got != MaxFile {
		t.Fatalf("size %d", got)
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, SkillsNS), 0o755)
	os.WriteFile(filepath.Join(dir, sk.Path()), sk.Encode(), 0o644)
	s := &Server{Dir: dir}
	if s.load(SkillsNS, sk.ID) == nil {
		t.Fatal("a file of MaxFile bytes was not read whole")
	}
	big := mk(n + 1)
	os.WriteFile(filepath.Join(dir, big.Path()), big.Encode(), 0o644)
	if s.load(SkillsNS, big.ID) != nil {
		t.Fatal("a file past MaxFile was offered")
	}
}

func post(t *testing.T, url string, body []byte) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

// The skill server takes POST only, answers JSON, echoes the request id,
// takes a body up to maxBody and refuses one past it, and answers a
// notification (no id) with 202 and nothing.
func TestServerProtocol(t *testing.T) {
	srv := httptest.NewServer(&Server{Dir: t.TempDir()})
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "POST" {
		t.Fatalf("GET: %d %q", resp.StatusCode, resp.Header.Get("Allow"))
	}

	ping := `{"jsonrpc":"2.0","id":41,"method":"ping"}`
	resp, raw := post(t, srv.URL, []byte(ping))
	var out struct {
		ID     int            `json:"id"`
		Result map[string]any `json:"result"`
		Error  any            `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.ID != 41 || out.Result == nil || out.Error != nil {
		t.Fatalf("ping: %s", raw)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q", ct)
	}

	resp, raw = post(t, srv.URL, []byte(`{"jsonrpc":"2.0","method":"ping"}`))
	if resp.StatusCode != http.StatusAccepted || len(raw) != 0 {
		t.Fatalf("notification: %d %q", resp.StatusCode, raw)
	}

	pad := func(n int) []byte { return append([]byte(ping), bytes.Repeat([]byte(" "), n-len(ping))...) }
	resp, raw = post(t, srv.URL, pad(maxBody))
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"result"`) {
		t.Fatalf("body of maxBody bytes: %d %s", resp.StatusCode, raw)
	}
	resp, _ = post(t, srv.URL, pad(maxBody+1))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("body past maxBody: %d", resp.StatusCode)
	}

	_, raw = post(t, srv.URL, []byte(`{`))
	if !strings.Contains(string(raw), `"id":null`) || !strings.Contains(string(raw), "-32600") {
		t.Fatalf("invalid request: %s", raw)
	}
}

// initialize echoes a protocol version the server speaks and offers its
// newest otherwise.
func TestServerInitialize(t *testing.T) {
	srv := httptest.NewServer(&Server{Dir: t.TempDir()})
	defer srv.Close()
	for in, want := range map[string]string{"2025-03-26": "2025-03-26", "2024-11-05": "2024-11-05", "1999-01-01": "2025-06-18"} {
		r := rpc(t, srv.URL, "initialize", map[string]any{"protocolVersion": in})["result"].(map[string]any)
		if r["protocolVersion"] != want || r["serverInfo"].(map[string]any)["name"] != "agentos-skills" {
			t.Fatalf("%s: %v", in, r)
		}
	}
}

// What the broker answers, MCPEffects returns: a JSON-RPC error as its
// message, an empty answer as one, a refusal as its text with the notes
// kept, and a state that does not parse as an error with the notes kept.
func TestMCPEffectsAnswers(t *testing.T) {
	for _, tc := range []struct {
		name, body, err string
		notes           []string
	}{
		{"rpc error", `{"error":{"message":"rpc says no"},"result":{"content":[{"text":"x"}]}}`, "rpc says no", nil},
		{"no result", `{}`, "empty broker answer", nil},
		{"no content", `{"result":{"content":[]}}`, "empty broker answer", nil},
		{"refused", `{"result":{"content":[{"text":"plan refused"},{"text":"n1"},{"text":""},{"text":"n2"}],"isError":true}}`, "plan refused", []string{"n1", "n2"}},
		{"unparsable", `{"result":{"content":[{"text":"not json"},{"text":"n1"}]}}`, "broker answer: invalid character 'o' in literal null (expecting 'u')", []string{"n1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bs := answerBroker(tc.body)
			defer bs.Close()
			m := &MCPEffects{Client: bs.Client(), URL: bs.URL}
			st, err := m.Request(context.Background(), Effect{RequestID: "x"})
			if err == nil || err.Error() != tc.err {
				t.Fatalf("err %v", err)
			}
			if !reflect.DeepEqual(st.Notes, tc.notes) {
				t.Fatalf("notes %q", st.Notes)
			}
		})
	}
}

// The request is JSON, and goes only to a URL that parses and a broker that
// answers.
func TestMCPEffectsRequestShape(t *testing.T) {
	var ct atomic.Value
	bs := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct.Store(r.Header.Get("Content-Type"))
		io.WriteString(w, `{"result":{"content":[{"text":"{\"state\":\"succeeded\"}"}]}}`)
	}))
	bs.Start()
	defer bs.Close()
	m := &MCPEffects{Client: bs.Client(), URL: bs.URL}
	for i := 0; i < 3; i++ {
		if _, err := m.Request(context.Background(), Effect{RequestID: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	if ct.Load() != "application/json" {
		t.Fatalf("content type %v", ct.Load())
	}

	if _, err := (&MCPEffects{Client: bs.Client(), URL: "http://bad host/\x7f"}).Request(context.Background(), Effect{}); err == nil {
		t.Fatal("a URL that does not parse must refuse")
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	url, c := dead.URL, dead.Client()
	dead.Close()
	if _, err := (&MCPEffects{Client: c, URL: url}).Request(context.Background(), Effect{}); err == nil {
		t.Fatal("an unreachable broker must refuse")
	}
}

// A step whose values do not fill (a recipient that is not a string) stops
// the run at that step before any request is made.
func TestRunStopsWhenAStepDoesNotFill(t *testing.T) {
	sk := report()
	sk.Steps[1].Recipients = []Node{lit(`7`)}
	sk.ID = "k" + sk.Shape()
	fx := &fakeFX{}
	res := Run(context.Background(), sk, "r1", args("to", `"bo@example.test"`, "week", `7`), fx)
	if res.Stopped == nil || res.Stopped.Step != 2 || res.Stopped.Why != "a recipient must be a string" || len(fx.got) != 0 {
		t.Fatalf("result %+v, %d requests", res, len(fx.got))
	}
}

// planOf carries a string param as it is, any other param as its JSON
// text, and "to" only when there are recipients.
func TestPlanOfArguments(t *testing.T) {
	p := planOf(Effect{RequestID: "r", Account: "mail", Action: "draft.create",
		Params: map[string]any{"s": "x", "n": 7, "o": map[string]any{"a": 1}}})
	a := p["steps"].([]map[string]any)[0]["args"].(map[string]string)
	want := map[string]string{"s": "x", "n": "7", "o": `{"a":1}`}
	if !reflect.DeepEqual(a, want) {
		t.Fatalf("args %v", a)
	}
	p = planOf(Effect{Action: "message.send", Recipients: []string{"a@example.test", "b@example.test"}})
	if a = p["steps"].([]map[string]any)[0]["args"].(map[string]string); a["to"] != "a@example.test,b@example.test" {
		t.Fatalf("args %v", a)
	}
}
