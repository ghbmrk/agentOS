package skill

// REQ: HLD-4

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A step the broker refused or the kernel rejected never ran, so it stays
// in Remaining; a step that started but did not finish does not. Each stop
// state gives the model its own reason.
func TestRunStopStatesKeepRemainingAndReason(t *testing.T) {
	a := args("to", `"bo@example.test"`, "week", `7`)
	for _, c := range []struct {
		state  string
		remain int
		why    string
	}{
		{"refused", 2, "the broker refused this step"},
		{"rejected", 2, "the kernel rejected this step"},
		{"pending", 1, "this step is not finished (it may be waiting for its hold or the owner); repeat plan with its request_id before going on"},
		{"active", 1, "this step is not finished (it may be waiting for its hold or the owner); repeat plan with its request_id before going on"},
		{"unknown", 1, "this step is not finished (it may be waiting for its hold or the owner); repeat plan with its request_id before going on"},
		{"failed", 1, "this step did not succeed"},
	} {
		res := Run(context.Background(), report(), "r1", a, &fakeFX{state: map[int]string{1: c.state}})
		if res.Stopped == nil || res.Stopped.Step != 1 || res.Stopped.State != c.state ||
			res.Stopped.Why != c.why || len(res.Remaining) != c.remain {
			t.Errorf("%s: result %+v", c.state, res)
		}
	}
}

// serve runs one request through a Server directly and returns its answer.
func serve(method string, body []byte) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	(&Server{Dir: "/nonexistent"}).ServeHTTP(w, httptest.NewRequest(method, "/mcp", bytes.NewReader(body)))
	return w
}

// Each refusal answers once and stops: a non-POST, a body past maxBody, and
// an invalid request that still names a method and id get only the refusal.
func TestServerRefusalsAnswerOnce(t *testing.T) {
	if w := serve(http.MethodGet, nil); w.Code != http.StatusMethodNotAllowed || w.Body.String() != "POST only\n" {
		t.Errorf("GET: %d %q", w.Code, w.Body.String())
	}
	ping := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"`
	big := ping + strings.Repeat("a", maxBody+1-len(ping)-3) + `"}}`
	if len(big) != maxBody+1 || !json.Valid([]byte(big)) {
		t.Fatalf("fixture %d bytes", len(big))
	}
	if w := serve(http.MethodPost, []byte(big)); w.Code != http.StatusRequestEntityTooLarge || w.Body.String() != "body too large\n" {
		t.Errorf("too large: %d %.80q", w.Code, w.Body.String())
	}
	w := serve(http.MethodPost, []byte(`{"jsonrpc":"1.0","id":1,"method":"ping"}`))
	dec := json.NewDecoder(w.Body)
	var first struct {
		ID    json.RawMessage `json:"id"`
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := dec.Decode(&first); err != nil || first.Error.Code != -32600 || string(first.ID) != "null" {
		t.Fatalf("invalid request: %v %+v", err, first)
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		t.Errorf("invalid request answered more than once: %v", err)
	}
}
