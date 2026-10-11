package guest

// LOOP-7 bullet 2 (P3-4b-3): fuzz target for the guest socket's MCP
// decoder, the frames an agent machine sends the broker, with a
// planted-decoder control.
// REQ: LOOP-7

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type reporter interface {
	Errorf(format string, args ...any)
}

type recorder struct{ msgs []string }

func (r *recorder) Errorf(format string, args ...any) {
	r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
}

// rpcRefusals are the only errors the decoder answers with.
var rpcRefusals = map[int]string{
	-32600: "invalid request (batches are not supported)",
	-32601: "method not found",
	-32602: "bad params",
}

// checkMCP posts body to serve and checks: no panic; the answer is 202
// with no body for a notification, else 200 with exactly one JSON-RPC 2.0
// object holding a result or one of the fixed refusals, never both, and
// echoing the request's id.
func checkMCP(r reporter, serve http.HandlerFunc, body []byte) {
	w := httptest.NewRecorder()
	panicked := false
	func() {
		defer func() {
			if p := recover(); p != nil {
				r.Errorf("decoder panicked on %q: %v", body, p)
				panicked = true
			}
		}()
		serve(w, httptest.NewRequest(http.MethodPost, "http://broker/mcp", bytes.NewReader(body)))
	}()
	if panicked {
		return
	}
	var req rpcRequest
	decoded := json.NewDecoder(bytes.NewReader(body)).Decode(&req) == nil && req.JSONRPC == "2.0" && req.Method != ""
	notification := decoded && (len(req.ID) == 0 || string(req.ID) == "null")
	if notification {
		if w.Code != http.StatusAccepted || w.Body.Len() != 0 {
			r.Errorf("notification %q answered %d %q", body, w.Code, w.Body)
		}
		return
	}
	if w.Code != http.StatusOK {
		r.Errorf("%q answered %d", body, w.Code)
		return
	}
	dec := json.NewDecoder(w.Body)
	var out struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Result  *json.RawMessage `json:"result"`
		Error   *rpcError        `json:"error"`
	}
	if err := dec.Decode(&out); err != nil {
		r.Errorf("%q: answer is not JSON: %v", body, err)
		return
	}
	if _, err := dec.Token(); err != io.EOF {
		r.Errorf("%q: answer holds more than one value", body)
	}
	if out.JSONRPC != "2.0" || (out.Result == nil) == (out.Error == nil) {
		r.Errorf("%q: answer is not one JSON-RPC result or error: %+v", body, out)
	}
	if out.Error != nil && rpcRefusals[out.Error.Code] != out.Error.Message {
		r.Errorf("%q: refusal %d %q is not a fixed one", body, out.Error.Code, out.Error.Message)
	}
	wantID := json.RawMessage("null")
	if decoded {
		wantID = req.ID
	}
	if !jsonEqual(out.ID, wantID) {
		r.Errorf("%q: answer id %s, want %s", body, out.ID, wantID)
	}
}

func jsonEqual(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return fmt.Sprint(x) == fmt.Sprint(y)
}

// fuzzServe is the MCP decoder of machine m1 on a rig built once.
func fuzzServe(t testing.TB) http.HandlerFunc {
	r := newRig(t, nil)
	if _, err := r.p.Open("m1"); err != nil {
		t.Fatal(err)
	}
	m := r.p.get("m1")
	return func(w http.ResponseWriter, req *http.Request) { r.p.mcp(m, w, req) }
}

func FuzzMCP(f *testing.F) {
	for _, s := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","id":"a","method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":null,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"effect_status","arguments":{"request_id":"r1"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"effect_request","arguments":{"request_id":"r2","account":"other","action":"message.send"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":"x"}`,
		`{"jsonrpc":"2.0","id":6,"method":"resources/list"}`,
		`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, `{"jsonrpc":"1.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}`, ``, `null`,
	} {
		f.Add([]byte(s))
	}
	serve := fuzzServe(f)
	f.Fuzz(func(t *testing.T, body []byte) { checkMCP(t, serve, body) })
}

// The check reports a planted decoder that panics, answers with a
// refusal outside the fixed set, or writes a second value after its
// answer; it passes the real decoder.
func TestMCPCheckReportsAPlantedDecoder(t *testing.T) {
	real := fuzzServe(t)
	input := []byte(`{"jsonrpc":"2.0","id":7,"method":"planted"}`)
	planted := map[string]http.HandlerFunc{
		"panics": func(w http.ResponseWriter, req *http.Request) {
			var m *machine
			_ = m.id
		},
		"open refusal": func(w http.ResponseWriter, req *http.Request) {
			writeRPC(w, json.RawMessage("7"), nil, &rpcError{-32000, "no method planted in /srv/broker"})
		},
		"two values": func(w http.ResponseWriter, req *http.Request) {
			real(w, req)
			w.Write([]byte(`{"jsonrpc":"2.0","id":7,"result":{}}`))
		},
	}
	for name, serve := range planted {
		var rec recorder
		checkMCP(&rec, serve, input)
		if len(rec.msgs) == 0 {
			t.Errorf("%s: the check did not report the planted decoder", name)
		}
	}
	var rec recorder
	checkMCP(&rec, real, input)
	if len(rec.msgs) != 0 {
		t.Fatalf("the real decoder reported: %v", rec.msgs)
	}
}
