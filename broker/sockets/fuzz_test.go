package sockets

// LOOP-7 bullet 2 (P3-4b-3): fuzz targets for the socket frame decoder.
// Each target checks properties, not only "no panic", and each has a
// planted-decoder control showing its check reports a broken decoder.
// REQ: LOOP-7

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// reporter is the part of testing.TB the checks use, so the controls can
// record what a check reports.
type reporter interface {
	Errorf(format string, args ...any)
}

type recorder struct{ msgs []string }

func (r *recorder) Errorf(format string, args ...any) {
	r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
}

var fixedCodes = map[string]bool{
	string(ErrMalformed): true, string(ErrUnknownOp): true, string(ErrTooLarge): true,
	string(ErrTooMany): true, string(ErrPeer): true, string(ErrFailed): true,
	string(ErrInternal): true, "bad args": true,
}

// fuzzEndpoint serves "echo", which returns its args, and "fail", which
// fails with a handler error that is not a Code.
func fuzzEndpoint(calls *int) Endpoint {
	return Endpoint{Name: "g.sock", Peer: Peer{Kind: "guest", ID: "m1"}, Ops: map[string]Handler{
		"echo": func(_ context.Context, _ Peer, args json.RawMessage) (any, error) {
			*calls++
			if len(args) > 0 && !json.Valid(args) {
				return nil, Code("bad args")
			}
			return args, nil
		},
		"fail": func(context.Context, Peer, json.RawMessage) (any, error) {
			*calls++
			return nil, errors.New("handler detail that must not reach the peer")
		},
	}}
}

// checkRequest decodes one request line with decode and checks: no panic;
// a response is either ok or carries a fixed code; a line that is not a
// request object, or names an op the socket does not serve, reaches no
// handler.
func checkRequest(r reporter, decode func(context.Context, Endpoint, []byte) Response, line []byte) {
	calls := 0
	ep := fuzzEndpoint(&calls)
	var resp Response
	func() {
		defer func() {
			if p := recover(); p != nil {
				r.Errorf("decoder panicked on %q: %v", line, p)
			}
		}()
		resp = decode(context.Background(), ep, line)
	}()
	if resp.OK == (resp.Error != "") {
		r.Errorf("response is neither ok nor a refusal: %+v", resp)
	}
	if resp.Error != "" && !fixedCodes[resp.Error] {
		r.Errorf("refusal %q is not a fixed code", resp.Error)
	}
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		if calls != 0 || resp.Error != string(ErrMalformed) {
			r.Errorf("malformed %q: %d calls, %+v", line, calls, resp)
		}
		return
	}
	if _, served := ep.Ops[req.Op]; !served && (calls != 0 || resp.Error != string(ErrUnknownOp)) {
		r.Errorf("unknown op %q: %d calls, %+v", req.Op, calls, resp)
	}
}

// checkFrames splits data into request lines with read and checks: no
// panic; each line read is the input's next '\n'-terminated line, whole;
// a line, terminated or not, is refused as too large exactly when it is
// over MaxRequest bytes, and reading stops there.
func checkFrames(r reporter, read func(*bufio.Reader) ([]byte, error), data []byte) {
	br := bufio.NewReaderSize(bytes.NewReader(data), 4096)
	rest := data
	for {
		next := rest
		if n := bytes.IndexByte(rest, '\n'); n >= 0 {
			next = rest[:n+1]
		}
		var line []byte
		var err error
		func() {
			defer func() {
				if p := recover(); p != nil {
					r.Errorf("frame reader panicked: %v", p)
					err = errors.New("panic")
				}
			}()
			line, err = read(br)
		}()
		tooLarge := len(next) > MaxRequest
		switch {
		case err != nil && err.Error() == "panic":
			return
		case errors.Is(err, errTooLarge) != tooLarge:
			r.Errorf("a %d-byte line: refused as too large = %v", len(next), errors.Is(err, errTooLarge))
			return
		case tooLarge:
			return
		case err != nil:
			if len(line) != 0 || (len(next) > 0 && next[len(next)-1] == '\n') {
				r.Errorf("read failed on a whole line %q: %v", next, err)
			}
			return
		case !bytes.Equal(line, next):
			r.Errorf("read %q, want the next line %q", line, next)
			return
		}
		rest = rest[len(next):]
	}
}

func FuzzRequest(f *testing.F) {
	for _, s := range []string{
		``, `{}`, `{"op":"echo"}`, `{"op":"echo","args":{"a":1}}`, `{"op":"fail"}`,
		`{"op":"whoami"}`, `{"op":1}`, `[{"op":"echo"}]`, `{"op":"echo","args":`, `{"op":"echo"}{"op":"fail"}`,
		"{\"op\":\"echo\",\"op\":\"x\"}", `null`, `"echo"`, "\xff\xfe",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, line []byte) { checkRequest(t, handle, line) })
}

func FuzzFrames(f *testing.F) {
	for _, s := range []string{"", "\n", "{}\n{}\n", "no newline", strings.Repeat("a", 5000) + "\n", "x\r\n\n\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) { checkFrames(t, readLine, data) })
}

// The checks report a planted decoder that panics, leaks a handler's
// error, or runs a handler for a malformed line, and pass the real one.
func TestRequestCheckReportsAPlantedDecoder(t *testing.T) {
	planted := map[string]func(context.Context, Endpoint, []byte) Response{
		"panics": func(ctx context.Context, ep Endpoint, line []byte) Response {
			if bytes.Contains(line, []byte("planted")) {
				var m map[string]int
				m["x"]++
			}
			return handle(ctx, ep, line)
		},
		"leaks": func(ctx context.Context, ep Endpoint, line []byte) Response {
			if bytes.Contains(line, []byte("planted")) {
				return Response{Error: "open /secret: permission denied"}
			}
			return handle(ctx, ep, line)
		},
		"lenient": func(ctx context.Context, ep Endpoint, line []byte) Response {
			if bytes.Contains(line, []byte("planted")) {
				out, _ := ep.Ops["echo"](ctx, ep.Peer, nil)
				return Response{OK: true, Result: mustJSON(out)}
			}
			return handle(ctx, ep, line)
		},
	}
	input := []byte(`{"op":"planted"`)
	for name, dec := range planted {
		var rec recorder
		checkRequest(&rec, dec, input)
		if len(rec.msgs) == 0 {
			t.Errorf("%s: the check did not report the planted decoder", name)
		}
	}
	var rec recorder
	checkRequest(&rec, handle, input)
	if len(rec.msgs) != 0 {
		t.Fatalf("the real decoder reported: %v", rec.msgs)
	}
}

func TestFrameCheckReportsAPlantedReader(t *testing.T) {
	uncapped := func(r *bufio.Reader) ([]byte, error) { return r.ReadBytes('\n') }
	panics := func(r *bufio.Reader) ([]byte, error) {
		line, err := readLine(r)
		if bytes.Contains(line, []byte("planted")) {
			panic("planted")
		}
		return line, err
	}
	big := append(bytes.Repeat([]byte("a"), MaxRequest+10), '\n')
	for name, c := range map[string]struct {
		read func(*bufio.Reader) ([]byte, error)
		data []byte
	}{"uncapped": {uncapped, big}, "panics": {panics, []byte("planted\n")}} {
		var rec recorder
		checkFrames(&rec, c.read, c.data)
		if len(rec.msgs) == 0 {
			t.Errorf("%s: the check did not report the planted reader", name)
		}
		rec = recorder{}
		checkFrames(&rec, readLine, c.data)
		if len(rec.msgs) != 0 {
			t.Errorf("%s: the real reader reported: %v", name, rec.msgs)
		}
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
