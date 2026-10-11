package browser

// LOOP-7 bullet 2 (P3-4b-3): fuzz target for the action protocol decoder,
// with a planted-decoder control.
// REQ: LOOP-7

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

type reporter interface {
	Errorf(format string, args ...any)
}

type recorder struct{ msgs []string }

func (r *recorder) Errorf(format string, args ...any) {
	r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
}

// checkParse decodes raw with parse and checks: no panic; a refusal is a
// *ProtocolError; an accepted request is a closed verb within the limits,
// and its canonical encoding parses back to the same request and encodes
// to the same bytes, so the gate and the driver read one request.
func checkParse(r reporter, parse func([]byte) (Request, error), raw []byte) {
	var req Request
	var err error
	func() {
		defer func() {
			if p := recover(); p != nil {
				r.Errorf("decoder panicked on %q: %v", raw, p)
				err = errors.New("panic")
			}
		}()
		req, err = parse(raw)
	}()
	if err != nil {
		var pe *ProtocolError
		if err.Error() != "panic" && !errors.As(err, &pe) {
			r.Errorf("refusal is not a protocol error: %T %v", err, err)
		}
		return
	}
	if _, ok := verbs[req.Verb]; !ok {
		r.Errorf("accepted verb %q is not in the closed list", req.Verb)
		return
	}
	if len(req.Text) > MaxText || len(req.URL) > MaxURL || len(req.Ref) > MaxRef || len(req.Option) > MaxOption {
		r.Errorf("accepted %q past a limit", raw)
	}
	if req.Verb == "navigate" {
		if _, err := checkURL(req.URL); err != nil {
			r.Errorf("accepted navigate to %q: %v", req.URL, err)
		}
	}
	enc := req.Encode()
	again, err := Parse(enc)
	if err != nil || again != req {
		r.Errorf("canonical form %s reads back as %+v, %v; want %+v", enc, again, err, req)
		return
	}
	if !bytes.Equal(again.Encode(), enc) {
		r.Errorf("canonical form %s is not stable", enc)
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{
		`{"v":0,"verb":"navigate","url":"https://example.test/a?b=c"}`,
		`{"v":0,"verb":"click","ref":"f1e12"}`,
		`{"v":0,"verb":"type","ref":"e3","text":"hello","submit":true}`,
		`{"v":0,"verb":"select","ref":"e4","option":"x"}`,
		`{"v":0,"verb":"snapshot"}`, `{"v":0,"verb":"screenshot"}`, `{"v":0,"verb":"download","ref":"e9"}`,
		`{"v":0,"verb":"click","ref":"e1","ref":"e2"}`, `{"v":0,"verb":"evaluate"}`, `{"v":1,"verb":"snapshot"}`,
		`{"v":0,"verb":"navigate","url":"http://user@example.test/"}`,
		`{"v":0,"verb":"navigate","url":"http://exİmple.test/"}`,
		`{"v":0,"verb":"snapshot"} {}`, `[]`, ``, `{"v":0,"verb":"type","ref":"e1","text":"a","submit":"yes"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) { checkParse(t, Parse, raw) })
}

// The check reports a planted decoder that panics, refuses with a bare
// error, accepts a verb outside the list, or accepts a request whose
// canonical form reads differently; it passes the real Parse.
func TestParseCheckReportsAPlantedDecoder(t *testing.T) {
	input := []byte(`{"v":0,"verb":"type","ref":"e1","text":"planted"}`)
	planted := map[string]func([]byte) (Request, error){
		"panics": func(raw []byte) (Request, error) {
			if bytes.Contains(raw, []byte("planted")) {
				var p *Request
				_ = p.Verb
			}
			return Parse(raw)
		},
		"bare error": func(raw []byte) (Request, error) {
			if bytes.Contains(raw, []byte("planted")) {
				return Request{}, errors.New("planted")
			}
			return Parse(raw)
		},
		"open verb": func(raw []byte) (Request, error) {
			if bytes.Contains(raw, []byte("planted")) {
				return Request{Verb: "evaluate", Text: "planted"}, nil
			}
			return Parse(raw)
		},
		"two readings": func(raw []byte) (Request, error) {
			req, err := Parse(raw)
			if bytes.Contains(raw, []byte("planted")) {
				req.Option = "planted" // type has no option: lost in Encode
			}
			return req, err
		},
	}
	for name, parse := range planted {
		var rec recorder
		checkParse(&rec, parse, input)
		if len(rec.msgs) == 0 {
			t.Errorf("%s: the check did not report the planted decoder", name)
		}
	}
	var rec recorder
	checkParse(&rec, Parse, input)
	if len(rec.msgs) != 0 {
		t.Fatalf("the real decoder reported: %v", rec.msgs)
	}
}
