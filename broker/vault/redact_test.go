package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// REQ: CRED-7, CRED-1

func TestRedactCoversCommonEncodings(t *testing.T) {
	val := canary(t)
	r := NewRedactor([][]byte{val})
	hx := []byte(hex.EncodeToString(val))
	for i := range hx {
		if i%3 == 0 {
			hx[i] = bytes.ToUpper(hx[i : i+1])[0]
		}
	}
	js, _ := json.Marshal(string(val) + "<&>")
	forms := []string{
		string(val),
		base64.StdEncoding.EncodeToString(val),
		base64.RawURLEncoding.EncodeToString(val),
		hex.EncodeToString(val),
		strings.ToUpper(hex.EncodeToString(val)),
		string(hx), // mixed case
		url.QueryEscape(string(val) + "/+"),
		string(js),
	}
	// Inside a larger base64 blob, at every alignment, e.g. an echoed
	// "Authorization: Bearer <key>" header, base64-encoded.
	for _, pre := range []string{"Bearer ", "x", "xy", "xyz"} {
		forms = append(forms,
			base64.StdEncoding.EncodeToString([]byte(pre+string(val)+"!")),
			base64.URLEncoding.EncodeToString([]byte(pre+string(val))))
	}
	for _, form := range forms {
		in := []byte(`{"echo":"Bearer ` + form + `","n":1}`)
		out := r.Redact(in)
		if bytes.Contains(out, val) || strings.Contains(string(out), form) || bytes.Contains(out, val[len(val)-16:]) {
			t.Fatalf("form %q survived: %s", form, out)
		}
		if !bytes.Contains(out, []byte(Placeholder)) {
			t.Fatalf("no placeholder in %s", out)
		}
	}
	plain := []byte("nothing secret here")
	if got := r.Redact(plain); !bytes.Equal(got, plain) {
		t.Fatalf("changed clean input: %s", got)
	}
}

// A value split across any two writes is still redacted, and the stream
// is otherwise unchanged.
func TestStreamingRedactionAtEverySplit(t *testing.T) {
	val := canary(t)
	r := NewRedactor([][]byte{val})
	msg := []byte("data: {\"a\":\"" + string(val) + "\"}\n\ndata: [DONE]\n\n")
	want := r.Redact(msg)
	for i := 0; i <= len(msg); i++ {
		for j := i; j <= len(msg); j += 7 {
			var buf bytes.Buffer
			w := r.Writer(&buf)
			for _, part := range [][]byte{msg[:i], msg[i:j], msg[j:]} {
				if _, err := w.Write(part); err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(buf.Bytes(), val[:len(val)/2+1]) {
					t.Fatalf("split %d/%d: emitted a prefix of the secret", i, j)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Fatalf("split %d/%d: got %q want %q", i, j, buf.Bytes(), want)
			}
		}
	}
}

// Clean bytes far from any possible match are emitted promptly, so token
// streams keep flowing.
func TestStreamingEmitsCleanPrefixPromptly(t *testing.T) {
	val := canary(t)
	r := NewRedactor([][]byte{val})
	var buf bytes.Buffer
	w := r.Writer(&buf)
	clean := bytes.Repeat([]byte("x"), 4*r.MaxLen())
	w.Write(clean)
	if buf.Len() < len(clean)-r.MaxLen() {
		t.Fatalf("held back %d bytes, want < %d", len(clean)-buf.Len(), r.MaxLen())
	}
}

// declaredFormats mirror provagent's built-in credential formats, each with
// a synthetic canary (FMT-3).
var declaredFormats = map[string]string{
	`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`:              "sk-proj-CANARYcanary0000000000000000",
	`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*`: "eyJjYW5hcnkiOiIxIn0.eyJjYW5hcnkiOiIyIn0.c2lnY2FuYXJ5",
	`(?i)\brt_[a-z0-9._-]{20,}`:                                      "RT_CanaryCANARYcanary000000",
	`\bsk-ant-(?:oat|ort|api|admin)[0-9]{2}-[A-Za-z0-9_-]{20,}`:      "sk-ant-oat01-CANARYcanary0000000000000000",
}

func formatRedactor(t *testing.T, values ...[]byte) *Redactor {
	t.Helper()
	var fs []string
	for f := range declaredFormats {
		fs = append(fs, f)
	}
	r, err := NewRedactor(values).WithFormats(fs...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// leaks reports whether out carries any 6-byte run of canary.
func leaks(out []byte, canary string) bool {
	for i := 0; i+6 <= len(canary); i++ {
		if bytes.Contains(out, []byte(canary[i:i+6])) {
			return true
		}
	}
	return false
}

// REQ: CRED-7
func TestRedactorScrubsDeclaredFormats(t *testing.T) {
	val := canary(t)
	base := NewRedactor([][]byte{val})
	r := formatRedactor(t, val)
	for f, c := range declaredFormats {
		got := r.Redact([]byte(`{"text":"a ` + c + ` b"}`))
		if want := `{"text":"a ` + Placeholder + ` b"}`; string(got) != want {
			t.Errorf("%s: got %q want %q", f, got, want)
		}
		if !bytes.Contains(base.Redact([]byte(c)), []byte(c)) {
			t.Errorf("%s: WithFormats changed the redactor it was called on", f)
		}
	}
	if got := r.Redact(append([]byte("v="), val...)); string(got) != "v="+Placeholder {
		t.Errorf("value patterns lost: %q", got)
	}
	for _, bad := range [][]string{{`(`}, {`x*`}, {""}, {`\bsk-[a-z]{4,}`, `[`}} {
		if _, err := base.WithFormats(bad...); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

// REQ: CRED-7
func TestRedactorScrubsDeclaredFormatSplitAcrossWrites(t *testing.T) {
	r := formatRedactor(t)
	for f, c := range declaredFormats {
		msg := []byte("data: {\"t\":\"" + c + "\"}\n\ndata: x " + c + "\n")
		want := r.Redact(msg)
		if leaks(want, c) {
			t.Fatalf("%s: whole-message redaction leaks: %q", f, want)
		}
		for i := 0; i <= len(msg); i++ {
			for j := i; j <= len(msg); j += 5 {
				var buf bytes.Buffer
				w := r.Writer(&buf)
				for _, part := range [][]byte{msg[:i], msg[i:j], msg[j:]} {
					if _, err := w.Write(part); err != nil {
						t.Fatal(err)
					}
					if leaks(buf.Bytes(), c) {
						t.Fatalf("%s split %d/%d: emitted part of the canary: %q", f, i, j, buf.Bytes())
					}
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(buf.Bytes(), want) {
					t.Fatalf("%s split %d/%d: got %q want %q", f, i, j, buf.Bytes(), want)
				}
			}
		}
	}
	// A canary ending a stream far past the hold-back is still held whole
	// until it ends.
	long := append(bytes.Repeat([]byte("x "), FormatMaxLen), "rt_"+strings.Repeat("a", 30)...)
	var buf bytes.Buffer
	w := r.Writer(&buf)
	for k := 0; k < len(long); k += 7 {
		e := k + 7
		if e > len(long) {
			e = len(long)
		}
		if _, err := w.Write(long[k:e]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Write([]byte("aaaa end")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("aaaa")) {
		t.Errorf("tail of a streamed match emitted")
	}
}

// The stream hold-back is bounded as FormatMaxLen says: every write holds
// back its last FormatMaxLen-1 bytes, a shorter match running to the end is
// held whole, and of a longer one at least the first FormatMaxLen bytes are
// redacted (P17).
// REQ: CRED-7
func TestFormatStreamHoldBounds(t *testing.T) {
	r := formatRedactor(t)
	stream := func(in []byte) (emitted, out []byte) {
		var buf bytes.Buffer
		w := r.Writer(&buf)
		for k := 0; k < len(in); k += 100 {
			e := k + 100
			if e > len(in) {
				e = len(in)
			}
			if _, err := w.Write(in[k:e]); err != nil {
				t.Fatal(err)
			}
		}
		emitted = append([]byte(nil), buf.Bytes()...)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return emitted, buf.Bytes()
	}
	clean := bytes.Repeat([]byte("x"), 6000)
	if emitted, _ := stream(clean); len(clean)-len(emitted) != FormatMaxLen-1 {
		t.Errorf("clean stream held back %d bytes, want %d", len(clean)-len(emitted), FormatMaxLen-1)
	}
	short := "rt_" + strings.Repeat("a", FormatMaxLen-4)
	if _, out := stream([]byte(short + " end")); string(out) != Placeholder+" end" {
		t.Errorf("match of %d bytes: got %.40q...", len(short), out)
	}
	long := "rt_" + strings.Repeat("a", 5000)
	_, out := stream([]byte(long + " end"))
	if !bytes.HasPrefix(out, []byte(Placeholder)) {
		t.Fatalf("long match: no placeholder first: %.40q", out)
	}
	if leaked := len(out) - len(Placeholder) - len(" end"); leaked > len(long)-FormatMaxLen {
		t.Errorf("long match: %d bytes of it emitted, want at most %d", leaked, len(long)-FormatMaxLen)
	}
}
