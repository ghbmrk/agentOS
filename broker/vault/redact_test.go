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
