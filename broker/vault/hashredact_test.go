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

// The keyed-hash redactor redacts what the plaintext one does: every
// encoding, at any alignment inside a larger base64 blob, in any case of
// hex, and in a stream split anywhere.
func TestHashRedactCoversCommonEncodings(t *testing.T) {
	val := canary(t)
	r, err := NewHashRedactor([][]byte{val})
	if err != nil {
		t.Fatal(err)
	}
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
		string(hx),
		url.QueryEscape(string(val) + "/+"),
		string(js),
	}
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
	plain := []byte("nothing secret here, sk-canary- alone is not a match")
	if got := r.Redact(plain); !bytes.Equal(got, plain) {
		t.Fatalf("changed clean input: %s", got)
	}
}

// A truncated echo of the value's head or tail window is redacted too.
func TestHashRedactTruncatedEcho(t *testing.T) {
	val := canary(t)
	r, _ := NewHashRedactor([][]byte{val})
	for _, part := range [][]byte{val[:HashWindow+3], val[len(val)-HashWindow-2:]} {
		out := r.Redact(append([]byte("echo "), part...))
		if !bytes.Contains(out, []byte(Placeholder)) {
			t.Fatalf("truncated echo %q survived: %s", part, out)
		}
	}
}

// A value shorter than the window is hashed whole and still redacted.
func TestHashRedactShortValue(t *testing.T) {
	short := []byte("pw-" + hex.EncodeToString(canary(t)[10:16]))
	r, _ := NewHashRedactor([][]byte{short})
	out := r.Redact([]byte("login with " + string(short) + " ok"))
	if bytes.Contains(out, short) || !bytes.Contains(out, []byte(Placeholder)) {
		t.Fatalf("short value survived: %s", out)
	}
}

func TestHashStreamingAtEverySplit(t *testing.T) {
	val := canary(t)
	r, _ := NewHashRedactor([][]byte{val})
	msg := []byte("data: {\"a\":\"" + string(val) + "\"}\n\ndata: [DONE]\n\n")
	want := r.Redact(msg)
	if bytes.Contains(want, val[:HashWindow]) {
		t.Fatalf("whole redaction kept the head: %s", want)
	}
	for i := 0; i <= len(msg); i++ {
		for j := i; j <= len(msg); j += 7 {
			var buf bytes.Buffer
			w := r.Writer(&buf)
			for _, part := range [][]byte{msg[:i], msg[i:j], msg[j:]} {
				if _, err := w.Write(part); err != nil {
					t.Fatal(err)
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

// The redactor egress holds carries no plaintext: neither the value nor
// any window of it, in any encoding, appears in its encoded form, and the
// decoded copy redacts as the original did (SIM-split).
func TestHashRedactorHoldsNoPlaintext(t *testing.T) {
	a, b := canary(t), canary(t)
	r, _ := NewHashRedactor([][]byte{a, b})
	enc, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range [][]byte{a, b} {
		for _, form := range [][]byte{
			v, []byte(hex.EncodeToString(v)),
			[]byte(base64.StdEncoding.EncodeToString(v)),
		} {
			for i := 0; i+8 <= len(form); i++ {
				if bytes.Contains(enc, form[i:i+8]) {
					t.Fatalf("encoded redactor holds plaintext %q", form[i:i+8])
				}
			}
		}
	}
	var got HashRedactor
	if err := got.UnmarshalBinary(enc); err != nil {
		t.Fatal(err)
	}
	in := []byte("A: " + string(a) + " B: " + base64.StdEncoding.EncodeToString(b))
	if out := got.Redact(in); bytes.Contains(out, a) || bytes.Count(out, []byte(Placeholder)) != 2 {
		t.Fatalf("decoded redactor: %s", out)
	}
	if err := got.UnmarshalBinary([]byte("{")); err == nil {
		t.Fatal("garbage decoded")
	}
}

// A value with an encoding exactly a window long, such as the base64 of
// a 16-byte private-data marker, round-trips: the decoded redactor is not
// refused, so the proxy process does not lock on it (SIM-split, CRED-7).
func TestHashRedactorRoundTripsAWindowLongForm(t *testing.T) {
	for n := HashWindow - 9; n <= HashWindow+1; n++ {
		v := bytes.Repeat([]byte{0xa5}, n)
		r, err := NewHashRedactor([][]byte{v})
		if err != nil {
			t.Fatal(err)
		}
		enc, err := r.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var got HashRedactor
		if err := got.UnmarshalBinary(enc); err != nil {
			t.Fatalf("%d-byte value: %v", n, err)
		}
		in := []byte("x " + base64.StdEncoding.EncodeToString(v) + " y")
		if out := got.Redact(in); bytes.Contains(out, []byte(base64.StdEncoding.EncodeToString(v))) {
			t.Fatalf("%d-byte value: decoded redactor missed its base64: %s", n, out)
		}
	}
}

// The vault builds the hashed redactor over every entry.
func TestVaultHashRedactor(t *testing.T) {
	v, a, b := twoEntryVault(t)
	r, err := v.HashRedactor()
	if err != nil {
		t.Fatal(err)
	}
	out := r.Redact([]byte(string(a) + "|" + string(b)))
	if bytes.Contains(out, a) || bytes.Contains(out, b) {
		t.Fatalf("vault hash redactor: %s", out)
	}
	v.Close()
	if _, err := v.HashRedactor(); err != ErrClosed {
		t.Fatalf("closed vault: %v", err)
	}
}

func twoEntryVault(t *testing.T) (*Vault, []byte, []byte) {
	t.Helper()
	v, err := Create(t.TempDir()+"/vault", testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	a, b := canary(t), canary(t)
	if err := v.Put("a", KindAPIKey, a); err != nil {
		t.Fatal(err)
	}
	if err := v.Put("b", KindAPIKey, b); err != nil {
		t.Fatal(err)
	}
	return v, a, b
}
