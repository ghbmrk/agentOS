// Package browser is the broker side of the credentialed browser executor
// (SPEC CRED-4, CRED-10; BOARD CRED-4b). Agents reach a logged-in browser only
// through Gate, which accepts the closed, versioned action protocol, forwards a
// canonical re-encoding of each valid request to a sandboxed driver process,
// and filters everything the driver returns before an agent sees it.
//
// The driver (S5's Playwright executor) is treated as untrusted: it runs pages
// written by strangers. Every check that keeps credentials in is repeated here,
// outside the driver: the verb list, declared origins, the output detector, the
// vault's exact values, screenshot withholding and download scanning.
package browser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Version is the action protocol version this gate speaks.
const Version = 0

// MaxText bounds the text of one type request.
const MaxText = 2000

var refRE = regexp.MustCompile(`^(?:f[0-9]+)?e[0-9]+$`)

// verbs is the closed list (CRED-4): verb -> its arguments. Nothing else
// exists: no evaluate, cookies, storage, headers, devtools or tabs.
var verbs = map[string][]string{
	"navigate":   {"url"},
	"click":      {"ref"},
	"type":       {"ref", "text", "submit"},
	"select":     {"ref", "option"},
	"snapshot":   nil,
	"screenshot": nil,
	"download":   {"ref"},
}

var optional = map[string]bool{"type.submit": true}

// ProtocolError is a request the protocol does not allow. It never reaches
// the driver.
type ProtocolError struct{ Msg string }

func (e *ProtocolError) Error() string { return e.Msg }

func perr(format string, a ...any) error { return &ProtocolError{fmt.Sprintf(format, a...)} }

// Request is one validated protocol request.
type Request struct {
	Verb   string
	URL    string
	Ref    string
	Text   string
	Submit bool
	Option string
}

// Parse validates one request line. It refuses duplicate keys, unknown
// arguments, wrong JSON types and trailing data, so the gate and the driver can
// never read different requests from the same bytes.
func Parse(raw []byte) (Request, error) {
	fields, err := strictObject(raw)
	if err != nil {
		return Request{}, err
	}
	v, ok := fields["v"]
	if !ok || string(v) != "0" {
		return Request{}, perr("unsupported protocol version %s", v)
	}
	var r Request
	if err := str(fields, "verb", &r.Verb); err != nil {
		return Request{}, err
	}
	args, ok := verbs[r.Verb]
	if !ok {
		return Request{}, perr("unknown verb %q", r.Verb)
	}
	allowed := map[string]bool{"v": true, "verb": true}
	for _, a := range args {
		allowed[a] = true
	}
	for k := range fields {
		if !allowed[k] {
			return Request{}, perr("unknown argument %q for %s", k, r.Verb)
		}
	}
	for _, a := range args {
		if _, ok := fields[a]; !ok {
			if optional[r.Verb+"."+a] {
				continue
			}
			return Request{}, perr("%s needs %s", r.Verb, a)
		}
		var err error
		switch a {
		case "url":
			err = str(fields, a, &r.URL)
		case "ref":
			err = str(fields, a, &r.Ref)
		case "text":
			err = str(fields, a, &r.Text)
		case "option":
			err = str(fields, a, &r.Option)
		case "submit":
			if s := string(fields[a]); s == "true" || s == "false" {
				r.Submit = s == "true"
			} else {
				err = perr("%s.submit must be a boolean", r.Verb)
			}
		}
		if err != nil {
			return Request{}, err
		}
	}
	if r.Ref != "" || hasArg(args, "ref") {
		if !refRE.MatchString(r.Ref) {
			return Request{}, perr("ref must come from a snapshot (e.g. e12)")
		}
	}
	if r.Verb == "navigate" {
		if _, err := checkURL(r.URL); err != nil {
			return Request{}, err
		}
	}
	if len(r.Text) > MaxText {
		return Request{}, perr("text too long")
	}
	return r, nil
}

// Encode is the canonical form sent to the driver: fixed key order, only the
// verb's own arguments.
func (r Request) Encode() []byte {
	var b bytes.Buffer
	b.WriteString(`{"v":0,"verb":`)
	b.Write(js(r.Verb))
	for _, a := range verbs[r.Verb] {
		b.WriteString(`,"` + a + `":`)
		switch a {
		case "url":
			b.Write(js(r.URL))
		case "ref":
			b.Write(js(r.Ref))
		case "text":
			b.Write(js(r.Text))
		case "option":
			b.Write(js(r.Option))
		case "submit":
			b.Write(js(r.Submit))
		}
	}
	b.WriteString("}")
	return b.Bytes()
}

func js(v any) []byte { b, _ := json.Marshal(v); return b }

func hasArg(args []string, a string) bool {
	for _, x := range args {
		if x == a {
			return true
		}
	}
	return false
}

func str(fields map[string]json.RawMessage, k string, dst *string) error {
	raw, ok := fields[k]
	if !ok || len(raw) == 0 || raw[0] != '"' {
		return perr("%s must be a string", k)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return perr("%s: %v", k, err)
	}
	return nil
}

// strictObject decodes one JSON object, refusing duplicate keys and anything
// after it.
func strictObject(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, perr("request must be a JSON object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, perr("not JSON")
		}
		k := kt.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, perr("not JSON")
		}
		if _, dup := out[k]; dup {
			return nil, perr("duplicate key %q", k)
		}
		out[k] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, perr("not JSON")
	}
	if _, err := dec.Token(); err == nil {
		return nil, perr("trailing data after the request")
	}
	return out, nil
}

func checkURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, perr("navigate takes an http(s) URL only")
	}
	if u.User != nil {
		return nil, perr("URLs with userinfo are refused")
	}
	return u, nil
}

// Origins is an account's declared origin set (CRED-10).
type Origins map[string]bool

// NewOrigins builds the set; an executor needs at least one http(s) origin.
func NewOrigins(list []string) (Origins, error) {
	if len(list) == 0 {
		return nil, fmt.Errorf("browser: no declared origin")
	}
	o := Origins{}
	for _, s := range list {
		k, ok := originKey(s)
		if !ok {
			return nil, fmt.Errorf("browser: bad declared origin %q", s)
		}
		o[k] = true
	}
	return o, nil
}

// Declared reports whether s is an http(s) URL on a declared origin.
func (o Origins) Declared(s string) bool {
	k, ok := originKey(s)
	return ok && o[k]
}

func originKey(s string) (string, bool) {
	u, err := checkURL(s)
	if err != nil {
		return "", false
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return u.Scheme + "://" + strings.ToLower(u.Hostname()) + ":" + port, true
}
