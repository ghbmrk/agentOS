// Package browseract is the closed action protocol a credentialed
// browser accepts (CRED-4). A request is one JSON object. Targets are
// snapshot refs, never a selector. There is no evaluate, cookie,
// storage, header, or devtools verb. This package does not drive a
// browser and holds no session.
package browseract

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

const (
	Version     = 0
	MaxText     = 2000
	MaxSnapshot = 256 * 1024
)

// verbs is the whole protocol. A key's value is the required arguments.
// submit on type is optional.
var verbs = map[string][]string{
	"navigate":   {"url"},
	"click":      {"ref"},
	"type":       {"ref", "text"},
	"select":     {"ref", "option"},
	"snapshot":   nil,
	"screenshot": nil,
	"download":   {"ref"},
}

var refRE = regexp.MustCompile(`^(?:f\d+)?e\d+$`)

// Request is one validated action.
type Request struct {
	V         int
	Verb      string
	URL       string
	Ref       string
	Text      string
	Submit    bool
	Option    string
	hasSubmit bool
}

// HasSubmit reports whether a type request set submit.
func (r Request) HasSubmit() bool { return r.hasSubmit }

// Error is a refusal. Its text names the rule, not the request body.
type Error string

func (e Error) Error() string { return string(e) }

// Parse accepts one v0 request and refuses anything else.
func Parse(raw []byte) (Request, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var req map[string]any
	if err := dec.Decode(&req); err != nil || len(req) == 0 && !bytes.Contains(raw, []byte{'{'}) {
		return Request{}, Error("request must be an object")
	}
	if dec.More() {
		return Request{}, Error("request must be one object")
	}
	v, ok := req["v"]
	if !ok {
		return Request{}, Error("unsupported protocol version")
	}
	n, ok := v.(json.Number)
	if !ok || n.String() != "0" {
		return Request{}, Error("unsupported protocol version")
	}
	verb, _ := req["verb"].(string)
	spec, known := verbs[verb]
	if !known {
		return Request{}, Error("unknown verb")
	}
	allowed := map[string]bool{"v": true, "verb": true}
	for _, a := range spec {
		allowed[a] = true
	}
	if verb == "type" {
		allowed["submit"] = true
	}
	for k := range req {
		if !allowed[k] {
			return Request{}, Error("unknown argument for " + verb)
		}
	}
	out := Request{V: Version, Verb: verb}
	for _, a := range spec {
		val, present := req[a]
		if !present {
			return Request{}, Error(verb + " needs " + a)
		}
		s, ok := val.(string)
		if !ok {
			return Request{}, Error(verb + " " + a + " must be a string")
		}
		switch a {
		case "url":
			if err := checkURL(s); err != nil {
				return Request{}, err
			}
			out.URL = s
		case "ref":
			if !refRE.MatchString(s) {
				return Request{}, Error("ref must come from a snapshot")
			}
			out.Ref = s
		case "text":
			if len(s) > MaxText {
				return Request{}, Error("text too long")
			}
			out.Text = s
		case "option":
			out.Option = s
		}
	}
	if verb == "type" {
		if s, ok := req["submit"]; ok {
			b, ok := s.(bool)
			if !ok {
				return Request{}, Error("type submit must be a boolean")
			}
			out.Submit = b
			out.hasSubmit = true
		}
	}
	return out, nil
}

func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return Error("navigate takes an http(s) URL only")
	}
	if u.User != nil {
		return Error("URLs with userinfo are refused")
	}
	return nil
}

// Origin is scheme, host, and port, with the scheme's default port filled
// in. ok is false when raw is not an http(s) URL.
func Origin(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", false
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	return u.Scheme + "://" + u.Hostname() + ":" + port, true
}

// OnDeclaredOrigin reports whether raw is on one of the account's declared
// origins (CRED-10). A URL that does not parse is not.
func OnDeclaredOrigin(raw string, declared []string) bool {
	o, ok := Origin(raw)
	if !ok {
		return false
	}
	for _, d := range declared {
		if got, ok := Origin(d); ok && got == o {
			return true
		}
	}
	return false
}

var (
	refToken = regexp.MustCompile(`\[ref=((?:f\d+)?e\d+)\]`)
	roleRE   = regexp.MustCompile(`^- '?[A-Za-z][A-Za-z-]* ?`)
	attrsRE  = regexp.MustCompile(`^(?: \[[^\]]*\])*`)
)

// nameEnd returns the index just past the quoted accessible name of a
// snapshot line, or the end of the role when there is no name. The name
// is page-controlled, so a [ref=...] token inside it is not the
// element's ref and the search starts after it (CRED-4).
func nameEnd(line string) int {
	m := roleRE.FindStringIndex(line)
	if m == nil {
		return 0
	}
	i := m[1]
	if i >= len(line) || line[i] != '"' {
		return i
	}
	for i++; i < len(line); i++ {
		switch line[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return len(line)
}

// OmitValues removes the value text of snapshot lines whose ref is in
// refs. The line stays, so a login form is still visible. refs are
// password fields (CRED-4).
func OmitValues(snapshot string, refs map[string]bool) string {
	lines := strings.Split(snapshot, "\n")
	for i, line := range lines {
		start := nameEnd(line)
		m := refToken.FindStringSubmatchIndex(line[start:])
		if m == nil {
			continue
		}
		for j := range m {
			m[j] += start
		}
		if !refs[line[m[2]:m[3]]] {
			continue
		}
		rest := line[m[1]:]
		attr := attrsRE.FindString(rest)
		head := strings.Replace(line[:m[1]]+attr, "- '", "- ", 1)
		tail := strings.TrimLeft(rest[len(attr):], "'")
		switch {
		case strings.HasPrefix(tail, ":") && strings.TrimSpace(tail[1:]) != "":
			lines[i] = head + ": [password omitted]"
		case strings.HasPrefix(tail, ":"):
			lines[i] = head + ":"
		default:
			lines[i] = head
		}
	}
	return strings.Join(lines, "\n")
}

// CapSnapshot bounds a snapshot the same way the spike does.
func CapSnapshot(text string) (string, bool) {
	if len(text) <= MaxSnapshot {
		return text, false
	}
	return text[:MaxSnapshot] + "\n[snapshot truncated]", true
}
