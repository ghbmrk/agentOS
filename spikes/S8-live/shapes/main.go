// Shape extractor for #2313: reads a Codex CLI auth.json and prints, for every string in it, only
// its shape (length, a public prefix, character classes, dot segments, JWT header values from an
// allowlist and claim names) and whether each Codex CredFormats pattern of
// broker/provagent/declare.go matches it. It never prints, logs or writes a value: the output is
// built from the shape fields alone. Usage: shapes AUTH_JSON
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// The Codex declaration's CredFormats, verbatim (TestFormatsMatchDeclaration checks them).
var formats = []string{
	`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`,
	`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*`,
	`[A-Za-z0-9_-]{2}\.[A-Za-z0-9_-]\.[A-Za-z0-9_-]{160,}`,
	`\brt_[A-Za-z0-9_-]{40,}`,
}

// Public prefixes, longest first. A token with none of them reports a generic prefix only when it
// starts with two to four lowercase letters and an underscore or hyphen (the vendor-prefix form).
var prefixes = []string{"sk-svcacct-", "sk-admin-", "sk-proj-", "sk-", "eyJ", "rt_"}
var generic = regexp.MustCompile(`^[a-z]{2,4}[_-]`)

// Values printed as-is only when they are one of these (they name a mode or algorithm, not a
// secret); anything else prints as "other".
var allowed = map[string]bool{"chatgpt": true, "apikey": true, "api_key": true,
	"RS256": true, "ES256": true, "HS256": true, "none": true, "JWT": true, "at+jwt": true}

type JWT struct {
	Alg       string   `json:"alg"`
	Typ       string   `json:"typ,omitempty"`
	Header    []string `json:"header_keys"`
	Claims    []string `json:"claim_names"`
	SigLength int      `json:"sig_len"`
}

type Shape struct {
	Len      int               `json:"len"`
	Prefix   string            `json:"prefix"`
	Classes  []string          `json:"classes"`
	Segments []int             `json:"segment_lens,omitempty"`
	JWT      *JWT              `json:"jwt,omitempty"`
	Formats  map[string]string `json:"formats"`
}

func classes(s string) []string {
	var up, low, dig, nonASCII bool
	other := map[string]bool{}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			up = true
		case r >= 'a' && r <= 'z':
			low = true
		case r >= '0' && r <= '9':
			dig = true
		case r > 0x20 && r < 0x7f:
			other[string(r)] = true
		default:
			nonASCII = true
		}
	}
	var out []string
	for _, c := range []struct {
		on bool
		n  string
	}{{up, "A-Z"}, {low, "a-z"}, {dig, "0-9"}} {
		if c.on {
			out = append(out, c.n)
		}
	}
	var o []string
	for k := range other {
		o = append(o, k)
	}
	sort.Strings(o)
	out = append(out, o...)
	if nonASCII {
		out = append(out, "non-printable-or-non-ascii")
	}
	return out
}

func pick(v string) string {
	if allowed[v] {
		return v
	}
	return "other"
}

func keysOf(b []byte) []string {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func jwt(segs []string) *JWT {
	if len(segs) != 3 {
		return nil
	}
	h, err := base64.RawURLEncoding.DecodeString(segs[0])
	if err != nil {
		return nil
	}
	var hv struct{ Alg, Typ string }
	if json.Unmarshal(h, &hv) != nil {
		return nil
	}
	j := &JWT{Alg: pick(hv.Alg), Header: keysOf(h), SigLength: len(segs[2])}
	if hv.Typ != "" {
		j.Typ = pick(hv.Typ)
	}
	if p, err := base64.RawURLEncoding.DecodeString(segs[1]); err == nil {
		j.Claims = keysOf(p)
	}
	return j
}

func shape(s string) Shape {
	sh := Shape{Len: len(s), Prefix: "none", Classes: classes(s), Formats: map[string]string{}}
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			sh.Prefix = p
			break
		}
	}
	if sh.Prefix == "none" {
		if m := generic.FindString(s); m != "" {
			sh.Prefix = m + " (generic)"
		}
	}
	if strings.Contains(s, ".") {
		segs := strings.Split(s, ".")
		for _, g := range segs {
			sh.Segments = append(sh.Segments, len(g))
		}
		sh.JWT = jwt(segs)
	}
	for i, f := range formats {
		loc := regexp.MustCompile(f).FindStringIndex(s)
		r := "none"
		if loc != nil {
			r = "partial"
			if loc[0] == 0 && loc[1] == len(s) {
				r = "full"
			}
		}
		sh.Formats[fmt.Sprint(i)] = r
	}
	return sh
}

// walk shapes every string leaf under its dotted path. Strings shorter than 16 bytes report their
// length only; auth_mode reports its value from the allowlist; last_refresh (a timestamp) is skipped.
func walk(path string, v any, out map[string]any) {
	switch t := v.(type) {
	case map[string]any:
		for k, c := range t {
			p := k
			if path != "" {
				p = path + "." + k
			}
			walk(p, c, out)
		}
	case []any:
		for i, c := range t {
			walk(fmt.Sprintf("%s[%d]", path, i), c, out)
		}
	case string:
		switch {
		case path == "auth_mode":
			out[path] = map[string]string{"value": pick(t)}
		case path == "last_refresh":
			out[path] = map[string]bool{"present": true}
		case len(t) < 16:
			out[path] = map[string]int{"len": len(t)}
		default:
			out[path] = shape(t)
		}
	case nil:
		out[path] = map[string]bool{"null": true}
	default:
		out[path] = map[string]string{"type": fmt.Sprintf("%T", t)}
	}
}

func run(b []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("auth file is not JSON")
	}
	out := map[string]any{}
	walk("", v, out)
	return json.MarshalIndent(map[string]any{"formats": formats, "fields": out}, "", "  ")
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: shapes AUTH_JSON")
		os.Exit(2)
	}
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "shapes: no auth file at", os.Args[1])
		os.Exit(1)
	}
	o, err := run(b)
	if err != nil {
		fmt.Fprintln(os.Stderr, "shapes:", err)
		os.Exit(1)
	}
	os.Stdout.Write(append(o, '\n'))
}
