package inbox

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// header is one message header: its name and its raw value with folding kept.
type header struct{ name, value []byte }

func (h header) key() string { return strings.ToLower(strings.TrimSpace(string(h.name))) }

// splitMessage returns a message's headers in order and its body.
func splitMessage(raw []byte) ([]header, []byte) {
	head, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok {
		head, body = raw, nil
	}
	var hs []header
	for _, line := range bytes.Split(head, []byte("\r\n")) {
		switch {
		case len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && len(hs) > 0:
			last := &hs[len(hs)-1]
			last.value = append(append(append([]byte(nil), last.value...), "\r\n"...), line...)
		case len(line) > 0:
			n, v, _ := bytes.Cut(line, []byte(":"))
			hs = append(hs, header{n, v})
		}
	}
	return hs, body
}

var wsp = regexp.MustCompile(`[ \t]+`)

// relaxedHeader is RFC 6376 section 3.4.2.
func relaxedHeader(name string, value []byte) []byte {
	v := bytes.ReplaceAll(value, []byte("\r\n"), nil)
	v = bytes.Trim(wsp.ReplaceAll(v, []byte(" ")), " ")
	return append(append([]byte(strings.ToLower(strings.TrimSpace(name))+":"), v...), "\r\n"...)
}

// relaxedBody is RFC 6376 section 3.4.4, cut to limit bytes when limit >= 0.
func relaxedBody(body []byte, limit int) []byte {
	lines := bytes.Split(body, []byte("\r\n"))
	if n := len(lines); n > 0 && len(lines[n-1]) == 0 {
		lines = lines[:n-1]
	}
	for i, l := range lines {
		lines[i] = bytes.TrimRight(wsp.ReplaceAll(l, []byte(" ")), " ")
	}
	for n := len(lines); n > 0 && len(lines[n-1]) == 0; n-- {
		lines = lines[:n-1]
	}
	var out []byte
	for _, l := range lines {
		out = append(append(out, l...), "\r\n"...)
	}
	if limit >= 0 && limit < len(out) {
		out = out[:limit]
	}
	return out
}

// sigTags parses a DKIM-Signature's tag list; a repeated tag is an error.
func sigTags(value []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, part := range strings.Split(strings.Join(strings.Fields(string(value)), ""), ";") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if _, dup := out[k]; dup {
			return nil, errors.New("repeated tag " + k)
		}
		out[k] = v
	}
	return out, nil
}

// signedHeaders picks the instances h= names, bottom-up per name. A name listed
// more times than it occurs signs as empty, which is what over-signing relies on.
func signedHeaders(hs []header, names []string) []header {
	used := map[string]int{}
	var picked []header
	for _, n := range names {
		k := strings.ToLower(strings.TrimSpace(n))
		var inst []header
		for _, h := range hs {
			if h.key() == k {
				inst = append(inst, h)
			}
		}
		if seen := used[k]; seen < len(inst) {
			picked = append(picked, inst[len(inst)-1-seen])
		}
		used[k]++
	}
	return picked
}

var bTag = regexp.MustCompile(`\bb=[^;]*`)

// Sig is one DKIM-Signature's result.
type Sig struct {
	D    string   // the d= domain, "" when absent
	H    []string // the h= names, lower case
	L    bool     // the signature carries l=
	Pass bool
}

// VerifyDKIM checks every DKIM-Signature of raw (RFC 6376: rsa-sha256,
// relaxed/relaxed). keys maps "<s>._domainkey.<d>" to a key record's base64 p=.
func VerifyDKIM(raw []byte, keys map[string]string) []Sig {
	hs, body := splitMessage(raw)
	var out []Sig
	for _, h := range hs {
		if h.key() != "dkim-signature" {
			continue
		}
		out = append(out, verifyOne(hs, body, h.value, keys))
	}
	return out
}

func verifyOne(hs []header, body, value []byte, keys map[string]string) Sig {
	var r Sig
	t, err := sigTags(value)
	if err != nil {
		return r
	}
	r.D = strings.ToLower(t["d"])
	for _, x := range strings.Split(t["h"], ":") {
		if x = strings.ToLower(strings.TrimSpace(x)); x != "" {
			r.H = append(r.H, x)
		}
	}
	l, hasL := t["l"]
	r.L = hasL
	if t["v"] != "1" || t["a"] != "rsa-sha256" || t["c"] != "relaxed/relaxed" {
		return r
	}
	if !contains(r.H, "from") {
		return r
	}
	rec, ok := keys[t["s"]+"._domainkey."+r.D]
	if !ok {
		return r
	}
	limit := -1
	if n, err := strconv.Atoi(l); hasL && err == nil && n >= 0 {
		limit = n
	}
	bh := sha256.Sum256(relaxedBody(body, limit))
	if base64.StdEncoding.EncodeToString(bh[:]) != t["bh"] {
		return r
	}
	der, err := base64.StdEncoding.DecodeString(rec)
	if err != nil {
		return r
	}
	pk, err := x509.ParsePKIXPublicKey(der)
	pub, isRSA := pk.(*rsa.PublicKey)
	if err != nil || !isRSA {
		return r
	}
	sig, err := base64.StdEncoding.DecodeString(t["b"])
	if err != nil {
		return r
	}
	var in []byte
	for _, p := range signedHeaders(hs, strings.Split(t["h"], ":")) {
		in = append(in, relaxedHeader(string(p.name), p.value)...)
	}
	unsigned := bTag.ReplaceAllLiteral(value, []byte("b="))
	in = append(in, bytes.TrimRight(relaxedHeader("DKIM-Signature", unsigned), "\r\n")...)
	sum := sha256.Sum256(in)
	r.Pass = rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) == nil
	return r
}

func contains(s []string, x string) bool {
	for _, y := range s {
		if y == x {
			return true
		}
	}
	return false
}
