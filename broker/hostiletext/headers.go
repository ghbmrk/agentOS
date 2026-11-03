package hostiletext

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The header corpus (REV-PROOF-corpus, #4910): header names a declaration
// must not set, because they carry a credential (#2623), reshape the
// request a server or proxy acts on, or end at the next hop, and names that
// are not one header at all. A header list or check runs it with the names
// it means to accept; every other entry must be refused.

// credentialWords are the words that mark a header as carrying a
// credential (#2623). Each is fed alone and in the shapes credentialShapes
// makes from it.
var credentialWords = []string{"key", "token", "auth", "secret", "session", "csrf", "xsrf", "signature", "password", "cookie", "credential"}

// credentialNames are credential headers servers use by name.
var credentialNames = []string{
	"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "Cookie2",
	"X-Api-Key", "Api-Key", "Apikey", "X-Auth-Token", "X-Access-Token", "X-Auth",
	"X-Session-Id", "X-Session-Token", "Session-Id", "X-Csrf-Token", "X-Csrftoken", "X-Xsrf-Token",
	"X-Amz-Security-Token", "X-Goog-Api-Key", "X-Hub-Signature-256", "X-Signature",
	"X-Password", "X-Credential", "Ocp-Apim-Subscription-Key", "X-Client-Secret", "Private-Token",
}

// reshapingNames make a server or a proxy act on a request other than
// the one declared: another method, host, path or client.
var reshapingNames = []string{
	"X-Http-Method-Override", "X-Method-Override", "X-Http-Method", "X-Original-Method",
	"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Prefix",
	"X-Forwarded-Server", "X-Forwarded-Scheme", "Forwarded",
	"X-Original-Url", "X-Original-Host", "X-Original-Uri", "X-Rewrite-Url", "X-Rewrite-Uri",
	"X-Real-Ip", "X-Host", "X-Client-Ip", "True-Client-Ip", "Host",
	"Content-Length", "Content-Type", "Content-Encoding", "Expect", "Max-Forwards",
}

// hopNames end at the next hop (RFC 9110 §7.6.1), or frame the message.
var hopNames = []string{
	"Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate", "Te", "Trailer",
	"Transfer-Encoding", "Upgrade", "Http2-Settings",
}

// brokenNames are not one header name: a line break, a colon or a space
// would end the name or the line and begin another.
var brokenNames = []Entry{
	{"empty", ""},
	{"CRLF then a header", "Accept\r\nX-Injected"},
	{"LF then a header", "Accept\nX-Injected"},
	{"lone CR", "Accept\r"},
	{"trailing LF", "Accept\n"},
	{"leading CRLF", "\r\nAccept"},
	{"colon", "Accept:"},
	{"colon and value", "Accept: */*"},
	{"space inside", "Accept Language"},
	{"trailing space", "Accept "},
	{"leading space", " Accept"},
	{"tab", "Accept\t"},
	{"NUL", "Accept\x00"},
	{"non-ASCII", "Accépt"},
}

// upperFirst is s with each dash-separated word capitalised, as
// http.CanonicalHeaderKey writes it.
func upperFirst(s string) string {
	b := []byte(strings.ToLower(s))
	up := true
	for i, c := range b {
		if up && c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
		up = c == '-'
	}
	return string(b)
}

// cased is name as given, canonical, lower and upper case, each once.
func cased(name string) []string {
	var out []string
	for _, n := range []string{name, upperFirst(name), strings.ToLower(name), strings.ToUpper(name)} {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// HeaderNames is the header-name corpus: each credential word alone, with
// "X-" and as "X-Api-<word>", each named credential, reshaping and hop
// header, every one in each case, and the broken names.
func HeaderNames() []Entry {
	var out []Entry
	add := func(kind, name string) {
		for _, n := range cased(name) {
			out = append(out, Entry{kind + " " + strconv.Quote(n), n})
		}
	}
	for _, w := range credentialWords {
		for _, n := range []string{w, "X-" + w, "X-Api-" + w, w + "-Id"} {
			add("credential", n)
		}
	}
	for _, n := range credentialNames {
		add("credential", n)
	}
	for _, n := range reshapingNames {
		add("reshaping", n)
	}
	for _, n := range hopNames {
		add("hop-by-hop", n)
	}
	for _, e := range brokenNames {
		out = append(out, Entry{"broken name " + e.Name, e.Text})
	}
	return out
}

// HeaderValues are values no declared header may carry: each would end the
// header line and begin another, or is not text.
var HeaderValues = []Entry{
	{"CR", "v\r"},
	{"LF", "v\n"},
	{"CRLF", "v\r\n"},
	{"CRLF then a header", "v\r\nX-Injected: 1"},
	{"LF then a header", "v\nX-Injected: 1"},
	{"obsolete fold", "v\r\n folded"},
	{"leading CRLF", "\r\nv"},
	{"NUL", "v\x00"},
	{"DEL", "v\x7f"},
	{"escape", "v\x1b[2J"},
}

// HeadersAccepted lists what accept wrongly decides about header names:
// each corpus entry it accepts that named does not hold exactly, each name
// in named it refuses (the positive control), and named being empty. named
// is what the list or check means to accept; "exactly" is byte for byte, so
// "authorization" is not "Authorization".
func HeadersAccepted(accept func(name string) bool, named ...string) []string {
	var bad []string
	if len(named) == 0 {
		bad = append(bad, "names no header it accepts (positive control)")
	}
	for _, n := range named {
		if !accept(n) {
			bad = append(bad, "refuses "+strconv.Quote(n)+", which it names (positive control)")
		}
	}
	for _, e := range HeaderNames() {
		if !slices.Contains(named, e.Text) && accept(e.Text) {
			bad = append(bad, "accepts "+e.Name+" "+strconv.QuoteToASCII(e.Text))
		}
	}
	return bad
}

// RunHeaders fails t for each wrong decision HeadersAccepted finds. accept
// is the list or check as its caller uses it, deciding one header name.
func RunHeaders(t testing.TB, accept func(name string) bool, named ...string) {
	t.Helper()
	for _, b := range HeadersAccepted(accept, named...) {
		t.Errorf("hostiletext headers: %s", b)
	}
}

// ValuesAccepted lists what accept wrongly decides about header values:
// each HeaderValues entry it accepts, and refusing the plain "v".
func ValuesAccepted(accept func(value string) bool) []string {
	var bad []string
	if !accept("v") {
		bad = append(bad, `refuses the plain value "v" (positive control)`)
	}
	for _, e := range HeaderValues {
		if accept(e.Text) {
			bad = append(bad, "accepts value "+e.Name+" "+strconv.QuoteToASCII(e.Text))
		}
	}
	return bad
}

// RunHeaderValues fails t for each wrong decision ValuesAccepted finds.
func RunHeaderValues(t testing.TB, accept func(value string) bool) {
	t.Helper()
	for _, b := range ValuesAccepted(accept) {
		t.Errorf("hostiletext header values: %s", b)
	}
}
