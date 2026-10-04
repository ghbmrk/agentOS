package egress

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Adapter declares one credentialed upstream: where it lives, which vault
// entry authenticates to it, how that credential is written into a request,
// and the exact requests it may carry (ADP-10).
type Adapter struct {
	// Name is the first path segment a guest uses: /<Name>/<upstream path>.
	Name string
	// Host is the upstream host name; requests always go to https://Host.
	Host string
	// Credential names the vault entry injected into each request.
	Credential string
	Inject     Injection
	Operations []Operation
	// RequestHeaders and ResponseHeaders are forwarded in addition to the
	// fixed allowlists. Credential-bearing names are refused.
	RequestHeaders  []string
	ResponseHeaders []string
}

// Injection writes the credential as Header: Prefix + value.
type Injection struct {
	Header string
	Prefix string
}

// Operation is one declared request shape. Path is a template of literal
// segments and {name} segments, each of which matches one non-empty
// segment.
type Operation struct {
	Name   string
	Method string
	Path   string
}

// OpenAI is the OpenAI-compatible model relay: inference endpoints only
// (CRED-5, ADP-10).
func OpenAI(credential string) Adapter {
	return Adapter{
		Name:       "openai",
		Host:       "api.openai.com",
		Credential: credential,
		Inject:     Injection{Header: "Authorization", Prefix: "Bearer "},
		Operations: []Operation{
			{Name: "chat.completions", Method: "POST", Path: "/v1/chat/completions"},
			{Name: "responses", Method: "POST", Path: "/v1/responses"},
		},
	}
}

// Anthropic is the Anthropic Messages relay: inference endpoints only.
func Anthropic(credential string) Adapter {
	return Adapter{
		Name:           "anthropic",
		Host:           "api.anthropic.com",
		Credential:     credential,
		Inject:         Injection{Header: "X-Api-Key"},
		Operations:     []Operation{{Name: "messages", Method: "POST", Path: "/v1/messages"}},
		RequestHeaders: []string{"Anthropic-Version", "Anthropic-Beta"},
	}
}

// Headers a guest may send and a provider may return, for every adapter.
// Everything else is dropped. Accept-Encoding is deliberately absent so the
// proxy sees plain bytes to redact.
var (
	baseRequestHeaders  = []string{"Content-Type", "Accept", "User-Agent"}
	baseResponseHeaders = []string{"Content-Type", "Retry-After", "X-Request-Id", "Request-Id"}
)

// Header names that carry credentials, or steer a response somewhere else.
// No adapter may forward them.
var credentialHeaders = map[string]bool{
	"Authorization": true, "Proxy-Authorization": true, "Cookie": true,
	"Set-Cookie": true, "X-Api-Key": true, "Api-Key": true,
	"X-Goog-Api-Key": true, "Location": true, "Www-Authenticate": true,
	"Proxy-Authenticate": true,
}

func (a Adapter) validate() error {
	if a.Name == "" || strings.ContainsAny(a.Name, "/?#%. ") {
		return fmt.Errorf("adapter name %q", a.Name)
	}
	if a.Host == "" || strings.ContainsAny(a.Host, "/:@?#% ") {
		return fmt.Errorf("adapter %s: host %q must be a bare host name", a.Name, a.Host)
	}
	if a.Credential == "" || a.Inject.Header == "" {
		return fmt.Errorf("adapter %s: credential and injection header required", a.Name)
	}
	if len(a.Operations) == 0 {
		return fmt.Errorf("adapter %s: no declared operations", a.Name)
	}
	for _, op := range a.Operations {
		if op.Name == "" || op.Method == "" || op.Method != strings.ToUpper(op.Method) {
			return fmt.Errorf("adapter %s: bad operation %+v", a.Name, op)
		}
		if _, err := splitPath(op.Path); err != nil {
			return fmt.Errorf("adapter %s: operation %s: %v", a.Name, op.Name, err)
		}
	}
	inject := http.CanonicalHeaderKey(a.Inject.Header)
	for _, h := range append(append([]string(nil), a.RequestHeaders...), a.ResponseHeaders...) {
		c := http.CanonicalHeaderKey(h)
		if credentialHeaders[c] || c == inject {
			return fmt.Errorf("adapter %s: may not forward header %s", a.Name, c)
		}
	}
	return nil
}

// match returns the operation that method and path satisfy.
func (a Adapter) match(method, path string) (Operation, bool) {
	segs, err := splitPath(path)
	if err != nil {
		return Operation{}, false
	}
	for _, op := range a.Operations {
		if op.Method != method {
			continue
		}
		tmpl, _ := splitPath(op.Path)
		if len(tmpl) != len(segs) {
			continue
		}
		ok := true
		for i, t := range tmpl {
			if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") {
				continue
			}
			if t != segs[i] {
				ok = false
				break
			}
		}
		if ok {
			return op, true
		}
	}
	return Operation{}, false
}

// splitPath accepts only clean absolute paths: no empty, "." or ".."
// segments, and no characters that would need escaping.
func splitPath(p string) ([]string, error) {
	if !strings.HasPrefix(p, "/") {
		return nil, errors.New("path must be absolute")
	}
	segs := strings.Split(p[1:], "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return nil, fmt.Errorf("path %q is not clean", p)
		}
		for _, c := range s {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.~{}:", c)) {
				return nil, fmt.Errorf("path %q has character %q", p, c)
			}
		}
	}
	return segs, nil
}
