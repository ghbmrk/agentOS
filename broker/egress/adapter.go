package egress

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/ghbmrk/agentos/broker/verb"
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

// Operation is one declared request shape. Verb maps it to one verb of the
// broker's closed list (ADP-2). Path is a template of literal segments and
// {name} segments, each of which matches one non-empty segment. Body, when
// set, requires a JSON object body and constrains it.
type Operation struct {
	Name   string
	Verb   string
	Method string
	Path   string
	Body   *BodyRule
}

// The broker's closed verb list (ADP-2), from package verb. An adapter maps
// each operation to one of these; it cannot define its own.
const (
	VerbRead          = verb.Read
	VerbDraft         = verb.Draft
	VerbSend          = verb.Send
	VerbPost          = verb.Post
	VerbBuy           = verb.Buy
	VerbShare         = verb.Share
	VerbDeleteRemote  = verb.DeleteRemote
	VerbChangeAccount = verb.ChangeAccount
	VerbRevealSecret  = verb.RevealSecret
)

// BodyRule constrains a JSON request body (ADP-10). The proxy decodes the
// body, checks it, applies Set, and forwards its own re-encoding, so the
// provider parses exactly what was checked (no duplicate keys, no trailing
// data).
type BodyRule struct {
	// DenyKeys are top-level keys that may never appear.
	DenyKeys []string
	// Every body with a rule is held to the strict form unless
	// PublicMayFetch is set and the calling machine is labelled public
	// (REV-5). The strict form keeps the provider off the network with the
	// owner's key: tools[] entries must be client-executed (no "type", or
	// "function" or "custom"), none of ServerToolKeys may appear, and no
	// remote content source may appear (see remoteSource). Server tools,
	// remote MCP, and URL image or document sources would each have the
	// provider fetch from an address the guest chose.
	PublicMayFetch bool
	// ServerToolKeys are top-level keys that switch on provider-side tools.
	ServerToolKeys []string
	// Set forces top-level keys, e.g. store:false.
	Set map[string]any
}

// OpenAI is the OpenAI-compatible model relay: inference endpoints only
// (CRED-5, ADP-10).
func OpenAI(credential string) Adapter {
	return Adapter{
		Name:       "openai",
		Host:       "api.openai.com",
		Credential: credential,
		Inject:     Injection{Header: "Authorization", Prefix: "Bearer "},
		Operations: []Operation{{
			Name: "chat.completions", Verb: VerbRead, Method: "POST", Path: "/v1/chat/completions",
			Body: &BodyRule{
				DenyKeys:       []string{"background"},
				PublicMayFetch: true,
				ServerToolKeys: []string{"web_search_options", "mcp_servers", "container"},
				Set:            map[string]any{"store": false},
			},
		}},
	}
}

// Anthropic is the Anthropic Messages relay: inference endpoints only. It
// is not yet qualified as a guest interface (ARC-6 (a) qualifies OpenAI
// chat completions only); it exists so the declaration is reviewed with
// the rest. Anthropic-Beta is not forwarded: betas switch on server tools.
func Anthropic(credential string) Adapter {
	return Adapter{
		Name:       "anthropic",
		Host:       "api.anthropic.com",
		Credential: credential,
		Inject:     Injection{Header: "X-Api-Key"},
		Operations: []Operation{{
			Name: "messages", Verb: VerbRead, Method: "POST", Path: "/v1/messages",
			Body: &BodyRule{
				DenyKeys:       []string{"background"},
				PublicMayFetch: true,
				ServerToolKeys: []string{"mcp_servers", "container"},
			},
		}},
		RequestHeaders: []string{"Anthropic-Version"},
	}
}

// Headers a guest may send and a provider may return, for every adapter.
// Everything else is dropped. The proxy itself sends Accept-Encoding:
// identity and refuses encoded responses, so it always redacts plain bytes.
var (
	baseRequestHeaders  = []string{"Content-Type", "Accept", "User-Agent"}
	baseResponseHeaders = []string{"Content-Type", "Retry-After", "X-Request-Id", "Request-Id"}
)

// Header names no adapter may forward: they carry credentials, pick the
// account or project billed, or steer a response somewhere else. Any name
// containing one of credentialWords is refused too.
var credentialHeaders = map[string]bool{
	"Location": true, "Openai-Organization": true, "Openai-Project": true,
	"Anthropic-Beta": true, "Accept-Encoding": true, "Content-Encoding": true,
}

var credentialWords = []string{"auth", "key", "token", "session", "cookie", "secret", "password"}

func forbiddenHeader(canonical string) bool {
	if credentialHeaders[canonical] {
		return true
	}
	l := strings.ToLower(canonical)
	for _, w := range credentialWords {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
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
		if !verb.Valid(op.Verb) {
			return fmt.Errorf("adapter %s: operation %s: verb %q is not on the broker's list (ADP-2)", a.Name, op.Name, op.Verb)
		}
		if _, err := splitPath(op.Path); err != nil {
			return fmt.Errorf("adapter %s: operation %s: %v", a.Name, op.Name, err)
		}
	}
	inject := http.CanonicalHeaderKey(a.Inject.Header)
	for _, h := range append(append([]string(nil), a.RequestHeaders...), a.ResponseHeaders...) {
		c := http.CanonicalHeaderKey(h)
		if forbiddenHeader(c) || c == inject {
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
