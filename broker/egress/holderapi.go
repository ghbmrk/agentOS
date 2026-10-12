package egress

import (
	"net/http"
	"time"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// What a holder process (SIM-split, package holder) shares with the proxy:
// it checks the same declaration, forwards the same headers, swaps the
// same exchange shape, and dials through the same address policy.

// Validate checks the declaration, as New does.
func (a Adapter) Validate() error { return a.validate() }

// Match returns the declared operation that method and path satisfy.
func (a Adapter) Match(method, path string) (Operation, bool) { return a.match(method, path) }

// ForwardedRequestHeaders are the request headers the proxy forwards for a.
func (a Adapter) ForwardedRequestHeaders() []string {
	return append(append([]string(nil), baseRequestHeaders...), a.RequestHeaders...)
}

// ForwardedResponseHeaders are the response headers the proxy returns for a.
func (a Adapter) ForwardedResponseHeaders() []string {
	return append(append([]string(nil), baseResponseHeaders...), a.ResponseHeaders...)
}

// RefusesLogin reports whether status is one the operation declares as the
// provider refusing the login (CRED-5t).
func (op Operation) RefusesLogin(status int) bool { return op.refused(status) }

// SwapResponse checks an exchange response against the operation's
// declared shape, as the proxy does, and returns the body to forward with
// every credential swapped and the commit that stores them.
func (op Operation) SwapResponse(resp *http.Response, adapter string, sw Swapper) ([]byte, func() error, error) {
	rule := ResponseRule{Fields: append([]Field(nil), op.Response.Fields...)}
	if err := rule.compile(); err != nil {
		return nil, nil, err
	}
	return rule.swap(resp, adapter, sw)
}

// Encoded reports whether a response carries any Content-Encoding other
// than identity, which a redactor cannot read.
func Encoded(h http.Header) bool { return encoded(h) }

// DefaultTransport is the proxy's default upstream transport: no proxy
// from the environment, bounded connect, handshake and response-header
// waits, and every dial and handshake owned by g (DEV-2).
func DefaultTransport(g *netguard.Policy) *http.Transport {
	return &http.Transport{
		DialContext:           g.DialContext,
		TLSClientConfig:       g.TLSConfig(nil),
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Minute,
		IdleConnTimeout:       90 * time.Second,
	}
}
