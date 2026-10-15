package codexstub

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/ghbmrk/agentos/broker/egress"
)

// Transport sends https requests for the Codex hosts, with or without a
// port, to the stub on the unix socket sock, as plain HTTP with the
// request's own Host, and every other request to fallback. A request for a
// Codex host on any other scheme fails, so no Codex request leaves for the
// internet. Only the agentos_e2e egress build uses it.
func Transport(sock string, fallback http.RoundTripper) http.RoundTripper {
	set := map[string]bool{}
	for _, h := range hosts(egress.Codex()) {
		set[h] = true
	}
	// DialTLSContext's conn is used as is: no TLS and no HTTP/2 on the
	// socket, which only the stub serves.
	stub := &http.Transport{DisableCompression: true}
	stub.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}
	stub.DialTLSContext = stub.DialContext
	return &stubTransport{hosts: set, stub: stub, fallback: fallback}
}

type stubTransport struct {
	hosts    map[string]bool
	stub     http.RoundTripper
	fallback http.RoundTripper
}

func (t *stubTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !t.hosts[strings.ToLower(r.URL.Hostname())] {
		return t.fallback.RoundTrip(r)
	}
	if r.URL.Scheme != "https" {
		return nil, fmt.Errorf("codexstub: %s request for a Codex host", r.URL.Scheme)
	}
	return t.stub.RoundTrip(r)
}
