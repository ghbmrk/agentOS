package codexstub

import (
	"context"
	"net"
	"net/http"

	"github.com/ghbmrk/agentos/broker/egress"
)

// Transport sends https requests for the Codex hosts to the stub on the
// unix socket sock, as plain HTTP with the request's own Host, and every
// other request to fallback. Only the agentos_e2e egress build uses it.
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
	if r.URL.Scheme == "https" && t.hosts[r.URL.Host] {
		return t.stub.RoundTrip(r)
	}
	return t.fallback.RoundTrip(r)
}
