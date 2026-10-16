//go:build agentos_e2e

package main

import (
	"net/http"

	"github.com/ghbmrk/agentos/broker/e2e/boxe2e/codexstub"
	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// planUpstream, in the in-image end-to-end build only (#1701), sends the
// Codex hosts to the box-e2e stub's socket and everything else through the
// address guard. The shipped image never carries this build.
func planUpstream(g *netguard.Policy) http.RoundTripper {
	return codexstub.Transport(codexstub.Socket, egress.DefaultTransport(g))
}
