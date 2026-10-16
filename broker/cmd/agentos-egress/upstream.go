//go:build !agentos_e2e

package main

import (
	"net/http"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// planUpstream is the plan route's way to the provider when the custody
// sets none: nil, so the route dials through the address guard. Only the
// agentos_e2e build (upstream_e2e.go) answers otherwise.
func planUpstream(*netguard.Policy) http.RoundTripper { return nil }
