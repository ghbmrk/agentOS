package guest

import (
	"net/http"

	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/route"
)

// Routed is the Model a box with the model router (P2-7) serves: each
// machine's /model/ path goes to the router's handler for that machine,
// which translates the guest's OpenAI chat completions for whichever
// provider routes the class and reaches it only through the egress proxy.
// The plane meters it like any Model (OP-8, Plane.model), so it is not
// wrapped again here; the router reports each served call's provider
// usage into the metered call, so the meter settles from it even when
// the guest asked for no usage and the response it got carries none.
// Configure the meter's MaxReserve as the router's MaxOutputTokens.
func Routed(r *route.Router) func(machine string) http.Handler {
	return func(machine string) http.Handler {
		h := r.Handler(machine)
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := req.Context()
			ctx = route.WithUsage(ctx, func(provider string, u route.Usage) {
				meter.Report(req.Context(), meter.Usage{
					Provider: provider, Input: u.Input, Output: u.Output, CacheRead: u.CacheRead, CacheWrite: u.CacheWrite,
					Reported: u.Reported, Complete: u.Complete, OutputChars: u.OutputChars,
				})
			})
			h.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}
