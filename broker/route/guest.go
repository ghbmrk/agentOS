package route

import (
	"net/http"

	"github.com/ghbmrk/agentos/broker/meter"
)

// Routed is the guest plane's Model for a box with the model router
// (P2-7): each machine's /model/ path goes to the router's handler for
// that machine, which translates the guest's OpenAI chat completions for
// whichever provider routes the class and reaches it only through the
// egress proxy. The plane meters it like any Model (OP-8), so it is not
// wrapped again here; the router reports each served call's provider
// usage into the metered call, so the meter settles from it even when the
// guest asked for no usage and the response it got carries none.
// Configure the meter's MaxReserve as the router's MaxOutputTokens. It
// lives here, not in guest, so the guest plane links no router (ARC-2).
// It does not report meter.Usage's NoResponse or Unanswered (#84), so a
// failed upstream call is metered as the guest saw it; agentosd forwards
// to the vault process through modelroute, which does, and Routed must
// not take its place without that rule.
func Routed(r *Router) func(machine string) http.Handler {
	return func(machine string) http.Handler {
		h := r.Handler(machine)
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := WithUsage(req.Context(), func(provider string, u Usage) {
				meter.Report(req.Context(), meter.Usage{
					Provider: provider, Input: u.Input, Output: u.Output, CacheRead: u.CacheRead, CacheWrite: u.CacheWrite,
					Reported: u.Reported, Complete: u.Complete, OutputChars: u.OutputChars,
				})
			})
			h.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}
