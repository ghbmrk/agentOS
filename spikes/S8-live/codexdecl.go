//go:build ignore

// codexdecl prints what qualify.py checks a live run against, read from the
// Codex declaration itself (broker/clerk/plan Codex): the refresh body's
// fixed values and the refresh headers. run.sh runs it from broker/:
// go run ../spikes/S8-live/codexdecl.go
package main

import (
	"encoding/json"
	"os"

	"github.com/ghbmrk/agentos/broker/clerk/plan"
)

func main() {
	d := plan.Codex(nil)
	if err := json.NewEncoder(os.Stdout).Encode(map[string]map[string]string{
		"refresh": d.Refresh, "refresh_headers": d.RefreshHeaders,
	}); err != nil {
		os.Exit(1)
	}
}
