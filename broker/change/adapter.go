package change

import (
	"fmt"
	"strings"

	"github.com/ghbmrk/agentos/broker/verb"
)

// Adapter is one tool's adapter file, adapters/<tool>.json (ADP-1). It
// maps each operation to a verb on the closed list, or to "" while the
// owner has not chosen one, which keeps it draft-only (ADP-2), and names
// the grants it needs. It has no field for a class or an observed effect:
// an adapter sets neither (ADP-2, ADP-8), and a file that tries does not
// parse.
type Adapter struct {
	Operations map[string]string `json:"operations"`
	Grants     []string          `json:"grants,omitempty"`
}

// DemoHarness exercises an adapter against its tool's demo or sandbox
// environment with synthetic data only, and reports what each run of each
// operation was observed to do there (ADP-8). The adapters target
// implements it; an error, including a tool with no demo environment,
// adopts nothing.
type DemoHarness interface {
	Demo(tool string, a Adapter) ([]verb.DemoRun, error)
}

// checkAdapter qualifies a change to an adapter (ADP-6). An adapter is
// never authority-neutral: the owner is asked, and sees its grants and any
// unmapped operation in the file. A new or changed adapter is adopted only
// if its demo run passes the mismatch check (ADP-8). Removing one needs no
// demo. A shared source cannot carry one (classify, CHG-5) and Export
// never shares one, so an adapter stays private-derived (OSS-3).
func (p *Pipeline) checkAdapter(cl *classification, e Edit) {
	cl.neutral = false
	tool, ok := strings.CutSuffix(strings.TrimPrefix(e.Path, "adapters/"), ".json")
	if !ok || tool == "" || strings.Contains(tool, "/") {
		cl.forbid("an adapter is adapters/<tool>.json")
		return
	}
	if e.After == nil {
		return
	}
	var a Adapter
	if err := decodeStrict(e.After, &a); err != nil {
		cl.forbid("adapter " + tool + " does not parse: " + err.Error())
		return
	}
	h, ok := p.cfg.Targets["adapters"].(DemoHarness)
	if !ok {
		cl.forbid("adapter " + tool + " has no demo harness to run its mismatch check (ADP-8)")
		return
	}
	runs, err := h.Demo(tool, a)
	if err != nil {
		cl.forbid("adapter " + tool + " demo run failed: " + err.Error())
		return
	}
	if op, why := verb.Mismatch(a.Operations, runs); why != "" {
		cl.forbid(fmt.Sprintf("adapter %s operation %q %s (ADP-8)", tool, op, why))
	}
}
