package loops

import (
	"context"
	"testing"
	"time"
)

// ProbeRig runs a probe through Guard for tests in package loops_test,
// which may import a probe package that imports loops (probecmd).
type ProbeRig struct{ r *reportRig }

func NewProbeRig(t *testing.T, p Probe) *ProbeRig {
	r := newReportRig(t, nil)
	r.probes = []Probe{p}
	r.reopen(t)
	return &ProbeRig{r}
}

// Run takes and runs Guard's next job.
func (x *ProbeRig) Run(t *testing.T) (string, Result) { return runJob(t, x.r.g, context.Background()) }

func (x *ProbeRig) Evidence() []Record      { return x.r.g.Evidence() }
func (x *ProbeRig) Advance(d time.Duration) { x.r.now = x.r.now.Add(d) }

// Contained names what was contained, in order.
func (x *ProbeRig) Contained() []string {
	var n []string
	for _, t := range x.r.c.got {
		n = append(n, t.Name)
	}
	return n
}

func (x *ProbeRig) Open(id string) bool { _, ok := x.r.open(id); return ok }
