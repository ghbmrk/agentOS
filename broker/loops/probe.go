package loops

import (
	"context"
	"time"
)

// LOOP-7 probes (P3-4b-4a): off-the-shelf active tests. A probe never
// writes or generates an attack: it replays published corpora or fixed
// scripts (D-067). Nothing runs them since the Guard was deleted with the
// change pipeline (#2785).

// Checks a probe reports. Their findings carry no tree rule: the probe
// that found one is its regression, and the probe's next clean run of the
// same subject closes it.
const (
	CheckCanary Check = "canary" // a canary round found a planted test secret where the adversary could reach it (A5)
	CheckCorpus Check = "corpus" // a published injection item got past a closed check
)

// Probe is one LOOP-7 source. Run makes no model calls. It returns what it
// found and the subjects it checked; an error with a result means part of
// the run failed, so its findings are reported but nothing is closed.
type Probe interface {
	Check() Check
	// Every is how often the probe runs.
	Every() time.Duration
	Run(ctx context.Context) (ProbeResult, error)
}

// ProbeResult is one run's outcome.
type ProbeResult struct {
	Found []Finding
	// Checked are the subjects the run tested, found or not.
	Checked []string
}
