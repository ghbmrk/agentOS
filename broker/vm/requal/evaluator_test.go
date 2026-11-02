package requal

// REQ: UPD-5, EVL-3, HLD-2, HLD-3

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/update"
	"github.com/ghbmrk/agentos/broker/update/updatetest"
	drv "github.com/ghbmrk/agentos/broker/vm/requal/driver"
)

// TestTheShippedEvaluatorRequalifiesOnTheShippedSuite (UPD-5r-b7): the
// release's injection tests, held in the log, run through the production
// sandbox's channel and metering into the shipped driver's security
// evaluator, which runs the release's own reader, planner, kernel and clerk;
// the host grades every case a pass, so a candidate equal to the baseline
// requalifies, whatever the reader model answers.
func TestTheShippedEvaluatorRequalifiesOnTheShippedSuite(t *testing.T) {
	ctx := context.Background()
	b := newBox(t)
	n := b.seed(t)
	if n == 0 {
		t.Fatal("no shipped security case")
	}
	for name, model := range map[string]ModelFunc{
		// A reader the content fully steers: it answers with the mail.
		"echo": func(_ context.Context, req []byte) ([]byte, error) { return req, nil },
		"spam": func(context.Context, []byte) ([]byte, error) { return []byte("spam"), nil },
	} {
		st := &fakeStreams{eval: func(<-chan struct{}) drv.Evaluator { return drv.Security }}
		sb := newSandbox(t, st, &fakeImages{}, func(c *SandboxConfig) {
			c.Models, c.ModelCalls, c.MaxOutput = model, 6*n, 64<<10
		})
		suites := map[string]Suite{
			update.SuiteHeldOut:  {cases{}, echo},
			update.SuiteReplay:   {cases{}, echo},
			update.SuiteSecurity: SecuritySuite(b),
		}
		v, store := updatetest.Box(t, 2, false, map[string][]byte{"host-image/usr.img": []byte("usr-2")})
		q, err := update.NewRequalifier(store, runner(t, sb, suites), filepath.Join(t.TempDir(), "requal.json"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := q.Requalify(ctx, v)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		sec := got.Scores[2]
		if !got.Passed || sec.Cases != n || sec.Passed != n {
			t.Fatalf("%s: %+v", name, got)
		}
	}
}
