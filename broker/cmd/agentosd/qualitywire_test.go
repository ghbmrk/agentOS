package main

// REQ: OP-7, SM-AQ-1, SM-AQ-4

import (
	"context"
	"testing"

	"github.com/ghbmrk/agentos/broker/loops"
)

type fakeQuality struct {
	due  bool
	runs int
}

func (f *fakeQuality) QualityDue() bool { return f.due }
func (f *fakeQuality) RecheckQuality(context.Context) ([]string, error) {
	f.runs++
	f.due = false
	return []string{"c1"}, nil
}

type innerSource struct{ offered int }

func (s *innerSource) Loop() loops.Loop { return loops.Improve }
func (s *innerSource) Next(context.Context, bool) (loops.Job, bool) {
	s.offered++
	return loops.Job{Name: "inner"}, true
}

// The scheduler is offered the re-evaluation while a revision is due, and
// Loop 1's own work otherwise.
func TestQualitySourceOffersRecheckWhenDue(t *testing.T) {
	q, in := &fakeQuality{due: true}, &innerSource{}
	src := qualitySource{Source: in, pipe: q, model: true}
	if _, ok := src.Next(context.Background(), false); !ok || q.runs != 0 {
		// Without the model, Loop 1's model-free work still runs.
		t.Fatal("no fallback without the model")
	}
	job, ok := src.Next(context.Background(), true)
	if !ok || job.Name != "requality" || !job.Evaluates || !job.UsesModel {
		t.Fatalf("job %+v", job)
	}
	if r := job.Run(context.Background()); r.Err != nil || r.Value != 1 || q.runs != 1 {
		t.Fatalf("run %+v, %d runs", r, q.runs)
	}
	if job, _ := src.Next(context.Background(), true); job.Name != "inner" {
		t.Fatalf("not due: offered %q", job.Name)
	}
}
