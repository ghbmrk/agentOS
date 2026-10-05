package cleanroom

import (
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/hint"
)

// REQ: OSS-11
//
// TR2: the public repository is a publication channel, not a runtime
// dependency. The hint emitter's outbox is the clean-room builder, whose
// queue and results live in a local directory: a day's hints cross,
// build and are stored with no repository reachable or configured.
func TestTheHintOutboxWorksFromALocalDirectory(t *testing.T) {
	r := newRig(t, nil)
	r.f.guest = func(id, dir string) {
		c := client(dir)
		call(c, "GET", "/cleanroom/hint", nil)
		if code, body := call(c, "POST", "/cleanroom/result", goodResult()); code != 200 {
			t.Errorf("result: %d %s", code, body)
		}
	}
	now := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	e, err := hint.New(hint.Config{Log: &hint.MemLog{}, Outbox: r.b, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	h := hint.Hint{Kind: "skill_gap", Fields: map[string]string{"domain": "calendar", "format": "ics", "failure": "timezone", "frequency": "sometimes"}}
	if res, err := e.Emit(h); err != nil || res.Outcome != hint.Queued {
		t.Fatalf("emit: %+v %v", res, err)
	}
	now = now.Add(24 * time.Hour)
	if err := e.Release(); err != nil {
		t.Fatal(err)
	}
	jobs, err := r.queued()
	if err != nil || len(jobs) != 1 {
		t.Fatalf("queued in %s: %d %v", r.cfg.Dir, len(jobs), err)
	}
	r.run()
	waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
	if o := r.outcomes()[0]; o.Result != "built" || o.Artifact == "" {
		t.Fatalf("outcome %+v", o)
	}
}
