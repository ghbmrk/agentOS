package corpus

// REQ: LOOP-7, ADP-11

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/owner"
)

// fakeRelay stands in for a guest machine: each route does what the real
// check on it does, unless open says the route lets everything through.
type fakeRelay struct {
	a    *mail.Adapter
	open map[string]bool
	err  error
}

func (f fakeRelay) Reply(_ context.Context, s string) (string, error) {
	if !f.open[CodeFilter] && owner.SecretShaped(s) {
		return "hidden", f.err
	}
	return owner.AgentPrefix + s, f.err
}

func (f fakeRelay) Label(_ context.Context, s string) (bool, error) {
	_, err := f.a.LabelClass(s)
	return f.open[LabelCheck] || err == nil, f.err
}

func (f fakeRelay) Archive(_ context.Context, s string) (bool, error) {
	return f.open[AlertPatterns] || !f.a.AlertWording(s), f.err
}

func (f fakeRelay) AutoReply(_ context.Context, s string) (bool, error) {
	return f.open[CommitmentFilter] || owner.Commitments{}.Match(s) == "", f.err
}

// LOOP-7 (P3-4b-4d): the checks taken through a guest keep Checks' names
// and payloads, and a guest path that holds reports nothing.
func TestPlaneChecksHoldOverThePublishedCorpus(t *testing.T) {
	checks := PlaneChecks(fakeRelay{a: adapter(t)})
	want := map[string]string{CodeFilter: CodePayload, AlertPatterns: AlertPayload, LabelCheck: LabelPayload,
		CommitmentFilter: CommitmentPayload}
	if len(checks) != len(want) {
		t.Fatalf("%d checks", len(checks))
	}
	for _, c := range checks {
		if p, ok := want[c.Name]; !ok || c.Payload != p || c.Deliver == nil || c.Hit != nil {
			t.Fatalf("check %q", c.Name)
		}
	}
	res, err := probe(t, checks).Run(context.Background())
	if err != nil || len(res.Found) != 0 || len(res.Checked) < 10 {
		t.Fatalf("%+v %v", res, err)
	}
}

// LOOP-7: a guest path that lets a check's payload through fails the run
// on the bare payload, and one that lets only attack texts through
// reports findings that carry an item ID and a check name, nothing of the
// text.
func TestAnOpenGuestPathIsFound(t *testing.T) {
	a := adapter(t)
	for _, name := range []string{CodeFilter, AlertPatterns, LabelCheck, CommitmentFilter} {
		if _, err := probe(t, PlaneChecks(fakeRelay{a: a, open: map[string]bool{name: true}})).Run(context.Background()); err == nil {
			t.Fatalf("%s: an open path passed its bare payload", name)
		}
	}
	p := probe(t, nil)
	ids := map[string]bool{}
	for _, it := range p.Items {
		ids[it.ID] = true
	}
	for _, c := range PlaneChecks(fakeRelay{a: a}) {
		inner := c.Deliver
		c.Deliver = func(ctx context.Context, s string) (bool, error) {
			caught, err := inner(ctx, s)
			return caught && s == c.Payload, err
		}
		p.Checks = []loops.ClosedCheck{c}
		res, err := p.Run(context.Background())
		if err != nil || len(res.Found) != len(p.Items) {
			t.Fatalf("%s: %+v %v", c.Name, res, err)
		}
		for _, f := range res.Found {
			if !ids[f.Subject] || f.Detail != c.Name || f.Check != loops.CheckCorpus || f.Rule != nil {
				t.Fatalf("finding %+v", f)
			}
		}
	}
}

// LOOP-7: a route the broker saw no outcome on fails the run.
func TestAFailedRouteFailsThePlaneRun(t *testing.T) {
	res, err := probe(t, PlaneChecks(fakeRelay{a: adapter(t), err: errors.New("guest gone")})).Run(context.Background())
	if err == nil || len(res.Found) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
}

// LOOP-7: a replayed text the owner's line would clip is no verdict for
// the code filter: the clip could drop the code, so the run fails before
// the guest is asked.
func TestATextOverOneOwnerTextFailsTheCodeFilter(t *testing.T) {
	asked := false
	r := fakeRelay{a: adapter(t)}
	for _, c := range PlaneChecks(askedRelay{r, &asked}) {
		if c.Name != CodeFilter {
			continue
		}
		long := CodePayload + strings.Repeat(" x", control.MaxText)
		if _, err := c.Deliver(context.Background(), long); err == nil || asked {
			t.Fatalf("an over-long text got a verdict (asked %v): %v", asked, err)
		}
		if caught, err := c.Deliver(context.Background(), CodePayload); err != nil || !caught || !asked {
			t.Fatalf("the bare payload: %v %v %v", caught, err, asked)
		}
	}
}

type askedRelay struct {
	fakeRelay
	asked *bool
}

func (r askedRelay) Reply(ctx context.Context, s string) (string, error) {
	*r.asked = true
	return r.fakeRelay.Reply(ctx, s)
}

// LOOP-7, ADP-11 (P3-4b-4e): the commitment filter's plane entry takes
// its verdict from what the broker did with the auto-reply: queued means
// the filter missed, a normal approval request means it caught the text,
// and a route error is no verdict either way.
func TestTheCommitmentFilterMapsTheBrokersVerdict(t *testing.T) {
	for _, tc := range []struct {
		queued, caught bool
		err            error
	}{{true, false, nil}, {false, true, nil}, {false, false, errors.New("the gate refused it")}} {
		c := planeCheck(t, verdictRelay{queued: tc.queued, err: tc.err}, CommitmentFilter)
		if c.Payload != CommitmentPayload {
			t.Fatalf("payload %q", c.Payload)
		}
		caught, err := c.Deliver(context.Background(), CommitmentPayload)
		if (err != nil) != (tc.err != nil) || tc.err == nil && caught != tc.caught {
			t.Fatalf("queued %v, err %v: caught %v, %v", tc.queued, tc.err, caught, err)
		}
	}
}

// verdictRelay answers every auto-reply with a fixed broker verdict.
type verdictRelay struct {
	fakeRelay
	queued bool
	err    error
}

func (r verdictRelay) AutoReply(context.Context, string) (bool, error) { return r.queued, r.err }

// planeCheck is PlaneChecks(r)'s check named name.
func planeCheck(t *testing.T, r Relay, name string) loops.ClosedCheck {
	t.Helper()
	for _, c := range PlaneChecks(r) {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no plane check %q", name)
	return loops.ClosedCheck{}
}
