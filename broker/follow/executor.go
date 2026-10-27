package follow

// The journal executor for meta.update.follow, kept only while agentosd
// still routes the page's grants.FollowIntent through the journal. f2
// (#3430) wires the follow clerk (clerk.go) in agentosd and deletes this
// file; nothing else in the package imports journal or grants
// (TestOnlyTheExecutorImportsTheOldCore).

import (
	"context"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
)

// parse reads what an intent asks for: the digest and the name. why is set
// when the intent is not a well-formed follow.
func parse(in journal.Intent) (digest, name, why string) {
	if in.Action != journal.ActionUpdateFollow {
		return "", "", "not a request to change where updates come from"
	}
	digest, name, ok := grants.FollowOf(in.ID)
	if !ok {
		return "", "", "malformed request to change where updates come from"
	}
	return digest, name, ""
}

var results = map[switched]journal.Result{
	notSwitched: journal.ResultNotApplied, switchedOK: journal.ResultSucceeded, switchedUnknown: journal.ResultUnknown,
}

// Execute switches to the held root the intent's digest names.
func (x *Executor) Execute(ctx context.Context, in journal.Intent, _ int) journal.Outcome {
	digest, name, why := parse(in)
	if why != "" {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: why}
	}
	s, ev := x.switchTo(ctx, digest, name)
	return journal.Outcome{Result: results[s], Evidence: ev}
}

// Reconcile reports a switch done when the box trusts the root the intent
// approved, under the intent's name, and alerts again (at least once).
func (x *Executor) Reconcile(ctx context.Context, in journal.Intent, _ int) journal.Outcome {
	digest, name, why := parse(in)
	if why != "" {
		return journal.Outcome{Result: journal.ResultUnknown, Evidence: why}
	}
	s, ev := x.settled(digest, name)
	if s == switchedOK {
		ev += x.alert(ctx, name, x.latest(ctx))
	}
	return journal.Outcome{Result: results[s], Evidence: ev}
}

// Route shares the "update" executor name between following and release
// activation (apply): follows go to f, everything else to other. Without
// other, nothing but a follow runs.
func Route(f *Executor, other journal.Executor) journal.Executor {
	return router{f, other}
}

type router struct {
	f     *Executor
	other journal.Executor
}

func (r router) pick(in journal.Intent) journal.Executor {
	if in.Action == journal.ActionUpdateFollow {
		return r.f
	}
	return r.other
}

func (r router) Execute(ctx context.Context, in journal.Intent, attempt int) journal.Outcome {
	x := r.pick(in)
	if x == nil {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "no executor for " + in.Action}
	}
	return x.Execute(ctx, in, attempt)
}

func (r router) Reconcile(ctx context.Context, in journal.Intent, attempt int) journal.Outcome {
	x := r.pick(in)
	if x == nil {
		return journal.Outcome{Result: journal.ResultUnknown, Evidence: "no executor for " + in.Action}
	}
	return x.Reconcile(ctx, in, attempt)
}
