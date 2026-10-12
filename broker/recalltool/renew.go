package recalltool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// The owner's control over a lineage whose reads reached the cap
// (RECALL-prov-owner, CAP-3): the owner channel lists Full by agent name,
// AskRenew puts the renewal to the owner as the broker's own rollback
// question (the grants gate asks; its YES carries the texted code), and
// Execute runs Renew's take-back only on that approval.

// ErrNotFull: the lineage is not one Provenance.ReadsFull lists, so
// there is nothing to renew and nothing is asked.
var ErrNotFull = errors.New("recall: that agent's memory is not full")

// AgentName names a lineage by its root machine, which the broker chose
// (never guest text).
func AgentName(lineage string) string { return agentName(lineage) }

// Full lists the lineages whose reads reached the cap (ReadsFull).
func (r *Reach) Full() []string { return r.Prov.ReadsFull() }

func (r *Reach) full(lineage string) bool {
	for _, l := range r.Prov.ReadsFull() {
		if l == lineage {
			return true
		}
	}
	return false
}

// AskRenew asks the owner to start lineage's memory over: take its
// machines back to before its first read still held, which forgets every
// read since and loses the work since. Only a lineage Full lists is asked
// about. Each ask is a new question; an approval made stale by an earlier
// one changes nothing (Execute).
func (r *Reach) AskRenew(ctx context.Context, lineage string) error {
	if r.Ask == nil || r.Machines == nil {
		return errors.New("recall: renewal not wired")
	}
	if !r.full(lineage) {
		return ErrNotFull
	}
	first, ok := r.Prov.firstRead(lineage)
	if !ok {
		return ErrNotFull
	}
	plan, err := r.Machines.Plan(lineage, first)
	if err != nil {
		plan.To = first // unmeasured: only "before" the first read is claimed
	}
	object, detail := r.renewLine(lineage, plan, err == nil)
	since := first.UTC().Format(time.RFC3339Nano)
	h := sha256.Sum256([]byte(fmt.Sprintf("%s@%s#renew#%d", lineage, since, r.now().UnixNano())))
	in := journal.Intent{ID: "recall-renew-" + hex.EncodeToString(h[:12]), Origin: Origin, Account: journal.BrokerAccount,
		Action: journal.ActionRecallRollback, Executor: ExecutorName,
		Params: map[string]any{"lineage": lineage, "since": since, "renew": true, "object": object, "detail": detail}}
	st, err := r.Ask.Submit(in)
	if err != nil {
		return err
	}
	if st.State != journal.Pending {
		return fmt.Errorf("recall: renewal question is %s", st.State)
	}
	_, err = r.Ask.Authorize(ctx, in.ID)
	return err
}

// renewLine is the renewal question's object and detail, within the caps:
// what it does and what it costs, e.g.
//
//	forget root's reads to renew its memory, back to 12:20 Oct 5; work
//	since is lost
func (r *Reach) renewLine(lineage string, plan Plan, known bool) (object, detail string) {
	object = agentName(lineage) + "'s reads to renew its memory"
	if len(object) > fieldCap {
		object = "an agent's reads to renew its memory"
	}
	lead := "back to "
	var points []string
	if !known {
		// Unknown: plan.To is the first read, and only "before" it is
		// claimed.
		lead = "back before "
	}
	if plan.To.IsZero() {
		points = []string{"its start"}
	} else {
		t := plan.To.In(r.loc())
		points = []string{t.Format("15:04 Jan 2"), t.Format("15:04")}
	}
	for _, tail := range []string{"; work since is lost", "; work since lost"} {
		for _, p := range points {
			if d := lead + p + tail; len(d) <= fieldCap {
				return object, d
			}
		}
	}
	return object, "its work since then is lost"
}

// Renewal texts to the owner.
const (
	renewStale   = "Nothing to do: %s's memory is no longer full."
	renewCarried = "Not done yet: %s's memory has not started over. I keep trying."
	renewFailed  = "Not renewed: I couldn't start %s's memory over. Send RENEW to try again."
	// renewStaleEvidence closes an approval an earlier renewal or a
	// deletion's reach made moot.
	renewStaleEvidence = "nothing reset: that agent's memory is no longer full"
)

// executeRenew runs an approved renewal: Renew's take-back, if the
// lineage is still full from the same first read. Called without run.
func (r *Reach) executeRenew(ctx context.Context, lineage string, since time.Time) journal.Outcome {
	if r.Machines == nil {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "machines not wired"}
	}
	name := agentName(lineage)
	if first, ok := r.Prov.firstRead(lineage); !ok || !first.Equal(since) || !r.full(lineage) {
		r.tell(lineage, fmt.Sprintf(renewStale, name))
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: renewStaleEvidence}
	}
	plan, perr := r.Machines.Plan(lineage, since)
	err := r.TakeBack(ctx, lineage, since, true)
	switch {
	case err == nil:
		back := "its start"
		switch {
		case perr != nil:
			back = "before " + since.In(r.loc()).Format("15:04 Jan 2")
		case !plan.To.IsZero():
			back = plan.To.In(r.loc()).Format("15:04 Jan 2")
		}
		r.tell(lineage, fmt.Sprintf("Done: %s's memory starts over; its reads are forgotten and it is back to %s. Actions it took stay done.", name, back))
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "renewed"}
	case errors.Is(err, ErrCarried):
		// Recorded owed before the machines were touched: Retry carries
		// it through, across a restart too.
		r.logf("recall: renewal of %s still owed: %v", lineage, err)
		r.tell(lineage, fmt.Sprintf(renewCarried, name))
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: approvedOnly + "the reset did not finish"}
	}
	r.logf("recall: renewal of %s not run: %v", lineage, err)
	r.tell(lineage, fmt.Sprintf(renewFailed, name))
	return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "renewal not recorded"}
}
