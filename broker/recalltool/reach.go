package recalltool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/recall"
)

// Journal is the part of the broker's journal deletion reaches
// (journal.Engine).
type Journal interface {
	Between(origin string, from, until time.Time) []string
	Erase(ids []string) (erased, held []string, err error)
	Get(id string) (journal.Status, error)
}

// Machines is the part of the VM manager deletion reaches (vm.Manager,
// adapted by agentosd).
type Machines interface {
	ForgetSince(ctx context.Context, lineage string, since time.Time) error
	Plan(lineage string, since time.Time) (Plan, error)
}

// Plan is what a ForgetSince would take back now (vm.ResetPlan): the
// oldest restore point among the lineage's machines (zero: a fresh start)
// and the files changed since it.
type Plan struct {
	To      time.Time
	Changes int
}

// Cases is the part of the change pipeline deletion reaches
// (change.Pipeline).
type Cases interface {
	ForgetTasks(tasks ...string) (int, error)
}

// Asker submits the broker's rollback intents for the owner's approval
// (the grants gate: Submit, Authorize, Get).
type Asker interface {
	Submit(in journal.Intent) (journal.Status, error)
	Authorize(ctx context.Context, id string) (journal.Status, error)
	Get(id string) (journal.Status, error)
}

// The broker's rollback intents (journal.ActionRecallRollback). The grants
// gate checks the same names (grants.OriginRecall, grants.RecallExecutor).
const (
	ExecutorName = "recall"
	Origin       = "broker:recall"
)

// ownerNo is how the journal records the owner's own NO on an approval
// (grants: "not approved: " + the owner channel's Why). Any other denial
// (expired, void, restart) is no answer.
const ownerNo = "not approved: owner"

// Reach carries a recall deletion past the index (CAP-3, K2b). A fork
// lineage the provenance record says was given deleted items, the first
// at T, is taken back from T:
//
//  1. its machines go back to their newest snapshots from before T (the
//     restore point) and its snapshots from T on are deleted (Machines);
//     the reset time R is recorded in the provenance record at once;
//  2. the journal intents it submitted from T until R are erased:
//     parameters and evidence go, the audit trail stays (Journal). Replay
//     recordings are read from the journal, so they go with them;
//  3. change-pipeline cases built on those intents are removed (Cases);
//  4. the provenance record forgets what it was given from T until R.
//     What it was given after the reset stays (#59 L3 2).
//
// The owner decides when that loses work (Mark, 2026-10-05; W10, and the
// #59 arbitrator): a lineage that has done no work since T (no action
// that took effect, no file changed since the restore point) is taken
// back at once. One that has is asked about once, at its earliest T, with
// the restore point and the actions so far; meanwhile it keeps running
// but is contained (Contained). YES takes it back and confirms with the
// real count (Notify); the owner's NO keeps its work and lifts the
// containment, though recall still refuses notes derived from the item;
// no answer keeps it pending and contained. The item itself is gone from
// recall at once either way.
//
// An intent still in flight is held: the deletion stays pending and Retry
// finishes it once the intent settles. A failure keeps it pending too.
// After a crash the index's replay of its tombstones at start runs the
// reach again; a recorded reset is finished, not repeated.
type Reach struct {
	Prov     *Provenance
	Journal  Journal  // nil: not wired
	Machines Machines // nil: not wired; nothing is taken back
	Cases    Cases    // nil: not wired
	// Deleted reports an item the owner deleted (recall.Index.Deleted).
	Deleted func(id string) bool
	// Ask is where a rollback that loses work goes for approval. Nil:
	// such a rollback waits (pending) and nothing is undone.
	Ask Asker
	// Notify tells the owner an approved rollback is done (the owner
	// channel). Nil: not told.
	Notify func(text string) error
	// Location is the owner's time zone for the owner's texts.
	Location *time.Location
	Now      func() time.Time
	Logf     func(format string, args ...any)

	// run serializes settling and executing, so an approval running while
	// Retry settles the same lineage does not reset it twice.
	run     sync.Mutex
	mu      sync.Mutex
	pending map[string]bool   // deleted item IDs not yet fully reached
	kinds   map[string]string // deleted item ID -> source kind, as deleted
	// held: lineages asked about and not yet taken back (contained);
	// kept: lineages the owner said NO for, which still hold a deleted
	// record.
	held, kept map[string]bool
}

// Contained reports a lineage being asked about, or left unanswered: no
// fork, merge, pre-allowance or note until it is settled (#59 W10, C2).
func (r *Reach) Contained(lineage string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.held[lineage]
}

// Status is a line for STATUS while some agent still holds a record the
// owner deleted, or "".
func (r *Reach) Status() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var names []string
	for l := range r.kept {
		names = append(names, agentName(l))
	}
	for l := range r.held {
		if !r.kept[l] {
			names = append(names, agentName(l))
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return strings.Join(names, ", ") + " still holds a record you deleted"
}

func (r *Reach) set(m *map[string]bool, lineage string, on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !on {
		delete(*m, lineage)
		return
	}
	if *m == nil {
		*m = map[string]bool{}
	}
	(*m)[lineage] = true
}

// errWaiting keeps a deletion pending while the owner decides.
var errWaiting = errors.New("waiting for the owner")

// OnDelete is the recall.Index deletion hook. A deletion waiting for the
// owner is not an error.
func (r *Reach) OnDelete(d recall.Deleted) error {
	if d.Source.Kind != "" {
		r.mu.Lock()
		if r.kinds == nil {
			r.kinds = map[string]string{}
		}
		r.kinds[d.ID] = d.Source.Kind
		r.mu.Unlock()
	}
	if err := r.reach(context.Background(), d.ID); !errors.Is(err, errWaiting) {
		return err
	}
	return nil
}

// Retry runs every pending deletion again; Service.Run calls it.
func (r *Reach) Retry(ctx context.Context) error {
	r.mu.Lock()
	ids := make([]string, 0, len(r.pending))
	for id := range r.pending {
		ids = append(ids, id)
	}
	r.mu.Unlock()
	sort.Strings(ids)
	var errs []error
	for _, id := range ids {
		if err := r.reach(ctx, id); err != nil && !errors.Is(err, errWaiting) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Pending reports how many deletions are not yet fully reached.
func (r *Reach) Pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

func (r *Reach) reach(ctx context.Context, id string) error {
	holders := r.Prov.Holders(id)
	lineages := make([]string, 0, len(holders))
	for l := range holders {
		lineages = append(lineages, l)
	}
	sort.Strings(lineages)
	var errs []error
	waiting := false
	for _, l := range lineages {
		err := r.settle(ctx, l)
		switch {
		case errors.Is(err, errWaiting):
			waiting = true
		case err != nil:
			errs = append(errs, fmt.Errorf("deletion reach into %s: %w", l, err))
		}
	}
	err := errors.Join(errs...)
	r.mu.Lock()
	if r.pending == nil {
		r.pending = map[string]bool{}
	}
	if err != nil || waiting {
		r.pending[id] = true
	} else {
		delete(r.pending, id)
	}
	r.mu.Unlock()
	if err != nil && r.Logf != nil {
		r.Logf("recall: %v", err)
	}
	if err == nil && waiting {
		return errWaiting
	}
	return err
}

// held lists the deleted items lineage holds and the earliest time it was
// given one.
func (r *Reach) heldBy(lineage string) (ids []string, first time.Time) {
	for id, t := range r.Prov.Items(lineage) {
		if r.Deleted == nil || !r.Deleted(id) {
			continue
		}
		ids = append(ids, id)
		if first.IsZero() || t.Before(first) {
			first = t
		}
	}
	sort.Strings(ids)
	return ids, first
}

// settle takes lineage back from the first deleted item it was given, at
// once or once the owner approves.
func (r *Reach) settle(ctx context.Context, lineage string) error {
	if r.Machines == nil {
		// Its memory cannot be reached, so it keeps what it was given;
		// notes derived from a deleted item are still refused.
		return nil
	}
	r.run.Lock()
	defer r.run.Unlock()
	// A reset already done (an approval run, or before a restart) is
	// finished, never repeated.
	for _, rs := range r.Prov.Resets(lineage) {
		if err := r.finish(lineage, rs); err != nil {
			return err
		}
	}
	ids, since := r.heldBy(lineage)
	if len(ids) == 0 {
		r.set(&r.held, lineage, false)
		r.set(&r.kept, lineage, false)
		return nil
	}
	actions := r.actions(lineage, since, time.Time{})
	plan, err := r.Machines.Plan(lineage, since)
	if err != nil {
		plan.Changes = 1 // unmeasured: ask rather than lose work unasked
	}
	if actions == 0 && plan.Changes == 0 {
		return r.reset(ctx, lineage, since, false)
	}
	r.set(&r.held, lineage, true)
	if r.Ask == nil {
		return errWaiting
	}
	id, st, err := r.current(lineage, since, ids)
	if errors.Is(err, errKept) {
		r.set(&r.held, lineage, false)
		r.set(&r.kept, lineage, true)
		return nil
	}
	if err != nil {
		// First ask: the line is fixed now, so a later count does not
		// make the same intent disagree with itself (OP-1).
		object, detail := r.line(lineage, ids, plan.To, actions)
		in := journal.Intent{ID: id, Origin: Origin, Account: journal.BrokerAccount,
			Action: journal.ActionRecallRollback, Executor: ExecutorName,
			Params: map[string]any{"lineage": lineage, "since": since.UTC().Format(time.RFC3339Nano),
				"items": strings.Join(ids, ","), "object": object, "detail": detail}}
		if st, err = r.Ask.Submit(in); err != nil {
			return err
		}
	}
	switch st.State {
	case journal.Pending:
		if _, err := r.Ask.Authorize(ctx, id); err != nil {
			return err
		}
		return errWaiting
	case journal.Succeeded:
		// Approved, but Execute could not reset the machines: do it now.
		return r.reset(ctx, lineage, since, true)
	case journal.Denied:
		// No answer is not a decline: pending and contained until the
		// owner answers (the digest asks again; BOARD W5).
		return errWaiting
	default:
		return errWaiting
	}
}

// errKept: the owner said NO to taking back every deleted item lineage
// holds.
var errKept = errors.New("kept by the owner")

// current finds the lineage's rollback question for since: the first one
// asked, or, once the owner said NO to it, one naming the deleted items
// that NO did not cover. ids: the deleted items it holds now. An error
// other than errKept means no question exists yet: Submit one as id.
func (r *Reach) current(lineage string, since time.Time, ids []string) (string, journal.Status, error) {
	id := rollbackID(lineage, since, nil)
	for {
		st, err := r.Ask.Get(id)
		if err != nil {
			return id, st, err
		}
		if st.State != journal.Denied || st.Permission.Reason != ownerNo {
			return id, st, nil
		}
		// NO keeps everything it named (#59 arbitrator, W10). An item
		// deleted after that is a new question, asked once.
		asked, _ := st.Intent.Params["items"].(string)
		covered := map[string]bool{}
		for _, a := range strings.Split(asked, ",") {
			covered[a] = true
		}
		all := true
		for _, x := range ids {
			all = all && covered[x]
		}
		if all {
			return id, st, errKept
		}
		next := rollbackID(lineage, since, ids)
		if next == id {
			return id, st, errKept
		}
		id = next
	}
}

// actions counts the intents lineage carried out from since (until R, if
// not zero): succeeded, in flight, or of unknown outcome. Denied, refused
// or never-run intents change nothing outside (#59 security B2).
func (r *Reach) actions(lineage string, since, until time.Time) int {
	if r.Journal == nil {
		return 0
	}
	n := 0
	for _, id := range r.Journal.Between("guest:"+lineage, since, until) {
		st, err := r.Journal.Get(id)
		if err != nil {
			n++ // unknown: count it, so the owner is asked
			continue
		}
		switch st.State {
		case journal.Succeeded, journal.InFlight, journal.OutcomeUnknown:
			n++
		}
	}
	return n
}

// Execute runs an approved rollback intent (the journal executor named
// ExecutorName).
func (r *Reach) Execute(ctx context.Context, in journal.Intent, _ int) journal.Outcome {
	lineage, _ := in.Params["lineage"].(string)
	s, _ := in.Params["since"].(string)
	since, err := time.Parse(time.RFC3339Nano, s)
	if in.Action != journal.ActionRecallRollback || in.Origin != Origin || in.Account != journal.BrokerAccount || lineage == "" || err != nil {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "malformed recall rollback"}
	}
	if r.Machines == nil {
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: approvedOnly + "machines not wired"}
	}
	r.run.Lock()
	defer r.run.Unlock()
	for _, rs := range r.Prov.Resets(lineage) {
		if rs.Since.Equal(since) {
			return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "machines reset; finishing"}
		}
	}
	// A stale approval undoes nothing (#59 L3 4): the lineage must still
	// hold a deleted item it was given by since. If an earlier rollback
	// took it back, what it did since was never asked about. What the
	// owner approved (the agent no longer holds the record) already
	// holds, so the intent closes as done, with nothing reset, rather
	// than staying open as not applied.
	if _, first := r.heldBy(lineage); first.IsZero() || first.After(since) {
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: staleEvidence}
	}
	// The owner's YES is the effect: once approved, the rollback is
	// carried through by Retry whatever fails now.
	err = r.reset(ctx, lineage, since, true)
	switch {
	case err == nil:
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "rolled back"}
	case len(r.Prov.Resets(lineage)) > 0:
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "machines reset; finishing: " + err.Error()}
	}
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: approvedOnly + err.Error()}
}

// staleEvidence closes an approval an earlier rollback made moot.
const staleEvidence = "nothing reset: an earlier rollback already took the record back"

// approvedOnly starts the evidence of a rollback approved but whose
// machines are not reset yet.
const approvedOnly = "approved; machines not reset yet: "

// Reconcile: a rollback a crash interrupted was approved; Retry finishes
// a recorded reset, or resets the machines if none is recorded.
func (r *Reach) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: approvedOnly + "interrupted by a restart"}
}

// reset takes lineage's machines back to before since, records the reset
// time, tells the owner when they approved it, and finishes the reach.
// Called with run held.
func (r *Reach) reset(ctx context.Context, lineage string, since time.Time, approved bool) error {
	// R is taken before the machines go back: a read while they do may be
	// by a machine already reset, so it is kept (#59 L3 2).
	at := r.now()
	plan, _ := r.Machines.Plan(lineage, since)
	if err := r.Machines.ForgetSince(ctx, lineage, since); err != nil {
		return err
	}
	rs := Reset{Since: since, At: at}
	if err := r.Prov.MarkReset(lineage, since, at); err != nil {
		return err
	}
	if approved && r.Notify != nil {
		ids, _ := r.heldBy(lineage)
		if err := r.Notify(r.done(lineage, ids, plan.To, r.actions(lineage, since, at))); err != nil && r.Logf != nil {
			r.Logf("recall: rollback of %s done; owner not told: %v", lineage, err)
		}
	}
	if err := r.finish(lineage, rs); err != nil {
		return err
	}
	r.set(&r.held, lineage, false)
	r.set(&r.kept, lineage, false)
	return nil
}

// finish erases what lineage did between a reset's since and its time,
// and forgets what it was given then. Called with run held.
func (r *Reach) finish(lineage string, rs Reset) error {
	if r.Journal != nil {
		ids := r.Journal.Between("guest:"+lineage, rs.Since, rs.At)
		_, held, err := r.Journal.Erase(ids)
		if err != nil {
			return err
		}
		if r.Cases != nil {
			// Every intent in the window, not only those erased now, so a
			// retry after a failed removal still removes their cases.
			if _, err := r.Cases.ForgetTasks(ids...); err != nil {
				return err
			}
		}
		if len(held) > 0 {
			return fmt.Errorf("%d intents in flight; erased once they settle", len(held))
		}
	}
	return r.Prov.Finish(lineage, rs)
}

func (r *Reach) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func resetKey(lineage string, since time.Time) string {
	return lineage + "@" + since.UTC().Format(time.RFC3339Nano)
}

// rollbackID names the rollback question for lineage from since: the
// first one asked (items nil), or the one after a NO, naming the items.
func rollbackID(lineage string, since time.Time, items []string) string {
	k := resetKey(lineage, since)
	if items != nil {
		k += "#" + strings.Join(items, ",")
	}
	h := sha256.Sum256([]byte(k))
	return "recall-rollback-" + hex.EncodeToString(h[:12])
}

// agentName names a lineage by its root machine.
func agentName(lineage string) string {
	if i := strings.LastIndex(lineage, "."); i > 0 {
		return lineage[:i]
	}
	return lineage
}

// what names the deleted items by kind only, never by content (#59
// UX-59-1): "a mail", "3 mails", "2 records".
func (r *Reach) what(ids []string) string {
	r.mu.Lock()
	kind := ""
	for i, id := range ids {
		k := noun(r.kinds[id])
		if i > 0 && k != kind {
			kind = "record"
			break
		}
		kind = k
	}
	r.mu.Unlock()
	if len(ids) == 1 {
		if kind == "event" {
			return "an event"
		}
		return "a " + kind
	}
	return fmt.Sprintf("%d %ss", len(ids), kind)
}

func noun(kind string) string {
	switch kind {
	case "mail", "file", "contact":
		return kind
	case "calendar":
		return "event"
	}
	return "record"
}

// Owner-text field caps (owner.Item: Object and Detail render at most 40
// characters; a longer one is cut).
const fieldCap = 40

// line is the approval's object and detail (#59 UX-59-1, security C1):
// what is forgotten, the restore point, and that actions taken stay done,
// in fixed words that fit the caps, e.g.
//
//	forget a mail you deleted from agent, back to 08:12 Oct 5; 2 actions
//	stay done, cannot be undone
func (r *Reach) line(lineage string, ids []string, to time.Time, actions int) (object, detail string) {
	object = r.what(ids) + " you deleted from " + agentName(lineage)
	if len(object) > fieldCap {
		object = r.what(ids) + " you deleted"
	}
	var points []string
	if to.IsZero() {
		points = []string{"its start"}
	} else {
		t := to.In(r.loc())
		points = []string{t.Format("15:04 Jan 2")}
		if now := r.now().In(r.loc()); now.YearDay() == t.YearDay() && now.Year() == t.Year() {
			points = append(points, t.Format("15:04"))
		}
	}
	var tails []string
	switch actions {
	case 0:
		tails = []string{"; no actions yet", ""}
	case 1:
		tails = []string{"; 1 action so far stays done", "; 1 action stays done", ""}
	default:
		tails = []string{
			fmt.Sprintf("; %d actions so far stay done", actions),
			fmt.Sprintf("; %d actions stay done", actions),
			fmt.Sprintf("; %d stay done", actions), ""}
	}
	for _, tail := range tails {
		for _, p := range points {
			if d := "back to " + p + tail; len(d) <= fieldCap {
				return object, d
			}
		}
	}
	return object, "back to " + points[len(points)-1]
}

// done is the confirmation after an approved rollback, with the real count
// (#59 UX-59-2).
func (r *Reach) done(lineage string, ids []string, to time.Time, actions int) string {
	back := "its start"
	if !to.IsZero() {
		back = to.In(r.loc()).Format("15:04 Jan 2")
	}
	what := "a record you deleted"
	if len(ids) > 0 {
		what = r.what(ids) + " you deleted"
	}
	n := fmt.Sprintf("Its %d actions since stay done; their details are erased.", actions)
	switch actions {
	case 0:
		n = "It had taken no actions since."
	case 1:
		n = "Its 1 action since stays done; its details are erased."
	}
	return fmt.Sprintf("Done: %s forgot %s and is back to %s. %s", agentName(lineage), what, back, n)
}

func (r *Reach) loc() *time.Location {
	if r.Location != nil {
		return r.Location
	}
	return time.UTC
}

// Needed reports a deleted item some lineage still holds: its tombstone
// must outlive the prune policy (Index.KeepTombstones), so nothing derived
// from it comes back and the reach is replayed at each start.
func (r *Reach) Needed(id string) bool { return len(r.Prov.Holders(id)) > 0 }
