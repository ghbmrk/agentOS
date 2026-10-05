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
	Since(origin string, since time.Time) []string
	Erase(ids []string) (erased, held []string, err error)
	Get(id string) (journal.Status, error)
}

// Machines is the part of the VM manager deletion reaches (vm.Manager).
type Machines interface {
	ForgetSince(ctx context.Context, lineage string, since time.Time) error
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

// Reach carries a recall deletion past the index (CAP-3, K2b). For each
// fork lineage the provenance record says was given a deleted item, first
// at T, taking it back means:
//
//  1. the lineage's machines go back to before T and its snapshots from T
//     on are deleted (Machines);
//  2. the journal intents the lineage submitted from T on are erased:
//     parameters and evidence go, the audit trail stays (Journal). Replay
//     recordings are read from the journal, so they go with it;
//  3. change-pipeline cases built on those intents are removed (Cases);
//  4. the provenance record forgets what the lineage was given from T on.
//
// The owner decides when that loses work (Mark, 2026-10-05; W10): a
// lineage that has submitted nothing since T is taken back at once; one
// that has is taken back only once the owner approves a rollback intent
// naming what would be undone (Ask). Until then, or if the owner says no
// or does not answer, the lineage keeps its work and what it read. The
// item itself is gone from recall at once either way.
//
// An intent still in flight is held: the deletion stays pending and Retry
// finishes it once the intent settles. A failure keeps it pending too.
// Provenance is forgotten last, so after a crash the index's replay of its
// tombstones at start runs the reach again; a rollback the journal records
// as done does not reset the machines a second time.
type Reach struct {
	Prov     *Provenance
	Journal  Journal  // nil: not wired
	Machines Machines // nil: not wired
	Cases    Cases    // nil: not wired
	// Ask is where a rollback that loses work goes for approval. Nil:
	// such a rollback waits (pending) and nothing is undone.
	Ask Asker
	// Location is the owner's time zone for the approval line.
	Location *time.Location
	Logf     func(format string, args ...any)

	mu      sync.Mutex
	pending map[string]bool // deleted item IDs not yet fully reached
	reset   map[string]bool // lineage@T whose machines are done this run
	// held: lineages that still hold a deleted item, asked or declined.
	held map[string]map[string]bool // lineage -> lineage@T
}

// Contained reports a lineage that still holds a record the owner deleted
// (asked, declined or unanswered): the grants gate gives its intents no
// pre-allowance (#59 security C2).
func (r *Reach) Contained(lineage string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.held[lineage]) > 0
}

func (r *Reach) hold(lineage string, since time.Time, on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := resetKey(lineage, since)
	if on {
		if r.held == nil {
			r.held = map[string]map[string]bool{}
		}
		if r.held[lineage] == nil {
			r.held[lineage] = map[string]bool{}
		}
		r.held[lineage][k] = true
		return
	}
	delete(r.held[lineage], k)
	if len(r.held[lineage]) == 0 {
		delete(r.held, lineage)
	}
}

// errWaiting keeps a deletion pending while the owner decides.
var errWaiting = errors.New("waiting for the owner")

// OnDelete is the recall.Index deletion hook. A deletion waiting for the
// owner is not an error.
func (r *Reach) OnDelete(d recall.Deleted) error {
	if err := r.reach(context.Background(), d.ID, d.Source.Kind); !errors.Is(err, errWaiting) {
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
		if err := r.reach(ctx, id, ""); err != nil && !errors.Is(err, errWaiting) {
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

func (r *Reach) reach(ctx context.Context, id, kind string) error {
	holders := r.Prov.Holders(id)
	lineages := make([]string, 0, len(holders))
	for l := range holders {
		lineages = append(lineages, l)
	}
	sort.Strings(lineages)
	var errs []error
	waiting := false
	for _, l := range lineages {
		err := r.decide(ctx, l, holders[l], kind)
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

// decide takes lineage back from since at once, or asks the owner first
// when it has done work since.
func (r *Reach) decide(ctx context.Context, lineage string, since time.Time, kind string) error {
	work := r.work(lineage, since)
	if work == 0 {
		return r.lineage(ctx, lineage, since, true)
	}
	r.hold(lineage, since, true)
	if r.Ask == nil {
		return errWaiting
	}
	id := rollbackID(lineage, since)
	st, err := r.Ask.Get(id)
	if err != nil {
		// First ask: the line is fixed now, so a later count does not
		// make the same intent disagree with itself (OP-1).
		in := journal.Intent{ID: id, Origin: Origin, Account: journal.BrokerAccount,
			Action: journal.ActionRecallRollback, Executor: ExecutorName,
			Params: map[string]any{"lineage": lineage, "since": since.UTC().Format(time.RFC3339Nano),
				"object": r.line(lineage, since), "detail": detail(work, kind)}}
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
	case journal.Authorized, journal.InFlight, journal.OutcomeUnknown:
		return errWaiting
	case journal.Succeeded:
		// Approved and run (Execute): finish what it left, resetting the
		// machines only if that had failed.
		reset := false
		if n := len(st.Attempts); n > 0 {
			reset = strings.HasPrefix(st.Attempts[n-1].Evidence, approvedOnly)
		}
		return r.lineage(ctx, lineage, since, reset)
	default:
		// Declined, unanswered, or refused: the lineage keeps its work and
		// what it read, contained (no pre-allowance, no notes derived from
		// the item, its tombstone kept); nothing more is asked for it.
		return nil
	}
}

// work counts the intents lineage has carried out since: succeeded, in
// flight, or of unknown outcome. Denied, refused or never-run intents
// change nothing outside and do not force a question (#59 security B2).
func (r *Reach) work(lineage string, since time.Time) int {
	if r.Journal == nil {
		return 0
	}
	n := 0
	for _, id := range r.Journal.Since("guest:"+lineage, since) {
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
	if in.Action != journal.ActionRecallRollback || lineage == "" || err != nil {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "malformed recall rollback"}
	}
	// The owner's YES is the effect: once approved, the rollback is
	// carried through by Retry whatever fails now. The evidence says
	// whether the machines still need resetting.
	err = r.lineage(ctx, lineage, since, true)
	switch {
	case err == nil:
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "rolled back"}
	case r.machinesDone(lineage, since):
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "machines reset; finishing: " + err.Error()}
	}
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: approvedOnly + err.Error()}
}

// approvedOnly starts the evidence of a rollback approved but whose
// machines are not reset yet.
const approvedOnly = "approved; machines not reset yet: "

// Reconcile: a rollback a crash interrupted was approved; Retry resets
// the machines (again, if they had been) and finishes it.
func (r *Reach) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: approvedOnly + "interrupted by a restart"}
}

func (r *Reach) machinesDone(lineage string, since time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reset[resetKey(lineage, since)]
}

func resetKey(lineage string, since time.Time) string {
	return lineage + "@" + since.UTC().Format(time.RFC3339Nano)
}

func rollbackID(lineage string, since time.Time) string {
	h := sha256.Sum256([]byte(resetKey(lineage, since)))
	return "recall-rollback-" + hex.EncodeToString(h[:12])
}

// line is the approval's object: whose work, since when, in the owner's
// time zone. The agent is named by its lineage's root machine.
func (r *Reach) line(lineage string, since time.Time) string {
	loc := r.Location
	if loc == nil {
		loc = time.UTC
	}
	name := lineage
	if i := strings.LastIndex(name, "."); i > 0 {
		name = name[:i]
	}
	return fmt.Sprintf("%s to %s", name, since.In(loc).Format("15:04 Jan 2"))
}

// detail says what a reset keeps: actions that took effect stay done (a
// reset cannot recall a sent mail); only their details leave the box
// (#59 security C1). kind is accepted for the line's wording later.
func detail(actions int, _ string) string {
	if actions == 1 {
		return "its 1 action since stays done; its details are erased"
	}
	return fmt.Sprintf("its %d actions since stay done; their details are erased", actions)
}

// lineage takes lineage back from since; machines false skips the machine
// reset (already done).
func (r *Reach) lineage(ctx context.Context, lineage string, since time.Time, machines bool) error {
	key := resetKey(lineage, since)
	r.mu.Lock()
	done := r.reset[key] || !machines
	r.mu.Unlock()
	if r.Machines != nil && !done {
		if err := r.Machines.ForgetSince(ctx, lineage, since); err != nil {
			return err
		}
		r.mu.Lock()
		if r.reset == nil {
			r.reset = map[string]bool{}
		}
		r.reset[key] = true
		r.mu.Unlock()
	}
	if r.Journal != nil {
		ids := r.Journal.Since("guest:"+lineage, since)
		_, held, err := r.Journal.Erase(ids)
		if err != nil {
			return err
		}
		if r.Cases != nil {
			// Every intent from T on, not only those erased now, so a
			// retry after a failed removal still removes their cases.
			if _, err := r.Cases.ForgetTasks(ids...); err != nil {
				return err
			}
		}
		if len(held) > 0 {
			return fmt.Errorf("%d intents in flight; erased once they settle", len(held))
		}
	}
	if r.Machines == nil {
		// Its memory was not reached, so it still holds what it was given;
		// notes it makes keep deriving from it.
		return nil
	}
	if err := r.Prov.ForgetSince(lineage, since); err != nil {
		return err
	}
	r.mu.Lock()
	delete(r.reset, key)
	r.mu.Unlock()
	r.hold(lineage, since, false)
	return nil
}

// Needed reports a deleted item some lineage still holds: its tombstone
// must outlive the prune policy (Index.KeepTombstones), so nothing derived
// from it comes back and the reach is replayed at each start.
func (r *Reach) Needed(id string) bool { return len(r.Prov.Holders(id)) > 0 }
