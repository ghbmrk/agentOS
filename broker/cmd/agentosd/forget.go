package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/recalltool"
)

// The owner's FORGET (W3-forget, CAP-3; design and lens conditions in
// w3/w3-forget-design.md). FORGET lists the owner's last five kept tasks;
// FORGET n or FORGET LAST asks to forget one. The ask is a broker intent
// (journal.ActionLearnForget, origin grants.OriginForget) that the gate
// puts to the owner as an ordinary approval request, so its YES carries
// the request's texted code at the tier the owner's limits give a forget
// (security C1). Once approved, the task is forgotten tombstone first
// (learning.forgetTask), retried until every save holds, and only then is
// the owner told, with what it undid as a count (#160 ruling).

const (
	// forgetList is how many tasks FORGET lists.
	forgetList = 5
	// forgetListFor is how long FORGET n picks from the list last sent.
	forgetListFor = 10 * time.Minute
	// forgetNotYet is when a forget still not saved is told to the owner.
	forgetNotYet = 2 * time.Minute
	// forgetRetryMax caps the wait between retries of a failed save.
	forgetRetryMax = time.Minute
	// forgetClip is how much of a task's text a list or line shows.
	forgetClip = 24
)

// Fixed texts (UX F1, F2, F6, F7 on W3-forget).
const (
	forgetNone     = "No recent tasks to forget."
	forgetStale    = "Send FORGET to see your recent tasks."
	forgetRefused  = "I couldn't ask to forget that task. Try again."
	forgetNotSaved = "Not forgotten yet: I couldn't save it. I keep trying and will text you when it's done."
	forgetNotDone  = "Not forgotten: I couldn't save it. Send FORGET to try again."
	// W3-forget-b2b: the notice before a request whose item 2 takes the
	// agent's work back, the reply when item 2 is approved without item
	// 1, and the done text for item 2.
	forgetAgentNotice = "Your agent has worked since that task, so item 2 takes it back to before the task; actions it took stay done. " +
		"Approve only item 1 to keep that work; your agent then still holds the task."
	forgetAgentAlone  = "Nothing taken back: item 2 goes only with item 1. Send FORGET to ask again."
	forgetAgentDone   = recalltool.TakenBack
	forgetAgentNotYet = "Your agent is not back to before that task yet. I keep trying and will text you when it is."
	// Item 1 has forgotten the task, so these never offer FORGET again
	// (CH-12); carrying them as owed take-backs is a release row.
	forgetAgentNoAgent  = "Nothing taken back: your agent is not running, so it holds nothing new. Nothing is needed."
	forgetAgentNotTaken = "Not taken back: I couldn't save the request. Your agent's own files may still hold that task."
	forgetAgentNotOpen  = "Not taken back: memory was not open yet. Your agent's own files may still hold that task."
	// forgetAgentWhenOpen: an approved item 2 waits for recall to open
	// (#327 L3 B-3).
	forgetAgentWhenOpen = "Not taken back yet: memory is not open. I will do it when it opens and text you."
	// forgetSiblingWait bounds how long item 2 waits for item 1's outcome;
	// the gate settles the items of one answer together.
	forgetSiblingWait = 30 * time.Second
)

// forgetAgent takes the agent machine's work since a task back on the
// ask-first deletion-rollback rule (W3-forget-b2b): recall's Reach, with
// the agent machine's lineage.
type forgetAgent struct {
	work interface {
		Work(lineage string, since time.Time) (worked, ok bool)
		Actions(lineage string, since time.Time) (n int, ok bool)
		TakeBack(ctx context.Context, lineage string, since time.Time, approved bool) error
		Handled(since time.Time) (handled, ok bool)
	}
	lineage func() (string, error)
}

// worked reports whether the agent worked since at; ok false: not known
// (no agent machine or recall not open), and nothing is taken back.
func (a *forgetAgent) worked(at time.Time) (worked, ok bool) {
	if a == nil {
		return false, false
	}
	l, err := a.lineage()
	if err != nil {
		return false, false
	}
	return a.work.Work(l, at)
}

// takeBack takes the agent back to before since; approved, recall records
// it owed first and never repeats it once done (recalltool.Reach.TakeBack).
func (a *forgetAgent) takeBack(ctx context.Context, since time.Time, approved bool) error {
	if a == nil {
		return errors.New("forget: no agent machine")
	}
	l, err := a.lineage()
	if err != nil {
		return err
	}
	return a.work.TakeBack(ctx, l, since, approved)
}

// lister is the gate's List: the journal's intents, which hold every
// approved item 2 across restarts.
type lister interface {
	List() []journal.Status
}

// statusGetter is the gate's Get, which item 2 reads item 1's outcome by.
type statusGetter interface {
	Get(id string) (journal.Status, error)
}

type ownerForget struct {
	tasks *taskTexts
	// learned counts what a forget of the goal would undo now
	// (change.Pipeline.LearnedFrom).
	learned func(goal string) int
	// forget is learning.forgetTask: tombstone first, then every store.
	forget func(goal string) error
	// forgotten reports a goal's tombstone (forgotten.has).
	forgotten func(goal string) bool
	gate      atomic.Pointer[pauseGateBox]
	// agent is the agent machine's take-back, once machines are open.
	agent  atomic.Pointer[forgetAgent]
	inform func(string)
	now    func() time.Time
	loc    *time.Location
	// sleep waits between retries; false stops them (shutdown).
	sleep func(context.Context, time.Duration) bool
	// retried, if set, is called when a retry loop ends (tests).
	retried func()
	// whenOpen, if set, runs resumeAgent once recall opens
	// (LateExecutor.OnOpen); nil when recall is off.
	whenOpen func()
	// resuming serializes resumeAgent: recall's open runs every queued
	// OnOpen together, and each run must see the take-backs the one
	// before it did (Handled), so none is taken back or told twice.
	resuming sync.Mutex
	// forgetLog, if set, is the authenticated forget log a restore replays
	// (W3-forget-b1; security C3); nil until the vault process serves it,
	// and the done text then keeps part a's caveat.
	forgetLog forgetLogger
	// owed holds the done texts promised across a restart (W3-forget-b3);
	// owedAtStart is its goals as the last boot left them, which
	// finishOwed texts once the start-up replay has finished them.
	owed        *forgetOwed
	owedAtStart []string

	mu sync.Mutex
	// interrupted: approved item 2s a restart interrupted, by ID, taken
	// back by resumeAgent once recall opens.
	interrupted []string
	// restored: the take-backs a restored forget log holds, by where the
	// agent went back to, taken back by resumeAgent once recall opens.
	restored []time.Time
	list     []string // goals, as last listed
	listAt   time.Time
	seq      int
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// parseForget reads FORGET, FORGET n (1 to forgetList) and FORGET LAST as
// the whole message, ignoring case and punctuation like every owner word.
// n is 0 for the list and -1 for LAST.
func parseForget(msg string) (n int, ok bool) {
	f := strings.Fields(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return ' '
	}, strings.ToUpper(msg)))
	if len(f) == 0 || f[0] != "FORGET" || len(f) > 2 {
		return 0, false
	}
	if len(f) == 1 {
		return 0, true
	}
	if f[1] == "LAST" {
		return -1, true
	}
	if v, err := strconv.Atoi(f[1]); err == nil && len(f[1]) <= 2 {
		return v, true
	}
	return 0, false
}

// Text answers FORGET (the owner channel's settings hook). In a locked
// session it is not taken, so the channel asks for the unlock (CH-21):
// the list shows the owner's own texts and the ask deletes their data.
func (f *ownerForget) Text(ctx context.Context, msg string, unlocked bool) (string, bool) {
	n, ok := parseForget(msg)
	if !ok || !unlocked {
		return "", false
	}
	now := f.now()
	f.mu.Lock()
	defer f.mu.Unlock()
	if n == 0 {
		recent := f.tasks.recent(forgetList)
		if len(recent) == 0 {
			f.list = nil
			return forgetNone, true
		}
		f.list, f.listAt = nil, now
		var b strings.Builder
		if len(recent) == 1 {
			b.WriteString("Reply FORGET 1 to forget it:")
		} else {
			fmt.Fprintf(&b, "Reply FORGET 1-%d to forget a task:", len(recent))
		}
		for i, t := range recent {
			f.list = append(f.list, t.Goal)
			fmt.Fprintf(&b, " %d %s", i+1, f.shown(t.taskText, true))
		}
		return b.String(), true
	}
	var goal string
	switch {
	case n < 0:
		recent := f.tasks.recent(1)
		if len(recent) == 0 {
			return forgetNone, true
		}
		goal = recent[0].Goal
	case n <= len(f.list) && now.Sub(f.listAt) <= forgetListFor:
		goal = f.list[n-1]
	default:
		return forgetStale, true
	}
	if _, ok := f.tasks.get(goal); !ok {
		return forgetStale, true
	}
	if !f.ask(ctx, goal, f.now()) {
		return forgetRefused, true
	}
	// No reply of its own (UX U-F8): the request names the task and what
	// it undoes, says it cannot be undone, and comes before anything is
	// deleted, so it is the notice. The gate sends it at its next tick,
	// at once for an owner active in chat.
	return "", true
}

// ask submits the forget intent; the gate asks the owner. When the agent
// worked since the task, the same request's item 2 takes that work back,
// after a notice of what approving only item 1 keeps (W3-forget-b2b):
// with no work, item 1 alone takes the agent back without asking, on the
// ask-first rule.
func (f *ownerForget) ask(ctx context.Context, goal string, now time.Time) bool {
	box := f.gate.Load()
	t, ok := f.tasks.get(goal)
	if box == nil || !ok {
		return false
	}
	f.seq++
	// The goal ID only, in the intent's ID: the task's text never
	// enters the journal. The task's time rides in the nonce, which item 2
	// takes the agent back to after item 1 has deleted the task.
	nonce := fmt.Sprintf("%d.%d.%d", now.UnixNano(), f.seq, t.At.UnixNano())
	id := grants.ForgetID(nonce, goal)
	st, err := box.g.Submit(journal.Intent{ID: id, Origin: grants.OriginForget, Account: journal.BrokerAccount,
		Action: journal.ActionLearnForget, Executor: grants.ForgetExecutor})
	if err != nil || st.State != journal.Pending {
		if err != nil {
			log.Printf("forget: ask: %v", err)
		}
		return false
	}
	var id2 string
	if worked, ok := f.agent.Load().worked(t.At); ok && worked {
		id2 = grants.ForgetAgentID(nonce, goal)
		// Its own effect, so the journal does not hold item 1 behind it
		// as a duplicate (its effect fingerprint leaves out the ID). The
		// work so far is fixed here, so a re-issue asks what was asked
		// (OP-3; #327 L3 B-1); a count not known is not named.
		params := map[string]any{"agent": true}
		if n, ok := f.agentActions(t.At); ok {
			params["actions"] = n
		}
		st2, err := box.g.Submit(journal.Intent{ID: id2, Origin: grants.OriginForget, Account: journal.BrokerAccount,
			Action: journal.ActionLearnForget, Executor: grants.ForgetExecutor, Params: params})
		if err != nil || st2.State != journal.Pending {
			log.Printf("forget: ask item 2: %v %s", err, st2.State)
			id2 = ""
		}
	}
	if id2 != "" {
		// Before the request, which the gate sends at its next tick.
		f.inform(forgetAgentNotice)
	}
	st, err = box.g.Authorize(ctx, id)
	if err == nil && id2 != "" && st.State == journal.Pending {
		// Never item 2 without item 1 on the request.
		_, err = box.g.Authorize(ctx, id2)
	}
	if err != nil {
		log.Printf("forget: ask: %v", err)
		return false
	}
	return st.State == journal.Pending
}

// forgetSince is the task's time a forget or take-back ID carries.
func forgetSince(id string) (time.Time, bool) {
	parts := strings.Split(id, "/")
	if len(parts) < 3 {
		return time.Time{}, false
	}
	n := strings.Split(parts[1], ".")
	v, err := strconv.ParseInt(n[len(n)-1], 10, 64)
	if len(n) != 3 || err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, v), true
}

// Item is the gate's approval line for a forget (grants Config.ForgetItem):
// the task as the owner may see it, and what the forget undoes.
func (f *ownerForget) Item(goal string) (object, detail string, ok bool) {
	t, ok := f.tasks.get(goal)
	if !ok {
		return "", "", false
	}
	if c := f.learned(goal); c > 0 {
		detail = "undoes " + things(c)
	}
	// In the request's own characters (CH-12 drops '"' and '…'), so a
	// clipped task still reads as clipped.
	obj := strings.NewReplacer(`"`, "'", "…", "..").Replace(f.shown(t, false))
	return obj, detail, true
}

// AgentItem is the gate's line for item 2, by its ID (grants
// Config.ForgetAgentItem); its detail is fixed in item 2's params when
// asked, so none here. The time is the ID's, not the task's: approving
// both items may forget the task before item 2 is authorized.
func (f *ownerForget) AgentItem(id string) (object, detail string, ok bool) {
	since, ok := forgetSince(id)
	if !ok || grants.ForgetAgentGoal(id) == "" {
		return "", "", false
	}
	return "your agent's work since " + f.date(since), "", true
}

// agentActions counts the agent's actions since at, which item 2 leaves
// done; ok false when not known.
func (f *ownerForget) agentActions(at time.Time) (n int, ok bool) {
	a := f.agent.Load()
	if a == nil {
		return 0, false
	}
	l, err := a.lineage()
	if err != nil {
		return 0, false
	}
	return a.work.Actions(l, at)
}

// shown is a task as a text may show it: a task the owner texted by its
// clipped text, any other by when it came only (security C2), with the
// time when listed.
func (f *ownerForget) shown(t taskText, when bool) string {
	at := f.when(t.At)
	if !when {
		at = f.date(t.At) // a request line (Item)
	}
	if t.Via != viaSMS {
		return "(a task, " + at + ")"
	}
	s := `"` + clipTask(t.Text, forgetClip) + `"`
	if when {
		s += " (" + at + ")"
	}
	return s
}

// when is a task's time as the owner reads it.
func (f *ownerForget) when(at time.Time) string {
	now, t := f.now().In(f.loc), at.In(f.loc)
	y1, m1, d1 := now.Date()
	y2, m2, d2 := t.Date()
	switch {
	case y1 == y2 && m1 == m2 && d1 == d2:
		return "today " + t.Format("15:04")
	case now.AddDate(0, 0, -1).Format(time.DateOnly) == t.Format(time.DateOnly):
		return "yesterday " + t.Format("15:04")
	}
	return t.Format("Mon 2 Jan 15:04")
}

// date is a task's time in a request's line: fixed, not "today", so a
// re-issue after midnight keeps the line, and the request (OP-3, #327 L3
// re-review 1).
func (f *ownerForget) date(at time.Time) string {
	return at.In(f.loc).Format("Mon 2 Jan 15:04")
}

// clipTask keeps the first n characters of s on one line, marking a cut.
func clipTask(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	// A run of 4 or more digits shows as "####", so a task cannot echo a
	// request code in the box's voice (security R2 on #182).
	s = longRun.ReplaceAllString(s, "####")
	s = strings.Map(func(r rune) rune {
		if r == '"' {
			return '\''
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return strings.TrimRight(string(r[:n]), " ") + "…"
}

var longRun = regexp.MustCompile(`\p{Nd}{4,}`)

func things(n int) string {
	if n == 1 {
		return "1 thing I learned"
	}
	return fmt.Sprintf("%d things I learned", n)
}

// Execute runs an approved forget (the engine's executor for
// grants.ForgetExecutor). The owner's YES is the effect: once the
// tombstone holds nothing is learned from the task again, and the rest is
// retried until every save holds; the owner hears it is done only then.
func (f *ownerForget) Execute(ctx context.Context, in journal.Intent, _ int) journal.Outcome {
	if in.Action != journal.ActionLearnForget || in.Origin != grants.OriginForget || in.Account != journal.BrokerAccount {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "malformed forget"}
	}
	if grants.ForgetAgentGoal(in.ID) != "" {
		return f.executeAgent(ctx, in)
	}
	goal := grants.ForgetGoal(in.ID)
	if goal == "" {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "malformed forget"}
	}
	undone := f.learned(goal)
	since, _ := forgetSince(in.ID)
	// Owed before the tombstone, so a tombstone that holds always has its
	// done text owed across a restart (UX-182-3). A failed write does not
	// stop the forget; the next write carries it.
	if err := f.owed.owe(goal, owedForget{Since: since, Undone: undone}); err != nil {
		log.Printf("forget: done text not kept for a restart: %v", err)
	}
	err := f.forget(goal)
	switch {
	case err == nil:
		back := f.agentBackWithoutAsking(ctx, in.ID)
		f.inform(forgetDone(undone, back, f.logForget(goal, since, back)))
		f.paid(goal)
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "forgotten"}
	case errors.Is(err, errNotTombstoned):
		// Nothing was deleted and a restart would not finish it, so it
		// is not done and the owner is told now (security R1 on #182).
		// It stays owed: the goal stays tombstoned in memory, so a later
		// forget's save may write it, and the next start's replay then
		// forgets the task, which the owner is told (SHOULD 4 of L3 on
		// #182).
		log.Printf("forget: %v", err)
		f.inform(forgetNotDone)
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "not saved"}
	}
	// The tombstone holds: the replay at start finishes it if this
	// process does not.
	go f.retry(context.WithoutCancel(ctx), goal, undone)
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "forgetting; retrying"}
}

// retry forgets goal again with backoff until every save holds, saying
// once that it is not done yet when that takes forgetNotYet.
func (f *ownerForget) retry(ctx context.Context, goal string, undone int) {
	if f.retried != nil {
		defer f.retried()
	}
	start, wait, said := f.now(), 2*time.Second, false
	for {
		if !f.sleep(ctx, wait) {
			// Shutdown: the tombstone's replay at start finishes it, and
			// finishOwed then texts the done text.
			return
		}
		err := f.forget(goal)
		if err == nil {
			f.inform(forgetDone(undone, false, f.logForget(goal, time.Time{}, false)))
			f.paid(goal)
			return
		}
		log.Printf("forget: not saved yet: %v", err)
		if !said && f.now().Sub(start) >= forgetNotYet {
			said = true
			f.inform(forgetNotSaved)
		}
		wait = min(2*wait, forgetRetryMax)
	}
}

// forgetBackups is the done text's true half about backups and the agent
// machine's files, which part a does not reach (UX-182-1); it stays when
// the forget is not in the forget log.
const forgetBackups = " Older backups and your agent's own files may still hold it."

// forgetBackupsOnly is forgetBackups once the agent is taken back.
const forgetBackupsOnly = " Older backups may still hold it."

// forgetLogged and forgetLoggedOnly replace them once the forget is in the
// forget log, which a restore replays or holds on (UX F4 on #317,
// verbatim).
const (
	forgetLogged     = " Your agent's own files may still hold it. Older backups do too, but restoring one won't bring it back."
	forgetLoggedOnly = " Older backups may still hold it, but restoring one won't bring it back."
)

func forgetDone(undone int, agentBack, logged bool) string {
	return "Forgotten." + forgetDoneRest(undone, agentBack, logged)
}

// forgetDoneRest is a done text after its first sentence.
func forgetDoneRest(undone int, agentBack, logged bool) string {
	tail := forgetBackups
	switch {
	case logged && agentBack:
		tail = forgetLoggedOnly
	case logged:
		tail = forgetLogged
	case agentBack:
		tail = forgetBackupsOnly
	}
	if undone == 0 {
		return tail
	}
	return " I also undid " + things(undone) + " from it; I'll relearn what I can without it." + tail
}

// doneLater is the done text of a forget the start-up replay finished: the
// owner may have texted since, or was told it was not forgotten, so it
// names the task by its time (never its text, security C2).
func (f *ownerForget) doneLater(undone int, since time.Time, logged bool) string {
	first := "A task you asked me to forget is forgotten now."
	if !since.IsZero() {
		first = "Your task from " + f.date(since) + " is forgotten now."
	}
	return first + forgetDoneRest(undone, false, logged)
}

// forgetLogger appends a forget to the authenticated forget log
// (broker/recovery AppendForget); since is where the agent went back to,
// when agent.
type forgetLogger interface {
	Append(goal string, at, since time.Time, agent bool) error
}

// logForget appends a done forget to the forget log, reporting whether it
// holds; a failure leaves the done text's caveat.
func (f *ownerForget) logForget(goal string, since time.Time, agent bool) bool {
	if f.forgetLog == nil {
		return false
	}
	if err := f.forgetLog.Append(goal, f.now(), since, agent); err != nil {
		log.Printf("forget: forget log: %v", err)
		return false
	}
	return true
}

// agentBackWithoutAsking takes the agent back to before a forgotten task
// when the request had no item 2 and the agent still has not worked
// since: on the ask-first rule that loses nothing, so it needs no ask.
// Work since the ask is kept, and the done text says the agent may hold
// the task.
func (f *ownerForget) agentBackWithoutAsking(ctx context.Context, id string) bool {
	since, ok := forgetSince(id)
	a := f.agent.Load()
	if !ok || a == nil {
		return false
	}
	if box := f.gate.Load(); box != nil {
		g, ok := box.g.(statusGetter)
		if !ok {
			return false
		}
		if _, err := g.Get(grants.ForgetSibling(id)); err == nil {
			return false // item 2 takes the agent back, if approved
		}
	}
	if worked, ok := a.worked(since); !ok || worked {
		return false
	}
	if err := a.takeBack(ctx, since, false); err != nil {
		log.Printf("forget: agent take-back: %v", err)
		return false
	}
	return true
}

// executeAgent runs an approved item 2: approved with item 1, the
// agent's work since the task is taken back once, and a failure recall
// recorded is carried through by its Retry, which tells the owner when it
// is done (#327 L3 1); approved without item 1, nothing is, and the owner
// is told so plainly.
func (f *ownerForget) executeAgent(ctx context.Context, in journal.Intent) journal.Outcome {
	since, ok := forgetSince(in.ID)
	if !ok {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "malformed take-back"}
	}
	if !f.siblingApproved(ctx, grants.ForgetSibling(in.ID)) {
		f.inform(forgetAgentAlone)
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "item 1 not approved"}
	}
	return f.agentBack(ctx, in.ID, since)
}

// agentBack takes the agent back for an approved item 2 (id) and tells
// the owner how it went.
func (f *ownerForget) agentBack(ctx context.Context, id string, since time.Time) journal.Outcome {
	a := f.agent.Load()
	if a == nil {
		f.inform(forgetAgentNoAgent)
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "no agent machine"}
	}
	err := a.takeBack(ctx, since, true)
	switch {
	case err == nil:
		f.logForget(grants.ForgetAgentGoal(id), since, true)
		f.inform(forgetAgentDone)
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "taken back"}
	case errors.Is(err, recalltool.ErrCarried):
		log.Printf("forget: agent take-back: %v", err)
		f.logForget(grants.ForgetAgentGoal(id), since, true) // recall owes it
		f.inform(forgetAgentNotYet)
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "taking back; recall retries"}
	case errors.Is(err, recalltool.ErrNotOpen) && f.whenOpen != nil:
		// Approved before the vault is unlocked (a request re-issued
		// after a restart): taken back once recall opens (#327 L3 B-3).
		f.mu.Lock()
		f.interrupted = append(f.interrupted, id)
		f.mu.Unlock()
		f.whenOpen()
		f.inform(forgetAgentWhenOpen)
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "queued until recall opens"}
	case errors.Is(err, recalltool.ErrNotOpen):
		f.inform(forgetAgentNotOpen)
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "recall not open"}
	default:
		log.Printf("forget: agent take-back: %v", err)
		f.inform(forgetAgentNotTaken)
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "not recorded"}
	}
}

// resumeAgent runs the approved item 2s a restart interrupted or that
// found recall not open, once recall is open (LateExecutor.OnOpen). The
// journal holds them, so one queued in a boot before a restart, or in one
// where recall never opened, is run too (#327 L3 re-review 2); one recall
// recorded, owed or done, is not run again.
func (f *ownerForget) resumeAgent(ctx context.Context) {
	f.resuming.Lock()
	defer f.resuming.Unlock()
	f.mu.Lock()
	ids := f.interrupted
	f.interrupted = nil
	f.mu.Unlock()
	queued := map[string]bool{}
	for _, id := range ids {
		queued[id] = true
	}
	if box := f.gate.Load(); box != nil {
		if g, ok := box.g.(lister); ok {
			for _, st := range g.List() {
				if id := st.Intent.ID; st.State == journal.Succeeded && grants.ForgetAgentGoal(id) != "" && !queued[id] {
					ids = append(ids, id)
				}
			}
		}
	}
	a := f.agent.Load()
	seen := map[string]bool{}
	for _, id := range ids {
		since, ok := forgetSince(id)
		if seen[id] || !ok {
			continue
		}
		seen[id] = true
		if a != nil {
			handled, known := a.work.Handled(since)
			if handled || !known && !queued[id] {
				// Recorded: recall carries it. Not known (recall off): only
				// one interrupted in this boot is told it cannot be done.
				continue
			}
		} else if !queued[id] {
			continue
		}
		if !f.siblingApproved(ctx, grants.ForgetSibling(id)) {
			if queued[id] {
				f.inform(forgetAgentAlone)
			} // else it was told when it ran, item 1 since not applied
			continue
		}
		out := f.agentBack(ctx, id, since)
		log.Printf("forget: item 2 resumed: %s", out.Evidence)
	}
	f.resumeRestored(ctx, a)
}

// resumeRestored takes the agent back for each take-back a restored forget
// log holds that recall has not recorded; the owner approved each before
// the backup, so it is not asked or told again. One that fails stays
// queued for recall's next open.
func (f *ownerForget) resumeRestored(ctx context.Context, a *forgetAgent) {
	f.mu.Lock()
	sinces := f.restored
	f.restored = nil
	f.mu.Unlock()
	var left []time.Time
	for _, since := range sinces {
		if a == nil {
			left = append(left, since)
			continue
		}
		if handled, known := a.work.Handled(since); handled {
			continue
		} else if !known {
			left = append(left, since)
			continue
		}
		if err := a.takeBack(ctx, since, true); err != nil && !errors.Is(err, recalltool.ErrCarried) {
			log.Printf("forget: restored take-back: %v", err)
			left = append(left, since)
		}
	}
	f.mu.Lock()
	f.restored = append(left, f.restored...)
	f.mu.Unlock()
}

// siblingApproved waits for the owner's decision on item 1, which the
// channel settles before item 2's, for at most forgetSiblingWait. It
// does not wait for item 1 to run: the journal runs one broker intent at
// a time, so item 1 runs after this one.
func (f *ownerForget) siblingApproved(ctx context.Context, id string) bool {
	box := f.gate.Load()
	if box == nil {
		return false
	}
	g, ok := box.g.(statusGetter)
	if !ok {
		return false
	}
	const step = 100 * time.Millisecond
	for waited := time.Duration(0); ; waited += step {
		st, err := g.Get(id)
		if err != nil {
			return false
		}
		switch st.State {
		case journal.Authorized, journal.InFlight, journal.Succeeded:
			return true
		case journal.Pending:
		default:
			return false
		}
		if waited >= forgetSiblingWait || !f.sleep(ctx, step) {
			return false
		}
	}
}

// Reconcile: a forget interrupted by a restart is finished by the
// tombstone's replay at start (learning.replayForgotten) once the
// tombstone holds; otherwise it did not happen.
func (f *ownerForget) Reconcile(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	if grants.ForgetAgentGoal(in.ID) != "" {
		// An approved item 2 interrupted by a restart: resumed once recall
		// opens (resumeAgent), which does not repeat a done take-back
		// (#327 L3 2).
		if _, ok := forgetSince(in.ID); !ok {
			return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "malformed take-back"}
		}
		f.mu.Lock()
		f.interrupted = append(f.interrupted, in.ID)
		f.mu.Unlock()
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "approved; interrupted by a restart; resumed when recall opens"}
	}
	if goal := grants.ForgetGoal(in.ID); goal != "" && f.forgotten != nil && f.forgotten(goal) {
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "tombstoned; finished at start"}
	}
	return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "no tombstone"}
}

// owedForget is a forget whose done text is owed: when the task was from
// (its ID's time) and what the forget undid, counted before it ran.
type owedForget struct {
	Since  time.Time `json:"since,omitzero"`
	Undone int       `json:"undone,omitempty"`
}

// forgetOwed keeps, by goal ID, the approved forgets whose done text is
// still owed (W3-forget-b3): written before the tombstone, dropped once
// the owner is told. It holds goal IDs, times and counts, never a task's
// text. A nil forgetOwed keeps nothing.
type forgetOwed struct {
	store change.Store

	mu sync.Mutex
	st map[string]owedForget
}

func openForgetOwed(store change.Store) (*forgetOwed, error) {
	o := &forgetOwed{store: store, st: map[string]owedForget{}}
	b, err := store.Load()
	if err != nil {
		return nil, err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &o.st); err != nil {
			return nil, fmt.Errorf("forget: owed done texts: %v", err)
		}
	}
	return o, nil
}

// owe records goal's done text as owed and saves. On a failed save it
// stays owed in memory, and the next save writes it.
func (o *forgetOwed) owe(goal string, e owedForget) error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.st[goal] = e
	return o.save()
}

// get reports goal's owed entry.
func (o *forgetOwed) get(goal string) (owedForget, bool) {
	if o == nil {
		return owedForget{}, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	e, ok := o.st[goal]
	return e, ok
}

// drop records goal's done text as told, or no longer owed.
func (o *forgetOwed) drop(goal string) error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.st[goal]; !ok {
		return nil
	}
	delete(o.st, goal)
	return o.save()
}

// goals lists the owed goals, sorted.
func (o *forgetOwed) goals() []string {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]string, 0, len(o.st))
	for g := range o.st {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

func (o *forgetOwed) save() error {
	b, err := json.Marshal(o.st)
	if err != nil {
		return err
	}
	return o.store.Save(b)
}

// paid drops goal's owed done text once the owner was told. A failed save
// leaves it on disk, so a restart may tell it again: a repeated done text
// is the lesser harm next to a missing one.
func (f *ownerForget) paid(goal string) {
	if err := f.owed.drop(goal); err != nil {
		log.Printf("forget: told done text not cleared: %v", err)
	}
}

// finishOwed texts the done text of each forget the last boot owed, once
// the start-up replay (learning.replayForgotten, which runs before the
// learning plane opens) has finished it: a forget still retrying at
// shutdown (UX-182-3), cut off by a crash after its tombstone, or told
// "Not forgotten" whose tombstone a later save wrote (SHOULD 4 of L3 on
// #182). Like any done forget it is appended to the forget log. One whose
// tombstone never held was not forgotten, and is dropped untold. It runs
// once the owner channel is attached.
func (f *ownerForget) finishOwed() {
	goals := f.owedAtStart
	f.owedAtStart = nil
	for _, g := range goals {
		e, ok := f.owed.get(g)
		if !ok {
			continue
		}
		if f.forgotten != nil && f.forgotten(g) {
			f.inform(f.doneLater(e.Undone, e.Since, f.logForget(g, time.Time{}, false)))
		}
		f.paid(g)
	}
}
