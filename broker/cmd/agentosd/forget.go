package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
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
)

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
	inform    func(string)
	now       func() time.Time
	loc       *time.Location
	// sleep waits between retries; false stops them (shutdown).
	sleep func(context.Context, time.Duration) bool
	// retried, if set, is called when a retry loop ends (tests).
	retried func()

	mu     sync.Mutex
	list   []string // goals, as last listed
	listAt time.Time
	seq    int
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
	if !f.ask(ctx, goal) {
		return forgetRefused, true
	}
	// No reply of its own (UX U-F8): the request names the task and what
	// it undoes, says it cannot be undone, and comes before anything is
	// deleted, so it is the notice. The gate sends it at its next tick,
	// at once for an owner active in chat.
	return "", true
}

// ask submits the forget intent; the gate asks the owner.
func (f *ownerForget) ask(ctx context.Context, goal string) bool {
	box := f.gate.Load()
	if box == nil {
		return false
	}
	f.seq++
	// The goal ID only, in the intent's ID: the task's text never
	// enters the journal.
	id := grants.ForgetID(fmt.Sprintf("%d.%d", f.now().UnixNano(), f.seq), goal)
	st, err := box.g.Submit(journal.Intent{ID: id, Origin: grants.OriginForget, Account: journal.BrokerAccount,
		Action: journal.ActionLearnForget, Executor: grants.ForgetExecutor})
	if err == nil && st.State == journal.Pending {
		st, err = box.g.Authorize(ctx, id)
	}
	if err != nil {
		log.Printf("forget: ask: %v", err)
		return false
	}
	return st.State == journal.Pending
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

// shown is a task as a text may show it: a task the owner texted by its
// clipped text, any other by when it came only (security C2), with the
// time when listed.
func (f *ownerForget) shown(t taskText, when bool) string {
	at := f.when(t.At)
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
	goal := grants.ForgetGoal(in.ID)
	if in.Action != journal.ActionLearnForget || in.Origin != grants.OriginForget || in.Account != journal.BrokerAccount || goal == "" {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "malformed forget"}
	}
	undone := f.learned(goal)
	err := f.forget(goal)
	switch {
	case err == nil:
		f.inform(forgetDone(undone))
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "forgotten"}
	case errors.Is(err, errNotTombstoned):
		// Nothing was deleted and a restart would not finish it, so it
		// is not done and the owner is told now (security R1 on #182).
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
			return // shutdown: the tombstone's replay at start finishes it
		}
		err := f.forget(goal)
		if err == nil {
			f.inform(forgetDone(undone))
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
// machine's files, which part a does not reach (UX-182-1);
// W3-forget-b, with the forget log's replay, adds that a restored backup
// is forgotten again at once.
const forgetBackups = " Older backups and your agent's own files may still hold it."

func forgetDone(undone int) string {
	if undone == 0 {
		return "Forgotten." + forgetBackups
	}
	return "Forgotten. I also undid " + things(undone) + " from it; I'll relearn what I can without it." + forgetBackups
}

// Reconcile: a forget interrupted by a restart is finished by the
// tombstone's replay at start (learning.replayForgotten) once the
// tombstone holds; otherwise it did not happen.
func (f *ownerForget) Reconcile(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	if goal := grants.ForgetGoal(in.ID); goal != "" && f.forgotten != nil && f.forgotten(goal) {
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "tombstoned; finished at start"}
	}
	return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "no tombstone"}
}
