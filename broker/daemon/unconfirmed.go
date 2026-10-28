package daemon

import (
	"fmt"
	"strings"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
)

// unconfirmedAfter is how many startup reconcile rounds must miss an
// intent's evidence before STATUS names it (#1373). One: the first round
// runs as the daemon starts, so an owner told a change is on hold (loops'
// fenced reply) finds it in STATUS.
const unconfirmedAfter = 1

// unconfirmedWhat names an executor's effect in the owner's words (CH-12:
// no internal parts). Unlisted executors are "an action".
var unconfirmedWhat = map[string]string{
	"loops":               "a setting change",
	grants.ForgetExecutor: "a FORGET",
	grants.RecallExecutor: "a memory rollback",
	grants.ExecutorName:   "a permission change",
	"mail":                "an email",
	"change":              "a learned change",
}

// unconfirmedLineMax is the longest note control.Handler shows whole in
// STATUS (it cuts each note there): each unconfirmed line fits it (S2 on
// #1382).
const unconfirmedLineMax = 100

// unconfirmedWait is the second unconfirmed line: nothing is needed, since
// the box keeps asking and no owner step settles it yet.
const unconfirmedWait = "Some changes wait while I keep checking; nothing is needed from you."

// unconfirmedNotes are STATUS note sources for what a restart left
// unconfirmed once startup reconcile has missed its evidence (#1373): one
// line naming it, in the box's own voice (CH-21), and one saying nothing
// is needed; both are "" while nothing is unconfirmed. Each fits
// unconfirmedLineMax, so STATUS never cuts the list.
func unconfirmedNotes(eng *journal.Engine) []func() string {
	return []func() string{
		func() string { return unconfirmedLine(eng.Unconfirmed(unconfirmedAfter)) },
		func() string {
			if len(eng.Unconfirmed(unconfirmedAfter)) == 0 {
				return ""
			}
			return unconfirmedWait
		},
	}
}

// unconfirmedLine names the effects of ins in the owner's words, each
// once, joined with a final "or" (U2 on #1382). Kinds that would push the
// line past unconfirmedLineMax are counted instead ("or 2 more").
func unconfirmedLine(ins []journal.Intent) string {
	if len(ins) == 0 {
		return ""
	}
	var what []string
	seen := map[string]bool{}
	for _, in := range ins {
		w := unconfirmedWhat[in.Executor]
		if w == "" {
			w = "an action"
		}
		if !seen[w] {
			seen[w] = true
			what = append(what, w)
		}
	}
	const head, tail = "I cannot yet confirm ", " from before the restart."
	for n := len(what); ; n-- {
		list := append([]string(nil), what[:n]...)
		if n < len(what) {
			list = append(list, fmt.Sprintf("%d more", len(what)-n))
		}
		if l := head + orList(list) + tail; len(l) <= unconfirmedLineMax || n == 1 {
			return l
		}
	}
}

// orList joins items as "a, b or c".
func orList(items []string) string {
	if len(items) < 2 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " or " + items[len(items)-1]
}
