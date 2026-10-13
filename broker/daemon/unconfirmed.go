package daemon

import (
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
	grants.FollowExecutor: "an update change",
	grants.ForgetExecutor: "a FORGET",
	grants.RecallExecutor: "a memory rollback",
	grants.ExecutorName:   "a permission change",
	"mail":                "an email",
	"change":              "a learned change",
}

// unconfirmedNote is a STATUS note source: one line naming what a restart
// left unconfirmed once startup reconcile has missed its evidence, or ""
// (#1373). It says nothing is needed, since the box keeps asking and no
// owner step settles it yet.
func unconfirmedNote(eng *journal.Engine) func() string {
	return func() string {
		ins := eng.Unconfirmed(unconfirmedAfter)
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
		return "Not confirmed since the restart: whether " + strings.Join(what, ", ") +
			" went through. Some changes wait while the box keeps checking; nothing is needed from you."
	}
}
