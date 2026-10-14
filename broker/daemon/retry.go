package daemon

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// settleEvery paces the settle rounds after the startup one (OP-2): each
// round checks every unknown outcome through the same tool again, parked
// ones included, so a check that later settles one closes it.
var settleEvery = time.Hour

// settleLoop runs SettleUnknown at startup and then every settleEvery
// until ctx ends. Nothing is retried that the engine's own rules do not
// allow (OP-2b).
func settleLoop(ctx context.Context, eng *journal.Engine, every time.Duration) {
	for {
		eng.SettleUnknown(ctx, settleWait, settleMaxWait)
		t := time.NewTimer(every)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// retryRefPrefix marks an owner-channel item that asks to retry a parked
// effect (OP-2c), as opposed to a journal intent the gate asked about.
const retryRefPrefix = "retry:"

// retryMax is the most parked effects one RETRY asks about.
const retryMax = 20

func retryRef(p journal.ParkedIntent) string {
	return retryRefPrefix + p.Intent.ID + ":" + strconv.Itoa(p.Attempt)
}

// parseRetryRef returns the intent ID and parked attempt a retry ref names.
func parseRetryRef(ref string) (id string, attempt int, ok bool) {
	rest, ok := strings.CutPrefix(ref, retryRefPrefix)
	if !ok {
		return "", 0, false
	}
	i := strings.LastIndexByte(rest, ':')
	if i <= 0 {
		return "", 0, false
	}
	n, err := strconv.Atoi(rest[i+1:])
	if err != nil || n < 1 {
		return "", 0, false
	}
	return rest[:i], n, true
}

// EffectWord names an executor's effect in the owner's words, such as "an
// email"; unlisted executors are "an action".
func EffectWord(executor string) string {
	if w := unconfirmedWhat[executor]; w != "" {
		return w
	}
	return "an action"
}

// retryItems lists the parked effects as owner-channel items (Config
// Retry). Each is low tier, approved with a texted code (CH-10), and says
// the effect may happen twice.
func retryItems(eng *journal.Engine) func() []ownerch.Item {
	return func() []ownerch.Item {
		ps := eng.Parked()
		if len(ps) > retryMax {
			ps = ps[:retryMax]
		}
		items := make([]ownerch.Item, 0, len(ps))
		for _, p := range ps {
			items = append(items, ownerch.Item{
				Ref:    retryRef(p),
				Object: EffectWord(p.Intent.Executor) + " that may not have gone",
				Detail: "it may go twice",
				Facts:  ownerch.Facts{Verb: "Retry", NoRecipient: true},
			})
		}
		return items
	}
}

// retryDecide wraps the gate's Decide hook: an approved retry item runs
// Engine.Retry for the attempt the owner was asked about, off the owner
// channel's goroutine; any other retry decision is dropped (the effect
// stays parked), and every other decision goes to next.
func retryDecide(ctx context.Context, eng *journal.Engine, next func(ownerch.Decision)) func(ownerch.Decision) {
	return func(d ownerch.Decision) {
		if !strings.HasPrefix(d.Ref, retryRefPrefix) {
			next(d)
			return
		}
		id, n, ok := parseRetryRef(d.Ref)
		if !ok || !d.Approved {
			return
		}
		go eng.Retry(ctx, id, n)
	}
}
