package daemon

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
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

// retrier lists the parked effects for RETRY and runs an approved retry
// (OP-2c). Each item is the effect's own verified line, as the gate would
// ask it now (grants.RetryItem), so its tier is the one its facts give and
// money takes a code-generator code; the owner is texted how the retry
// ended, and a refused one is listed again in the next digest.
type retrier struct {
	ctx  context.Context
	eng  *journal.Engine
	gate *grants.Gate

	running sync.WaitGroup // retries started by decide

	mu        sync.Mutex
	lines     map[string]grants.RetryLine
	inform    func(string) error
	onRefused func()
}

func newRetrier(ctx context.Context, eng *journal.Engine, gate *grants.Gate) *retrier {
	return &retrier{ctx: ctx, eng: eng, gate: gate, lines: map[string]grants.RetryLine{}}
}

// items lists the parked effects as owner-channel items (Config Retry),
// at most retryMax, and keeps the line each asks about.
func (r *retrier) items() []ownerch.Item {
	ps := r.eng.Parked()
	if len(ps) > retryMax {
		ps = ps[:retryMax]
	}
	items := make([]ownerch.Item, 0, len(ps))
	lines := make(map[string]grants.RetryLine, len(ps))
	for _, p := range ps {
		l := r.gate.RetryItem(r.ctx, p, EffectWord(p.Intent.Executor))
		ref := retryRef(p)
		l.Shown.Ref = ref
		lines[ref] = l
		items = append(items, l.Shown)
	}
	r.mu.Lock()
	for ref, l := range lines {
		r.lines[ref] = l
	}
	r.mu.Unlock()
	return items
}

// decide wraps the gate's Decide hook: an approved retry item runs the
// retry for the attempt the owner was asked about, off the owner
// channel's goroutine; a declined, expired or restart-dropped one does
// nothing (the effect stays parked), and every other decision goes to
// next.
func (r *retrier) decide(next func(ownerch.Decision)) func(ownerch.Decision) {
	return func(d ownerch.Decision) {
		if !strings.HasPrefix(d.Ref, retryRefPrefix) {
			next(d)
			return
		}
		id, n, ok := parseRetryRef(d.Ref)
		r.mu.Lock()
		l, known := r.lines[d.Ref]
		delete(r.lines, d.Ref)
		r.mu.Unlock()
		if !ok || !d.Approved || !known {
			return
		}
		page := d.Page && d.Sum == ownerch.ItemSum(l.Shown)
		r.running.Add(1)
		go func() {
			defer r.running.Done()
			r.run(d.Request, id, n, l, page)
		}()
	}
}

// run retries and texts the owner how it ended.
func (r *retrier) run(req, id string, n int, l grants.RetryLine, page bool) {
	st, err := r.gate.Retry(r.ctx, id, n, l, page)
	what := l.Shown.Object
	var text string
	switch {
	case err == nil && st.State == journal.Succeeded:
		text = fmt.Sprintf("Retry %s: %s went through.", req, what)
	case err == nil && (st.State == journal.NotApplied || st.State == journal.Denied):
		text = fmt.Sprintf("Retry %s: %s did not go.", req, what)
	case err == nil && st.State == journal.OutcomeUnknown:
		text = fmt.Sprintf("Retry %s: %s is unclear again; it may have gone. Text RETRY to try again; it may go twice.", req, what)
	case err == nil:
		text = fmt.Sprintf("Retry %s: %s is still being tried.", req, what)
	default:
		text = fmt.Sprintf("Retry %s refused: %s. %s was not tried again; text RETRY later.", req, refusal(err), capital(what))
	}
	r.mu.Lock()
	inform, refused := r.inform, r.onRefused
	r.mu.Unlock()
	if err != nil && refused != nil {
		refused()
	}
	if inform != nil {
		inform(text)
	}
}

// refusal names why a retry was refused, in fixed words.
func refusal(err error) string {
	switch {
	case errors.Is(err, journal.ErrStopped):
		return "STOP is on"
	case errors.Is(err, journal.ErrUnreconciled):
		return "another action on the account is still unclear"
	case errors.Is(err, journal.ErrRecheck):
		return "the broker's checks refused it"
	case errors.Is(err, grants.ErrRetryNotConfirmed):
		return "it must be approved on my Wi-Fi page"
	case errors.Is(err, journal.ErrState):
		return "it is no longer waiting for a retry"
	default:
		return "it could not be started"
	}
}

func capital(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
