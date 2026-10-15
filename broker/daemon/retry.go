package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
// allow (OP-2b). wait and maxWait are passed in, not read from the package
// settings, so the goroutine never touches them after the caller returns.
// After each, it dispatches through dispatch (the gate's
// Dispatch) the held resubmissions that a not-done effect waits for
// (journal Release, R12), so that effect is not left to the agent.
func settleLoop(ctx context.Context, eng *journal.Engine, every, wait, maxWait time.Duration, dispatch func(context.Context, string) (journal.Status, error)) {
	for {
		eng.SettleUnknown(ctx, wait, maxWait)
		eng.Release(ctx, dispatch)
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

// retryRef is the ref of one ask about p: "retry:<id>:<attempt>:<nonce>".
// The nonce is new for every ask, so each request the owner is sent has
// its own ref, and a decision on one request touches only the line that
// request showed (CH-12, OP-3): approving an older request never runs a
// newer line, and an older request's NO or expiry never drops a newer
// one's.
func retryRef(p journal.ParkedIntent, nonce string) string {
	return retryRefPrefix + p.Intent.ID + ":" + strconv.Itoa(p.Attempt) + ":" + nonce
}

// newNonce is a fresh retry-ask nonce.
func newNonce() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand does not fail on Linux
	}
	return hex.EncodeToString(b[:])
}

// parseRetryRef returns the intent ID and attempt a retry ref names.
func parseRetryRef(ref string) (id string, attempt int, ok bool) {
	rest, ok := strings.CutPrefix(ref, retryRefPrefix)
	if !ok {
		return "", 0, false
	}
	i := strings.LastIndexByte(rest, ':')
	if i <= 0 || i == len(rest)-1 {
		return "", 0, false
	}
	rest = rest[:i]
	i = strings.LastIndexByte(rest, ':')
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

// retrier lists the parked effects, and the effects a check proved were
// not done but that were not sent again, for RETRY, and runs an approved
// retry (OP-2c). Each item is the effect's own verified line, as the gate
// would ask it now (grants.RetryItem), so its tier is the one its facts
// give and a parked payment takes a code-generator code; the owner is
// texted how the retry ended, and a refused one is listed again in the
// next digest, unless the same effect went another way.
type retrier struct {
	ctx  context.Context
	eng  *journal.Engine
	gate *grants.Gate
	// line builds the line asked about, and send runs an approved one:
	// the gate's RetryItem, and its Retry or (for a not-done effect)
	// Resend. Tests replace them.
	line func(context.Context, journal.ParkedIntent, string) grants.RetryLine
	send func(ctx context.Context, a retryAsk, page bool) (journal.Status, error)

	running sync.WaitGroup // retries started by decide

	mu        sync.Mutex
	lines     map[string]retryAsk // by ref, which is unique to one ask
	inform    func(string) error
	onRefused func()
}

// retryAsk is one effect the owner was asked to retry, as asked.
type retryAsk struct {
	id      string
	attempt int
	line    grants.RetryLine
	notDone bool // a check proved attempt did not go (journal.NotResent)
}

func newRetrier(ctx context.Context, eng *journal.Engine, gate *grants.Gate) *retrier {
	r := &retrier{ctx: ctx, eng: eng, gate: gate, lines: map[string]retryAsk{}, line: gate.RetryItem}
	r.send = func(ctx context.Context, a retryAsk, page bool) (journal.Status, error) {
		if a.notDone {
			return gate.Resend(ctx, a.id, a.attempt, a.line, page)
		}
		return gate.Retry(ctx, a.id, a.attempt, a.line, page)
	}
	return r
}

// waiting lists the effects RETRY may offer: the parked ones, then those
// a check proved were not done and that were not sent again.
func (r *retrier) waiting() []journal.ParkedIntent {
	return append(r.eng.Parked(), r.eng.NotResent()...)
}

// items lists the waiting effects as owner-channel items (Config Retry),
// at most retryMax, and keeps the line each asks about under a ref new
// to this ask.
func (r *retrier) items() []ownerch.Item {
	ps := r.waiting()
	if len(ps) > retryMax {
		ps = ps[:retryMax]
	}
	items := make([]ownerch.Item, 0, len(ps))
	lines := make(map[string]retryAsk, len(ps))
	for _, p := range ps {
		l := r.line(r.ctx, p, EffectWord(p.Intent.Executor))
		ref := retryRef(p, newNonce())
		l.Shown.Ref = ref
		lines[ref] = retryAsk{id: p.Intent.ID, attempt: p.Attempt, line: l, notDone: p.NotDone}
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
// retry of the line that request showed, for the attempt it asked about,
// off the owner channel's goroutine; a declined, expired or
// restart-dropped one does nothing (the effect stays waiting), and every
// other decision goes to next. Each ref is one ask's own, so a decision
// on one request never runs or drops another request's line.
func (r *retrier) decide(next func(ownerch.Decision)) func(ownerch.Decision) {
	return func(d ownerch.Decision) {
		if !strings.HasPrefix(d.Ref, retryRefPrefix) {
			next(d)
			return
		}
		id, n, ok := parseRetryRef(d.Ref)
		r.mu.Lock()
		a, known := r.lines[d.Ref]
		delete(r.lines, d.Ref)
		r.mu.Unlock()
		if !ok || !d.Approved || !known || a.id != id || a.attempt != n {
			return
		}
		page := d.Page && d.Sum == ownerch.ItemSum(a.line.Shown)
		r.running.Add(1)
		go func() {
			defer r.running.Done()
			r.run(d.Request, a, page)
		}()
	}
}

// run retries and texts the owner how it ended.
func (r *retrier) run(req string, a retryAsk, page bool) {
	st, err := r.send(r.ctx, a, page)
	what := a.line.Shown.Object
	var text string
	var superseded *journal.SupersededError
	switch {
	case errors.As(err, &superseded):
		// The same effect went, waits to go, or may have gone as another
		// request (journal sameEffect): nothing is left to retry now, so
		// it is not listed again and the owner is not told to try later;
		// the engine offers it again if that request is proved not done
		// or denied.
		text = fmt.Sprintf("Retry %s: nothing was sent. %s %s as another request, so it was not sent again.", req, capital(what), supersededHow(superseded.Rival))
	case err == nil && st.State == journal.Succeeded:
		text = fmt.Sprintf("Retry %s: %s went through.", req, what)
	case err == nil && st.Unclear() != 0:
		// The service refused this try, but the parked first try may
		// still have gone (journal Status.Unclear): never "did not go"
		// (CH-12). It stays parked and is listed again.
		text = fmt.Sprintf("Retry %s: this try of %s did not go, but the first try may still have gone. I keep checking. Text RETRY to try again; it may go twice.", req, what)
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
	if (err != nil && superseded == nil || err == nil && st.Unclear() != 0) && refused != nil {
		refused()
	}
	if inform != nil {
		inform(text)
	}
}

// supersededHow says, in fixed words, what the request that superseded a
// retry did (journal SupersededError.Rival).
func supersededHow(rival journal.State) string {
	switch rival {
	case journal.Succeeded:
		return "already went"
	case journal.Pending, journal.Authorized:
		return "is waiting to go"
	case journal.InFlight, journal.OutcomeUnknown:
		return "may have gone"
	}
	return "already went, or is waiting to go,"
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
