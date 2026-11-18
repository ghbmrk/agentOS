package main

// REQ: REV-CHK-mut
//
// OWN-page-session-mut2c (#5881): tests that kill the statement-deletion
// survivors #5862 left in evidence.go, main.go, held.go and signinhost.go.
// New functions only, in a file of their own, so no existing test's lines
// join the mutation gate's targets.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeclient"
	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/budget"
	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/recovery"
	"github.com/ghbmrk/agentos/broker/sockets"
	"github.com/ghbmrk/agentos/broker/vm"
)

// logLines collects what a logf prints, safe for the worker's goroutine.
type logLines struct {
	mu sync.Mutex
	l  []string
}

func (g *logLines) logf(format string, args ...any) {
	g.mu.Lock()
	g.l = append(g.l, fmt.Sprintf(format, args...))
	g.mu.Unlock()
}

func (g *logLines) has(sub string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.ContainsFunc(g.l, func(s string) bool { return strings.Contains(s, sub) })
}

// stuckOutbox is an outbox whose ReplyDone fails, so a routed reply stays.
type stuckOutbox struct{ fakeOutbox }

func (s *stuckOutbox) ReplyDone(string, string) error { return errors.New("outbox store unwritable") }

// The evidence worker, woken before the guest plane's outbox is served,
// waits for it, routes once it comes, and ends with its context
// (evidence.run).
func TestEvidenceRunWaitsForTheOutboxAndEndsWithItsContext(t *testing.T) {
	r := newEvRig(t)
	r.ev.wake = make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { r.ev.run(ctx); close(done) }()
	r.ev.poke() // no outbox yet
	time.Sleep(20 * time.Millisecond)
	src := &fakeOutbox{sent: r.texts}
	src.add("canary-mut2c-run")
	r.ev.serve(src)
	for end := time.Now().Add(5 * time.Second); !slices.Contains(r.texts(), "canary-mut2c-run"); time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("not routed once the outbox came: %q", r.texts())
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not end with its context")
	}
}

// A reply the outbox cannot retire is texted once and logged as staying,
// not texted again in a loop (evidence.run).
func TestEvidenceAReplyThatStaysIsTextedOnce(t *testing.T) {
	r := newEvRig(t)
	var logs logLines
	r.ev.logf = logs.logf
	r.ev.wake = make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.ev.run(ctx)
	src := &stuckOutbox{fakeOutbox{sent: r.texts}}
	src.add("canary-mut2c-stays")
	r.ev.serve(src)
	for end := time.Now().Add(5 * time.Second); !logs.has("stays in the outbox"); time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("no stay logged; texted %d", len(r.texts()))
		}
	}
	time.Sleep(20 * time.Millisecond)
	if got := r.texts(); !slices.Equal(got, []string{"canary-mut2c-stays"}) {
		t.Fatalf("texted %d times: %q", len(got), got)
	}
}

// A text that does not go is logged with its place in the reply; with no
// owner notice wired, a reply that could not be kept tells no one and does
// not fail (sendSplit, tellNotKept).
func TestEvidenceUnsentTextIsLoggedAndNoInformIsNoNotice(t *testing.T) {
	r := newEvRig(t)
	var logs logLines
	r.ev.logf = logs.logf
	r.ev.kept.store = failStore{}
	n := 0
	r.ev.notify = func(string) error {
		if n++; n == 2 {
			return errNoSend
		}
		return nil
	}
	r.ev.sendSplit("agent", strings.Repeat("A reply in two texts. ", 30))
	if !logs.has("reply from agent not sent (text 2 of 2)") {
		t.Fatalf("logged %q", logs.l)
	}
}

// cutAt falls back to the last word break in the first half when the
// second half has none.
func TestCutAtFallsBackToAWordInTheFirstHalf(t *testing.T) {
	if got := cutAt("ab "+strings.Repeat("x", 30), 20); got != 2 {
		t.Fatalf("cutAt = %d, want 2", got)
	}
	if got := cutAt(strings.Repeat("x", 30), 20); got != 20 {
		t.Fatalf("cutAt with no break = %d, want 20", got)
	}
}

// Two words that do not start with EVIDENCE or EMAIL REPLIES are no
// setting, even when the second is ON or OFF.
func TestSettingsNeedsEvidenceFirst(t *testing.T) {
	for _, msg := range []string{"LIGHTS OFF", "turn on", "EMAIL OFF"} {
		if r, ok := settings(msg, true); ok || r != "" {
			t.Fatalf("settings(%q) = %q, %t", msg, r, ok)
		}
	}
	if r, ok := settings("EVIDENCE OFF", true); !ok || r != evidenceNotYet {
		t.Fatalf("EVIDENCE OFF = %q, %t", r, ok)
	}
}

// wireOwner wires the broker's own notices too: with no owner channel they
// fail rather than vanish.
func TestWireOwnerWiresInform(t *testing.T) {
	r := newEvRig(t)
	r.ev.wireOwner(func() *owner.Channel { return nil })
	if r.ev.inform == nil {
		t.Fatal("inform not wired")
	}
	if err := r.ev.inform("x"); err == nil || !strings.Contains(err.Error(), "no owner channel") {
		t.Fatalf("inform with no channel: %v", err)
	}
}

// settle after a deletion releases the deletion lock: the next read and
// the next deletion go through.
func TestSettleAfterADeletionReleasesTheLock(t *testing.T) {
	r := newEvRig(t)
	src := &forgettingOutbox{fakeOutbox: fakeOutbox{sent: r.texts}}
	r.ev.kept.attach(src)
	gen, _ := r.ev.kept.pending(src)
	if _, err := r.ev.kept.forget(); err != nil {
		t.Fatal(err)
	}
	r.ev.kept.settle(gen)
	done := make(chan struct{})
	go func() {
		r.ev.kept.pending(src)
		r.ev.kept.forget()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("settle left the deletion lock held")
	}
}

// A count of dropped held texts with no owner channel is an error, not a
// crash (tellHeldDropped).
func TestTellHeldDroppedWithNoChannel(t *testing.T) {
	if err := tellHeldDropped(nil, 2); err == nil {
		t.Fatal("no channel, no error")
	}
	if err := tellHeldDropped(nil, 0); err != nil {
		t.Fatalf("none to tell: %v", err)
	}
}

// A reply that could not be kept is logged by kind, without its text.
func TestKeepLogsARefusal(t *testing.T) {
	r := newEvRig(t)
	var logs logLines
	r.ev.kept.logf = logs.logf
	r.store.Fail = errors.New("disk full")
	if err := r.ev.kept.keep(localapi.HeldLong, "canary-mut2c-keep"); err == nil {
		t.Fatal("kept on a failing store")
	}
	if !logs.has("a long reply was not kept: disk full") || logs.has("canary-mut2c-keep") {
		t.Fatalf("logged %q", logs.l)
	}
}

// A kept list that cannot be encoded (a time past year 9999) is refused,
// not saved empty.
func TestKeepRefusesAnUnencodableList(t *testing.T) {
	r := newEvRig(t)
	r.now = time.Date(10001, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := r.ev.kept.keep(localapi.HeldLong, "far future"); err == nil {
		t.Fatal("an unencodable list was saved")
	}
	if raw, _ := r.store.Load(); raw != nil {
		t.Fatalf("store holds %q", raw)
	}
}

// A sweep of a store that holds nothing writes nothing; one it cannot
// read is logged and left as it is.
func TestSweepLeavesAnEmptyStoreAndLogsABadOne(t *testing.T) {
	r := newEvRig(t)
	var logs logLines
	r.ev.kept.logf = logs.logf
	r.ev.kept.sweep()
	if raw, _ := r.store.Load(); raw != nil {
		t.Fatalf("an empty store was written: %q", raw)
	}
	if err := r.store.Save([]byte("{not json")); err != nil {
		t.Fatal(err)
	}
	r.ev.kept.sweep()
	if !logs.has("kept replies not swept") {
		t.Fatalf("logged %q", logs.l)
	}
	if raw, _ := r.store.Load(); string(raw) != "{not json" {
		t.Fatalf("a bad store was rewritten: %q", raw)
	}
	if err := r.ev.kept.keep(localapi.HeldLong, "x"); err == nil {
		t.Fatal("kept over a store it cannot read")
	}
	if raw, _ := r.store.Load(); string(raw) != "{not json" {
		t.Fatalf("keep wrote over a bad store: %q", raw)
	}
}

// A code kept before items carried their expired view reads, once its
// hour passes, with the code replaced and the rest of the text kept.
func TestALegacyKeptCodeExpiresToItsView(t *testing.T) {
	r := newEvRig(t)
	text := "Your Acme verification code is 482913. Ask me if it fails."
	at := r.now.Add(-2 * time.Hour)
	raw := fmt.Sprintf(`[{"id":"a1","kind":%q,"text":%q,"at":%q,"code_until":%q}]`,
		owner.KeptOneTime, text, at.Format(time.RFC3339Nano), at.Add(time.Hour).Format(time.RFC3339Nano))
	if err := r.store.Save([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	l := r.ev.kept.list()
	if len(l) != 1 || !l[0].CodeExpired || l[0].Text != owner.ExpireCodes(text) || !strings.Contains(l[0].Text, "Ask me if it fails.") {
		t.Fatalf("list %+v", l)
	}
}

// logged captures the standard logger's output for the test.
func logged(t *testing.T) func() string {
	t.Helper()
	var mu sync.Mutex
	var b strings.Builder
	log.SetOutput(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return b.Write(p)
	}))
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return b.String()
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// A floor the budget refuses falls back to the N95 floor's capacity,
// saying why (capacityFor).
func TestCapacityForFallsBackWhenTheBudgetRefusesTheFloor(t *testing.T) {
	floor := budget.Floor()
	floor.HeadroomMB = 0
	c, total, why := capacityFor("MemTotal: 16777216 kB\n", 4, false, 0, floor)
	if c != n95CapacityMB || total != 16384 || !strings.Contains(why, "; the N95 floor's") {
		t.Fatalf("capacityFor = %d, %d, %q", c, total, why)
	}
}

// The memory plan's budget is the floor with the pool admission hands
// out: capacity less headroom (planMemory).
func TestPlanMemoryBudgetIsTheFloorWithItsPool(t *testing.T) {
	floor := budget.Floor()
	for _, explicit := range []bool{false, true} {
		p := planMemory("MemTotal: 16777216 kB\n", 4, explicit, 1500, floor, defaultAgentMemMB)
		want := floor
		want.PoolMB = p.CapacityMB - floor.HeadroomMB
		if p.Budget != want || want.PoolMB <= 0 {
			t.Fatalf("explicit %t: budget %+v, want %+v", explicit, p.Budget, want)
		}
	}
}

// No worker image is no worker tools, even when an image is registered
// under the empty name; an unregistered one is logged.
func TestWorkerToolsNeedANamedRegisteredImage(t *testing.T) {
	out := logged(t)
	if workerTools(nil, images{"": "/x"}, "", "sleep infinity", 2048, workerGates{}) != nil {
		t.Fatal("tools with no image named")
	}
	if workerTools(nil, images{"base": "/x"}, "worker", "sleep infinity", 2048, workerGates{}) != nil {
		t.Fatal("tools for an unregistered image")
	}
	if !strings.Contains(out(), `worker tools off: image "worker" is not registered with -image`) {
		t.Fatalf("logged %q", out())
	}
}

// A plan seed with no route control is refused, not a crash.
func TestPlanSeederWithNoRouteControl(t *testing.T) {
	if _, err := (planSeeder{}).Seed("codex", "pw-a", false); err == nil || !strings.Contains(err.Error(), "no plan route control") {
		t.Fatalf("Seed: %v", err)
	}
}

type countReap struct{ n atomic.Int32 }

func (c *countReap) Reap(context.Context) []string { c.n.Add(1); return nil }

// The reaper parks idle workers once a minute, not on every tick, logs
// the commands STOP ended, and ends with its context (reapWorkers).
func TestReaperParksByTheMinuteLogsAndEnds(t *testing.T) {
	out := logged(t)
	reap, e := &countReap{}, &ender{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { reapWorkers(ctx, reap, e, func() bool { return true }, time.Millisecond); close(done) }()
	for end := time.Now().Add(5 * time.Second); e.n.Load() < 5; time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("the reaper did not tick")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the reaper did not end with its context")
	}
	if n := reap.n.Load(); n != 0 {
		t.Fatalf("parked %d times within a minute", n)
	}
	if !strings.Contains(out(), "STOP: ended 1 worker commands") {
		t.Fatalf("logged %q", out())
	}
}

// The agent's spec needs a named image that is registered, before its
// launch file is read (agentSpec).
func TestAgentSpecNeedsANamedRegisteredImage(t *testing.T) {
	launch := filepath.Join(t.TempDir(), "launch.json")
	must(t, os.WriteFile(launch, []byte(`{"Argv":["/bin/agent"]}`), 0o600))
	if _, err := agentSpec(images{"": "/x"}, "", launch, defaultAgentMemMB); err == nil || err.Error() != "-agent-image is empty" {
		t.Fatalf("no image: %v", err)
	}
	if _, err := agentSpec(images{"base": "/x"}, "openclaw", launch, defaultAgentMemMB); err == nil || !strings.Contains(err.Error(), `image "openclaw" is not registered`) {
		t.Fatalf("unregistered image: %v", err)
	}
	if s, err := agentSpec(images{"openclaw": "/x"}, "openclaw", launch, defaultAgentMemMB); err != nil || s.Image != "openclaw" {
		t.Fatalf("registered image: %+v, %v", s, err)
	}
}

// openPool stops at a root that is no cgroup v2 group, and at one whose
// budget cannot be applied (no pids.max).
func TestOpenPoolStopsAtEachFailure(t *testing.T) {
	mem, err := budget.ForHost(7680, 4, budget.Floor())
	must(t, err)
	if _, err := openPool(t.TempDir(), mem); !errors.Is(err, cgroup.ErrNotV2) {
		t.Fatalf("not a cgroup: %v", err)
	}
	root := t.TempDir()
	must(t, os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu io memory pids\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte("cpu io memory pids\n"), 0o644))
	if g, err := openPool(root, mem); err == nil {
		t.Fatalf("a budget with no pids.max applied: %+v", g)
	}
}

// A sweep of the guest inbox's directory that fails is logged.
func TestInboxSweepFailureIsLogged(t *testing.T) {
	out := logged(t)
	dir := t.TempDir()
	// ".durable-" is durable.TempPrefix, spelled out: the old-core ratchet counts imports of broker/durable.
	must(t, os.MkdirAll(filepath.Join(dir, ".durable-stage", "x"), 0o700))
	sweepInboxTemps(filepath.Join(dir, "guest-inbox.json"))
	if !strings.Contains(out(), "guest inbox: removing crash-left temporary files:") {
		t.Fatalf("logged %q", out())
	}
}

// The owner pacer's loop ends with its context.
func TestOwnerPacerRunEndsWithItsContext(t *testing.T) {
	p := &ownerPacer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.run(ctx, time.Hour); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the pacer did not end with its context")
	}
}

// removeOldDigest reports a path it cannot inspect rather than removing
// anything.
func TestRemoveOldDigestReportsAnUnreadablePath(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	must(t, os.WriteFile(file, nil, 0o600))
	if removed, err := removeOldDigest(filepath.Join(file, "digest")); removed || err == nil {
		t.Fatalf("removeOldDigest = %t, %v", removed, err)
	}
}

// heldFakeLink is the owner line as the held mode sees it: Send records
// each text and fails while fail is set, or blocks while hold is set;
// ops are served on the owner socket beside the state op.
type heldFakeLink struct {
	mu    sync.Mutex
	sent  []string
	fail  bool
	hold  chan struct{} // when set, Send waits for it to close
	in    chan modem.SMS
	ops   map[string]sockets.Handler
	calls chan string // each Send, as it starts
}

func newHeldFakeLink() *heldFakeLink {
	l := &heldFakeLink{in: make(chan modem.SMS, 8), calls: make(chan string, 16)}
	l.ops = map[string]sockets.Handler{
		bridgeproto.OpState: func(context.Context, sockets.Peer, json.RawMessage) (any, error) { return struct{}{}, nil },
	}
	return l
}

func (l *heldFakeLink) Send(_, text string) error {
	l.calls <- text
	l.mu.Lock()
	hold, fail := l.hold, l.fail
	l.mu.Unlock()
	if hold != nil {
		<-hold
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sent = append(l.sent, text)
	if fail {
		return errors.New("owner line down")
	}
	return nil
}

func (l *heldFakeLink) Inbox() <-chan modem.SMS         { return l.in }
func (l *heldFakeLink) Ops() map[string]sockets.Handler { return l.ops }

func (l *heldFakeLink) texts() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.sent)
}

// heldUp reports the owner line usable on m's owner socket, retrying
// until the socket serves.
func heldUp(t *testing.T, m heldMode) {
	t.Helper()
	b := fakeBridge{t: t, c: bridgeclient.Client{Path: filepath.Join(m.Dir, daemon.OwnerSocket)}}
	for end := time.Now().Add(5 * time.Second); b.call(bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil) != nil; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("owner.sock never served")
		}
	}
}

// With no Retry set, a first text that did not go is sent again only after
// heldResend, however soon the line reports usable again (heldMode.run).
func TestHeldRetryDefaultsToTheResendWait(t *testing.T) {
	learn := t.TempDir()
	writeHeld(t, learn, recovery.PendingUnanchored, 2, nil)
	m := newHeldMode(t, learn)
	m.Retry = 0
	link := newHeldFakeLink()
	link.fail = true
	m.Link = link
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.run(ctx) }()
	defer func() { cancel(); <-done }()
	heldUp(t, m)
	select {
	case <-link.calls:
	case <-time.After(5 * time.Second):
		t.Fatal("no first text")
	}
	heldUp(t, m)
	select {
	case text := <-link.calls:
		t.Fatalf("sent again before the resend wait: %q", text)
	case <-time.After(300 * time.Millisecond):
	}
}

// The held mode returns only once its sender has finished: a text in
// flight when its context ends holds the return (heldMode.run).
func TestHeldRunWaitsForATextInFlight(t *testing.T) {
	learn := t.TempDir()
	writeHeld(t, learn, recovery.PendingUnanchored, 2, nil)
	m := newHeldMode(t, learn)
	link := newHeldFakeLink()
	link.hold = make(chan struct{})
	m.Link = link
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.run(ctx) }()
	heldUp(t, m)
	<-link.calls
	cancel()
	select {
	case err := <-done:
		t.Fatalf("returned with a text in flight: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(link.hold)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run: %v", err)
	}
}

// The held mode returns only once its owner socket has finished serving:
// an op in flight holds the return (heldMode.run).
func TestHeldRunWaitsForTheSocket(t *testing.T) {
	learn := t.TempDir()
	writeHeld(t, learn, recovery.PendingUnanchored, 2, nil)
	m := newHeldMode(t, learn)
	link := newHeldFakeLink()
	entered, release := make(chan struct{}), make(chan struct{})
	link.ops["hang"] = func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
		close(entered)
		<-release
		return struct{}{}, nil
	}
	m.Link = link
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.run(ctx) }()
	heldUp(t, m)
	b := fakeBridge{t: t, c: bridgeclient.Client{Path: filepath.Join(m.Dir, daemon.OwnerSocket)}}
	go b.call("hang", nil, nil)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the op never ran")
	}
	cancel()
	select {
	case err := <-done:
		t.Fatalf("returned with an op in flight: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run: %v", err)
	}
}

// The opener sends nothing once its context has ended (heldMode.open).
func TestHeldOpenSendsNothingAfterItsContext(t *testing.T) {
	learn := t.TempDir()
	writeHeld(t, learn, recovery.PendingUnanchored, 2, nil)
	m := newHeldMode(t, learn)
	link := newHeldFakeLink()
	m.Link = link
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.open(ctx, &heldReplies{dir: learn, logf: t.Logf}, make(chan struct{}))
	if got := link.texts(); len(got) != 0 {
		t.Fatalf("sent %q after the context ended", got)
	}
}

// The answerer takes texts only from the owner's own number, and returns
// once one releases the restore (heldMode.answer).
func TestHeldAnswerTakesOnlyTheOwnerAndEndsAtRelease(t *testing.T) {
	learn := t.TempDir()
	writeHeld(t, learn, recovery.PendingUnanchored, 2, nil)
	m := newHeldMode(t, learn)
	link := newHeldFakeLink()
	m.Link = link
	var released atomic.Int32
	done := make(chan struct{})
	go func() {
		m.answer(context.Background(), &heldReplies{dir: learn, logf: t.Logf}, func() { released.Add(1) })
		close(done)
	}()
	link.in <- modem.SMS{From: "+15550100199", Text: "c"}
	link.in <- modem.SMS{From: heldOwnerNumber, Text: "c", Alphanumeric: true}
	time.Sleep(50 * time.Millisecond)
	if released.Load() != 0 || len(link.texts()) != 0 || restoreHold(learn) == nil {
		t.Fatalf("another sender was answered: %q, %d releases", link.texts(), released.Load())
	}
	link.in <- modem.SMS{From: heldOwnerNumber, Text: "c"}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("answer did not end at release")
	}
	if released.Load() != 1 || !slices.Equal(link.texts(), []string{heldReleased}) {
		t.Fatalf("released %d, sent %q", released.Load(), link.texts())
	}
}

// signInHook is the sign-in sandbox with a hook in its create, a start
// command that exits with exit, and reads that wait while readHold is set.
type signInHook struct {
	*signInBox
	afterCreate func()
	exit        int
	readIn      chan struct{}
	readHold    chan struct{}
}

func (b *signInHook) CreateProviderWorker(ctx context.Context, id string, s vm.Spec, seed map[string][]byte) (vm.Machine, error) {
	m, err := b.signInBox.CreateProviderWorker(ctx, id, s, seed)
	if b.afterCreate != nil {
		b.afterCreate()
	}
	return m, err
}

func (b *signInHook) Exec(ctx context.Context, id string, c vm.Command, timeout time.Duration) (vm.ExecResult, error) {
	if c.Argv[0] == "cat" && b.readHold != nil {
		b.readIn <- struct{}{}
		<-b.readHold
	}
	res, err := b.signInBox.Exec(ctx, id, c, timeout)
	if c.Argv[0] != "cat" && err == nil {
		res.ExitCode = b.exit
	}
	return res, err
}

// watching says whether h's lease watch still runs.
func watching(h *signInHost) bool {
	buf := make([]byte, 1<<20)
	for n := runtime.Stack(buf, true); ; n = runtime.Stack(buf, true) {
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	return strings.Contains(string(buf), fmt.Sprintf("(*signInHost).watch(%p", h))
}

func signInUnwatched(t *testing.T, h *signInHost) {
	t.Helper()
	signInWait(t, "the lease watch to end", func() bool { return !watching(h) })
}

// A second route for a guest with no sign-in running replaces the first,
// whatever the clerk left in it (signInHost.Route).
func TestSignInRouteAgainReplacesTheOld(t *testing.T) {
	h := newSignInHost(t, newSignInBox(func(string) string { return "" }), nil)
	route := signInRoute(t, h, "signin-a")
	must(t, os.WriteFile(filepath.Join(route, "left"), []byte("x"), 0o600))
	if again := signInRoute(t, h, "signin-a"); again != route {
		t.Fatalf("route %q, then %q", route, again)
	}
	if ents, _ := os.ReadDir(route); len(ents) != 0 {
		t.Fatalf("the old route's files stayed: %v", ents)
	}
}

// A sign-in command that exits non-zero is a failed start: logged with
// its status only, its machine destroyed and its guest freed.
func TestSignInStartThatExitsIsAFailure(t *testing.T) {
	out := logged(t)
	box := newSignInBox(func(string) string { return "" })
	h := newSignInHost(t, box, nil)
	hook := &signInHook{signInBox: box, exit: 3}
	h.M = hook
	signInRoute(t, h, "signin-a")
	if err := h.Start(context.Background(), "signin-a"); !errors.Is(err, errSignInFailed) {
		t.Fatalf("start: %v", err)
	}
	id := <-box.created
	if !box.gone(id) || h.byGuest["signin-a"] != nil {
		t.Fatal("a failed start kept its machine or guest")
	}
	if got := out(); !strings.Contains(got, "signin: signin-a: start "+id+": exit status 3, timed out false") {
		t.Fatalf("logged %q", got)
	}
}

// A sign-in stopped while its machine is created is destroyed and its
// start says so (signInHost.Start, stop).
func TestSignInStoppedAsItStarts(t *testing.T) {
	box := newSignInBox(func(string) string { return "" })
	h := newSignInHost(t, box, nil)
	hook := &signInHook{signInBox: box}
	hook.afterCreate = func() { h.Stop("signin-a") }
	h.M = hook
	signInRoute(t, h, "signin-a")
	if err := h.Start(context.Background(), "signin-a"); !errors.Is(err, errSignInStopped) {
		t.Fatalf("start: %v", err)
	}
	if id := <-box.created; !box.gone(id) {
		t.Fatal("the stopped sign-in's machine stayed")
	}
	signInUnwatched(t, h)
}

// Stop of a name that is no guest touches no route, even one whose name
// would sit in the routes directory.
func TestSignInStopOfABadNameTouchesNothing(t *testing.T) {
	h := newSignInHost(t, newSignInBox(func(string) string { return "" }), nil)
	odd := filepath.Join(h.Routes, "SIGNIN-A")
	must(t, os.Mkdir(odd, 0o700))
	h.Stop("SIGNIN-A")
	if _, err := os.Stat(odd); err != nil {
		t.Fatalf("Stop removed %s: %v", odd, err)
	}
}

// A machine that will not be destroyed is logged by guest and ID.
func TestSignInDestroyFailureIsLogged(t *testing.T) {
	out := logged(t)
	box := newSignInBox(func(string) string { return "" })
	h := newSignInHost(t, box, nil)
	signInRoute(t, h, "signin-a")
	must(t, h.Start(context.Background(), "signin-a"))
	id := <-box.created
	box.mu.Lock()
	box.stuck = map[string]bool{id: true}
	box.mu.Unlock()
	h.Stop("signin-a")
	if got := out(); !strings.Contains(got, "signin: signin-a: destroy "+id+": the runtime did not stop") {
		t.Fatalf("logged %q", got)
	}
}

// The lease watch ends when its sign-in is stopped, and when it ends the
// sign-in itself (signInHost.watch).
func TestSignInWatchEndsWithItsSignIn(t *testing.T) {
	box := newSignInBox(func(string) string { return "" })
	h := newSignInHost(t, box, nil)
	h.Lease = time.Hour
	signInRoute(t, h, "signin-a")
	must(t, h.Start(context.Background(), "signin-a"))
	<-box.created
	signInWait(t, "the lease watch", func() bool { return watching(h) })
	h.Stop("signin-a")
	signInUnwatched(t, h)

	h.Lease = 20 * time.Millisecond
	signInRoute(t, h, "signin-a")
	must(t, h.Start(context.Background(), "signin-a"))
	id := <-box.created
	signInWait(t, "the lease to end it", func() bool { return box.gone(id) })
	signInUnwatched(t, h)
}

// Each op refuses arguments it cannot read before it acts.
func TestSignInOpsRefuseMalformedArguments(t *testing.T) {
	box := newSignInBox(func(string) string { return "" })
	h := newSignInHost(t, box, nil)
	sock := filepath.Join(t.TempDir(), "signin", "signin.sock")
	stop, err := serveSignIns(sock, os.Getgid(), h)
	must(t, err)
	defer stop()
	c := bridgeclient.Client{Path: sock}
	for _, op := range []string{"signinroute", "signinstart", "signinread", "signinstop"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := c.Call(ctx, op, "signin-a", nil)
		cancel()
		if err == nil || !strings.Contains(err.Error(), string(sockets.ErrMalformed)) {
			t.Errorf("%s with malformed arguments: %v", op, err)
		}
	}
}

// serveSignIns reports a socket it cannot serve.
func TestServeSignInsReportsASocketItCannotServe(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	must(t, os.WriteFile(file, nil, 0o600))
	h := newSignInHost(t, newSignInBox(func(string) string { return "" }), nil)
	if stop, err := serveSignIns(filepath.Join(file, "signin.sock"), os.Getgid(), h); err == nil || stop != nil {
		t.Fatalf("serveSignIns in a file: %v", err)
	}
}

// Stopping the socket waits for an op in flight, then destroys every
// sign-in machine (serveSignIns' stop).
func TestSignInSockStopWaitsThenShutsDown(t *testing.T) {
	box := newSignInBox(func(string) string { return "" })
	h := newSignInHost(t, box, nil)
	hook := &signInHook{signInBox: box, readIn: make(chan struct{}, 1), readHold: make(chan struct{})}
	h.M = hook
	sock := filepath.Join(t.TempDir(), "signin", "signin.sock")
	stop, err := serveSignIns(sock, os.Getgid(), h)
	must(t, err)
	signInRoute(t, h, "signin-a")
	must(t, h.Start(context.Background(), "signin-a"))
	id := <-box.created
	go func() {
		c := bridgeclient.Client{Path: sock}
		c.Call(context.Background(), "signinread", signInArgs{Guest: "signin-a"}, nil)
	}()
	select {
	case <-hook.readIn:
	case <-time.After(5 * time.Second):
		t.Fatal("the read never ran")
	}
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("stop returned with an op in flight")
	case <-time.After(200 * time.Millisecond):
	}
	if box.gone(id) {
		t.Fatal("shut down with an op in flight")
	}
	close(hook.readHold)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not return")
	}
	if !box.gone(id) {
		t.Fatal("stop left the sign-in machine")
	}
}

// A code kept again through Keep keeps the view the first keep gave it,
// as KeepCode does: the same text is no stricter view (keptReplies.Keep).
func TestKeepOfAKeptCodeKeepsItsView(t *testing.T) {
	r := newEvRig(t)
	text := "Your Acme verification code is 482913. Ask me if it fails."
	view := owner.ExpireCodes(text)
	must(t, r.ev.kept.KeepCode(text, view))
	must(t, r.ev.kept.Keep(owner.KeptOneTime, text))
	r.now = r.now.Add(defaultCodeFor)
	if l := r.ev.kept.list(); len(l) != 1 || l[0].Text != view || view == owner.ExpiredCode {
		t.Fatalf("list %+v, want the view %q", l, view)
	}
}
