package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: ARC-2, CH-2, OP-2, CH-10, CH-12

// Small helpers keep their edge cases: the default redactor keeps an empty
// value empty, so a reader tells "nothing" from "kept back"; capital of ""
// is ""; a ref without the retry prefix is not a retry ref; an empty or
// over-long machine id is refused. (#4972: each case is a statement
// deletion the suite did not see.)
func TestTheDaemonsSmallHelpersKeepTheirEdges(t *testing.T) {
	if got := redactAll(""); got != "" {
		t.Errorf("redactAll(\"\") = %q", got)
	}
	if got := redactAll("x"); got != Redacted {
		t.Errorf("redactAll(x) = %q", got)
	}
	if got := capital(""); got != "" {
		t.Errorf("capital(\"\") = %q", got)
	}
	if id, n, ok := parseRetryRef("loops:off:1:2:abcd"); ok {
		t.Errorf("a ref without %q parsed as %q %d", retryRefPrefix, id, n)
	}
	if id, n, ok := parseRetryRef(retryRefPrefix + "loops:off:1:2:abcd"); !ok || id != "loops:off:1" || n != 2 {
		t.Errorf("a retry ref parsed as %q %d %v", id, n, ok)
	}
	for _, bad := range []string{"", strings.Repeat("a", 33)} {
		if validID(bad) {
			t.Errorf("validID(%q)", bad)
		}
	}
	if !validID(strings.Repeat("a", 32)) {
		t.Error("a 32-character id refused")
	}
}

// A call the stage serves gets a context that ends when the call returns,
// so nothing the handler started outlives it; once shut, a call is refused
// even while the daemon's own context is still live (owner O34).
func TestTheStagesCallsEndWithTheirCallAndShutRefuses(t *testing.T) {
	s := &stage{}
	var got context.Context
	h := s.wrap(context.Background(), func(ctx context.Context, _ sockets.Peer, _ json.RawMessage) (any, error) {
		got = ctx
		return "ok", nil
	})
	if r, err := h(context.Background(), sockets.Peer{}, nil); err != nil || r != "ok" {
		t.Fatalf("call: %v %v", r, err)
	}
	if got.Err() == nil {
		t.Fatal("the handler's context outlived its call")
	}
	s.shut()
	if _, err := h(context.Background(), sockets.Peer{}, nil); !errors.Is(err, errStopping) {
		t.Fatalf("a call after shut: %v", err)
	}
}

// ctxKernel is a kernel that keeps the context of every call, so a test
// sees each is ended once its owner command returns.
type ctxKernel struct {
	mu         sync.Mutex
	ctxs       []context.Context
	stoppedErr error
	resumed    int
	steps      []KernelStep
}

func (k *ctxKernel) keep(ctx context.Context) {
	k.mu.Lock()
	k.ctxs = append(k.ctxs, ctx)
	k.mu.Unlock()
}

func (k *ctxKernel) Stop(ctx context.Context) error { k.keep(ctx); return nil }
func (k *ctxKernel) Resume(ctx context.Context, _ uint64) error {
	k.keep(ctx)
	k.mu.Lock()
	k.resumed++
	k.mu.Unlock()
	return nil
}
func (k *ctxKernel) Stopped(ctx context.Context) (bool, uint64, error) {
	k.keep(ctx)
	return false, 0, k.stoppedErr
}
func (k *ctxKernel) SetupOpen(ctx context.Context) (bool, error) { k.keep(ctx); return false, nil }
func (k *ctxKernel) Status(ctx context.Context) ([]KernelStep, error) {
	k.keep(ctx)
	return k.steps, nil
}
func (k *ctxKernel) Retry(ctx context.Context, _ string, _, _ int) error { k.keep(ctx); return nil }

// live names the kept contexts not yet ended, and forgets them all.
func (k *ctxKernel) live() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	n := 0
	for _, c := range k.ctxs {
		if c.Err() == nil {
			n++
		}
	}
	k.ctxs = nil
	return n
}

// Every kernel leg an owner command runs is bounded by its own context,
// ended when the leg returns, so a kernel that keeps a call's context sees
// it end at once rather than at kernelFor (#2783). RESUME reads the stop
// count first; a failed read is the RESUME's error, and nothing is
// resumed on a count never read (#3078).
func TestEveryKernelLegsContextEndsWithTheLeg(t *testing.T) {
	k := &ctxKernel{}
	b := &bothStops{Engine: nopEngine{}, k: k}
	if err := b.kernel(context.Background(), k.Stop); err != nil {
		t.Fatal(err)
	}
	if n := k.live(); n != 0 {
		t.Errorf("STOP: %d kernel contexts still live", n)
	}
	b.Stopped()
	if n := k.live(); n != 0 {
		t.Errorf("Stopped: %d kernel contexts still live", n)
	}
	b.List()
	if n := k.live(); n != 0 {
		t.Errorf("List: %d kernel contexts still live", n)
	}
	k.stoppedErr = errors.New("read refused")
	if err := b.resumeKernel(context.Background()); err == nil || !strings.Contains(err.Error(), "read refused") {
		t.Errorf("resumeKernel with its read refused: %v", err)
	}
	if k.resumed != 0 {
		t.Errorf("resumed %d times on a stop count never read", k.resumed)
	}
}

// nopEngine is a journal side with nothing in it.
type nopEngine struct{ control.Engine }

func (nopEngine) Stopped() bool          { return false }
func (nopEngine) List() []control.Status { return nil }

// RETRY's kernel legs, reading the parked steps and sending the retry, end
// their contexts when they return (#2783 b).
func TestRETRYsKernelLegsEndTheirContexts(t *testing.T) {
	k := &ctxKernel{steps: []KernelStep{{Plan: "p1", Index: 1, Verb: "organize", Clerk: "mail", Phase: KernelParked, Retry: true, Attempt: 1}}}
	r := newRetrier(context.Background(), nil, nil)
	r.k = k
	if got, err := r.kernelParked(1); err != nil || len(got) != 1 {
		t.Fatalf("kernelParked: %v %v", got, err)
	}
	if n := k.live(); n != 0 {
		t.Errorf("kernelParked: %d kernel contexts still live", n)
	}
	a := kernelAsk(k.steps[0], "", nil)
	r.runKernel("R1", a, true)
	if n := k.live(); n != 0 {
		t.Errorf("runKernel: %d kernel contexts still live", n)
	}
}

// A kernel RETRY ask is used once: the same approval delivered twice
// retries the step once. A decision that is no retry's goes on to the gate
// (#2783 b, CH-12).
func TestAKernelRETRYAskActsOnceAndOtherDecisionsGoOn(t *testing.T) {
	k := &countKernel{}
	r := newRetrier(context.Background(), nil, nil)
	r.k = k
	a := kernelAsk(KernelStep{Plan: "p1", Index: 1, Verb: "organize", Clerk: "mail", Phase: KernelParked, Retry: true, Attempt: 1}, "", nil)
	r.lines[a.line.Shown.Ref] = a
	var next []string
	decide := r.decide(func(d ownerch.Decision) { next = append(next, d.Ref) })
	d := ownerch.Decision{Request: "R1", Item: 1, Ref: a.line.Shown.Ref, Approved: true, Page: true, Sum: ownerch.ItemSum(a.line.Shown)}
	decide(d)
	decide(d)
	r.running.Wait()
	if k.retries != 1 {
		t.Errorf("one approval delivered twice retried %d times", k.retries)
	}
	if len(next) != 0 {
		t.Errorf("a kernel retry decision went on: %q", next)
	}
	decide(ownerch.Decision{Request: "R2", Item: 1, Ref: "grant/1", Approved: true})
	if len(next) != 1 || next[0] != "grant/1" {
		t.Errorf("a gate decision went to %q", next)
	}
}

type countKernel struct {
	ctxKernel
	retries int
}

func (k *countKernel) Retry(context.Context, string, int, int) error {
	k.mu.Lock()
	k.retries++
	k.mu.Unlock()
	return nil
}

// unknownExec never learns what its effects did.
type unknownExec struct{}

func (unknownExec) Execute(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultUnknown}
}
func (unknownExec) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultUnknown}
}

// One RETRY asks about at most retryMax effects, however many wait (OP-2):
// with more parked, the ask lists retryMax and offers none of the kernel's.
func TestOneRETRYAsksAboutAtMostRetryMax(t *testing.T) {
	ctx := context.Background()
	eng, err := journal.Open(&journal.MemStore{}, allowAll{}, map[string]journal.Executor{"x": unknownExec{}}, redactAll)
	if err != nil {
		t.Fatal(err)
	}
	for i := range retryMax + 1 {
		in := journal.Intent{ID: fmt.Sprintf("x/%d", i), Origin: "owner", Account: fmt.Sprintf("acct%d", i), Action: "x.do", Executor: "x"}
		if _, err := eng.Submit(in); err != nil {
			t.Fatal(err)
		}
		if _, err := eng.Authorize(ctx, in.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := eng.Dispatch(ctx, in.ID); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(eng.Parked()) < retryMax+1 {
		if time.Now().After(deadline) {
			t.Fatalf("%d parked", len(eng.Parked()))
		}
		eng.SettleUnknown(ctx, time.Microsecond, time.Microsecond)
	}
	r := newRetrier(ctx, eng, nil)
	r.line = func(_ context.Context, p journal.ParkedIntent, _ string) grants.RetryLine {
		return grants.RetryLine{Shown: ownerch.Item{Object: p.Intent.ID}}
	}
	r.k = &ctxKernel{steps: []KernelStep{{Plan: "p1", Index: 1, Verb: "organize", Clerk: "mail", Phase: KernelParked, Retry: true}}}
	items, err := r.items()
	if err != nil || len(items) != retryMax {
		t.Fatalf("one RETRY asks about %d items (%v), want %d", len(items), err, retryMax)
	}
}
