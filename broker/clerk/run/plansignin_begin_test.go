package run

// REQ: CLK-7

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"sync/atomic"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/plan"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// beginHookCtx runs hook once when Begin first asks for its Done channel:
// context.AfterFunc does so in Begin after its own stop check and before
// plan.Login.BeginSignIn, so hook can change the login in between. Its nil
// channel means it is never done.
type beginHookCtx struct {
	context.Context
	hook func()
	ran  atomic.Bool
}

func (c *beginHookCtx) Done() <-chan struct{} {
	if !c.ran.Swap(true) {
		c.hook()
	}
	return nil
}

// A login that stops as unswappable after Begin's first check is refused by
// BeginSignIn with plan.ErrStopped: Begin tells that stop and starts no
// sandbox (CLK-7).
func TestPlanSignInBeginTellsAStopFromBeginSignIn(t *testing.T) {
	k := make([]byte, 32)
	rand.Read(k)
	s, err := clerk.NewAESSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	store := plan.NewStore(s, nil)
	d := plan.Codex(netguard.New(netguard.Config{}))
	d.Mode = plan.Permitted
	login, err := plan.New(d, store, x509.NewCertPool())
	if err != nil {
		t.Fatal(err)
	}
	cli := newFakeCLI(login, codexPrinted)
	h := &PlanHost{Login: login, Prompt: CodexSignIn(), Workers: cli, Times: quick}
	ctx := &beginHookCtx{Context: context.Background(), hook: func() {
		if login.Stopped() != "" {
			t.Error("stopped before the hook")
		}
		store.Load([]byte("not a sealed login"))
	}}
	if b := h.Begin(ctx); b != (PlanBegun{Detail: plan.DStopped + " " + plan.StopUnswappable}) {
		t.Fatalf("begun: %+v", b)
	}
	if !ctx.ran.Load() {
		t.Fatal("the hook did not run")
	}
	if n, _ := cli.started(); n != 0 {
		t.Fatal("a sandbox was started")
	}
	if st := h.State(); st.Signing || st.Last != plan.DStopped+" "+plan.StopUnswappable {
		t.Fatalf("after begin: %+v", st)
	}
}

// A guest BeginSignIn refuses for another reason (here it became a run
// guest) fails the sign-in: no sandbox starts (CLK-7).
func TestPlanSignInBeginStartsNoSandboxWhenBeginSignInFails(t *testing.T) {
	var calls atomic.Int32
	login, _ := planLoginAt(t, plan.Permitted, tokenProvider(&calls, nil))
	codeExchange(t, login, "s")
	login.Forget("s")
	cli := newFakeCLI(login, codexPrinted)
	h := &PlanHost{Login: login, Prompt: CodexSignIn(), Workers: cli, Times: quick}
	ctx := &beginHookCtx{Context: context.Background()}
	ctx.hook = func() {
		h.mu.Lock()
		guest := h.cur.guest
		h.mu.Unlock()
		if _, err := login.Guest(guest); err != nil {
			t.Errorf("the sign-in guest as a run guest: %v", err)
		}
	}
	if b := h.Begin(ctx); b != (PlanBegun{Detail: DSignInFailed}) {
		t.Fatalf("begun: %+v", b)
	}
	if !ctx.ran.Load() {
		t.Fatal("the hook did not run")
	}
	if n, _ := cli.started(); n != 0 {
		t.Fatal("a sandbox was started")
	}
	if st := h.State(); st.Signing || st.Last != DSignInFailed {
		t.Fatalf("after begin: %+v", st)
	}
}
