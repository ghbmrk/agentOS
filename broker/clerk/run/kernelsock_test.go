package run

// REQ: CLK-1, CLK-7, LOG-7, KRN-7

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/model"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// serveSide serves side of b's kernel on a fresh socket that admits uid, and
// returns a Conn to it.
func serveSide(t *testing.T, b *box, side Side, uid int) Conn {
	t.Helper()
	sock := filepath.Join(shortDir(t), side.name+".sock")
	ln, err := ListenKernel(sock, uid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go ServeKernel(ln, b.h, side, func() int64 { return time.Now().UnixMilli() })
	return Conn{Socket: sock, UID: os.Getuid(), Timeout: 10 * time.Second}
}

// entries is how many entries b's log holds.
func (b *box) entries() int {
	n := 0
	b.h.With(func(k *kernel.Kernel) error { n = len(k.Log().Entries()); return nil })
	return n
}

// The owner seam crosses the owner socket as the frozen interface lists it
// (docs/LANES.md): each action lands in the log as the direct call does, a
// refusal keeps its code, and each read answers as State() does.
func TestOwnerSocketServesTheSeam(t *testing.T) {
	b := newBox(t, filepath.Join(shortDir(t), "web.sock"))
	o := Owner{serveSide(t, b, OwnerSide, os.Getuid())}

	p := kernel.SignPlan(kernel.Plan{ID: "o1", Key: b.key, Steps: []kernel.PlanStep{{Verb: key.Post, Clerk: "web",
		Args: map[string]string{"to": "alice", "msg": "hi"}, Content: "text", Labels: []string{"public"}}}}, holderPriv)
	if err := o.Submit(p); err != nil {
		t.Fatal(err)
	}
	if err := o.Submit(p); err == nil || err.Error() != kernel.ErrDuplicatePlan.Error() {
		t.Fatalf("a second submit: %v, want %v", err, kernel.ErrDuplicatePlan)
	}
	var rf *key.Refusal
	if err := o.Extend(b.key, "o1"); !errors.As(err, &rf) || rf.Code != kernel.CNotHeld {
		t.Fatalf("extend of an unheld plan: %v, want refusal %s", err, kernel.CNotHeld)
	}
	if err := o.Retry("o1", 0); err == nil || err.Error() != kernel.ErrNotParked.Error() {
		t.Fatalf("retry of an unparked step: %v", err)
	}
	ver, err := kernel.VerifyPlan(p, anchors)
	if err != nil {
		t.Fatal(err)
	}
	id := ver.ID()
	for _, a := range []func() error{
		func() error { return o.Pause(id) }, func() error { return o.Stop() }, func() error { return o.Reserve("codex-5h", 200) },
	} {
		if err := a(); err != nil {
			t.Fatal(err)
		}
	}
	b.h.With(func(k *kernel.Kernel) error {
		s := k.State()
		if s.Plans["o1"] == nil || !s.Changes.Paused[id] || !s.Changes.Stopped || s.Pools["codex-5h"].Reserve != 200 {
			t.Fatalf("the log after the owner's calls: plan %v, paused %v, stopped %v, pools %v",
				s.Plans["o1"] != nil, s.Changes.Paused[id], s.Changes.Stopped, s.Pools)
		}
		return nil
	})
	for _, a := range []func() error{func() error { return o.Unpause(id) }, func() error { return o.Resume() }, func() error { return o.Cancel("o1") }} {
		if err := a(); err != nil {
			t.Fatal(err)
		}
	}

	var (
		status []kernel.Unsettled
		lines  int
		held   map[string]kernel.SpendHold
		pools  map[string]kernel.Pool
	)
	b.h.With(func(k *kernel.Kernel) error {
		s := k.State()
		status, lines, held, pools = s.Status(), s.LineChanges(), s.SpendHeld, s.Pools
		if s.Changes.Paused[id] || s.Changes.Stopped || s.Plans["o1"].Status != kernel.SCancelled {
			t.Fatal("unpause, resume or cancel did not land")
		}
		return nil
	})
	gs, err := o.Status()
	same(t, "status", gs, status, err)
	gl, err := o.LineChanges()
	same(t, "line changes", gl, lines, err)
	gh, err := o.SpendHeld()
	same(t, "spend held", len(gh), len(held), err)
	gp, err := o.Pools()
	same(t, "pools", gp, pools, err)
	if _, ok, err := o.Task("none"); ok || err != nil {
		t.Fatalf("a task never opened reads live (%v)", err)
	}
}

func same(t *testing.T, what string, got, want any, err error) {
	t.Helper()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%s over the socket: %+v (%v), the log says %+v", what, got, err, want)
	}
}

// Each socket serves its side's calls and no other: the model clerk cannot
// STOP, issue or read the owner's state, and the owner side cannot meter. A
// call outside the table logs nothing (CLK-7).
func TestEachSocketServesOnlyItsSide(t *testing.T) {
	b := newBox(t, filepath.Join(shortDir(t), "web.sock"))
	owner := serveSide(t, b, OwnerSide, os.Getuid())
	meter := serveSide(t, b, MeterSide, os.Getuid())
	for name := range OwnerSide.ops {
		if _, ok := MeterSide.ops[name]; ok {
			t.Fatalf("both sides serve %s", name)
		}
	}
	before := b.entries()
	for _, op := range []string{"stop", "issue", "resume", "status", "submit"} {
		if err := meter.call(op, nil, nil); err == nil || !strings.Contains(err.Error(), "no call") {
			t.Fatalf("%s on the meter socket: %v, want refused", op, err)
		}
	}
	for _, op := range []string{"meter", "hold", "readpool", "admitspend"} {
		if err := owner.call(op, spendArgs{Plan: "p1", Amount: 1}, nil); err == nil || !strings.Contains(err.Error(), "no call") {
			t.Fatalf("%s on the owner socket: %v, want refused", op, err)
		}
	}
	if n := b.entries(); n != before {
		t.Fatalf("refused calls logged %d entries", n-before)
	}
}

// A kernel socket admits only its side's uid, and a caller sends nothing to
// a socket another uid holds (CLK-1).
func TestKernelSocketsCheckPeerUID(t *testing.T) {
	b := newBox(t, filepath.Join(shortDir(t), "web.sock"))
	before := b.entries()
	other := Owner{serveSide(t, b, OwnerSide, os.Getuid()+1)}
	if err := other.Stop(); err == nil {
		t.Fatal("a socket for another uid took the caller's STOP")
	}
	mine := serveSide(t, b, OwnerSide, os.Getuid())
	mine.UID = os.Getuid() + 1
	if err := (Owner{mine}).Stop(); err == nil {
		t.Fatal("a caller sent STOP to a socket another uid holds")
	}
	if n := b.entries(); n != before {
		t.Fatalf("calls refused by uid logged %d entries", n-before)
	}
}

// fakeProvider answers every model call with 400 bytes and counts them.
type fakeProvider struct{ calls int }

func (f *fakeProvider) Call(route, prompt string, maxOut int64) (string, model.Usage, error) {
	f.calls++
	return strings.Repeat("x", 400), model.Usage{}, nil
}

// The model clerk runs apart from the kernel and meters through the meter
// socket: a call is admitted against the plan's cap, its use lands in the
// log on the kernel's clock whatever the clerk's says, and a call past the
// cap is refused with the cap's code, which holds the plan, without reaching
// the provider (LOG-7, #2572).
func TestModelClerkMetersThroughTheKernelSocket(t *testing.T) {
	b := newBoxFor(t, filepath.Join(shortDir(t), "web.sock"), "model", key.Read)
	root := key.Issue(ownerPriv, key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "m"})
	ky, err := key.ClerkKey(root, ownerPriv, holderPub, b.now, 1<<40, key.LimitSpendTask(100))
	if err != nil {
		t.Fatal(err)
	}
	cos := []key.Cosign{key.Approve(ownerPriv, kernel.BatchHash(root, ky)), key.Approve(sparePriv, kernel.BatchHash(root, ky))}
	p := kernel.SignPlan(kernel.Plan{ID: "t", Key: ky, Steps: []kernel.PlanStep{{Verb: key.Read, Clerk: "model", Args: map[string]string{"query": "q"}}}}, holderPriv)
	if err := b.h.With(func(k *kernel.Kernel) error {
		if err := k.Issue(b.now-kernel.GrantHold, cos, root, ky); err != nil {
			return err
		}
		return k.Submit(b.now, p)
	}); err != nil {
		t.Fatal(err)
	}

	pr := &fakeProvider{}
	c := &model.Clerk{Routes: map[string]model.Price{"api": {InPerM: 1_000_000, OutPerM: 1_000_000}}, Provider: pr,
		Ledger: Meter{serveSide(t, b, MeterSide, os.Getuid())}}
	sock := filepath.Join(shortDir(t), "model.sock")
	ln, err := ListenModel(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ServeModel(ln, c, func() int64 { return 0 }) // a clerk clock far behind
	m := Model{Conn{Socket: sock, UID: os.Getuid(), Timeout: 10 * time.Second}}

	start := time.Now().UnixMilli()
	if reply, err := m.Call("t", "api", "hi", 50); err != nil || len(reply) != 400 {
		t.Fatalf("a call within the cap: %d bytes, %v", len(reply), err)
	}
	var used kernel.Entry
	b.h.With(func(k *kernel.Kernel) error {
		for _, e := range k.Log().Entries() {
			if e.Type == kernel.TModelUsed {
				used = e
			}
		}
		return nil
	})
	if used.Type == "" || used.At < start || !strings.Contains(string(used.Body), `"api"`) {
		t.Fatalf("the metered use: %+v, want a model.used entry at the kernel's time (>= %d)", used, start)
	}

	_, err = m.Call("t", "api", "hi", 1000)
	var rf *key.Refusal
	if !errors.As(err, &rf) || rf.Code != key.RSpendTask {
		t.Fatalf("a call past the cap: %v, want refusal %s", err, key.RSpendTask)
	}
	if pr.calls != 1 {
		t.Fatalf("the provider saw %d calls, want 1", pr.calls)
	}
	b.h.With(func(k *kernel.Kernel) error {
		if _, ok := k.State().SpendHeld["t"]; !ok {
			t.Fatal("the plan past its cap is not held")
		}
		return nil
	})
}

// A meter socket that cannot be reached admits nothing: the clerk refuses
// the call as the broken log does, and the provider is never called.
func TestModelClerkWithoutTheKernelCallsNothing(t *testing.T) {
	pr := &fakeProvider{}
	c := &model.Clerk{Routes: map[string]model.Price{"api": {InPerM: 1, OutPerM: 1}}, Provider: pr,
		Ledger: Meter{Conn{Socket: filepath.Join(shortDir(t), "none.sock"), UID: os.Getuid()}}}
	_, err := c.Call(0, "t", "api", "hi", 10)
	var rf *key.Refusal
	if !errors.As(err, &rf) || rf.Code != kernel.CBroken || pr.calls != 0 {
		t.Fatalf("no kernel: %v with %d provider calls, want refusal %s and none", err, pr.calls, kernel.CBroken)
	}
}

// A call whose answer is cut off is ErrLost, never a success or a refusal
// the caller might act on.
func TestAKernelCallCutOffIsLost(t *testing.T) {
	sock := filepath.Join(shortDir(t), "cut.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Read(make([]byte, 1))
			c.Close()
		}
	}()
	err = Owner{Conn{Socket: sock, UID: os.Getuid(), Timeout: 5 * time.Second}}.Stop()
	if !errors.Is(err, ErrLost) {
		t.Fatalf("a cut-off STOP: %v, want %v", err, ErrLost)
	}
}
