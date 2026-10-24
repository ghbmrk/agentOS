package run

// REQ: LOG-7, CLK-1

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/model"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernelproc"
)

// fakeProvider answers every model call with 400 bytes, or err, and counts
// them.
type fakeProvider struct {
	calls int
	err   error
}

func (f *fakeProvider) Call(route, prompt string, maxOut int64) (string, model.Usage, error) {
	f.calls++
	return strings.Repeat("x", 400), model.Usage{}, f.err
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
		Ledger: kernelproc.Meter{Conn: serveMeter(t, b)}}
	sock := filepath.Join(shortDir(t), "model.sock")
	ln, err := ListenModel(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ServeModel(ln, c, func() int64 { return 0 }) // a clerk clock far behind
	m := Model{kernelproc.Conn{Socket: sock, UID: os.Getuid(), Timeout: 10 * time.Second}}

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
		Ledger: kernelproc.Meter{Conn: kernelproc.Conn{Socket: filepath.Join(shortDir(t), "none.sock"), UID: os.Getuid()}}}
	_, err := c.Call(0, "t", "api", "hi", 10)
	var rf *key.Refusal
	if !errors.As(err, &rf) || rf.Code != kernel.CBroken || pr.calls != 0 {
		t.Fatalf("no kernel: %v with %d provider calls, want refusal %s and none", err, pr.calls, kernel.CBroken)
	}
}

// A provider's own error, which can carry its URL or a key, never leaves the
// model clerk's process: the planner sees ErrModelCall, while a refusal
// still crosses with its code (CLK-1, #2717 Security 1).
func TestAProviderErrorStaysInTheModelClerk(t *testing.T) {
	const canary = "CANARY-SECRET-2717"
	pr := &fakeProvider{err: errors.New("Post https://api.example.test/v1?key=" + canary + ": 401")}
	c := &model.Clerk{Routes: map[string]model.Price{"api": {InPerM: 1, OutPerM: 1}}, Provider: pr, Ledger: admitAll{}}
	sock := filepath.Join(shortDir(t), "model.sock")
	ln, err := ListenModel(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ServeModel(ln, c, func() int64 { return 0 })
	m := Model{kernelproc.Conn{Socket: sock, UID: os.Getuid(), Timeout: 10 * time.Second}}
	_, err = m.Call("t", "api", "hi", 10)
	if !errors.Is(err, ErrModelCall) || strings.Contains(err.Error(), canary) || pr.calls != 1 {
		t.Fatalf("a failed provider call: %v (%d calls), want %v without the canary", err, pr.calls, ErrModelCall)
	}
}

// admitAll is a ledger that admits and records everything.
type admitAll struct{}

func (admitAll) AdmitSpend(_ int64, plan string, _ int64) (kernel.Admitted, *key.Refusal) {
	return kernel.Admitted{Plan: plan}, nil
}

func (admitAll) Meter(int64, kernel.Admitted, string, int64, string) error { return nil }

func (admitAll) Hold(int64, string, *key.Refusal) error { return nil }

func (admitAll) AdmitPool(int64, string) *key.Refusal { return nil }

func (admitAll) ReadPool(int64, string, int64, int64) error { return nil }

// serveMeter serves b's kernel's meter side on a fresh socket that admits
// this uid, and returns a Conn to it.
func serveMeter(t *testing.T, b *box) kernelproc.Conn {
	t.Helper()
	sock := filepath.Join(shortDir(t), "meter.sock")
	ln, err := kernelproc.ListenKernel(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go kernelproc.ServeKernel(ln, b.h, kernelproc.MeterSide, func() int64 { return time.Now().UnixMilli() })
	return kernelproc.Conn{Socket: sock, UID: os.Getuid(), Timeout: 10 * time.Second}
}
