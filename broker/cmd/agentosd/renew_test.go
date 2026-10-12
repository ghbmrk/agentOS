package main

// REQ: CAP-3

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/recalltool"
)

type fakeRenewer struct {
	full  []string
	asked []string
	err   error
}

func (f *fakeRenewer) Full() []string { return f.full }

func (f *fakeRenewer) AskRenew(_ context.Context, lineage string) error {
	if f.err != nil {
		return f.err
	}
	f.asked = append(f.asked, lineage)
	return nil
}

func newOwnerRenew(full ...string) (*ownerRenew, *fakeRenewer, *time.Time) {
	f := &fakeRenewer{full: full}
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	return &ownerRenew{r: f, now: func() time.Time { return now }}, f, &now
}

func TestRecallProvOwnerRenewListsFullAgentsByName(t *testing.T) {
	o, f, _ := newOwnerRenew("root.3fa9c2", "helper.77aa", "bad name!.01", "averyveryverylongrootname.01")
	r, ok := o.Text(context.Background(), "renew", true)
	if !ok || !strings.Contains(r, "1 root") || !strings.Contains(r, "2 helper") || !strings.Contains(r, "lost") {
		t.Fatalf("list %q", r)
	}
	if strings.Contains(r, "3fa9c2") || strings.Contains(r, "!") || strings.Contains(r, "bystander") {
		t.Fatalf("list shows a raw suffix, odd text, or an agent not full: %q", r)
	}
	if !strings.Contains(r, "3 agent") || !strings.Contains(r, "4 averyveryverylon") || strings.Contains(r, "rootname") {
		t.Fatalf("names not cleaned: %q", r)
	}
	if len(f.asked) != 0 {
		t.Fatalf("listing asked %v", f.asked)
	}
}

func TestRecallProvOwnerRenewAsksOnlyForAListedLineage(t *testing.T) {
	o, f, _ := newOwnerRenew("root.3fa9c2")
	o.Text(context.Background(), "RENEW", true)
	if r, ok := o.Text(context.Background(), "renew 1", true); !ok || r != "" {
		t.Fatalf("RENEW 1 = %q %v", r, ok)
	}
	if len(f.asked) != 1 || f.asked[0] != "root.3fa9c2" {
		t.Fatalf("asked %v", f.asked)
	}
	// A number past the list, or with no list sent, asks nothing.
	if r, _ := o.Text(context.Background(), "RENEW 2", true); r != renewStale {
		t.Fatalf("RENEW 2 = %q", r)
	}
	o2, f2, _ := newOwnerRenew("root.3fa9c2")
	if r, _ := o2.Text(context.Background(), "RENEW 1", true); r != renewStale || len(f2.asked) != 0 {
		t.Fatalf("RENEW 1 with no list = %q, asked %v", r, f2.asked)
	}
}

func TestRecallProvOwnerRenewLockedAsksNothing(t *testing.T) {
	o, f, _ := newOwnerRenew("root.3fa9c2")
	for _, m := range []string{"RENEW", "RENEW 1"} {
		if r, ok := o.Text(context.Background(), m, false); ok || r != "" {
			t.Fatalf("locked %q = %q %v", m, r, ok)
		}
	}
	o.Text(context.Background(), "RENEW", true)
	if _, ok := o.Text(context.Background(), "RENEW 1", false); ok || len(f.asked) != 0 {
		t.Fatalf("locked RENEW 1 asked %v", f.asked)
	}
}

func TestRecallProvOwnerRenewStaleAndErrors(t *testing.T) {
	o, f, now := newOwnerRenew("root.3fa9c2")
	o.Text(context.Background(), "RENEW", true)
	*now = now.Add(renewListFor + time.Second)
	if r, _ := o.Text(context.Background(), "RENEW 1", true); r != renewStale || len(f.asked) != 0 {
		t.Fatalf("stale pick = %q asked %v", r, f.asked)
	}
	for err, want := range map[error]string{recalltool.ErrNotFull: renewStale, recalltool.ErrNotOpen: renewNotOpen, context.Canceled: renewRefused} {
		o, f, _ := newOwnerRenew("root.3fa9c2")
		f.err = err
		o.Text(context.Background(), "RENEW", true)
		if r, _ := o.Text(context.Background(), "RENEW 1", true); r != want {
			t.Fatalf("%v: %q, want %q", err, r, want)
		}
	}
	o, _, _ = newOwnerRenew()
	if r, _ := o.Text(context.Background(), "RENEW", true); r != renewNone {
		t.Fatalf("empty = %q", r)
	}
	for _, m := range []string{"RENEWAL", "RENEW 0", "RENEW 123", "RENEW ALL", "please renew"} {
		if _, ok := o.Text(context.Background(), m, true); ok {
			t.Fatalf("%q taken", m)
		}
	}
}

func TestRecallProvOwnerRenewWireChains(t *testing.T) {
	o, _, _ := newOwnerRenew("root.3fa9c2")
	cfg := &daemon.Config{HelpExtra: "LOOPS OFF/ON.", Settings: func(_ context.Context, msg string, _ bool) (string, bool) {
		return "prev", msg == "LOOPS OFF"
	}}
	o.wire(cfg)
	if r, ok := cfg.Settings(context.Background(), "LOOPS OFF", true); !ok || r != "prev" {
		t.Fatalf("prev not reached: %q %v", r, ok)
	}
	if r, ok := cfg.Settings(context.Background(), "RENEW", true); !ok || !strings.Contains(r, "root") {
		t.Fatalf("RENEW not taken: %q", r)
	}
	if cfg.HelpExtra != "LOOPS OFF/ON. "+renewHelp {
		t.Fatalf("help %q", cfg.HelpExtra)
	}
	empty := &daemon.Config{}
	o.wire(empty)
	if _, ok := empty.Settings(context.Background(), "HELLO", true); ok || empty.HelpExtra != renewHelp {
		t.Fatalf("no prev: %q", empty.HelpExtra)
	}
}

// The daemon wires RENEW to recall's executor.
var _ renewer = (*recalltool.LateExecutor)(nil)
