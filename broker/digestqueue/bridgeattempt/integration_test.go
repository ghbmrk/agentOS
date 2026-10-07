package bridgeattempt

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/changesource"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/sockets"
)

type noEvaluation struct{}

func (noEvaluation) Run(context.Context, change.Tree, change.Probe) ([]byte, error) {
	return nil, errors.New("unexpected model evaluation")
}

type noControl struct{}

func (noControl) Stop(context.Context) (journal.StopReport, error) {
	panic("unexpected control effect")
}
func (noControl) Resume() error          { panic("unexpected control effect") }
func (noControl) Stopped() bool          { return false }
func (noControl) List() []journal.Status { return nil }
func bridgeCall(t *testing.T, l *modemlink.Link, op string, args, out any) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	res, err := l.Ops()[op](context.Background(), sockets.Peer{Kind: "owner"}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		raw, err = json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
	}
}

// REQ: CH-12, CH-19, OP-1, OP-2
// Actual pipeline, collector, owner channel and bridge handlers; all peer
// operations are local fixtures. No carrier, credential, VM or daemon is run.
func TestRealPipelineOwnerBridgeAttemptSurvivesQueueReopen(t *testing.T) {
	for _, cancelAfterHandoff := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "cancelled-after-handoff"}[cancelAfterHandoff], func(t *testing.T) {
			dir := t.TempDir()
			pipeline, err := change.New(change.Config{Store: &change.FileStore{Path: filepath.Join(dir, "pipeline.json")}, Evaluator: noEvaluation{}})
			if err != nil {
				t.Fatal(err)
			}
			if err = pipeline.Notice("note", "Fixed broker notice."); err != nil {
				t.Fatal(err)
			}
			source, err := changesource.New(pipeline)
			if err != nil {
				t.Fatal(err)
			}
			store := &change.FileStore{Path: filepath.Join(dir, "queue.json")}
			limits := digestqueue.Limits{MaxBatches: 8, MaxSources: 8, MaxAttempts: 2, MaxBytes: 1 << 20}
			q, err := digestqueue.New(store, limits)
			if err != nil {
				t.Fatal(err)
			}
			collector, err := digestqueue.NewCollector(q, map[string]digestqueue.Source{changesource.ID: source})
			if err != nil {
				t.Fatal(err)
			}
			b, err := collector.Collect(context.Background(), now, now.Add(time.Hour))
			if err != nil || b == nil {
				t.Fatal(b, err)
			}
			const number = "+15550000999"
			link := modemlink.New(modemlink.Config{Owner: number, Now: func() time.Time { return now }, SendWait: time.Second, PollWait: 20 * time.Millisecond})
			bridgeCall(t, link, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
			channel, err := owner.New(owner.Config{Owner: number, Modem: link, Engine: noControl{}, Store: &owner.MemStore{}, Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			a, err := New(Config{Queue: q, Owner: channel, Now: func() time.Time { return now }, Gate: func(context.Context, digestqueue.Batch) error { return nil }, Sources: map[string]Validator{changesource.ID: source.Validate}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- a.Send(ctx, b.ID) }()
			var out struct{ Item *bridgeproto.Item }
			for i := 0; i < 40 && out.Item == nil; i++ {
				bridgeCall(t, link, bridgeproto.OpOutbox, struct{}{}, &out)
			}
			if out.Item == nil {
				t.Fatal("no bridge item")
			}
			if out.Item.To != number || out.Item.Text != "Daily update: Fixed broker notice." {
				t.Fatal(out.Item)
			}
			if cancelAfterHandoff {
				cancel()
			} else {
				bridgeCall(t, link, bridgeproto.OpSent, bridgeproto.Sent{ID: out.Item.ID, Code: bridgeproto.CodeOK}, nil)
			}
			select {
			case err = <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("send did not return")
			}
			want := digestqueue.Accepted
			if cancelAfterHandoff {
				want = digestqueue.Unknown
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			reopened, err := digestqueue.New(store, limits)
			if err != nil {
				t.Fatal(err)
			}
			if got := state(t, reopened, b.ID); got.State != want || got.Attempts != 1 {
				t.Fatal(got)
			}
			if cancelAfterHandoff {
				bridgeCall(t, link, bridgeproto.OpSent, bridgeproto.Sent{ID: out.Item.ID, Code: bridgeproto.CodeOK}, nil)
				if link.Stray() != 1 || state(t, reopened, b.ID).State != digestqueue.Unknown {
					t.Fatal("late receipt changed durable outcome")
				}
			}
			if err = a.Send(context.Background(), b.ID); !errors.Is(err, digestqueue.ErrState) {
				t.Fatal("terminal/unknown batch retried", err)
			}
		})
	}
}
