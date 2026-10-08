//go:build linux

package dailyhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestnotes"
	dq "github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/daily"
	"github.com/ghbmrk/agentos/broker/digestqueue/dailypolicy"
	"github.com/ghbmrk/agentos/broker/digestqueue/heartbeat"
	"github.com/ghbmrk/agentos/broker/digestqueue/pacingfile"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/question"
)

// Approval notifications use the synchronous request path; digest uses the
// context path. Only the former blocks. No real provider or effect exists.
type lifecycleLine struct{ entered, release chan struct{} }

func (*lifecycleLine) Number() string                                    { return "+15550000001" }
func (*lifecycleLine) Inbox() <-chan modem.SMS                           { return nil }
func (m *lifecycleLine) Send(string, string) error                       { close(m.entered); <-m.release; return nil }
func (*lifecycleLine) SendContext(context.Context, string, string) error { return nil }

func lifecycleWait[T any](t *testing.T, c <-chan T) T {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("synthetic lifecycle did not advance")
		var zero T
		return zero
	}
}
func lifecycleRelease(c chan struct{}) {
	select {
	case <-c:
	default:
		close(c)
	}
}

// REQ: CH-15, CH-11, CH-2
func TestSharedApprovalQuestionHostDrainOrders(t *testing.T) {
	for _, first := range []string{"approval", "question"} {
		t.Run(first+"-first", func(t *testing.T) {
			dir := t.TempDir()
			private := filepath.Join(dir, "private")
			if err := os.Mkdir(private, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(private, "ledger")
			now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
			cfg := grants.Config{Now: func() time.Time { return now }, RequestsPerHour: 3, PacingMaxStoreLatency: time.Second, LocalUI: true, Declared: map[string]map[string]string{"mail": {"message.list": "read"}}}
			lease, err := pacingfile.OpenExclusive(path)
			if err != nil {
				t.Fatal(err)
			}
			cfg.PacingStore = lease
			if grants.New(cfg).PacingHealth() != nil {
				t.Fatal("synthetic provisioning failed")
			}
			if err = lease.Close(); err != nil {
				t.Fatal(err)
			}
			cfg.PacingStore = nil
			cfg.PacingRequireExisting = true
			var slot pacingfile.StartupSlot
			startup, err := slot.Start(path, cfg)
			if err != nil {
				t.Fatal(err)
			}
			line := &lifecycleLine{make(chan struct{}), make(chan struct{})}
			questionEntered, questionRelease := make(chan struct{}), make(chan struct{})
			hostRelease := make(chan struct{})
			js, err := journal.OpenFile(filepath.Join(dir, "journal"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				lifecycleRelease(line.release)
				lifecycleRelease(questionRelease)
				lifecycleRelease(hostRelease)
				slot.Drain(context.Background())
				js.Close()
			})
			deadline := time.After(5 * time.Second)
			for startup.State() == pacingfile.StartupOpening {
				select {
				case <-deadline:
					t.Fatal("startup did not complete")
				case <-time.After(time.Millisecond):
				}
			}
			if startup.State() != pacingfile.StartupReady {
				t.Fatal(startup.State())
			}

			hostReady := make(chan *Host, 1)
			hostDone := make(chan error, 1)
			// The fixture owns the journal medium through complete downstream drain.
			// The host hands its engine/channel to registered approval users; after
			// STOP its own workflow can quiesce independently of those handoffs.
			go func() {
				hostDone <- startup.Use(func(g *grants.Gate) error {
					eng, err := journal.Open(js, g, map[string]journal.Executor{grants.ExecutorName: g}, func(s string) string { return s }, journal.WithClock(cfg.Now))
					if err != nil {
						return err
					}
					notes, err := digestnotes.New(digestnotes.Config{Store: &change.FileStore{Path: filepath.Join(dir, "notes")}, Location: time.UTC})
					if err != nil {
						return err
					}
					queue, err := dq.New(&change.FileStore{Path: filepath.Join(dir, "queue")}, dq.Limits{MaxBatches: 8, MaxSources: 4, MaxAttempts: 3, MaxBytes: 65536})
					if err != nil {
						return err
					}
					clock := func() (time.Time, error) { return now, nil }
					beat, err := heartbeat.New(heartbeat.Config{Store: &change.FileStore{Path: filepath.Join(dir, "heartbeat")}, Clock: clock, Zone: "UTC", Minute: 720})
					if err != nil {
						return err
					}
					hc := Config{Owner: owner.Config{Owner: "+15550000999", Store: owner.FileStore{Path: filepath.Join(dir, "owner")}, Engine: eng, Modem: line, Now: cfg.Now, Location: time.UTC, Decide: g.Decide, Narrow: g.Narrow}, Notes: notes, Daily: daily.Config{Queue: queue, Heartbeat: beat, Clock: clock, TTL: time.Hour}, OwnerNotesEligible: func(context.Context, dq.Snapshot) error { return nil }, RetentionDays: 1, PollInterval: time.Minute, StepTimeout: time.Second}
					policy := dailypolicy.Config{Budget: g, Clock: func(context.Context) (time.Time, error) { return now, nil }, Quiet: func(time.Time) bool { return false }, Eligible: func(context.Context, dq.Batch) error { return nil }, AgedAfter: time.Minute}
					h, err := NewProvisioned(hc, policy)
					if err != nil {
						return err
					}
					g.Attach(eng, h.Channel())
					if err = h.Activate(); err != nil {
						return err
					}
					id, err := h.Step(t.Context())
					if err != nil {
						return err
					}
					if id == 0 {
						return errors.New("digest reservation absent")
					}
					hostReady <- h
					<-hostRelease
					if !eng.Stopped() || h.Health() != ErrPolicyRecovery || h.Activate() != ErrPolicyRecovery {
						return errors.New("STOP/recovery lost")
					}
					// No host runner exists. Complete the workflow before owner resources close.
					return h.Quiesce(t.Context(), func(context.Context) error { return nil })
				})
			}()
			h := lifecycleWait(t, hostReady)
			questionDone := make(chan error, 1)
			go func() {
				questionDone <- startup.Use(func(g *grants.Gate) error {
					book, err := question.New(question.Config{Reserve: g.Reserve, Now: func(context.Context) (time.Time, error) { return now, nil }, Send: func(string) error { close(questionEntered); <-questionRelease; return nil }})
					if err != nil {
						return err
					}
					_, err = book.Ask(t.Context(), "synthetic-agent", "synthetic-choice", question.Spec{Text: "Which color?", Default: "blue", Wait: 10 * time.Minute})
					return err
				})
			}()
			lifecycleWait(t, questionEntered)
			approvalDone := make(chan error, 1)
			go func() {
				approvalDone <- startup.Use(func(g *grants.Gate) error {
					in := journal.Intent{ID: "local/synthetic-grant", Origin: "local", Account: journal.BrokerAccount, Action: journal.ActionGrantChange, Executor: grants.ExecutorName, Params: map[string]any{"grant": map[string]any{"account": "mail", "executor": "mail", "ops": map[string]any{"message.list": "read"}}}}
					st, err := g.Submit(in)
					if err != nil {
						return err
					}
					if st.State != journal.Pending {
						return errors.New("grant did not wait for owner")
					}
					if _, err = g.Authorize(t.Context(), in.ID); err != nil {
						return err
					}
					g.Flush() // actual Channel.RequestLocalEach -> synchronous modem notification
					g.Wait()  // no approved executor or spawned work exists in this fixture
					st, err = g.Get(in.ID)
					if err != nil {
						return err
					}
					if _, connected := g.Route("mail"); connected || st.State == journal.Succeeded {
						return errors.New("unapproved grant executed")
					}
					return nil
				})
			}()
			select {
			case <-line.entered:
			case err := <-approvalDone:
				t.Fatal("approval ended before send", err)
			case <-time.After(5 * time.Second):
				t.Fatal("approval did not enter transport")
			}
			cancelled, cancel := context.WithCancel(t.Context())
			cancel()
			if err = slot.Drain(cancelled); err != context.Canceled {
				t.Fatal("incomplete drain", err)
			}
			if startup.State() != pacingfile.StartupRetired {
				t.Fatal(startup.State())
			}
			// Actual Channel -> host containment wrapper -> actual journal STOP. This
			// must not wait on either blocked consumer notification.
			stopped := make(chan error, 1)
			go func() { stopped <- h.Channel().LocalStop(t.Context()) }()
			if err = lifecycleWait(t, stopped); err != nil {
				t.Fatal(err)
			}
			assertHeld := func() {
				t.Helper()
				if other, e := pacingfile.OpenExclusive(path); e == nil {
					other.Close()
					t.Fatal("consumer custody released")
				}
				if _, e := slot.Start(path, cfg); e != pacingfile.ErrStartupOccupied {
					t.Fatal("slot escaped", e)
				}
			}
			lifecycleRelease(hostRelease)
			if err = lifecycleWait(t, hostDone); err != nil {
				t.Fatal(err)
			}
			assertHeld()
			if first == "approval" {
				lifecycleRelease(line.release)
				if err = lifecycleWait(t, approvalDone); err != nil {
					t.Fatal(err)
				}
			} else {
				lifecycleRelease(questionRelease)
				if err = lifecycleWait(t, questionDone); err != nil {
					t.Fatal(err)
				}
			}
			assertHeld()
			if first == "approval" {
				lifecycleRelease(questionRelease)
				if err = lifecycleWait(t, questionDone); err != nil {
					t.Fatal(err)
				}
			} else {
				lifecycleRelease(line.release)
				if err = lifecycleWait(t, approvalDone); err != nil {
					t.Fatal(err)
				}
			}
			// No registered consumer remains. Only complete drain can release custody.
			if err = slot.Drain(t.Context()); err != nil {
				t.Fatal(err)
			}
			next, err := pacingfile.OpenSession(path, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer next.Close(context.Background())
			if err = next.Use(func(g *grants.Gate) error {
				if g.PacingHealth() != nil || g.Reserve(false) {
					return errors.New("approval/question/digest debt lost")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
