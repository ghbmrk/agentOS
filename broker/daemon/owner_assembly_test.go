//go:build linux

package daemon

import (
	"context"
	"errors"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestnotes"
	dq "github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/daily"
	"github.com/ghbmrk/agentos/broker/digestqueue/dailyhost"
	"github.com/ghbmrk/agentos/broker/digestqueue/dailypolicy"
	"github.com/ghbmrk/agentos/broker/digestqueue/heartbeat"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/question"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/digestqueue/pacingfile"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-15, OP-5
func TestProvisionedOwnerFactoryPublishesOnlyItsActualChannel(t *testing.T) {
	path, gc := provisionedDaemonSession(t, true)
	session, e := pacingfile.OpenSession(path, gc)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close(context.Background())
	if e = session.Use(func(g *grants.Gate) error {
		cfg := provisionedDaemonConfig(t.TempDir())
		var made *ownerch.Channel
		var calls atomic.Int32
		cfg.OwnerFactory = func(oc ownerch.Config) (*ownerch.Channel, error) {
			calls.Add(1)
			if oc.Owner != cfg.OwnerNumber || oc.Engine == nil || oc.Store == nil || oc.Decide == nil || oc.Narrow == nil || oc.Reissue == nil {
				t.Fatal("owner factory lost trusted wiring")
			}
			var err error
			made, err = ownerch.New(oc)
			return made, err
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		d, err := RunProvisioned(ctx, cfg, g)
		if err != nil {
			return err
		}
		defer func() { cancel(); d.Wait() }()
		if calls.Load() != 1 || d.Owner() != made {
			t.Fatal("owner substituted or constructed twice")
		}
		if err = d.Owner().LocalStop(t.Context()); err != nil {
			return err
		}
		if !d.Engine().Stopped() {
			t.Fatal("owner changed journal identity")
		}
		cancel()
		return d.WaitError()
	}); e != nil {
		t.Fatal(e)
	}
}

// REQ: OP-5, CH-15
func TestProvisionedOwnerFactoryFailureHasFixedErrorAndReleasesJournal(t *testing.T) {
	for _, kind := range []string{"error", "nil", "panic"} {
		t.Run(kind, func(t *testing.T) {
			path, gc := provisionedDaemonSession(t, true)
			session, e := pacingfile.OpenSession(path, gc)
			if e != nil {
				t.Fatal(e)
			}
			defer session.Close(context.Background())
			if e = session.Use(func(g *grants.Gate) error {
				cfg := provisionedDaemonConfig(t.TempDir())
				var calls atomic.Int32
				cfg.OwnerFactory = func(ownerch.Config) (*ownerch.Channel, error) {
					calls.Add(1)
					switch kind {
					case "error":
						return nil, errors.New("SYNTHETIC PRIVATE CONSTRUCTOR DETAIL")
					case "panic":
						panic("SYNTHETIC PRIVATE CONSTRUCTOR DETAIL")
					}
					return nil, nil
				}
				if d, err := RunProvisioned(t.Context(), cfg, g); d != nil || err != ErrOwnerAssembly {
					t.Fatal("factory failure exposed or published", err)
				}
				if calls.Load() != 1 {
					t.Fatal("factory retried")
				}
				file, err := journal.OpenFile(cfg.JournalPath)
				if err != nil {
					t.Fatal("failed factory leaked journal custody", err)
				}
				file.Close()
				return nil
			}); e != nil {
				t.Fatal(e)
			}
		})
	}
}

// REQ: CH-15, OP-5
func TestOwnerFactoryRefusedBeforeIOOutsideProvisionedOwner(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		t.Run(map[bool]string{true: "legacy", false: "no-owner"}[legacy], func(t *testing.T) {
			dir := t.TempDir()
			cfg := provisionedDaemonConfig(dir)
			cfg.OwnerFactory = func(ownerch.Config) (*ownerch.Channel, error) { t.Fatal("refused factory called"); return nil, nil }
			if legacy {
				if d, e := Run(t.Context(), cfg); d != nil || e != ErrOwnerAssembly {
					t.Fatal("legacy factory admitted", e)
				}
			} else {
				cfg.OwnerState = ""
				path, gc := provisionedDaemonSession(t, true)
				s, e := pacingfile.OpenSession(path, gc)
				if e != nil {
					t.Fatal(e)
				}
				defer s.Close(context.Background())
				if e = s.Use(func(g *grants.Gate) error {
					if d, e := RunProvisioned(t.Context(), cfg, g); d != nil || e != ErrOwnerAssembly {
						t.Fatal("ownerless factory admitted", e)
					}
					return nil
				}); e != nil {
					t.Fatal(e)
				}
			}
			files, e := os.ReadDir(dir)
			if e != nil || len(files) != 0 {
				t.Fatal("refusal mutated filesystem", e)
			}
		})
	}
}

type assemblyLine struct{}

func (*assemblyLine) Number() string                                    { return "+15550000001" }
func (*assemblyLine) Inbox() <-chan modem.SMS                           { return nil }
func (*assemblyLine) Send(string, string) error                         { return nil }
func (*assemblyLine) SendContext(context.Context, string, string) error { return nil }

// REQ: CH-15, OP-5, CH-2
func TestActualSlotDaemonHostQuestionOwnerHandoffAndDebtReopen(t *testing.T) {
	dir := t.TempDir()
	private := filepath.Join(dir, "private")
	if e := os.Mkdir(private, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(private, "ledger")
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	gc := grants.Config{Now: func() time.Time { return now }, RequestsPerHour: 3, PacingMaxStoreLatency: time.Second}
	lease, e := pacingfile.OpenExclusive(path)
	if e != nil {
		t.Fatal(e)
	}
	gc.PacingStore = lease
	if grants.New(gc).PacingHealth() != nil {
		t.Fatal("fixture provisioning")
	}
	if e = lease.Close(); e != nil {
		t.Fatal(e)
	}
	gc.PacingStore = nil
	gc.PacingRequireExisting = true
	var slot pacingfile.StartupSlot
	start := func() *pacingfile.Startup {
		p, e := slot.Start(path, gc)
		if e != nil {
			t.Fatal(e)
		}
		deadline := time.Now().Add(5 * time.Second)
		for p.State() == pacingfile.StartupOpening && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if p.State() != pacingfile.StartupReady {
			t.Fatal(p.State())
		}
		return p
	}
	p := start()
	defer slot.Drain(context.Background())
	if e = p.Use(func(g *grants.Gate) error {
		notes, e := digestnotes.New(digestnotes.Config{Store: &change.FileStore{Path: filepath.Join(dir, "notes")}, Location: time.UTC})
		if e != nil {
			return e
		}
		queue, e := dq.New(&change.FileStore{Path: filepath.Join(dir, "queue")}, dq.Limits{MaxBatches: 8, MaxSources: 4, MaxAttempts: 3, MaxBytes: 65536})
		if e != nil {
			return e
		}
		clock := func() (time.Time, error) { return now, nil }
		beat, e := heartbeat.New(heartbeat.Config{Store: &change.FileStore{Path: filepath.Join(dir, "heartbeat")}, Clock: clock, Zone: "UTC", Minute: 720})
		if e != nil {
			return e
		}
		cfg := provisionedDaemonConfig(dir)
		cfg.Modem = &assemblyLine{}
		var host *dailyhost.Host
		cfg.OwnerFactory = func(oc ownerch.Config) (*ownerch.Channel, error) {
			oc.Now = gc.Now
			oc.Location = time.UTC
			hc := dailyhost.Config{Owner: oc, Notes: notes, Daily: daily.Config{Queue: queue, Heartbeat: beat, Clock: clock, TTL: time.Hour}, OwnerNotesEligible: func(context.Context, dq.Snapshot) error { return nil }, RetentionDays: 1, PollInterval: time.Minute, StepTimeout: time.Second}
			policy := dailypolicy.Config{Budget: g, Clock: func(context.Context) (time.Time, error) { return now, nil }, Quiet: func(time.Time) bool { return false }, Eligible: func(context.Context, dq.Batch) error { return nil }, AgedAfter: time.Minute}
			var e error
			host, e = dailyhost.NewProvisioned(hc, policy)
			if e != nil {
				return nil, e
			}
			return host.Channel(), nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		d, e := RunProvisioned(ctx, cfg, g)
		if e != nil {
			return e
		}
		defer func() { cancel(); d.Wait() }()
		if d.Owner() != host.Channel() || d.Gate() != g {
			t.Fatal("handoff substituted identity")
		}
		if e = host.Activate(); e != nil {
			return e
		}
		id, e := host.Step(t.Context())
		if e != nil {
			return e
		}
		if id == 0 {
			t.Fatal("host did not spend shared reservation")
		}
		book, e := question.New(question.Config{Reserve: g.Reserve, Now: func(context.Context) (time.Time, error) { return now, nil }, Send: func(text string) error { return d.Owner().InformContext(t.Context(), text) }})
		if e != nil {
			return e
		}
		asked, e := book.Ask(t.Context(), "synthetic-agent", "synthetic-choice", question.Spec{Text: "Which color?", Default: "blue", Wait: 10 * time.Minute})
		if e != nil {
			return e
		}
		if !d.Gate().Reserve(false) || g.Reserve(false) {
			t.Fatal("common allowance not shared")
		}
		if _, ok := book.Answer(t.Context(), asked.ID+" blue"); !ok {
			t.Fatal("question not answered")
		}
		final, e := book.Status(t.Context(), "synthetic-agent", "synthetic-choice", "")
		if e != nil || final.State != question.Answered {
			t.Fatal("question scope incomplete", e)
		}
		if e = d.Owner().LocalStop(t.Context()); e != nil {
			return e
		}
		if !d.Engine().Stopped() {
			t.Fatal("STOP lost engine")
		}
		if id, e = host.Step(t.Context()); id != 0 || !errors.Is(e, daily.ErrHeld) {
			t.Fatal("STOP did not contain actual host", id, e)
		}
		if e = host.Quiesce(t.Context(), func(context.Context) error { return nil }); e != nil {
			return e
		}
		cancel()
		return d.WaitError()
	}); e != nil {
		t.Fatal(e)
	}
	if e = slot.Drain(context.Background()); e != nil {
		t.Fatal(e)
	}
	p = start()
	if e = p.Use(func(g *grants.Gate) error {
		if g.Reserve(false) {
			t.Fatal("debt reset on strict reopen")
		}
		return g.PacingHealth()
	}); e != nil {
		t.Fatal(e)
	}
}
