//go:build linux

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/digestqueue/pacingfile"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/question"
)

func provisionedDaemonConfig(dir string) Config {
	return Config{JournalPath: filepath.Join(dir, "journal"), SocketDir: filepath.Join(dir, "run"), OwnerNumber: owner, ModemUID: os.Getuid(), OwnerState: filepath.Join(dir, "owner.json"), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600}}
}
func provisionedDaemonSession(t *testing.T, existing bool) (string, grants.Config) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ledger")
	cfg := grants.Config{Now: time.Now, RequestsPerHour: 2, PacingMaxStoreLatency: time.Second, Declared: map[string]map[string]string{"synthetic": {"message.list": "read"}}}
	if existing {
		lease, err := pacingfile.OpenExclusive(path)
		if err != nil {
			t.Fatal(err)
		}
		cfg.PacingStore = lease
		if grants.New(cfg).PacingHealth() != nil {
			lease.Close()
			t.Fatal("synthetic initial provisioning")
		}
		if err = lease.Close(); err != nil {
			t.Fatal(err)
		}
		cfg.PacingStore = nil
	}
	cfg.PacingRequireExisting = true
	return path, cfg
}

// REQ: CH-15, OP-5, ADP-2
func TestProvisionedDaemonSharesSessionQuestionDebt(t *testing.T) {
	path, cfg := provisionedDaemonSession(t, true)
	s, err := pacingfile.OpenSession(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close(context.Background()) })
	if err = s.Use(func(g *grants.Gate) error {
		dc := provisionedDaemonConfig(t.TempDir())
		dc.Executors = map[string]journal.Executor{"synthetic": &drainChanges{}}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		d, e := RunProvisioned(ctx, dc, g)
		if e != nil {
			return e
		}
		defer func() { cancel(); d.Wait() }()
		if d.Gate() != g {
			t.Fatal("daemon substituted Gate")
		}
		book, e := question.New(question.Config{Reserve: g.Reserve, Now: func(context.Context) (time.Time, error) { return time.Now(), nil }, Send: func(string) error { return nil }})
		if e != nil {
			return e
		}
		asked, e := book.Ask(t.Context(), "synthetic-agent", "synthetic-question", question.Spec{Text: "Which color?", Default: "blue", Wait: 10 * time.Minute})
		if e != nil {
			return e
		}
		if !d.Gate().Reserve(false) || d.Gate().Reserve(false) {
			t.Fatal("question and daemon have different allowances")
		}
		if _, ok := book.Answer(t.Context(), asked.ID+" blue"); !ok {
			t.Fatal("synthetic question did not finish")
		}
		final, e := book.Status(t.Context(), "synthetic-agent", "synthetic-question", "")
		if e != nil || final.State != question.Answered {
			t.Fatalf("question scope incomplete: %+v %v", final, e)
		}
		cancel()
		return d.WaitError()
	}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	reopened, err := pacingfile.OpenSession(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close(context.Background())
	if err = reopened.Use(func(g *grants.Gate) error {
		if g.PacingHealth() != nil || g.Reserve(false) {
			t.Fatal("spent debt not retained")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// REQ: CH-15, CH-2, OP-5
func TestProvisionedDaemonMissingAccountingKeepsOwnerStop(t *testing.T) {
	path, cfg := provisionedDaemonSession(t, false)
	s, err := pacingfile.OpenSession(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	if err = s.Use(func(g *grants.Gate) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		d, e := RunProvisioned(ctx, provisionedDaemonConfig(t.TempDir()), g)
		if e != nil {
			return e
		}
		defer func() { cancel(); d.Wait() }()
		if d.Gate() != g || g.PacingHealth() != grants.ErrPacingRecovery || g.Reserve(true) {
			t.Fatal("missing state not held")
		}
		if e = d.Owner().LocalStop(t.Context()); e != nil {
			return e
		}
		cancel()
		return d.WaitError()
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("missing ledger initialized", err)
	}
}

// REQ: CH-15, OP-5
func TestProvisionedDaemonRefusesCompetingConfigBeforeFilesystem(t *testing.T) {
	for _, kind := range []string{"nil", "volatile", "competing"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			cfg := provisionedDaemonConfig(dir)
			refuse := func(g *grants.Gate) {
				if d, e := RunProvisioned(context.Background(), cfg, g); d != nil || e != ErrProvisionedGate {
					t.Fatal("bad Gate/options admitted", e)
				}
			}
			switch kind {
			case "volatile":
				refuse(grants.New(grants.Config{}))
			case "competing":
				path, gc := provisionedDaemonSession(t, true)
				s, e := pacingfile.OpenSession(path, gc)
				if e != nil {
					t.Fatal(e)
				}
				defer s.Close(context.Background())
				cfg.Grants.LocalUI = true
				if e = s.Use(func(g *grants.Gate) error { refuse(g); return nil }); e != nil {
					t.Fatal(e)
				}
			default:
				refuse(nil)
			}
			files, e := os.ReadDir(dir)
			if e != nil || len(files) != 0 {
				t.Fatal("validation mutated filesystem", e)
			}
		})
	}
}

// REQ: OP-5, ADP-2
func TestProvisionedDaemonRejectsBoundGateWithoutRedirecting(t *testing.T) {
	path, gc := provisionedDaemonSession(t, true)
	s, e := pacingfile.OpenSession(path, gc)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	if e = s.Use(func(g *grants.Gate) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		first := provisionedDaemonConfig(t.TempDir())
		first.Executors = map[string]journal.Executor{"synthetic": &drainChanges{}}
		d, err := RunProvisioned(ctx, first, g)
		if err != nil {
			return err
		}
		defer func() { cancel(); d.Wait() }()
		second := provisionedDaemonConfig(t.TempDir())
		second.Executors = first.Executors
		if loser, err := RunProvisioned(ctx, second, g); loser != nil || err != ErrProvisionedGate {
			t.Fatal("bound Gate redirected", err)
		}
		in := journal.Intent{ID: "synthetic-after-refusal", Origin: "guest:synthetic", Account: "synthetic", Action: "message.list", Executor: "synthetic"}
		if _, err = g.Submit(in); err != nil {
			return err
		}
		if _, err = d.Engine().Get(in.ID); err != nil {
			t.Fatal("supplied Gate lost original journal", err)
		}
		// No approval/dispatch occurs. Normal loser cleanup releases its journal.
		file, err := journal.OpenFile(second.JournalPath)
		if err != nil {
			t.Fatal("loser journal retained", err)
		}
		file.Close()
		cancel()
		return d.WaitError()
	}); e != nil {
		t.Fatal(e)
	}
}
