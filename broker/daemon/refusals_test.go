package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: ARC-2, CH-2, ADP-2, OP-4

// refusedCfg is a config Run accepts, before a test breaks one field.
func refusedCfg(dir string) Config {
	return Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: owner, ModemUID: os.Getuid(), Machines: []string{"m1"},
		Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
	}
}

// Run refuses a config it cannot serve, each for its own reason, and a
// refusal made after the journal is open closes it, so the next start on
// the same journal is not locked out of it (the journal holds an
// exclusive lock while open).
func TestRunRefusesABadConfigAndLeavesTheJournalFree(t *testing.T) {
	for _, c := range []struct {
		name string
		mod  func(*Config)
		want string
	}{
		{"no owner", func(c *Config) { c.OwnerNumber = "" }, "owner number required"},
		{"duplicate machine", func(c *Config) { c.Machines = []string{"m1", "m1"} }, "duplicate machine id"},
		{"bad admission", func(c *Config) { c.Admission = admission.Config{} }, "admission"},
		{"reserved executor", func(c *Config) {
			c.Executors = map[string]journal.Executor{grants.ExecutorName: unknownExec{}}
		}, "reserved"},
		{"undeclared executor", func(c *Config) {
			c.Executors = map[string]journal.Executor{"mail": unknownExec{}}
		}, "declares no operations"},
		{"reserved broker executor", func(c *Config) {
			c.BrokerExecutors = map[string]journal.Executor{grants.RecallExecutor: unknownExec{}}
		}, "reserved"},
		{"adapter and broker executor", func(c *Config) {
			c.Executors = map[string]journal.Executor{"mail": unknownExec{}}
			c.Grants.Declared = map[string]map[string]string{"mail": {"message.send": "send"}}
			c.BrokerExecutors = map[string]journal.Executor{"mail": unknownExec{}}
		}, "both an adapter and the broker's"},
		{"page without the owner channel", func(c *Config) { c.PageSocket = &PageSocket{UID: os.Getuid()} }, "needs the owner channel"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := refusedCfg(t.TempDir())
			c.mod(&cfg)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			d, err := Run(ctx, cfg)
			if err == nil {
				cancel()
				d.Wait()
				t.Fatal("Run accepted it")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Run: %v, want %q", err, c.want)
			}
			s, err := journal.OpenFile(cfg.JournalPath)
			if err != nil {
				t.Fatalf("the refused start left the journal locked: %v", err)
			}
			s.Close()
		})
	}
}

// A journal another engine holds is Run's error: two engines never share
// one journal.
func TestRunRefusesAJournalAnotherEngineHolds(t *testing.T) {
	cfg := refusedCfg(t.TempDir())
	held, err := journal.OpenFile(cfg.JournalPath)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := Run(ctx, cfg)
	if err == nil {
		cancel()
		d.Wait()
		t.Fatal("Run shared a journal another engine holds")
	}
	if !errors.Is(err, journal.ErrLocked) {
		t.Fatalf("Run: %v, want %v", err, journal.ErrLocked)
	}
}

// A journal that does not replay is Run's error, not a broker serving
// over it (OP-4).
func TestRunRefusesAJournalThatDoesNotReplay(t *testing.T) {
	cfg := refusedCfg(t.TempDir())
	if err := os.WriteFile(cfg.JournalPath, []byte("not a journal\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := Run(ctx, cfg)
	if err == nil {
		cancel()
		d.Wait()
		t.Fatal("Run served a journal that does not replay")
	}
	s, err := journal.OpenFile(cfg.JournalPath)
	if err != nil {
		t.Fatalf("the refused start left the journal locked: %v", err)
	}
	s.Close()
}

// With no Auth given, the owner is the owner's number and no one else: a
// stranger's STOP stops nothing, and the owner's does (CH-2).
func TestTheDefaultAuthIsTheOwnersNumber(t *testing.T) {
	dir := t.TempDir()
	_, d := startWith(t, dir, func(c *Config) { c.Auth = nil })
	text(t, dir, "+15550000077", "STOP")
	if d.Owned().Stopped() {
		t.Fatal("a stranger's STOP stopped the broker")
	}
	if r := text(t, dir, owner, "STOP"); len(r) != 1 || !strings.HasPrefix(r[0], "Stopped.") {
		t.Fatalf("the owner's STOP: %q", r)
	}
	if !d.Owned().Stopped() {
		t.Fatal("the owner's STOP did not stop the broker")
	}
}
