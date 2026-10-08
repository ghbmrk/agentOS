//go:build linux

package dailyhost

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/digestqueue/pacingfile"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/question"
)

// REQ: CH-15, CH-11, CH-2
func TestOwnedSessionDrainsActualQuestionAndHostBeforeLeaseRelease(t *testing.T) {
	r := setup(t)
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ledger")
	lease, err := pacingfile.OpenExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := grants.Config{Now: func() time.Time { return r.now }, RequestsPerHour: 2, PacingStore: lease, PacingMaxStoreLatency: time.Second}
	if grants.New(cfg).PacingHealth() != nil {
		t.Fatal("trusted fixture provisioning")
	}
	lease.Close()
	cfg.PacingStore = nil
	cfg.PacingRequireExisting = true
	s, err := pacingfile.OpenSession(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	sent := make(chan struct{})
	releaseQuestion := make(chan struct{})
	checkHost := make(chan struct{})
	hostReady := make(chan struct{})
	questionDone := make(chan error, 1)
	hostDone := make(chan error, 1)
	t.Cleanup(func() {
		for _, c := range []chan struct{}{releaseQuestion, checkHost} {
			select {
			case <-c:
			default:
				close(c)
			}
		}
		s.Close(context.Background())
	})
	go func() {
		questionDone <- s.Use(func(g *grants.Gate) error {
			b, err := question.New(question.Config{Reserve: g.Reserve, Now: func(context.Context) (time.Time, error) { return r.now, nil }, Send: func(string) error { close(sent); <-releaseQuestion; return nil }})
			if err != nil {
				return err
			}
			_, err = b.Ask(t.Context(), "synthetic-agent", "synthetic-choice", question.Spec{Text: "Which color?", Default: "blue", Wait: 10 * time.Minute})
			return err
		})
	}()
	<-sent
	go func() {
		hostDone <- s.Use(func(g *grants.Gate) error {
			h, err := NewProvisioned(provisionedConfig(r), provisionedPolicy(r, g))
			if err != nil {
				return err
			}
			if err = h.Activate(); err != nil {
				return err
			}
			if _, err = h.Step(t.Context()); err != nil {
				return err
			}
			close(hostReady)
			<-checkHost
			if h.Health() != ErrPolicyRecovery || h.Activate() != ErrPolicyRecovery {
				return ErrConfig
			}
			if err = h.Channel().LocalStop(t.Context()); err != nil {
				return err
			}
			// No host runner or asynchronous host step exists in this fixture. STOP
			// plus Quiesce completes this host consumer before its scope returns.
			return h.Quiesce(t.Context(), func(context.Context) error { return nil })
		})
	}()
	<-hostReady
	if r.m.count() != 1 {
		t.Fatal("actual digest not sent")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err = s.Close(ctx); err != context.Canceled {
		t.Fatal("drain cancelled", err)
	}
	close(checkHost)
	if err = <-hostDone; err != nil {
		t.Fatal("retired host lost recovery/STOP/quiescence", err)
	}
	if !r.e.Stopped() {
		t.Fatal("STOP lost")
	}
	if competing, err := pacingfile.OpenExclusive(path); err == nil {
		competing.Close()
		t.Fatal("host quiescence released question's lease")
	}
	close(releaseQuestion)
	if err = <-questionDone; err != nil {
		t.Fatal(err)
	}
	if err = s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	next, err := pacingfile.OpenSession(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close(context.Background())
	if err = next.Use(func(g *grants.Gate) error {
		if g.PacingHealth() != nil || g.Reserve(false) {
			t.Fatal("question and digest debt not preserved")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
