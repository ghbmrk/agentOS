package daemon

import (
	"github.com/ghbmrk/agentos/broker/modem"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// REQ: OP-4, OP-8
func TestDaemonWaitErrorReportsJournalCloseFailure(t *testing.T) {
	cancel, d := start(t, t.TempDir())
	// Actual OS close failure model: prematurely close the journal, so shutdown's
	// close fails. This is not a deployment/media or custody qualification.
	if err := d.store.Close(); err != nil {
		cancel()
		d.Wait()
		t.Fatal(err)
	}
	cancel()
	d.Wait()
	const readers = 8
	results := make(chan error, readers)
	for i := 0; i < readers; i++ {
		go func() { results <- d.WaitError() }()
	}
	for i := 0; i < readers; i++ {
		if err := <-results; err != ErrShutdownRecovery {
			t.Fatalf("concurrent close failure: %v", err)
		}
	}
	for i := 0; i < 3; i++ {
		if err := d.WaitError(); err != ErrShutdownRecovery {
			t.Fatalf("fixed close failure: %v", err)
		}
	}
	if got := ErrShutdownRecovery.Error(); got != "daemon shutdown needs recovery" {
		t.Fatalf("nonfixed wording: %q", got)
	}
}

func TestDaemonWaitErrorHealthyConcurrentObservers(t *testing.T) {
	cancel, d := start(t, t.TempDir())
	cancel()
	const readers = 8
	results := make(chan error, readers)
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- d.WaitError() }()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("healthy close result: %v", err)
		}
	}
	d.Wait()
	if err := d.WaitError(); err != nil {
		t.Fatal(err)
	}
}

// REQ: OP-4, OP-8
func TestDaemonWaitErrorJoinsBlockedOwnerBeforeClose(t *testing.T) {
	dir := t.TempDir()
	ownerState := filepath.Join(dir, "owner.json")
	carrier := modem.NewCarrier()
	seedCancel, seed := startWith(t, dir, func(cfg *Config) {
		cfg.OwnerState = ownerState
		cfg.Modem = carrier.Line("+15550000002")
	})
	if _, err := seed.Owner().Request([]ownerch.Item{{Ref: "synthetic", Facts: ownerch.Facts{Verb: "read"}, Object: "synthetic object"}}, time.Minute); err != nil {
		seedCancel()
		seed.Wait()
		t.Fatal(err)
	}
	seedCancel()
	seed.Wait()
	line := &drainBlockedLine{entered: make(chan struct{}), release: make(chan struct{})}
	cancel, d := startWith(t, dir, func(cfg *Config) { cfg.OwnerState = ownerState; cfg.Modem = line })
	var once sync.Once
	unblock := func() { once.Do(func() { close(line.release) }) }
	t.Cleanup(func() { unblock(); cancel(); d.Wait() })
	select {
	case <-line.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("owner restart report did not start")
	}
	cancel()
	d.srv.Wait()
	result := make(chan error, 1)
	go func() { result <- d.WaitError() }()
	select {
	case err := <-result:
		t.Fatalf("result preceded worker return: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	unblock()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("result did not complete")
	}
	d.Wait()
}
