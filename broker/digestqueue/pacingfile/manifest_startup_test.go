//go:build linux

package pacingfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
)

type ownedManifestReader struct {
	reader           *bytes.Reader
	entered, release chan struct{}
	once             sync.Once
	reads            atomic.Int32
}

func (r *ownedManifestReader) Read(p []byte) (int, error) {
	r.reads.Add(1)
	r.once.Do(func() { close(r.entered); <-r.release })
	return r.reader.Read(p)
}

type brokenManifestReader struct{ panics bool }

func (r brokenManifestReader) Read([]byte) (int, error) {
	if r.panics {
		panic("synthetic-private-reader")
	}
	return 0, io.ErrUnexpectedEOF
}
func manifestStartupFixture(t *testing.T) (string, []byte, grants.Config) {
	t.Helper()
	path, _ := sessionFixture(t)
	if e := os.Remove(path + ".lock"); e != nil {
		t.Fatal(e)
	}
	image, e := json.Marshal(ProvisionedManifest{Version: 1, Ledger: path, RequestsPerHour: 2, MaxStoreLatencyMillis: 1000})
	if e != nil {
		t.Fatal(e)
	}
	return path, image, grants.Config{Now: time.Now}
}
func manifestStartupWait(t *testing.T, p *Startup) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for p.State() == StartupOpening {
		select {
		case <-deadline:
			t.Fatal("owned startup did not advance")
		case <-time.After(time.Millisecond):
		}
	}
}

// REQ: OP-8, CH-15
func TestManifestStartupOwnsReadAndRetiredLateBytesAcquireNoLease(t *testing.T) {
	path, image, cfg := manifestStartupFixture(t)
	var slot StartupSlot
	var clocks atomic.Int32
	cfg.Now = func() time.Time { clocks.Add(1); return time.Now() }
	r := &ownedManifestReader{reader: bytes.NewReader(image), entered: make(chan struct{}), release: make(chan struct{})}
	p, e := slot.StartManifest(r, sha256.Sum256(image), cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		select {
		case <-r.release:
		default:
			close(r.release)
		}
		slot.Drain(context.Background())
	})
	select {
	case <-r.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not enter")
	}
	if p.State() != StartupOpening {
		t.Fatal(p.State())
	}
	if e = p.Use(func(*grants.Gate) error { t.Fatal("consumer before config read"); return nil }); e != ErrSessionOpening {
		t.Fatal(e)
	}
	if _, e = slot.StartManifest(bytes.NewReader(image), sha256.Sum256(image), cfg); e != ErrStartupOccupied {
		t.Fatal("second reader admitted", e)
	}
	if e = slot.RecoverDuplicate(path, sha256.Sum256(image)); e != ErrStartupOccupied {
		t.Fatal("recovery bypassed reader", e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if e = slot.Drain(ctx); e != context.Canceled {
		t.Fatal(e)
	}
	if p.State() != StartupRetired {
		t.Fatal(p.State())
	}
	close(r.release)
	if e = slot.Drain(t.Context()); e != nil {
		t.Fatal(e)
	}
	if clocks.Load() != 0 {
		t.Fatal("late retired read constructed Gate")
	}
	if _, e = os.Stat(path + ".lock"); !os.IsNotExist(e) {
		t.Fatal("late retired read acquired lease", e)
	}
}

// REQ: OP-8, CH-15
func TestManifestStartupContainsFailedAndPanicReaders(t *testing.T) {
	for _, panics := range []bool{false, true} {
		t.Run(map[bool]string{false: "read-error", true: "panic"}[panics], func(t *testing.T) {
			path, image, cfg := manifestStartupFixture(t)
			var slot StartupSlot
			p, e := slot.StartManifest(brokenManifestReader{panics}, sha256.Sum256(image), cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer slot.Drain(context.Background())
			manifestStartupWait(t, p)
			if p.State() != StartupRecovery {
				t.Fatal(p.State())
			}
			if e = p.Use(func(*grants.Gate) error { t.Fatal("failed reader exposed consumer"); return nil }); e != ErrSessionRecovery {
				t.Fatal(e)
			}
			if _, e = slot.StartManifest(bytes.NewReader(image), sha256.Sum256(image), cfg); e != ErrStartupOccupied {
				t.Fatal("failed attempt lost occupancy", e)
			}
			if _, e = os.Stat(path + ".lock"); !os.IsNotExist(e) {
				t.Fatal("reader failure opened lease", e)
			}
		})
	}
}

// REQ: OP-8, CH-15
func TestManifestStartupPreservesActualStrictDebtAcrossSameSlotReopen(t *testing.T) {
	_, image, cfg := manifestStartupFixture(t)
	var slot StartupSlot
	for pass := 0; pass < 2; pass++ {
		p, e := slot.StartManifest(bytes.NewReader(image), sha256.Sum256(image), cfg)
		if e != nil {
			t.Fatal(e)
		}
		manifestStartupWait(t, p)
		if e = p.Use(func(g *grants.Gate) error {
			if g.PacingHealth() != nil || !g.Reserve(false) {
				t.Fatal("strict reservation failed")
			}
			if pass == 1 && g.Reserve(false) {
				t.Fatal("fresh allowance after manifest reopen")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
		if e = slot.Drain(t.Context()); e != nil {
			t.Fatal(e)
		}
	}
}

// REQ: OP-8, CH-15
func TestManifestStartupRejectsCompetingOptionsBeforeRead(t *testing.T) {
	_, image, cfg := manifestStartupFixture(t)
	for _, kind := range []string{"zero-pin", "nil-reader", "nil-clock", "allowance", "store", "require-existing", "latency"} {
		t.Run(kind, func(t *testing.T) {
			var slot StartupSlot
			candidate := cfg
			pin := sha256.Sum256(image)
			r := &ownedManifestReader{reader: bytes.NewReader(image), entered: make(chan struct{}), release: make(chan struct{})}
			var reader io.Reader = r
			switch kind {
			case "zero-pin":
				pin = [32]byte{}
			case "nil-reader":
				reader = nil
			case "nil-clock":
				candidate.Now = nil
			case "allowance":
				candidate.RequestsPerHour = 2
			case "store":
				candidate.PacingStore = &Store{}
			case "require-existing":
				candidate.PacingRequireExisting = true
			case "latency":
				candidate.PacingMaxStoreLatency = time.Second
			}
			t.Cleanup(func() {
				select {
				case <-r.release:
				default:
					close(r.release)
				}
				slot.Drain(context.Background())
			})
			p, e := slot.StartManifest(reader, pin, candidate)
			if p != nil || e != ErrManifest || r.reads.Load() != 0 || slot.current != nil {
				t.Fatal("invalid config started reader", e)
			}
		})
	}
}

// REQ: OP-8, CH-15
func TestManifestStartupDigestAndSchemaRefusalBeforeLedgerIO(t *testing.T) {
	for _, kind := range []string{"digest", "schema"} {
		t.Run(kind, func(t *testing.T) {
			path, image, cfg := manifestStartupFixture(t)
			var slot StartupSlot
			pin := sha256.Sum256(image)
			if kind == "digest" {
				pin = [32]byte{1}
			} else {
				image = bytes.Replace(image, []byte("\"version\":1"), []byte("\"version\":2"), 1)
				pin = sha256.Sum256(image)
			}
			p, e := slot.StartManifest(bytes.NewReader(image), pin, cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer slot.Drain(context.Background())
			manifestStartupWait(t, p)
			if p.State() != StartupRecovery {
				t.Fatal("bad image constructed consumer", p.State())
			}
			if _, e = os.Stat(path + ".lock"); !os.IsNotExist(e) {
				t.Fatal("bad config read acquired ledger lease", e)
			}
		})
	}
}
