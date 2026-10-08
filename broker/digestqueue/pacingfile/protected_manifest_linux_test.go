//go:build linux

package pacingfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/ghbmrk/agentos/broker/grants"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func protectedManifestImage(path string, owners []uint32) []byte {
	ledger, _ := json.Marshal(path)
	uids, _ := json.Marshal(owners)
	return []byte(fmt.Sprintf(`{"version":2,"ledger":%s,"requests_per_hour":2,"max_store_latency_ms":1000,"trusted_owners":%s}`, ledger, uids))
}
func waitProtectedManifest(t *testing.T, p *Startup) StartupState {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for p.State() == StartupOpening && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	return p.State()
}

// REQ: OP-1, CH-15
func TestPinnedProtectedManifestBothEntriesKeepStrictDebt(t *testing.T) {
	for _, entry := range []string{"owned-reader", "predecoded"} {
		t.Run(entry, func(t *testing.T) {
			path, owners := protectedFixture(t)
			lease, e := OpenExclusiveProtected(path, owners)
			if e != nil {
				t.Fatal(e)
			}
			now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
			clock := func() time.Time { return now }
			if grants.New(grants.Config{Now: clock, RequestsPerHour: 2, PacingStore: lease, PacingMaxStoreLatency: time.Second}).PacingHealth() != nil {
				lease.Close()
				t.Fatal("fixture provisioning")
			}
			if e = lease.Close(); e != nil {
				t.Fatal(e)
			}
			image := protectedManifestImage(path, owners)
			pin := sha256.Sum256(image)
			cfg := grants.Config{Now: clock, Declared: map[string]map[string]string{"synthetic": {"message.list": "read"}}}
			var slot StartupSlot
			defer slot.Drain(context.Background())
			start := func() *Startup {
				var p *Startup
				var e error
				if entry == "owned-reader" {
					p, e = slot.StartManifest(strings.NewReader(string(image)), pin, cfg)
				} else {
					m, x := ReadProvisionedManifest(strings.NewReader(string(image)), pin)
					if x != nil {
						t.Fatal("v2 decode", x)
					}
					p, e = m.Start(&slot, cfg)
				}
				if e != nil {
					t.Fatal(e)
				}
				if state := waitProtectedManifest(t, p); state != StartupReady {
					t.Fatal("v2 protected startup", state)
				}
				return p
			}
			p := start()
			if e = p.Use(func(g *grants.Gate) error {
				if !g.HasExecutorDeclaration("synthetic") || !g.Reserve(false) {
					t.Fatal("strict policy/config lost")
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			if e = slot.Drain(context.Background()); e != nil {
				t.Fatal(e)
			}
			p = start()
			if e = p.Use(func(g *grants.Gate) error {
				if g.PacingHealth() != nil || !g.Reserve(false) || g.Reserve(false) {
					t.Fatal("strict spent debt reset")
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
		})
	}
}

// REQ: OP-1, CH-15
func TestPinnedProtectedManifestLaterAncestorFaultHoldsGate(t *testing.T) {
	path, owners := protectedFixture(t)
	ancestor := filepath.Dir(path)
	private := filepath.Join(ancestor, "private")
	if e := os.Mkdir(private, 0700); e != nil {
		t.Fatal(e)
	}
	path = filepath.Join(private, "ledger")
	lease, e := OpenExclusiveProtected(path, owners)
	if e != nil {
		t.Fatal(e)
	}
	if grants.New(grants.Config{Now: time.Now, RequestsPerHour: 2, PacingStore: lease, PacingMaxStoreLatency: time.Second}).PacingHealth() != nil {
		lease.Close()
		t.Fatal("fixture")
	}
	lease.Close()
	image := protectedManifestImage(path, owners)
	var slot StartupSlot
	defer slot.Drain(context.Background())
	p, e := slot.StartManifest(strings.NewReader(string(image)), sha256.Sum256(image), grants.Config{Now: time.Now})
	if e != nil {
		t.Fatal(e)
	}
	if waitProtectedManifest(t, p) != StartupReady {
		t.Fatal("v2 unavailable")
	}
	if e = os.Chmod(ancestor, 0770); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(ancestor, 0700)
	if e = p.Use(func(g *grants.Gate) error {
		if g.Reserve(false) || g.Reserve(true) || g.PacingHealth() != grants.ErrPacingRecovery {
			t.Fatal("protected startup used ordinary lease")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

// REQ: OP-1, CH-15
func TestPinnedProtectedManifestUnsafePathNeverCallsClockOrCreatesLock(t *testing.T) {
	dir := t.TempDir()
	ancestor := filepath.Join(dir, "writable")
	if e := os.Mkdir(ancestor, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(ancestor, 0770); e != nil {
		t.Fatal(e)
	}
	private := filepath.Join(ancestor, "private")
	if e := os.Mkdir(private, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(private, "ledger")
	owners := []uint32{0, 65534, uint32(os.Geteuid())}
	seen := map[uint32]bool{}
	unique := []uint32{}
	for _, u := range owners {
		if !seen[u] {
			seen[u] = true
			unique = append(unique, u)
		}
	}
	image := protectedManifestImage(path, unique)
	var calls atomic.Int32
	var slot StartupSlot
	defer slot.Drain(context.Background())
	p, e := slot.StartManifest(strings.NewReader(string(image)), sha256.Sum256(image), grants.Config{Now: func() time.Time { calls.Add(1); return time.Now() }})
	if e != nil {
		t.Fatal(e)
	}
	if waitProtectedManifest(t, p) != StartupRecovery {
		t.Fatal("unsafe path admitted")
	}
	if calls.Load() != 0 {
		t.Fatal("unsafe config called clock")
	}
	if _, e = os.Stat(path + ".lock"); !os.IsNotExist(e) {
		t.Fatal("unsafe startup created lock", e)
	}
}

// REQ: OP-1, CH-15
func TestProtectedManifestV1BytesAndPolicyRefusals(t *testing.T) {
	v1 := []byte(`{"version":1,"ledger":"/synthetic/ledger","requests_per_hour":2,"max_store_latency_ms":1000}`)
	settings, e := ReadProvisionedManifest(bytes.NewReader(v1), sha256.Sum256(v1))
	if e != nil {
		t.Fatal("v1 changed", e)
	}
	marshalled, e := json.Marshal(settings.manifest)
	if e != nil || !bytes.Equal(marshalled, v1) {
		t.Fatal("v1 canonical bytes changed", e)
	}
	path, owners := protectedFixture(t)
	good := protectedManifestImage(path, owners)
	uids, _ := json.Marshal(owners)
	token := `"trusted_owners":` + string(uids)
	for _, kind := range []string{"missing", "empty", "null", "duplicate", "overbound", "negative", "overflow", "v1-owners", "unknown-field", "noncanonical", "wrong-pin", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			image := append([]byte(nil), good...)
			switch kind {
			case "missing":
				image = []byte(strings.Replace(string(good), ","+token, "", 1))
			case "empty", "null", "duplicate", "negative", "overflow":
				policy := map[string]string{"empty": "[]", "null": "null", "duplicate": "[0,0]", "negative": "[-1]", "overflow": "[4294967296]"}[kind]
				image = []byte(strings.Replace(string(good), token, `"trusted_owners":`+policy, 1))
			case "overbound":
				policy := make([]uint32, 17)
				for i := range policy {
					policy[i] = uint32(i)
				}
				image = protectedManifestImage(path, policy)
			case "v1-owners":
				image = []byte(strings.Replace(string(good), `"version":2`, `"version":1`, 1))
			case "unknown-field":
				image = append(image[:len(image)-1], []byte(`,"unexpected":true}`)...)
			case "noncanonical":
				image = append(image, '\n')
			case "oversize":
				image = bytes.Repeat([]byte("x"), MaxManifestBytes+1)
			}
			pin := sha256.Sum256(image)
			if kind == "wrong-pin" {
				pin = sha256.Sum256([]byte("SYNTHETIC WRONG CONFIG PIN"))
			}
			if m, e := ReadProvisionedManifest(bytes.NewReader(image), pin); m != nil || e != ErrManifest {
				t.Fatal("policy downgraded or accepted", e)
			}
		})
	}
}

// REQ: OP-1, CH-15
func TestProtectedOwnedReaderRetirementKeepsSlotAndNeverConstructs(t *testing.T) {
	path, owners := protectedFixture(t)
	image := protectedManifestImage(path, owners)
	pin := sha256.Sum256(image)
	r := &ownedManifestReader{reader: bytes.NewReader(image), entered: make(chan struct{}), release: make(chan struct{})}
	var slot StartupSlot
	var clocks atomic.Int32
	cfg := grants.Config{Now: func() time.Time { clocks.Add(1); return time.Now() }}
	p, e := slot.StartManifest(r, pin, cfg)
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
	never := &ownedManifestReader{reader: bytes.NewReader(image), entered: make(chan struct{}), release: make(chan struct{})}
	if _, e = slot.StartManifest(never, pin, cfg); e != ErrStartupOccupied || never.reads.Load() != 0 {
		t.Fatal("occupied reader entered", e)
	}
	if e = p.Use(func(*grants.Gate) error { t.Fatal("consumer before config completion"); return nil }); e != ErrSessionOpening {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if e = slot.Drain(ctx); e != context.Canceled {
		t.Fatal("incomplete drain", e)
	}
	if _, e = slot.StartManifest(never, pin, cfg); e != ErrStartupOccupied || never.reads.Load() != 0 {
		t.Fatal("retired reader lost slot", e)
	}
	close(r.release)
	if e = slot.Drain(t.Context()); e != nil {
		t.Fatal(e)
	}
	if clocks.Load() != 0 || p.State() != StartupRetired {
		t.Fatal("retired result constructed or published")
	}
	if _, e = os.Stat(path + ".lock"); !os.IsNotExist(e) {
		t.Fatal("retired reader created lock", e)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("retired reader created ledger", e)
	}
}
