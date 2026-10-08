//go:build linux

package pacingfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"github.com/ghbmrk/agentos/broker/grants"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func recoverySettings(t *testing.T, path string, owners []uint32) *ManifestSettings {
	t.Helper()
	wire := protectedManifestImage(path, owners)
	m, err := ReadProvisionedManifest(bytes.NewReader(wire), sha256.Sum256(wire))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// REQ: OP-1, CH-15
func TestProtectedManifestSameSlotDuplicateRecoveryRetainsSpentDebt(t *testing.T) {
	path, owners := protectedFixture(t)
	lease, err := OpenExclusiveProtected(path, owners)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	gate := grants.New(grants.Config{Now: clock, RequestsPerHour: 2, PacingStore: lease, PacingMaxStoreLatency: time.Second})
	if gate.PacingHealth() != nil || !gate.Reserve(false) || !gate.Reserve(false) {
		lease.Close()
		t.Fatal("spent fixture")
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	m := recoverySettings(t, path, owners)
	var slot StartupSlot
	p, err := m.Start(&slot, grants.Config{Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if state := waitProtectedManifest(t, p); state != StartupReady {
		t.Fatal(state)
	}
	if err = slot.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".tmp", image, 0600); err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(image) // synthetic fixture pin; production authority is separate.
	report, err := InspectTemporary(path, pin, m)
	if err != nil || report.State != TemporaryDuplicate {
		t.Fatal("protected report", report, err)
	}
	assertRecoveryLedger(t, path, image)
	if err = slot.RecoverDuplicate(path, pin, m); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("duplicate retained", err)
	}
	assertRecoveryLedger(t, path, image)
	p, err = m.Start(&slot, grants.Config{Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if state := waitProtectedManifest(t, p); state != StartupReady {
		t.Fatal(state)
	}
	if err = p.Use(func(g *grants.Gate) error {
		if g.PacingHealth() != nil || g.Reserve(false) {
			t.Fatal("debt reset")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = slot.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// REQ: OP-1, CH-15
func TestPinnedRecoveryNeverDowngradesUnsafeAncestor(t *testing.T) {
	ancestor, owners := protectedFixture(t)
	ancestor = filepath.Dir(ancestor)
	private := filepath.Join(ancestor, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "ledger")
	image := []byte("synthetic duplicate, not schema authority")
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".tmp", image, 0600); err != nil {
		t.Fatal(err)
	}
	m := recoverySettings(t, path, owners)
	pin := sha256.Sum256(image)
	if err := os.Chmod(ancestor, 0770); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(ancestor, 0700) // owned fixture only, never shared root.
	report, err := InspectTemporary(path, pin, m)
	if err != ErrStorage || report != (TemporaryReport{}) {
		t.Fatal("inspection downgraded", report, err)
	}
	if err = DiscardDuplicateTemporary(path, pin, m); err != ErrStorage {
		t.Fatal("cleanup downgraded", err)
	}
	var slot StartupSlot
	if err = slot.RecoverDuplicate(path, pin, m); err != ErrStorage || slot.RecoveryState() != RecoveryHeld {
		t.Fatal("owned recovery downgraded", err)
	}
	if _, err = os.Stat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatal("lock created on refused ancestry", err)
	}
	assertRecoveryLedger(t, path, image)
	temp, err := os.ReadFile(path + ".tmp")
	if err != nil || !bytes.Equal(temp, image) {
		t.Fatal("residue changed", err)
	}
}

// REQ: OP-1, CH-15
func TestInvalidManifestRecoveryBindingRefusesBeforeIOAndAdmission(t *testing.T) {
	path, owners := protectedFixture(t)
	m := recoverySettings(t, path+"-other", owners)
	pin := sha256.Sum256([]byte("synthetic pin"))
	for _, options := range [][]*ManifestSettings{{m}, {nil}, {&ManifestSettings{}}, {m, m}} {
		report, err := InspectTemporary(path, pin, options...)
		if err != ErrStorage || report != (TemporaryReport{}) {
			t.Fatal("bad binding read", err)
		}
		if err = DiscardDuplicateTemporary(path, pin, options...); err != ErrStorage {
			t.Fatal("bad binding cleanup", err)
		}
		var slot StartupSlot
		if err = slot.RecoverDuplicate(path, pin, options...); err != ErrSessionConfig || slot.RecoveryState() != RecoveryIdle {
			t.Fatal("bad binding admitted", err)
		}
	}
	if _, err := os.Stat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatal("invalid binding created lock", err)
	}
}

func provisionProtectedRecovery(t *testing.T) (string, *ManifestSettings, func() time.Time) {
	t.Helper()
	path, owners := protectedFixture(t)
	lease, err := OpenExclusiveProtected(path, owners)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	g := grants.New(grants.Config{Now: clock, RequestsPerHour: 2, PacingStore: lease, PacingMaxStoreLatency: time.Second})
	if g.PacingHealth() != nil || !g.Reserve(false) {
		lease.Close()
		t.Fatal("spent fixture")
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	return path, recoverySettings(t, path, owners), clock
}

// REQ: OP-1, CH-15
func TestProtectedRecoveryRefusesLiveAndCancelledIncompleteConsumerDrain(t *testing.T) {
	path, m, clock := provisionProtectedRecovery(t)
	var slot StartupSlot
	p, err := m.Start(&slot, grants.Config{Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if state := waitProtectedManifest(t, p); state != StartupReady {
		t.Fatal(state)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		slot.Drain(context.Background())
	})
	go func() { done <- p.Use(func(*grants.Gate) error { close(entered); <-release; return nil }) }()
	<-entered
	image, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(image)
	if err = slot.RecoverDuplicate(path, pin, m); err != ErrStartupOccupied {
		t.Fatal("live action admitted", err)
	}
	report, err := InspectTemporary(path, pin, m)
	if err != ErrStorage || report != (TemporaryReport{}) {
		t.Fatal("live lease inspected", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = slot.Drain(ctx); err != context.Canceled {
		t.Fatal(err)
	}
	if err = slot.RecoverDuplicate(path, pin, m); err != ErrStartupOccupied {
		t.Fatal("cancelled incomplete drain released action", err)
	}
	if err = DiscardDuplicateTemporary(path, pin, m); err != ErrStorage {
		t.Fatal("live direct action bypassed lease", err)
	}
	assertRecoveryLedger(t, path, image)
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = slot.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".tmp", image, 0600); err != nil {
		t.Fatal(err)
	}
	if err = slot.RecoverDuplicate(path, pin, m); err != nil {
		t.Fatal("complete healthy drain not released", err)
	}
	assertRecoveryLedger(t, path, image)
}

// REQ: OP-1, CH-15
func TestProtectedNonduplicateResidueHoldsOrdinaryUrgentAndOwnedRecovery(t *testing.T) {
	path, m, clock := provisionProtectedRecovery(t)
	var slot StartupSlot
	p, err := m.Start(&slot, grants.Config{Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if state := waitProtectedManifest(t, p); state != StartupReady {
		t.Fatal(state)
	}
	if err = slot.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	residue := []byte("synthetic nonduplicate residue")
	if err = os.WriteFile(path+".tmp", residue, 0600); err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(image)
	report, err := InspectTemporary(path, pin, m)
	if err != nil || report.State != TemporaryDifferent || report.TemporaryDigest != sha256.Sum256(residue) {
		t.Fatal(report, err)
	}
	// A strict actual protected Gate must remain held without consuming residue.
	p, err = m.Start(&slot, grants.Config{Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	if state := waitProtectedManifest(t, p); state != StartupRecovery {
		t.Fatal("residue bypassed startup hold", state)
	}
	if err = p.Use(func(g *grants.Gate) error {
		if g.PacingHealth() == nil || g.Reserve(false) || g.Reserve(true) {
			t.Fatal("residue admitted ordinary/urgent")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = slot.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = slot.RecoverDuplicate(path, pin, m); err != ErrStorage || slot.RecoveryState() != RecoveryHeld {
		t.Fatal("nonduplicate recovery admitted", err)
	}
	if _, err = m.Start(&slot, grants.Config{Now: clock}); err != ErrStartupOccupied {
		t.Fatal("failed action released startup", err)
	}
	if err = slot.Drain(context.Background()); err != ErrStartupOccupied {
		t.Fatal("failed recovery reset", err)
	}
	assertRecoveryLedger(t, path, image)
	after, err := os.ReadFile(path + ".tmp")
	if err != nil || !bytes.Equal(after, residue) {
		t.Fatal("nonduplicate overwritten", err)
	}
	// No restart/retry of the failed recovery action absent external determination.
}

// REQ: OP-1, CH-15
func TestPinnedV1RecoveryRetainsExplicitLegacyBehavior(t *testing.T) {
	path, image := recoveryFixture(t)
	wire := manifestImage(t, path, 2, 1000)
	m, err := ReadProvisionedManifest(bytes.NewReader(wire), sha256.Sum256(wire))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".tmp", image, 0600); err != nil {
		t.Fatal(err)
	}
	report, err := InspectTemporary(path, sha256.Sum256(image), m)
	if err != nil || report.State != TemporaryDuplicate {
		t.Fatal(report, err)
	}
	if err = DiscardDuplicateTemporary(path, sha256.Sum256(image), m); err != nil {
		t.Fatal(err)
	}
	assertRecoveryLedger(t, path, image)
}

// REQ: OP-1, CH-15
func TestManifestRecoveryPolicyCopyAndInvalidV2NeverBecomeLegacy(t *testing.T) {
	path, owners := protectedFixture(t)
	m := recoverySettings(t, path, owners)
	copied, err := manifestRecoveryOwners(path, []*ManifestSettings{m})
	if err != nil || len(copied) != len(owners) || len(copied) == 0 {
		t.Fatal("protected policy lost", err)
	}
	first := copied[0]
	m.manifest.TrustedOwners[0] = first + 1
	if copied[0] != first {
		t.Fatal("policy aliases settings")
	}
	for _, bad := range []ProvisionedManifest{
		{Version: 2, Ledger: path, RequestsPerHour: 2, MaxStoreLatencyMillis: 1000},
		{Version: 2, Ledger: path, RequestsPerHour: 2, MaxStoreLatencyMillis: 1000, TrustedOwners: []uint32{1, 1}},
		{Version: 2, Ledger: path, RequestsPerHour: 2, MaxStoreLatencyMillis: 1000, TrustedOwners: make([]uint32, 17)},
	} {
		if policy, err := manifestRecoveryOwners(path, []*ManifestSettings{{manifest: bad, valid: true}}); err == nil || policy != nil {
			t.Fatal("invalid v2 became legacy")
		}
	}
}
