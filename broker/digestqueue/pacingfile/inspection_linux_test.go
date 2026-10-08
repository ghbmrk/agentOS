//go:build linux

package pacingfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"github.com/ghbmrk/agentos/broker/grants"
	"os"
	"syscall"
	"testing"
)

// REQ: OP-1, CH-15
func TestInspectTemporaryReportsOnlyBoundedDigestsWithoutMutation(t *testing.T) {
	for _, kind := range []string{"duplicate", "different", "absent"} {
		t.Run(kind, func(t *testing.T) {
			path, ledger := recoveryFixture(t)
			temp := append([]byte(nil), ledger...)
			want := TemporaryDuplicate
			switch kind {
			case "different":
				temp = []byte("SYNTHETIC NONDUPLICATE RESIDUE")
				want = TemporaryDifferent
				if e := os.WriteFile(path+".tmp", temp, 0600); e != nil {
					t.Fatal(e)
				}
			case "absent":
				want = TemporaryAbsent
				temp = nil
				if e := os.Remove(path + ".tmp"); e != nil {
					t.Fatal(e)
				}
			}
			report, e := InspectTemporary(path, sha256.Sum256(ledger))
			if e != nil {
				t.Fatal(e)
			}
			if report.State != want || report.LedgerDigest != sha256.Sum256(ledger) || report.LedgerBytes != len(ledger) || report.TemporaryBytes != len(temp) {
				t.Fatal("incorrect fixed report", report)
			}
			if temp != nil {
				if report.TemporaryDigest != sha256.Sum256(temp) {
					t.Fatal("temp digest")
				}
				got, e := os.ReadFile(path + ".tmp")
				if e != nil || !bytes.Equal(got, temp) {
					t.Fatal("inspection changed residue", e)
				}
			} else {
				if report.TemporaryDigest != ([32]byte{}) {
					t.Fatal("absent digest")
				}
				if _, e := os.Stat(path + ".tmp"); !os.IsNotExist(e) {
					t.Fatal("inspection created temp", e)
				}
			}
			assertRecoveryLedger(t, path, ledger)
			// A report is a value: caller mutations never alter accounting or future output.
			report.LedgerDigest = [32]byte{}
			again, e := InspectTemporary(path, sha256.Sum256(ledger))
			if e != nil || again.LedgerDigest != sha256.Sum256(ledger) {
				t.Fatal("report shared mutable state", e)
			}
		})
	}
}

// REQ: OP-1, CH-15
func TestInspectTemporaryRefusesUnsafeImagesWithZeroReport(t *testing.T) {
	for _, kind := range []string{"zero-pin", "wrong-pin", "empty", "oversize", "symlink", "fifo", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			path, ledger := recoveryFixture(t)
			pin := sha256.Sum256(ledger)
			switch kind {
			case "zero-pin":
				pin = [32]byte{}
			case "wrong-pin":
				pin = sha256.Sum256([]byte("SYNTHETIC WRONG PIN"))
			case "empty":
				if e := os.WriteFile(path+".tmp", nil, 0600); e != nil {
					t.Fatal(e)
				}
			case "oversize":
				if e := os.Truncate(path+".tmp", grants.MaxPacingStateBytes+1); e != nil {
					t.Fatal(e)
				}
			case "symlink", "fifo", "hardlink":
				if e := os.Remove(path + ".tmp"); e != nil {
					t.Fatal(e)
				}
				var e error
				switch kind {
				case "symlink":
					e = os.Symlink(path, path+".tmp")
				case "fifo":
					e = syscall.Mkfifo(path+".tmp", 0600)
				case "hardlink":
					e = os.Link(path, path+".tmp")
				}
				if e != nil {
					t.Fatal(e)
				}
			}
			report, e := InspectTemporary(path, pin)
			if e != ErrStorage || report != (TemporaryReport{}) {
				t.Fatal("unsafe diagnostic published", report, e)
			}
			assertRecoveryLedger(t, path, ledger)
		})
	}
}

// REQ: OP-1, CH-15
func TestInspectionAfterSpentDebtDoesNotRepairNonduplicate(t *testing.T) {
	path, cfg := sessionFixture(t)
	s, e := OpenSession(path, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	if e = s.Use(func(g *grants.Gate) error {
		if !g.Reserve(false) {
			t.Fatal("fixture reserve")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	ledger, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	pin := sha256.Sum256(ledger)
	if report, e := InspectTemporary(path, pin); e != ErrStorage || report != (TemporaryReport{}) {
		t.Fatal("live custody bypass", e)
	}
	if e = s.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	residue := []byte("SYNTHETIC DIFFERENT RESIDUE")
	if e = os.WriteFile(path+".tmp", residue, 0600); e != nil {
		t.Fatal(e)
	}
	if report, e := InspectTemporary(path, pin); e != nil || report.State != TemporaryDifferent {
		t.Fatal(report, e)
	}
	reopened, e := OpenSession(path, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close(context.Background())
	if e = reopened.Use(func(g *grants.Gate) error {
		if g.Reserve(false) || g.Reserve(true) || g.PacingHealth() != grants.ErrPacingRecovery {
			t.Fatal("diagnosis cured residue/urgent hold")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	assertRecoveryLedger(t, path, ledger)
	got, e := os.ReadFile(path + ".tmp")
	if e != nil || !bytes.Equal(got, residue) {
		t.Fatal("residue changed", e)
	}
}

// REQ: OP-1, CH-15
func TestInspectionZeroPinRefusesBeforeLockCreation(t *testing.T) {
	path := t.TempDir() + "/ledger"
	if r, e := InspectTemporary(path, [32]byte{}); r != (TemporaryReport{}) || e != ErrStorage {
		t.Fatal(r, e)
	}
	if _, e := os.Stat(path + ".lock"); !os.IsNotExist(e) {
		t.Fatal("zero pin created lock", e)
	}
}

// REQ: OP-1, CH-15
func TestInspectionRefusesCancelledIncompleteScopeDrain(t *testing.T) {
	path, cfg := sessionFixture(t)
	s, e := OpenSession(path, cfg)
	if e != nil {
		t.Fatal(e)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		s.Close(context.Background())
	})
	go func() { done <- s.Use(func(*grants.Gate) error { close(entered); <-release; return nil }) }()
	<-entered
	ledger, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if e = s.Close(ctx); e != context.Canceled {
		t.Fatal("drain did not retain scope", e)
	}
	if r, e := InspectTemporary(path, sha256.Sum256(ledger)); r != (TemporaryReport{}) || e != ErrStorage {
		t.Fatal("cancelled drain lost custody", r, e)
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if e = s.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	if r, e := InspectTemporary(path, sha256.Sum256(ledger)); e != nil || r.State != TemporaryAbsent {
		t.Fatal("complete drain diagnosis", r, e)
	}
}
