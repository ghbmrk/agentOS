package pacingfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
)

// REQ: CH-15, OP-8
func TestLoadBoundsExactLimitAndOversizedSparseFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger")
	s := Store{Path: path}
	b, err := s.Load()
	if err != nil || b != nil {
		t.Fatal("missing-state convention", err)
	}
	for _, n := range []int{0, grants.MaxPacingStateBytes, grants.MaxPacingStateBytes + 1} {
		data := bytes.Repeat([]byte{'x'}, n)
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		b, err = s.Load()
		if n > grants.MaxPacingStateBytes {
			if err != ErrStorage || b != nil {
				t.Fatal("oversized file read", err)
			}
		} else if err != nil || b == nil || !bytes.Equal(b, data) {
			t.Fatal("bounded valid image", n, err)
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(1 << 30); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	if b, err = s.Load(); err != ErrStorage || b != nil {
		t.Fatal("sparse oversized file accepted", err)
	}
}

// REQ: CH-15, OP-8
func TestLoadRejectsFinalSymlinkDirectoryAndFIFO(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "synthetic-target")
	if err := os.WriteFile(target, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "absent"), dangling); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, dangling, dir, fifo} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			done := make(chan error, 1)
			go func() {
				b, err := (Store{Path: path}).Load()
				if b != nil {
					done <- errors.New("refused input returned bytes")
					return
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err != ErrStorage {
					t.Fatal("invalid file accepted", err)
				}
			case <-time.After(time.Second):
				t.Fatal("non-regular open stalled")
			}
		})
	}
}

// REQ: CH-15, OP-8
func TestStreamBoundRejectsOversizedInput(t *testing.T) {
	b, err := readBounded(bytes.NewReader(bytes.Repeat([]byte{'x'}, grants.MaxPacingStateBytes+1)))
	if b != nil || err != ErrStorage {
		t.Fatal("stream exceeded cap", err)
	}
}

// REQ: CH-15
func TestGateStrictReopenRetainsDebtThroughBoundedStore(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "ledger")}
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	cfg := grants.Config{Now: func() time.Time { return now }, RequestsPerHour: 1, PacingStore: s, PacingMaxStoreLatency: time.Second}
	g := grants.New(cfg)
	if g.PacingHealth() != nil || !g.Reserve(false) {
		t.Fatal("fixture provisioning/reservation")
	}
	cfg.PacingRequireExisting = true
	g = grants.New(cfg)
	if g.PacingHealth() != nil || !g.ProvisionedPacingConfigured() || g.Reserve(false) {
		t.Fatal("strict bounded reopen reset debt")
	}
	now = now.Add(time.Hour)
	if !g.Reserve(false) {
		t.Fatal("valid expiry refused")
	}
}

// REQ: CH-15, OP-8
func TestGateOversizedRecoveryNeverOverwritesImage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger")
	data := bytes.Repeat([]byte{'x'}, grants.MaxPacingStateBytes+1)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := grants.Config{PacingStore: Store{Path: path}, PacingRequireExisting: true, PacingMaxStoreLatency: time.Second}
	g := grants.New(cfg)
	if g.PacingHealth() != grants.ErrPacingRecovery || g.Reserve(false) {
		t.Fatal("oversized state admitted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, data) {
		t.Fatal("recovery rewrote image", err)
	}
	if _, err = os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recovery attempted save", err)
	}
}

// REQ: CH-15, OP-8
func TestSaveBoundsAndSanitizesErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger")
	s := Store{Path: path}
	if err := s.Save([]byte("synthetic-state")); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(bytes.Repeat([]byte{'x'}, grants.MaxPacingStateBytes+1)); err != ErrStorage {
		t.Fatal("oversized save accepted", err)
	}
	b, err := s.Load()
	if err != nil || string(b) != "synthetic-state" {
		t.Fatal("oversized save changed state")
	}
	bad := Store{Path: filepath.Join(path, "synthetic-private-path")}
	if b, err := bad.Load(); b != nil || err != ErrStorage {
		t.Fatal("read error leaked", err)
	}
	if err := bad.Save([]byte("synthetic")); err != ErrStorage {
		t.Fatal("write error leaked", err)
	}
}
