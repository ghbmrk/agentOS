package main

// REQ: OSS-10, CH-3

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clock"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/follow"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/update"
)

// Synthetic keys only: generated per test.
func followRoot(t *testing.T) []byte {
	t.Helper()
	key := func() ed25519.PublicKey {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return pub
	}
	var signers []ed25519.PrivateKey
	var root []ed25519.PublicKey
	for i := 0; i < 2; i++ {
		pub, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signers, root = append(signers, k), append(root, pub)
	}
	dir := filepath.Join(t.TempDir(), "repo")
	repo, err := update.Init(dir, update.RootConfig{Root: root, Targets: root,
		Snapshot: []ed25519.PublicKey{key()}, Timestamp: []ed25519.PublicKey{key()}, RootThreshold: 2, TargetsThreshold: 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range signers {
		if err := repo.Sign("root", k); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "staged", "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func noGuard() *clock.Guard { return nil }

// Following is off unless both the store and the shipped root are named,
// and the store must already trust a root: agentosd never initialises it.
func TestOSS10w2FollowSettingFlags(t *testing.T) {
	if s, err := newFollowSetting("", "", noGuard); s != nil || err != nil {
		t.Fatalf("off: %v %v", s, err)
	}
	shipped := filepath.Join(t.TempDir(), "root.json")
	if err := os.WriteFile(shipped, followRoot(t), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{t.TempDir(), ""}, {"", shipped}, {t.TempDir(), shipped}, {t.TempDir(), shipped + ".missing"}} {
		if s, err := newFollowSetting(c[0], c[1], noGuard); s != nil || err == nil {
			t.Fatalf("%q: no error", c)
		}
	}
	b, _ := os.ReadFile(shipped)
	dir := filepath.Join(t.TempDir(), "box")
	if _, err := update.InitStore(dir, b, 0); err != nil {
		t.Fatal(err)
	}
	s, err := newFollowSetting(dir, shipped, noGuard)
	if err != nil || s == nil {
		t.Fatalf("%v", err)
	}

	// Wired only with the page served.
	var cfg daemon.Config
	if s.wire(&cfg) || cfg.BrokerExecutors != nil || len(cfg.Notes) != 0 {
		t.Fatal("wired without the page")
	}
	cfg.PageSocket = &daemon.PageSocket{UID: 1000}
	if !s.wire(&cfg) || cfg.PageSocket.DescribeRoot == nil || cfg.BrokerExecutors[grants.FollowExecutor] == nil || len(cfg.Notes) != 1 {
		t.Fatalf("not wired: %+v", cfg)
	}
	if (*followSetting)(nil).wire(&cfg) {
		t.Fatal("nil setting wired")
	}

	// Before the clock guard runs, nothing is described.
	if sum, err := cfg.PageSocket.DescribeRoot(context.Background(), b); err == nil || sum.Digest != "" || sum.Reason != "" {
		t.Fatalf("described without a clock guard: %+v %v", sum, err)
	}
	// With no owner channel the alert fails and is held (STATUS shows it).
	if err := s.alert(context.Background(), "x"); err == nil {
		t.Fatal("alert without a channel")
	}
}

// An unchecked clock reads as the far future, so every root is expired.
func TestOSS10w2GuardClockFailsClosed(t *testing.T) {
	now, st := guardClock{noGuard}.Latest(context.Background())
	if now.Before(time.Now().AddDate(1000, 0, 0)) || st.State != clock.Unchecked {
		t.Fatalf("%v %+v", now, st)
	}
}

// OSS-10w L3 decision: the page names only a coarse cause, never the
// verifier's text, and copies a verified summary.
func TestOSS10w2PageSummaryReason(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("%w: root v3 expired 2026-01-01", update.ErrExpired), localapi.RootExpired},
		{fmt.Errorf("%w: 1 of 2", update.ErrSignatures), localapi.RootSignatures},
		{fmt.Errorf("%w: root 1 < 2", update.ErrWeakThreshold), localapi.RootThreshold},
		{errors.New("unexpected end of JSON input"), ""},
	} {
		sum, err := pageSummary(update.RootSummary{Version: 3, Digest: "d"}, c.err)
		if err == nil || sum.Reason != c.want || sum.Digest != "" || sum.Version != 0 {
			t.Fatalf("%v: %+v %v", c.err, sum, err)
		}
	}
	exp := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	sum, err := pageSummary(update.RootSummary{Version: 3, Keys: map[string][]string{"root": {"k1", "k2"}}, Thresholds: map[string]int{"root": 2}, Expires: exp, Digest: "d"}, nil)
	if err != nil || sum.Version != 3 || len(sum.Keys["root"]) != 2 || sum.Thresholds["root"] != 2 || !sum.Expires.Equal(exp) || sum.Digest != "d" || sum.Reason != "" {
		t.Fatalf("%+v %v", sum, err)
	}
}

// OSS-10w2 L3 blocker: the executor's pending alert lives in the update
// store dir, so an alert a previous run left unsent shows on STATUS after
// a restart.
func TestOSS10w2PendingAlertSurvivesARestart(t *testing.T) {
	shipped := filepath.Join(t.TempDir(), "root.json")
	b := followRoot(t)
	if err := os.WriteFile(shipped, b, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "box")
	if _, err := update.InitStore(dir, b, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, pendingAlert), []byte("switched"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := newFollowSetting(dir, shipped, noGuard)
	if err != nil {
		t.Fatal(err)
	}
	if n := s.x.Note(); n != follow.UnsentPrefix+"switched" {
		t.Fatalf("note %q", n)
	}
}

// L3 R2 (WF1 wiring): describe reports Project from the executor's check,
// true for the shipped root and false for any other.
func TestOSS10w2DescribeProject(t *testing.T) {
	shipped := filepath.Join(t.TempDir(), "root.json")
	b := followRoot(t)
	if err := os.WriteFile(shipped, b, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "box")
	if _, err := update.InitStore(dir, b, 0); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	g, err := clock.New(clock.Config{
		Synced:  func() (bool, error) { return true, nil },
		Carrier: func(context.Context) (time.Time, error) { return now, nil },
		Now:     func() time.Time { return now },
		Elapsed: func() time.Duration { return time.Hour },
		BootID:  func() string { return "boot" },
	})
	if err != nil {
		t.Fatal(err)
	}
	g.Check(context.Background())
	s, err := newFollowSetting(dir, shipped, func() *clock.Guard { return g })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if sum, err := s.describe(ctx, b); err != nil || !sum.Project {
		t.Fatalf("shipped root: %+v %v", sum, err)
	}
	if sum, err := s.describe(ctx, followRoot(t)); err != nil || sum.Project || sum.Digest == "" {
		t.Fatalf("fork root: %+v %v", sum, err)
	}
}
