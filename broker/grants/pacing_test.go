package grants

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-15, CAP-10
func TestDurablePacingSharesAllKindsAcrossReopen(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "pacing.json")
	open := func() *Gate {
		return New(Config{Now: func() time.Time { return now }, RequestsPerHour: 3, PacingStore: &change.FileStore{Path: path}})
	}
	g := open()
	if err := g.PacingHealth(); err != nil {
		t.Fatal(err)
	}
	if g.take(false, 1) != 1 || !g.Reserve(false) {
		t.Fatal("initial shared reservations")
	}
	g = open()
	if !g.Reserve(false) || g.Reserve(false) || g.take(true, 1) != 0 {
		t.Fatal("restart reset the common allowance")
	}
	now = now.Add(time.Hour)
	g = open()
	if g.take(true, 3) != 3 || g.Reserve(false) {
		t.Fatal("hour boundary allowance")
	}
	// Urgent traffic remains unpaced but spends the next paced allowance.
	if g.take(false, 100000) != 100000 {
		t.Fatal("urgent traffic was rate limited")
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() > maxPacingBytes {
		t.Fatalf("unbounded ledger: %v %v", info, err)
	}
	g = open()
	if g.Reserve(false) {
		t.Fatal("urgent debt disappeared on restart")
	}
	now = now.Add(time.Hour)
	if !g.Reserve(false) {
		t.Fatal("expired debt did not clear")
	}
}

// REQ: CH-15, CAP-10
func TestDurablePacingAgedPrioritySurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pacing.json")
	r := newRig(t, func(c *Config) { c.PacingStore = &change.FileStore{Path: path} })
	r.g.mu.Lock()
	r.g.batch = []string{"synthetic-waiting"}
	r.g.mu.Unlock()
	if !r.g.Reserve(true) {
		t.Fatal("first aged reservation")
	}
	r.open()
	r.g.mu.Lock()
	r.g.batch = []string{"synthetic-waiting"}
	r.g.mu.Unlock()
	if r.g.Reserve(true) {
		t.Fatal("restart reset the aged fairness turn")
	}
	r.advance(time.Hour)
	if !r.g.Reserve(true) {
		t.Fatal("aged turn did not expire")
	}
}

type pacingCut struct {
	file        *change.FileStore
	fail, after bool
}

func (s *pacingCut) Load() ([]byte, error) { return s.file.Load() }
func (s *pacingCut) Save(b []byte) error {
	if !s.fail {
		return s.file.Save(b)
	}
	if s.after {
		if err := s.file.Save(b); err != nil {
			return err
		}
	}
	return errors.New("synthetic private storage canary")
}

// REQ: CH-15
func TestDurablePacingUncertainWriteQuarantinesAndReopens(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[after], func(t *testing.T) {
			now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
			s := &pacingCut{file: &change.FileStore{Path: filepath.Join(t.TempDir(), "pacing.json")}, after: after}
			cfg := Config{Now: func() time.Time { return now }, RequestsPerHour: 1, PacingStore: s}
			g := New(cfg)
			s.fail = true
			if g.Reserve(false) || !errors.Is(g.PacingHealth(), ErrPacingRecovery) {
				t.Fatal("uncertain reservation escaped")
			}
			s.fail = false
			if g.Reserve(false) || g.take(false, 1) != 0 {
				t.Fatal("quarantined live object resumed")
			}
			cfg.PacingStore = &change.FileStore{Path: s.file.Path}
			g = New(cfg)
			if err := g.PacingHealth(); err != nil {
				t.Fatal(err)
			}
			if got := g.Reserve(false); got == after {
				t.Fatalf("durable result wrong after reopen: %v", got)
			}
		})
	}
}

// REQ: CH-15
func TestDurablePacingFaultRequeuesEveryRequestPath(t *testing.T) {
	for _, kind := range []string{"normal", "reissued", "page", "reissued-page"} {
		t.Run(kind, func(t *testing.T) {
			s := &pacingCut{file: &change.FileStore{Path: filepath.Join(t.TempDir(), "pacing.json")}}
			r := newRig(t, func(c *Config) { c.PacingStore = s })
			it := owner.Item{Ref: "synthetic-request", Object: "synthetic", Recipient: "a@example.com", Facts: owner.Facts{Verb: "send"}}
			w := &wait{item: it}
			if kind == "page" || kind == "reissued-page" {
				w.onlyUI = true
			}
			if kind == "reissued" || kind == "reissued-page" {
				w.expires = r.now().Add(time.Hour)
			}
			r.g.mu.Lock()
			r.g.waiting[it.Ref] = w
			r.g.batch = []string{it.Ref}
			r.g.mu.Unlock()
			s.fail = true
			r.g.Flush()
			if r.own.count() != 0 {
				t.Fatal("owner handoff after accounting failed")
			}
			r.g.mu.Lock()
			defer r.g.mu.Unlock()
			if len(r.g.batch) != 1 || r.g.waiting[it.Ref] == nil {
				t.Fatal("request lost instead of requeued")
			}
		})
	}
}

// REQ: CH-15
func TestDurablePacingClockAndStateRefusals(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "pacing.json")
	cfg := Config{Now: func() time.Time { return now }, RequestsPerHour: 3, PacingStore: &change.FileStore{Path: path}}
	g := New(cfg)
	if !g.Reserve(false) {
		t.Fatal("initial")
	}
	now = now.Add(-time.Nanosecond)
	if g.Reserve(false) || !errors.Is(g.PacingHealth(), ErrPacingRecovery) {
		t.Fatal("live rollback accepted")
	}
	if New(cfg).PacingHealth() == nil {
		t.Fatal("restart rollback accepted")
	}
	now = now.Add(time.Hour)
	cfg.RequestsPerHour = 4
	if New(cfg).PacingHealth() == nil {
		t.Fatal("unreviewed budget migration")
	}
	for _, data := range []string{"null", "{}", "{} {}", "{\"version\":99}", string(make([]byte, maxPacingBytes+1))} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		g := New(cfg)
		if g.PacingHealth() != ErrPacingRecovery || g.Reserve(false) || g.take(false, 1) != 0 {
			t.Fatal("malformed ledger admitted")
		}
	}
}

// REQ: CH-15
func TestDurablePacingConcurrentReservationsDoNotOverspend(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	cfg := Config{Now: func() time.Time { return now }, RequestsPerHour: 3, PacingStore: &change.FileStore{Path: filepath.Join(t.TempDir(), "pacing.json")}}
	g := New(cfg)
	var mu sync.Mutex
	count := 0
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if g.Reserve(false) {
				mu.Lock()
				count++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if count != 3 || New(cfg).Reserve(false) {
		t.Fatalf("overspent %d", count)
	}
}

// REQ: CH-15
func TestDurablePacingKeepsExactStaggeredAllowance(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	cfg := Config{Now: func() time.Time { return now }, RequestsPerHour: 3, PacingStore: &change.FileStore{Path: filepath.Join(t.TempDir(), "pacing.json")}}
	g := New(cfg)
	for range 5 {
		if g.take(false, 1) != 1 {
			t.Fatal("urgent refused")
		}
		now = now.Add(10 * time.Minute)
	}
	// Newest retained times are :20, :30, :40. At 13:20 the older two
	// retained/discarded times have all expired, leaving exactly one slot.
	now = time.Date(2026, 10, 8, 13, 20, 0, 0, time.UTC)
	g = New(cfg)
	if !g.Reserve(false) || g.Reserve(false) {
		t.Fatal("trimmed debt changed available allowance")
	}
	now = now.Add(10 * time.Minute)
	g = New(cfg)
	if !g.Reserve(false) || g.Reserve(false) {
		t.Fatal("staggered expiry changed allowance")
	}
}

type pacingBadLoad struct{}

func (pacingBadLoad) Load() ([]byte, error) { return nil, errors.New("synthetic load canary") }
func (pacingBadLoad) Save([]byte) error     { panic("save after failed load") }

// REQ: CH-15
func TestDurablePacingRefusesFailedProvisioningAndLoad(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	cases := []Config{
		{Now: func() time.Time { return now }, PacingStore: pacingBadLoad{}},
		{Now: func() time.Time { return time.Time{} }, PacingStore: pacingBadLoad{}},
		{Now: func() time.Time { return now }, RequestsPerHour: maxPacingLimit + 1, PacingStore: pacingBadLoad{}},
		{Now: func() time.Time { return now }, PacingStore: &pacingCut{file: &change.FileStore{Path: filepath.Join(t.TempDir(), "pacing.json")}, fail: true}},
	}
	for _, cfg := range cases {
		g := New(cfg)
		if g.PacingHealth() != ErrPacingRecovery || g.Reserve(false) || g.take(false, 1) != 0 {
			t.Fatal("failed startup admitted")
		}
	}
	// Existing volatile callers retain their previously unlimited config range.
	g := New(Config{Now: func() time.Time { return now }, RequestsPerHour: maxPacingLimit + 1})
	if g.PacingHealth() != nil || !g.Reserve(false) {
		t.Fatal("legacy configuration changed")
	}
}

// REQ: CH-15
func TestDurablePacingRejectsInvalidCanonicalState(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "pacing.json")
	for _, mutate := range []func(*pacingState){
		func(s *pacingState) { s.Last = time.Time{} },
		func(s *pacingState) { s.Texts = []time.Time{time.Time{}} },
		func(s *pacingState) { s.Texts = []time.Time{now.Add(time.Second)} },
		func(s *pacingState) { s.Texts = []time.Time{now, now.Add(-time.Second)} },
		func(s *pacingState) { s.Texts = []time.Time{now, now, now, now} },
		func(s *pacingState) { s.Aged = now.Add(time.Second) },
	} {
		s := pacingState{Version: 1, Limit: 3, Last: now}
		mutate(&s)
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		if New(Config{Now: func() time.Time { return now }, RequestsPerHour: 3, PacingStore: &change.FileStore{Path: path}}).PacingHealth() != ErrPacingRecovery {
			t.Fatal("invalid state accepted")
		}
	}
}

type pacingBlockedSave struct {
	file             *change.FileStore
	block            bool
	entered, release chan struct{}
}

func (s *pacingBlockedSave) Load() ([]byte, error) { return s.file.Load() }
func (s *pacingBlockedSave) Save(b []byte) error {
	if s.block {
		close(s.entered)
		<-s.release
	}
	return s.file.Save(b)
}

// REQ: CH-15, CH-11
func TestDurablePacingBlockedSaveDoesNotDelayStopOrSendAfterStop(t *testing.T) {
	s := &pacingBlockedSave{file: &change.FileStore{Path: filepath.Join(t.TempDir(), "pacing.json")}, entered: make(chan struct{}), release: make(chan struct{})}
	r := newRig(t, func(c *Config) { c.PacingStore = s })
	it := owner.Item{Ref: "synthetic-request", Object: "synthetic", Recipient: "a@example.com", Facts: owner.Facts{Verb: "send"}}
	r.g.mu.Lock()
	r.g.waiting[it.Ref] = &wait{item: it, expires: r.now().Add(time.Hour)}
	r.g.batch = []string{it.Ref}
	r.g.mu.Unlock()
	s.block = true
	done := make(chan struct{})
	go func() { defer close(done); r.g.Flush() }()
	select {
	case <-s.entered:
	case <-time.After(time.Second):
		t.Fatal("save did not start")
	}
	stop := make(chan error, 1)
	go func() { _, err := r.eng.Stop(t.Context()); stop <- err }()
	select {
	case err := <-stop:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		close(s.release)
		t.Fatal("STOP waited for pacing I/O")
	}
	close(s.release)
	<-done
	if r.own.count() != 0 {
		t.Fatal("reissued request sent after STOP during durable reservation")
	}
	r.g.mu.Lock()
	defer r.g.mu.Unlock()
	if len(r.g.batch) != 1 {
		t.Fatal("stopped request lost")
	}
}
