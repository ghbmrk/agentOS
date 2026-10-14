package loops

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/durable"
)

// REQ: OP-4, LOOP-0
//
// A settings save that published the new state but failed only at the
// directory sync (#1320) is what a restart loads, so the setting is
// applied and reported so; a save that failed before publishing still
// rolls back.

// saveFails stores and then fails at the directory sync, as
// durable.WriteFile does after the rename, or (early) fails before
// storing anything.
type saveFails struct {
	*change.MemStore
	early bool
}

func (f *saveFails) Save(b []byte) error {
	if f.early {
		return errors.New("write /var/lib/agentos/loops.json: no space left on device")
	}
	if err := f.MemStore.Save(b); err != nil {
		return err
	}
	return fmt.Errorf("%w: sync /var/lib/agentos: input/output error", durable.ErrDirSync)
}

func TestPublishedSettingIsReportedApplied(t *testing.T) {
	r := newRig(t)
	var logged []string
	r.s.cfg.Logf = func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }
	r.s.cfg.Store = &saveFails{MemStore: r.store}
	req, _ := ParseText("LOOP 1 OFF")
	if err := r.s.Set(context.Background(), req); err != nil {
		t.Fatalf("published setting reported failed: %v", err)
	}
	if r.s.Settings().On(Improve) {
		t.Fatal("published LOOP 1 OFF rolled back in memory")
	}
	if len(logged) == 0 || strings.Contains(strings.Join(logged, "\n"), "/var/") {
		t.Fatalf("logged %q", logged)
	}
	r.restart()
	if r.s.Settings().On(Improve) {
		t.Fatal("LOOP 1 OFF lost on restart")
	}
}

func TestUnpublishedSettingStillRollsBack(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	req, _ := ParseText("LOOP 1 OFF")
	must(t, r.s.Set(ctx, req))
	// Fail only the setting's own save: Set's sequence save goes first.
	bad := &saveFails{MemStore: r.store}
	r.s.cfg.Store = bad
	r.s.mu.Lock()
	r.s.st.Seq++
	r.s.mu.Unlock()
	bad.early = true
	req, _ = ParseText("LOOP 1 ON")
	if err := r.s.Set(ctx, req); err == nil {
		t.Fatal("an unsaved setting reported applied")
	}
	if r.s.Settings().On(Improve) {
		t.Fatal("an unsaved LOOP 1 ON stayed in memory")
	}
	r.restart()
	if r.s.Settings().On(Improve) {
		t.Fatal("an unsaved LOOP 1 ON took effect on restart")
	}
}
