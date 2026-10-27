package loops

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
	"github.com/ghbmrk/agentos/broker/loops/loopstest"
)

// REQ: HLD-4, KEY-6, RES-5
//
// A settings save that put the new state in place but failed only at the
// directory sync (privfile.ErrUnsynced, #1320) is what a restart loads, so
// the setting is applied and logged. A save that failed before that rolls
// back only a widening: a narrowing stays in effect (KEY-6), unsaved.

// saveFails stores and then fails at the directory sync, as
// privfile.WriteAtomic does after the rename, or (early) fails before
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
	return fmt.Errorf("%w: sync /var/lib/agentos: input/output error", privfile.ErrUnsynced)
}

func TestAnUnsyncedSaveCountsAsApplied(t *testing.T) {
	r := newRig(t)
	var logged []string
	r.s.cfg.Logf = func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }
	r.s.cfg.Store = &saveFails{MemStore: r.store}
	if got, ok := r.s.Text(context.Background(), "LOOP 1 OFF", true); !ok || got != "Learning is off until you reply LEARNING ON." {
		t.Fatalf("an unsynced setting reported failed: %q %v", got, ok)
	}
	if r.s.Settings().On(Improve) {
		t.Fatal("unsynced LOOP 1 OFF rolled back in memory")
	}
	if len(logged) == 0 || strings.Contains(strings.Join(logged, "\n"), "/var/") {
		t.Fatalf("logged %q", logged)
	}
	r.restart()
	if r.s.Settings().On(Improve) {
		t.Fatal("LOOP 1 OFF lost on restart")
	}
}

func TestAFailedSaveRollsBackOnlyAWidening(t *testing.T) {
	ctx := context.Background()
	one := SpareCap(1, loopstest.OutPerM)
	for _, passkey := range []bool{false, true} {
		t.Run(fmt.Sprintf("passkey %v", passkey), func(t *testing.T) {
			r := newRig(t)
			var asked atomic.Int32
			widen := r.spare.Widen
			r.spare.Widen = func(n int64) (key.Key, error) { asked.Add(1); return widen(n) }
			if !passkey {
				r.spare.Widen = nil
			}
			must(t, r.s.Set(ctx, Request{Kind: KindBudget, Calls: 100}, true))
			must(t, r.s.Set(ctx, Request{Kind: KindLoops, Loop: Secure}, true))
			bad := &saveFails{MemStore: r.store, early: true}
			r.s.cfg.Store = bad

			// Widenings that fail to save leave everything as it was.
			if passkey {
				if got, _ := r.s.Text(ctx, "SPARE BUDGET 400", true); got != "I could not save that setting. Try again later." {
					t.Fatalf("an unsaved raise: %q", got)
				}
				if asked.Load() != 1 {
					t.Fatalf("passkey asked %d times", asked.Load())
				}
			} else if got, _ := r.s.Text(ctx, "SPARE BUDGET 400", true); !strings.Contains(got, "passkey") {
				t.Fatalf("a raise with no passkey: %q", got)
			}
			if r.s.Settings().SpareCalls != 100 || r.spare.Cap() != SpareCap(100, loopstest.OutPerM) || capOf(t, r.spare.Key()) != SpareCap(100, loopstest.OutPerM) {
				t.Fatalf("a raise that did not save: budget %d, cap %d", r.s.Settings().SpareCalls, r.spare.Cap())
			}
			for _, msg := range []string{"LOOP 2 ON", "UPDATES FAST"} {
				if got, _ := r.s.Text(ctx, msg, true); got != "I could not save that setting. Try again later." {
					t.Fatalf("%s unsaved: %q", msg, got)
				}
			}
			if set := r.s.Settings(); set.On(Secure) || set.Updates.ChannelName() != ChannelStable {
				t.Fatalf("an unsaved widening stayed: %+v", set)
			}

			// Narrowings that fail to save stand, and say they lapse on
			// restart.
			before := asked.Load()
			old := r.spare.Key()
			if got, _ := r.s.Text(ctx, "SPARE BUDGET 20", false); !strings.HasSuffix(got, unsavedReply) {
				t.Fatalf("an unsaved lower: %q", got)
			}
			if r.s.Settings().SpareCalls != 20 || r.spare.Cap() != SpareCap(20, loopstest.OutPerM) {
				t.Fatalf("an unsaved lower rolled back: budget %d, cap %d", r.s.Settings().SpareCalls, r.spare.Cap())
			}
			if rf := r.kern.Call(old, one); rf == nil {
				t.Fatal("a key at the old cap is live after an unsaved lower")
			}
			if got, _ := r.s.Text(ctx, "LOOPS OFF", false); !strings.HasSuffix(got, unsavedReply) || !r.s.Settings().Off {
				t.Fatalf("an unsaved LOOPS OFF: %q, %+v", got, r.s.Settings())
			}
			if asked.Load() != before {
				t.Fatal("a narrowing asked the passkey")
			}
		})
	}
}
