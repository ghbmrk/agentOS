package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/privfile"
	"github.com/ghbmrk/agentos/broker/localapi"
)

// REV-CHK-save-owner (#4193): agentosd's saves (the lost-card request and
// shown files, the restart trigger, the plan holder key) are stopped after
// every step of their file write (privfile.WriteAtomic: 0 create the
// temporary, 1 write, 2 sync, 3 close, 4 rename, 5 sync the directory), as
// a crash would. agentosd keeps these in files only, so what the page is
// told next is what the disk holds: nothing new before the rename, the
// whole new file after it.

// stopAt is a write stop that ends the write after step.
func stopAt(step int) func(int) bool { return func(i int) bool { return i == step } }

// REQ: REC-4
// A lost-card tap whose request save is stopped answers unavailable. The
// page's next state read is the disk's: nothing filed and no restart
// offered (stopped before the rename), or the kernel's approval filed
// whole at this boot, so the restart is offered and the unlock step reads
// a whole approval. Either way a second tap files the request.
func TestLostCardRequestCrashDuringTheFileWrite(t *testing.T) {
	ctx := context.Background()
	for step := range 6 {
		r := newLostRig(t, "")
		r.l.stop = stopAt(step)
		b, err := r.l.LostBegin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		ad, cd, sig := r.anchors[0].get(t, b.Challenge)
		if err := r.l.Lost(ctx, ad, cd, sig); code(err) != localapi.ErrRecoveryUnavailable {
			t.Fatalf("step %d: a stopped filing answered %v", step, err)
		}
		st, err := r.l.LostState(ctx)
		if err != nil {
			t.Fatalf("step %d: state: %v", step, err)
		}
		if step < 4 {
			if st.Filed || r.filed() != nil {
				t.Fatalf("step %d: filed before the rename: %+v", step, st)
			}
			if err := r.l.Restart(ctx); code(err) != localapi.ErrRecoveryStale || r.reboots != 0 {
				t.Fatalf("step %d: a restart offered with nothing filed: %v", step, err)
			}
		} else {
			if !st.Filed || st.Ignored || !bytes.Equal(r.filed(), r.rk.approvals[0]) {
				t.Fatalf("step %d: the renamed request is not the whole approval: %+v %q", step, st, r.filed())
			}
		}
		r.l.stop = nil
		ad, cd, sig = r.anchors[0].get(t, b.Challenge)
		if err := r.l.Lost(ctx, ad, cd, sig); err != nil {
			t.Fatalf("step %d: a second tap: %v", step, err)
		}
		if n := len(r.rk.approvals); !bytes.Equal(r.filed(), r.rk.approvals[n-1]) {
			t.Fatalf("step %d: the second tap filed %q", step, r.filed())
		}
	}
}

// REQ: REC-4
// A shown card whose record save is stopped still reaches the page (the
// record only lets it name the card later). The next state read names no
// card (stopped before the rename) or the card shown, unconfirmed (after
// it); a confirm then records the one it wipes, and only that.
func TestLostCardShownCrashDuringTheFileWrite(t *testing.T) {
	ctx := context.Background()
	id := strings.Repeat("ab", 16)
	for step := range 6 {
		r := newLostRig(t, "")
		bits := r.hold(id, 0x3c)
		r.l.stop = stopAt(step)
		if got, err := r.show(0); err != nil || !bytes.Equal(got.Card, bits) {
			t.Fatalf("step %d: card %x %v", step, got.Card, err)
		}
		want := shown{}
		if step >= 4 {
			want = shown{ID: id}
		}
		if got := r.l.readShown(); got != want {
			t.Fatalf("step %d: shown record %+v, want %+v", step, got, want)
		}
		r.l.stop = nil
		must(t, r.l.LostDone(ctx))
		want.Confirmed = want.ID != ""
		if got := r.l.readShown(); got != want {
			t.Fatalf("step %d: after the confirm %+v, want %+v", step, got, want)
		}
	}
}

// REQ: REC-4
// A restart trigger whose write is stopped leaves no trigger (before the
// rename) or the whole empty one (after it); a second write succeeds over
// either, so a failed restart can be asked again.
func TestRestartTriggerCrashDuringTheFileWrite(t *testing.T) {
	for step := range 6 {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "agentos-recovery-restart")
		if err := writeTrigger(path, stopAt(step)); !errors.Is(err, privfile.ErrStopped) {
			t.Fatalf("step %d: got %v, want ErrStopped", step, err)
		}
		fi, err := os.Stat(path)
		switch {
		case step < 4 && !errors.Is(err, os.ErrNotExist):
			t.Fatalf("step %d: a trigger before the rename: %v", step, err)
		case step >= 4 && (err != nil || fi.Size() != 0):
			t.Fatalf("step %d: the renamed trigger: %v %v", step, fi, err)
		}
		if err := writeTrigger(path, nil); err != nil {
			t.Fatalf("step %d: a second write: %v", step, err)
		}
	}
}

// REQ: KEY-3, KEY-4
// The first start's holder key write stopped fails the start, so no plan
// is signed by a key the disk may not hold. The next start makes a key
// (stopped before the rename: no file, the temporary is never read) or
// reads the whole seed the stopped start wrote (after it); every later
// start reads that same key.
func TestPlanHolderCrashDuringTheFileWrite(t *testing.T) {
	for step := range 6 {
		path := filepath.Join(t.TempDir(), "plan-holder.key")
		if k, err := loadPlanHolderStop(path, stopAt(step)); !errors.Is(err, privfile.ErrStopped) || k != nil {
			t.Fatalf("step %d: got %v %v, want ErrStopped and no key", step, k != nil, err)
		}
		_, err := os.Stat(path)
		if (step < 4) != errors.Is(err, os.ErrNotExist) {
			t.Fatalf("step %d: holder file after the stop: %v", step, err)
		}
		h1, err := loadPlanHolder(path)
		if err != nil {
			t.Fatalf("step %d: the next start: %v", step, err)
		}
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() != ed25519.SeedSize {
			t.Fatalf("step %d: holder file %v %v", step, fi, err)
		}
		h2, err := loadPlanHolder(path)
		if err != nil || !h1.Equal(h2) {
			t.Fatalf("step %d: a later start read another key: %v", step, err)
		}
	}
}
