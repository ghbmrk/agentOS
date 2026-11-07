package owner

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// REV-CHK-save-owner (#4193): the owner's state save (FileStore.Save) is
// stopped after every step of its file write (privfile.WriteAtomic: 0
// create the temporary, 1 write, 2 sync, 3 close, 4 rename, 5 sync the
// directory), as a crash would. The channel keeps none of the stopped
// change in memory and tells the owner the code did not count; a restart
// then holds the old state whole (before the rename) or the new one whole
// (after it), never a mix.

// stopAt is a write stop that ends the write after step.
func stopAt(step int) func(int) bool { return func(i int) bool { return i == step } }

// REQ: CH-18
// A code-generator unlock whose save is stopped is refused with stateErr
// and leaves memory locked with the code unspent. Stopped before the
// rename, a restart is as before the code, so the same code then unlocks;
// stopped after it, a restart holds the whole new state: the code is
// spent and the session unlocked, so the code cannot be used again.
func TestOwnerStateSaveCrashDuringTheFileWrite(t *testing.T) {
	for step := range 6 {
		path := filepath.Join(t.TempDir(), "owner.json")
		r := newRig(t, FileStore{Path: path})
		r.unlock()
		r.advance(DefaultUnlockFor + time.Hour) // the unlock has lapsed
		if r.ch.codes.unlocked(r.clock()) {
			t.Fatalf("step %d: still unlocked after the lapse", step)
		}
		before := r.ch.codes.st

		r.store = FileStore{Path: path, stop: stopAt(step)}
		r.ch = r.open()
		code := r.totp()
		if got := r.say(code); got != stateErr {
			t.Fatalf("step %d: stopped unlock replied %q, want %q", step, got, stateErr)
		}
		if st := r.ch.codes.st; st.LastStep != before.LastStep || !st.UnlockedUntil.Equal(before.UnlockedUntil) {
			t.Fatalf("step %d: memory kept the stopped save: step %d until %v, want %d %v",
				step, st.LastStep, st.UnlockedUntil, before.LastStep, before.UnlockedUntil)
		}

		r.store = FileStore{Path: path}
		r.ch = r.open() // restart
		disk, err := FileStore{Path: path}.Load()
		if err != nil {
			t.Fatalf("step %d: load after the stop: %v", step, err)
		}
		if st := r.ch.codes.st; st.LastStep != disk.LastStep || !st.UnlockedUntil.Equal(disk.UnlockedUntil) {
			t.Fatalf("step %d: the restart's memory %+v is not the disk's %+v", step, st, disk)
		}
		if step < 4 {
			if disk.LastStep != before.LastStep || !disk.UnlockedUntil.Equal(before.UnlockedUntil) {
				t.Fatalf("step %d: the file changed before the rename: %+v", step, disk)
			}
			if got := r.say(code); !strings.HasPrefix(got, "Unlocked until") {
				t.Fatalf("step %d: the unspent code after a restart: %q", step, got)
			}
			continue
		}
		if disk.LastStep <= before.LastStep || !r.ch.codes.unlocked(r.clock()) {
			t.Fatalf("step %d: the renamed file is not the whole new state: %+v", step, disk)
		}
		spent := disk.LastStep
		r.say(code)
		if r.ch.codes.st.LastStep != spent {
			t.Fatalf("step %d: the spent code was taken again", step)
		}
	}
}
