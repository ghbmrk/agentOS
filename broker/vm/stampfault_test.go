package vm

// REQ: RES-2, A2

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
)

// TestStampLegacyWriteFault: a failed stamp write at the upgrade load fails
// Open (#1659, #1575 Potency P-R1). Kept only in memory, a stamp would be
// decided afresh at the next load, after the machine of its ID may have
// been destroyed and replaced, and the successor would get its
// predecessor's snapshot (security S-N1 on #1575).
func TestStampLegacyWriteFault(t *testing.T) {
	bg := context.Background()
	e := newEnv(t, 4096)
	e.create("exp", admission.Experiment, 500)
	e.guestWrite("exp", "who", "predecessor")
	var snaps []Snapshot
	for range 2 {
		s, err := e.m.Checkpoint(bg, "exp")
		must(t, err)
		s.Instance = "" // recorded before Instance
		must(t, writeJSON(filepath.Join(e.m.snapDir(s.ID), "meta.json"), s))
		snaps = append(snaps, s)
	}
	e.adm.Release("exp")

	restore := failSave(filepath.Join(e.m.snapDir(snaps[1].ID), "meta.json"))
	if _, err := Open(bg, e.cfg); err == nil {
		t.Fatal("Open succeeded although a stamp write failed")
	}
	restore()

	e.open() // the load decides again, with the same persisted machines
	w, err := e.m.Get("exp")
	must(t, err)
	for _, s := range snaps {
		var disk Snapshot
		must(t, readJSON(filepath.Join(e.m.snapDir(s.ID), "meta.json"), &disk))
		if disk.Instance != w.Instance {
			t.Errorf("snapshot %s stamped %q on disk, want the machine's %q", s.ID, disk.Instance, w.Instance)
		}
	}

	must(t, e.m.Destroy(bg, "exp"))
	e.create("exp", admission.Experiment, 500)
	e.guestWrite("exp", "who", "successor")
	e.adm.Release("exp")
	e.open() // stamped on disk before the destroy: not the successor's now
	for _, s := range snaps {
		if err := e.m.Rollback(bg, "exp", s.ID); !errors.Is(err, ErrLineage) {
			t.Errorf("successor's rollback to the predecessor's snapshot %s: %v, want ErrLineage", s.ID, err)
		}
	}
	if got := e.guestRead("exp", "who"); got != "successor" {
		t.Errorf("who = %q, want the successor's", got)
	}
}
