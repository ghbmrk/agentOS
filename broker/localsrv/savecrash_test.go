package localsrv

import (
	"fmt"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/privfile"
	"github.com/ghbmrk/agentos/broker/localapi"
)

// REV-CHK-save-owner (#4193): the setup record's save (FileRecord.Save) is
// stopped after every step of its file write (privfile.WriteAtomic: 0
// create the temporary, 1 write, 2 sync, 3 close, 4 rename, 5 sync the
// directory), as a crash would. Setup keeps none of the stopped change in
// memory and answers failed; a restart then holds the old record whole
// (before the rename) or the new one whole (after it).

// stopAt is a write stop that ends the write after step.
func stopAt(step int) func(int) bool { return func(i int) bool { return i == step } }

// REQ: ONB-3, ONB-6
// A finish whose record save is stopped answers failed, names no owner and
// leaves setup open in memory. After a restart, setup is still open and a
// second finish names the owner (stopped before the rename), or the record
// is finished whole: setup is closed for good and the restart's record
// names the owner, which agentosd's start carries out (setupMode.run).
func TestFinishCrashDuringTheRecordWrite(t *testing.T) {
	const owner = "+15550100100"
	for step := range 6 {
		r := newSetupRig(t)
		r.enrollAndConfirm()
		r.s.cfg.Record = FileRecord{Path: r.path, stop: stopAt(step)}
		if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: owner}, nil); code(err) != localapi.ErrFailed {
			t.Fatalf("step %d: stopped finish answered %v", step, err)
		}
		if _, ok := r.s.Owner(); ok || len(r.finished) != 0 {
			t.Fatalf("step %d: memory kept the stopped finish (finished %v)", step, r.finished)
		}
		if err := r.call(localapi.OpSetupProgress, nil, nil); err != nil {
			t.Fatalf("step %d: setup closed in memory after a stopped finish: %v", step, err)
		}

		r.start() // restart
		rec, err := FileRecord{Path: r.path}.Load()
		if err != nil {
			t.Fatalf("step %d: load after the stop: %v", step, err)
		}
		if step >= 4 {
			if !rec.Finished || rec.Owner != owner {
				t.Fatalf("step %d: the renamed record is not the whole finish: %+v", step, rec)
			}
			if got, ok := r.s.Owner(); !ok || got != owner {
				t.Fatalf("step %d: the restart does not name the owner: %q %v", step, got, ok)
			}
			if err := r.call(localapi.OpSetupProgress, nil, nil); code(err) != localapi.ErrSetupClosed {
				t.Fatalf("step %d: setup open after a restart on a finished record: %v", step, err)
			}
			continue
		}
		if rec.Finished {
			t.Fatalf("step %d: the record finished before the rename: %+v", step, rec)
		}
		if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: owner}, nil); err != nil {
			t.Fatalf("step %d: finish after the restart: %v", step, err)
		}
		if got, ok := r.s.Owner(); !ok || got != owner || len(r.finished) != 1 {
			t.Fatalf("step %d: finish after the restart named %q %v (finished %v)", step, got, ok, r.finished)
		}
	}
}

// unsyncedRecord is a FileRecord whose saves land on disk but report that
// the directory sync failed (privfile.ErrUnsynced).
type unsyncedRecord struct{ FileRecord }

func (u unsyncedRecord) Save(rec SetupRecord) error {
	if err := u.FileRecord.Save(rec); err != nil {
		return err
	}
	return fmt.Errorf("%w: synthetic", privfile.ErrUnsynced)
}

// REQ: ONB-3, ONB-6
// A finish whose record save fails only at the directory sync (#4971)
// renamed the finished record into place, so it counts: it answers ok,
// names the owner and closes setup in memory, as the file and a restart do.
func TestFinishUnsyncedKeepsMemoryEqualToTheRecord(t *testing.T) {
	const owner = "+15550100100"
	r := newSetupRig(t)
	r.enrollAndConfirm()
	r.s.cfg.Record = unsyncedRecord{FileRecord{Path: r.path}}
	if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: owner}, nil); err != nil {
		t.Fatalf("unsynced finish answered %v", err)
	}
	if got, ok := r.s.Owner(); !ok || got != owner || len(r.finished) != 1 {
		t.Fatalf("memory does not hold the finish: %q %v (finished %v)", got, ok, r.finished)
	}
	if err := r.call(localapi.OpSetupProgress, nil, nil); code(err) != localapi.ErrSetupClosed {
		t.Fatalf("setup open in memory after an unsynced finish: %v", err)
	}
	if rec, err := (FileRecord{Path: r.path}).Load(); err != nil || !rec.Finished || rec.Owner != owner {
		t.Fatalf("the record is not the finish: %+v %v", rec, err)
	}
}
