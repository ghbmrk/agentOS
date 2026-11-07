package update

// REQ: UPD-5, HLD-3

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// REV-CHK-save (#4192): a record save that stops before its rename, as a
// crash would, returns no verdict and leaves the record as it was: a passing
// candidate is not passed and no floor is written, and a security failure
// whose mark was not saved still holds in this process, so a clean retry on
// the same suite does not pass.
func TestStoppedRecordSaveHoldsTheRelease(t *testing.T) {
	for step := 0; step < 4; step++ {
		f, v := ordinary(t, Options{})
		path := filepath.Join(f.dir, "requal.json")
		q := requalifier(t, f, passing())
		q.saveStop = func(i int) bool { return i == step }
		if got, err := q.Requalify(context.Background(), v); !errors.Is(err, privfile.ErrStopped) || got.Passed {
			t.Fatalf("step %d: passing candidate on a stopped save: %+v, %v", step, got, err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("step %d: a stopped save left a record: %v", step, err)
		}

		r := passing()
		r.cand[SuiteSecurity] = sc(SuiteSecurity, 40, 39)
		q = requalifier(t, f, r)
		q.saveStop = func(i int) bool { return i == step }
		if _, err := q.Requalify(context.Background(), v); !errors.Is(err, privfile.ErrStopped) {
			t.Fatalf("step %d: failing candidate on a stopped save: %v", step, err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("step %d: a stopped mark left a record: %v", step, err)
		}
		q.saveStop = nil
		r.cand[SuiteSecurity] = sc(SuiteSecurity, 40, 40)
		if got, err := q.Requalify(context.Background(), v); err != nil || got.Passed {
			t.Fatalf("step %d: clean retry after a stopped mark: %+v, %v; want not passed", step, got, err)
		}
	}
}
