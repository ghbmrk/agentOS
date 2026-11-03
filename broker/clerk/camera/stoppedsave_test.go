package camera

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// REQ: DEV-7, CLK-1
// TestASegmentWriteStoppedAtEveryStep: a segment write stopped after any
// privfile.WriteAtomic step, as a crash would (REV-CHK-save, #4191), is
// refused, and its frames are not kept in memory past it: on the running
// store, the next segment opens to its own frames only. The restarted
// store lists the stopped segment only from the write's rename (step 4)
// on, opening whole to its frames; the temporary a stop leaves lists as
// none, and the next segment writes.
func TestASegmentWriteStoppedAtEveryStep(t *testing.T) {
	for i := 0; i < 6; i++ {
		r := newStoreRig(t, nil)
		if err := r.s.Add(testID, 24*time.Hour); err != nil {
			t.Fatal(err)
		}
		r.s.writeStop = func(j int) bool { return j == i }
		r.feed(t, testID, 4, time.Second)
		if err := r.s.Flush(); !errors.Is(err, ErrWrite) {
			t.Fatalf("stopped after step %d: %v, want %v", i, err, ErrWrite)
		}
		if i < 4 && !strings.Contains(r.log.all(), "segment not written") {
			t.Fatalf("stopped after step %d: the log says %q", i, r.log.all())
		}

		want := 0
		if i >= 4 {
			want = 1
		}

		// The running store: the next segment holds its own frames only,
		// from its own first frame on (#4236).
		r.s.writeStop = nil
		next := r.clk.now()
		r.feed(t, testID, 2, time.Second)
		if err := r.s.Flush(); err != nil {
			t.Fatalf("running store, write after a stop at step %d: %v", i, err)
		}
		segs := r.segments(t, testID)
		if len(segs) != want+1 {
			t.Fatalf("running store, stopped after step %d: %d segments, want %d", i, len(segs), want+1)
		}
		recs, err := r.s.Open(testID, segs[len(segs)-1])
		if err != nil || len(recs) != 2 {
			t.Fatalf("running store, stopped after step %d: the next segment opens to %d frames, %v; want its own 2", i, len(recs), err)
		}
		for _, rec := range recs {
			if rec.Time.Before(next) {
				t.Fatalf("running store, stopped after step %d: the next segment holds a frame from %v, before its own first at %v", i, rec.Time, next)
			}
		}
		want++

		r.open(t, nil) // the restarted store
		if err := r.s.Add(testID, 24*time.Hour); err != nil {
			t.Fatal(err)
		}
		segs = r.segments(t, testID)
		if len(segs) != want {
			t.Fatalf("stopped after step %d: restarted with %d segments, want %d", i, len(segs), want)
		}
		for j, seg := range segs {
			n := 4
			if j == len(segs)-1 {
				n = 2
			}
			if recs, err := r.s.Open(testID, seg); err != nil || len(recs) != n {
				t.Fatalf("stopped after step %d: segment %d opens to %d frames, %v; want %d", i, j, len(recs), err, n)
			}
		}

		r.feed(t, testID, 2, time.Second)
		if err := r.s.Flush(); err != nil {
			t.Fatalf("write after a stop at step %d: %v", i, err)
		}
		segs = r.segments(t, testID)
		if len(segs) != want+1 {
			t.Fatalf("after the next write: %d segments, want %d", len(segs), want+1)
		}
		if recs, err := r.s.Open(testID, segs[len(segs)-1]); err != nil || len(recs) != 2 {
			t.Fatalf("the next segment opens to %d frames, %v", len(recs), err)
		}
	}
}
