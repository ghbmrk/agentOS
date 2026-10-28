package camera

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/clerk"
)

// storeRig is a capture store over a real sealed store (clerk.Secrets with
// a per-run synthetic sealing key), a manual clock and a captured log.
type storeRig struct {
	s       *Store
	secrets *clerk.Secrets
	dir     string
	clk     *clock
	log     *lines
}

func newStoreRig(t *testing.T, edit func(*StoreConfig)) *storeRig {
	t.Helper()
	k := make([]byte, 32)
	rand.Read(k)
	sealer, err := clerk.NewAESSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	r := &storeRig{
		secrets: clerk.NewSecrets(sealer, nil),
		dir:     filepath.Join(t.TempDir(), "capture"),
		clk:     &clock{t: time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)},
		log:     &lines{},
	}
	r.open(t, edit)
	return r
}

// open (re)opens the store on the rig's directory and keys, as a restart.
func (r *storeRig) open(t *testing.T, edit func(*StoreConfig)) {
	t.Helper()
	cfg := StoreConfig{Dir: r.dir, Keys: SecretsKeys(r.secrets), Now: r.clk.now, Log: r.log.add}
	if edit != nil {
		edit(&cfg)
	}
	s, err := NewStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.s = s
}

func (r *storeRig) feed(t *testing.T, camera string, n int, step time.Duration) {
	t.Helper()
	for i := 0; i < n; i++ {
		f := video()
		if i%2 == 1 {
			f = thermal()
		}
		if err := r.s.Frame(camera, f); err != nil {
			t.Fatal(err)
		}
		r.clk.add(step)
	}
}

// files lists every file under the store's directory and reads them all.
func (r *storeRig) files(t *testing.T) (names []string, all []byte) {
	t.Helper()
	filepath.WalkDir(r.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(r.dir, p)
		names = append(names, rel)
		all = append(all, b...)
		return nil
	})
	return names, all
}

func (r *storeRig) segments(t *testing.T, camera string) []Segment {
	t.Helper()
	segs, err := r.s.Segments(camera)
	if err != nil {
		t.Fatal(err)
	}
	return segs
}

// REQ: DEV-7, LOG-4
// TestNoRetentionWritesNothing: with no owner-set retention, continuous
// capture is held in the memory ring only and nothing is written, not even
// a key; the ring is bounded by frames and by bytes.
func TestNoRetentionWritesNothing(t *testing.T) {
	r := newStoreRig(t, func(c *StoreConfig) { c.RingFrames = 5 })
	if err := r.s.Add(testID, 0); err != nil {
		t.Fatal(err)
	}
	r.feed(t, testID, 40, time.Second)
	if err := r.s.Sweep(); err != nil {
		t.Fatal(err)
	}
	if err := r.s.Flush(); err != nil {
		t.Fatal(err)
	}
	if names, _ := r.files(t); len(names) != 0 {
		t.Fatalf("no retention wrote %q", names)
	}
	if r.secrets.Has(SegmentSlots + testID) {
		t.Fatal("no retention made a segment key")
	}
	got, err := r.s.Recent(testID)
	if err != nil || len(got) != 5 {
		t.Fatalf("ring holds %d frames (%v), want its cap of 5", len(got), err)
	}
	if !bytes.Contains(got[4].Frame.Payload, marker) || got[0].Time.After(got[4].Time) {
		t.Fatal("ring is not the latest frames, oldest first")
	}
	// The byte cap bounds it too.
	r = newStoreRig(t, func(c *StoreConfig) { c.RingBytes = 3 * len(video().Payload) })
	r.s.Add(testID, 0)
	for i := 0; i < 10; i++ {
		r.s.Frame(testID, video())
	}
	if got, _ := r.s.Recent(testID); len(got) != 3 {
		t.Fatalf("byte-capped ring holds %d frames, want 3", len(got))
	}
	// Recent hands copies: changing one changes nothing held.
	got, _ = r.s.Recent(testID)
	clear(got[0].Frame.Payload)
	if again, _ := r.s.Recent(testID); !bytes.Contains(again[0].Frame.Payload, marker) {
		t.Fatal("Recent shares the ring's bytes")
	}
	// Only video and thermal are capture; a status frame is refused.
	if err := r.s.Frame(testID, status()); !errors.Is(err, ErrFrame) {
		t.Fatalf("status frame: %v, want ErrFrame", err)
	}
	if err := r.s.Frame("garden", video()); !errors.Is(err, ErrUnknown) {
		t.Fatalf("frame for a camera not added: %v, want ErrUnknown", err)
	}
}

// REQ: DEV-7
// TestRetentionSweepDeletes: with a retention, segments are written and
// kept for it, and the sweep deletes each once its last frame is older.
// Removing the retention deletes what was kept, and its key.
func TestRetentionSweepDeletes(t *testing.T) {
	r := newStoreRig(t, func(c *StoreConfig) { c.SegmentSpan = 10 * time.Second })
	if err := r.s.Add(testID, time.Hour); err != nil {
		t.Fatal(err)
	}
	r.feed(t, testID, 30, time.Second) // three segments of ten seconds
	if n := len(r.segments(t, testID)); n != 2 {
		t.Fatalf("%d segments closed, want 2 (the third is open)", n)
	}
	r.clk.add(10 * time.Second)
	if err := r.s.Sweep(); err != nil { // closes the third, past its span
		t.Fatal(err)
	}
	segs := r.segments(t, testID)
	if len(segs) != 3 {
		t.Fatalf("%d segments after the sweep, want 3", len(segs))
	}
	recs, err := r.s.Open(testID, segs[0])
	if err != nil || len(recs) != 10 {
		t.Fatalf("first segment opens to %d frames (%v), want 10", len(recs), err)
	}
	// Until the oldest segment's last frame is an hour old, all stay.
	r.clk.t = segs[0].To.Add(time.Hour - time.Second)
	r.s.Sweep()
	if n := len(r.segments(t, testID)); n != 3 {
		t.Fatalf("%d segments inside the retention, want 3", n)
	}
	r.clk.t = segs[1].To.Add(time.Hour)
	if err := r.s.Sweep(); err != nil {
		t.Fatal(err)
	}
	if left := r.segments(t, testID); len(left) != 1 || left[0] != segs[2] {
		t.Fatalf("after expiry of two, left %v", left)
	}
	if !strings.Contains(r.log.all(), "camera porch: 2 segments deleted at the end of their retention") {
		t.Fatalf("no sweep line: %s", r.log.all())
	}
	// A shorter retention takes effect at once.
	if err := r.s.SetRetention(testID, time.Minute); err != nil {
		t.Fatal(err)
	}
	if n := len(r.segments(t, testID)); n != 0 {
		t.Fatalf("%d segments past a shortened retention", n)
	}
	// No retention: the open segment, the files and the key go.
	r.feed(t, testID, 3, time.Second)
	if err := r.s.SetRetention(testID, 0); err != nil {
		t.Fatal(err)
	}
	r.s.Flush()
	if names, _ := r.files(t); len(names) != 0 {
		t.Fatalf("retention removed, still on disk: %q", names)
	}
	if r.secrets.Has(SegmentSlots + testID) {
		t.Fatal("retention removed, key kept")
	}
	if err := r.s.SetRetention(testID, -time.Second); !errors.Is(err, ErrRetention) {
		t.Fatalf("negative retention: %v", err)
	}
}

// REQ: DEV-7, CLK-1, LOG-4
// TestSegmentsEncrypted: no captured byte is on disk in the clear; a
// segment opens only under its camera's key, by its own name, unaltered;
// and the store's log carries no captured byte.
func TestSegmentsEncrypted(t *testing.T) {
	r := newStoreRig(t, nil)
	r.s.Add(testID, 24*time.Hour)
	r.s.Add("garden", 24*time.Hour)
	r.feed(t, testID, 6, time.Second)
	r.feed(t, "garden", 2, time.Second)
	if err := r.s.Flush(); err != nil {
		t.Fatal(err)
	}
	names, all := r.files(t)
	if len(names) != 2 {
		t.Fatalf("files %q, want one segment per camera", names)
	}
	if bytes.Contains(all, marker) || bytes.Contains(all, marker[:8]) {
		t.Fatal("a captured byte is on disk in the clear")
	}
	if strings.Contains(r.log.all(), string(marker[:8])) {
		t.Fatal("a captured byte is in the log")
	}
	seg := r.segments(t, testID)[0]
	recs, err := r.s.Open(testID, seg)
	if err != nil || len(recs) != 6 {
		t.Fatalf("open: %d frames, %v", len(recs), err)
	}
	if recs[0].Frame.Type != camwire.TypeVideo || !bytes.Equal(recs[0].Frame.Payload, video().Payload) ||
		recs[1].Frame.Type != camwire.TypeThermal || !bytes.Equal(recs[1].Frame.Payload, thermal().Payload) {
		t.Fatal("segment does not open to the frames written")
	}
	path := filepath.Join(r.dir, testID, seg.Name)
	orig, _ := os.ReadFile(path)

	// One flipped bit does not open.
	bad := bytes.Clone(orig)
	bad[len(bad)-1] ^= 1
	os.WriteFile(path, bad, 0o600)
	if _, err := r.s.Open(testID, seg); !errors.Is(err, ErrSegment) {
		t.Fatalf("tampered segment: %v", err)
	}
	os.WriteFile(path, orig, 0o600)

	// Renamed to a later expiry, it does not open.
	later := strings.Replace(seg.Name, seg.Name[17:33], "7fffffffffffffff", 1)
	os.Rename(path, filepath.Join(r.dir, testID, later))
	if _, err := r.s.Open(testID, Segment{Name: later}); !errors.Is(err, ErrSegment) {
		t.Fatalf("renamed segment: %v", err)
	}
	os.Rename(filepath.Join(r.dir, testID, later), path)

	// Moved to another camera, it does not open under that camera's key.
	moved := filepath.Join(r.dir, "garden", seg.Name)
	os.Rename(path, moved)
	if _, err := r.s.Open("garden", seg); !errors.Is(err, ErrSegment) {
		t.Fatalf("segment moved to another camera: %v", err)
	}
	os.Rename(moved, path)

	// Without the camera's key nothing opens.
	r.secrets.Remove(SegmentSlots + testID)
	if _, err := r.s.Open(testID, seg); !errors.Is(err, ErrSegment) {
		t.Fatalf("segment without its key: %v", err)
	}
}

// REQ: DEV-7, DEV-10
// TestDisconnectErases: a disconnect destroys the camera's key, its
// segments, its open segment and its ring, and refuses its later frames;
// another camera's capture is untouched. A camera disconnected while the
// store was down is erased by the first sweep.
func TestDisconnectErases(t *testing.T) {
	r := newStoreRig(t, nil)
	r.s.Add(testID, 24*time.Hour)
	r.s.Add("garden", 24*time.Hour)
	r.feed(t, testID, 4, time.Second)
	r.feed(t, "garden", 4, time.Second)
	r.s.Flush()
	r.feed(t, testID, 2, time.Second) // an open segment
	if err := r.s.Erase(testID); err != nil {
		t.Fatal(err)
	}
	if r.secrets.Has(SegmentSlots + testID) {
		t.Fatal("disconnect kept the camera's key")
	}
	if _, err := os.Stat(filepath.Join(r.dir, testID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("disconnect kept the camera's segments: %v", err)
	}
	if _, err := r.s.Recent(testID); !errors.Is(err, ErrUnknown) {
		t.Fatalf("ring after disconnect: %v", err)
	}
	if err := r.s.Frame(testID, video()); !errors.Is(err, ErrUnknown) {
		t.Fatalf("frame after disconnect: %v", err)
	}
	r.s.Flush()
	if names, _ := r.files(t); len(names) != 1 || !strings.HasPrefix(names[0], "garden/") {
		t.Fatalf("after disconnect, on disk: %q", names)
	}
	if !r.secrets.Has(SegmentSlots + "garden") {
		t.Fatal("disconnect erased another camera's key")
	}

	// garden is disconnected while the store is down: on restart it is
	// not added, and the sweep erases its segments and key.
	r.open(t, nil)
	if err := r.s.Sweep(); err != nil {
		t.Fatal(err)
	}
	if names, _ := r.files(t); len(names) != 0 {
		t.Fatalf("after a restart without the camera, on disk: %q", names)
	}
	if r.secrets.Has(SegmentSlots + "garden") {
		t.Fatal("restart kept a disconnected camera's key")
	}
}

// REQ: DEV-7
// TestOnRequestDeletedAtTaskEnd: on-request capture is deleted at its
// task's end unless the owner set a retention; with one, what the task
// captured is written and kept.
func TestOnRequestDeletedAtTaskEnd(t *testing.T) {
	r := newStoreRig(t, nil)
	r.s.Add(testID, 0)
	r.feed(t, testID, 5, time.Second)
	if got, _ := r.s.Recent(testID); len(got) != 5 {
		t.Fatalf("ring during the task holds %d", len(got))
	}
	if err := r.s.EndTask(testID); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.s.Recent(testID); len(got) != 0 {
		t.Fatalf("ring after the task holds %d", len(got))
	}
	r.s.Flush()
	if names, _ := r.files(t); len(names) != 0 {
		t.Fatalf("task end left %q", names)
	}

	r = newStoreRig(t, nil)
	r.s.Add(testID, time.Hour)
	r.feed(t, testID, 5, time.Second)
	if err := r.s.EndTask(testID); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.s.Recent(testID); len(got) != 0 {
		t.Fatal("ring kept after the task")
	}
	segs := r.segments(t, testID)
	if len(segs) != 1 {
		t.Fatalf("retained task wrote %d segments, want 1", len(segs))
	}
	if recs, err := r.s.Open(testID, segs[0]); err != nil || len(recs) != 5 {
		t.Fatalf("retained task's segment: %d frames, %v", len(recs), err)
	}
}

// REQ: DEV-7
// TestRestartKeepsOnlyRetained: on a restart nothing from before survives
// without a retention: a camera whose retention is gone, a camera not
// added, a torn write's temporary and a file the store did not name are
// deleted; a retained camera's segments open again.
func TestRestartKeepsOnlyRetained(t *testing.T) {
	r := newStoreRig(t, nil)
	r.s.Add(testID, time.Hour)
	r.s.Add("garden", time.Hour)
	r.feed(t, testID, 3, time.Second)
	r.feed(t, "garden", 3, time.Second)
	r.s.Flush()
	os.WriteFile(filepath.Join(r.dir, testID, "x.seg.tmp"), []byte("torn"), 0o600)
	os.WriteFile(filepath.Join(r.dir, testID, "stray"), []byte("stray"), 0o600)
	os.Mkdir(filepath.Join(r.dir, "Not-An-ID"), 0o700)

	r.open(t, nil)
	r.s.Add(testID, time.Hour)
	r.s.Add("garden", 0)
	if err := r.s.Sweep(); err != nil {
		t.Fatal(err)
	}
	names, _ := r.files(t)
	if len(names) != 1 || !strings.HasPrefix(names[0], testID+"/") || !strings.HasSuffix(names[0], segExt) {
		t.Fatalf("after restart, on disk: %q", names)
	}
	if _, err := os.Stat(filepath.Join(r.dir, "Not-An-ID")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("restart kept a directory the store did not make")
	}
	if recs, err := r.s.Open(testID, r.segments(t, testID)[0]); err != nil || len(recs) != 3 {
		t.Fatalf("retained segment after restart: %d frames, %v", len(recs), err)
	}
}

// REQ: DEV-8
// TestSegmentWriteRateCapped: a camera writes no more than its rate over a
// minute; frames past it stay in the ring only, and the segment's log
// line counts them.
func TestSegmentWriteRateCapped(t *testing.T) {
	per := recHead + len(video().Payload)
	r := newStoreRig(t, func(c *StoreConfig) { c.WriteRate = 1 }) // 60 bytes a minute
	r.s.Add(testID, time.Hour)
	for i := 0; i < 10; i++ {
		r.s.Frame(testID, video())
	}
	r.s.Flush()
	segs := r.segments(t, testID)
	recs, err := r.s.Open(testID, segs[0])
	if err != nil || len(recs) != 60/per {
		t.Fatalf("capped segment holds %d frames (%v), want %d", len(recs), err, 60/per)
	}
	if got, _ := r.s.Recent(testID); len(got) != 10 {
		t.Fatalf("ring holds %d, want all 10", len(got))
	}
	if want := "; " + strconv.Itoa(10-60/per) + " frames over the write rate kept in memory only"; !strings.Contains(r.log.all(), want) {
		t.Fatalf("no count of capped frames: %s", r.log.all())
	}
	// The next minute writes again.
	r.clk.add(time.Minute)
	r.s.Frame(testID, video())
	r.s.Flush()
	if n := len(r.segments(t, testID)); n != 2 {
		t.Fatalf("%d segments after the window turned, want 2", n)
	}
}

// REQ: CLK-1
// TestSegmentKeyInSealedStore: each camera's segment key is a static
// device slot of the sealed store, made once, lent only per call, and
// never in a file under the store's directory or its log.
func TestSegmentKeyInSealedStore(t *testing.T) {
	r := newStoreRig(t, nil)
	r.s.Add(testID, time.Hour)
	var key []byte
	if err := SecretsKeys(r.secrets).Lend(testID, func(k []byte) error {
		key = bytes.Clone(k)
		return nil
	}); err != nil || len(key) != 32 {
		t.Fatalf("segment key slot: %d bytes, %v", len(key), err)
	}
	r.s.SetRetention(testID, 2*time.Hour) // Make keeps the key there is
	SecretsKeys(r.secrets).Lend(testID, func(k []byte) error {
		if !bytes.Equal(k, key) {
			t.Fatal("a second Make replaced the key, orphaning segments")
		}
		return nil
	})
	r.feed(t, testID, 4, time.Second)
	r.s.Flush()
	_, all := r.files(t)
	if bytes.Contains(all, key) || strings.Contains(r.log.all(), string(key)) {
		t.Fatal("the segment key is on disk or in the log")
	}
}
