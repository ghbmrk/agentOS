package cleanroom

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/hint"
)

// ErrHint marks a hint the clean room refuses: not the exact canonical
// form of a valid hint of the public schema.
var ErrHint = errors.New("cleanroom: not a canonical hint")

// ErrFull is returned when a batch would take the queue past MaxQueue.
var ErrFull = errors.New("cleanroom: job queue is full")

// job is one hint waiting for, or running in, a clean room.
type job struct {
	ID       string `json:"id"`
	Hint     string `json:"hint"` // canonical form, as received
	Day      string `json:"day"`  // UTC day received
	Attempts int    `json:"attempts"`

	path string
}

// wire is the canonical hint as the emitter writes it (hint.Canonical).
type wire struct {
	Schema  int               `json:"schema"`
	Kind    string            `json:"kind"`
	Embargo bool              `json:"embargo"`
	Fields  map[string]string `json:"fields"`
}

// parseCanonical accepts only the exact bytes the public schema's Canonical
// produces for a valid hint: anything else (another schema version, key
// order, spacing, escapes, an embargo mark the schema does not give the
// kind) is refused, so nothing but the choice of hint reaches a clean room.
func parseCanonical(s *hint.Schema, b []byte) (hint.Hint, bool, error) {
	var w wire
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return hint.Hint{}, false, ErrHint
	}
	h := hint.Hint{Kind: w.Kind, Fields: w.Fields}
	c, err := s.Canonical(h)
	if err != nil || !bytes.Equal(c, b) {
		return hint.Hint{}, false, ErrHint
	}
	return h, w.Embargo, nil
}

// Send takes one day's batch of canonical hints from the emitter
// (hint.Outbox). Every hint is checked before any is queued, and the batch
// is queued by one rename, so it is taken whole or not at all and the
// emitter can resend a refused batch. Send is idempotent by day, as the
// emitter requires: a day already taken is acknowledged and not queued
// again. A hint identical to one queued or already built is coalesced into
// it rather than built twice.
func (b *Builder) Send(day string, batch [][]byte) error {
	if t, err := time.Parse("2006-01-02", day); err != nil || t.Format("2006-01-02") != day {
		return fmt.Errorf("%w: day %q", ErrHint, clip(day, 16))
	}
	for _, c := range batch {
		if _, _, err := parseCanonical(b.cfg.Schema, c); err != nil {
			return err
		}
	}
	b.qmu.Lock()
	defer b.qmu.Unlock()
	marker := filepath.Join(b.cfg.Dir, "days", day)
	sum := batchSum(batch)
	if got, err := os.ReadFile(marker); err == nil {
		if len(got) == 0 {
			// A marker from before batch hashes: acknowledge, record the hash.
			return writeFile(marker, []byte(sum))
		}
		if string(got) != sum {
			// The emitter resends a day's recorded bytes; anything else
			// for a day already taken is refused, never dropped silently.
			b.cfg.Logf("cleanroom: a different batch for %s, already taken, was refused", day)
			return fmt.Errorf("%w: %s", ErrDayTaken, day)
		}
		return nil
	}
	if _, err := os.Stat(filepath.Join(b.queueDir(), day)); err == nil {
		return writeFile(marker, []byte(sum)) // queued before a crash took the marker
	}
	b.pruneDays(day)
	jobs, err := b.queued()
	if err != nil {
		return err
	}
	have := map[string]into{} // canonical hint -> what it coalesces into
	for _, j := range jobs {
		have[j.Hint] = into{desc: "job " + j.ID}
	}
	built, err := b.store.list(func(Manifest) bool { return true })
	if err != nil {
		return err
	}
	for _, a := range built {
		have[string(a.m.Hint)] = into{desc: a.m.ID, artifact: a.m.ID}
	}
	for _, j := range b.parked() {
		have[j.Hint] = into{desc: "parked job " + j.ID}
	}
	var fresh [][]byte
	var merged []Outcome
	for _, c := range batch {
		if in, ok := have[string(c)]; ok {
			h, _, _ := parseCanonical(b.cfg.Schema, c)
			merged = append(merged, Outcome{Day: day, Kind: h.Kind, Result: "coalesced", Reason: "same hint as " + in.desc, Artifact: in.artifact})
			continue
		}
		have[string(c)] = into{desc: "this batch"}
		fresh = append(fresh, c)
	}
	if len(jobs)+len(fresh) > b.cfg.MaxQueue {
		return ErrFull
	}
	if len(fresh) > 0 {
		tmp, err := os.MkdirTemp(b.cfg.Dir, "incoming-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		for i, c := range fresh {
			j := job{ID: newID(), Hint: string(c), Day: day}
			if err := writeJSON(filepath.Join(tmp, fmt.Sprintf("%04d-%s.json", i, j.ID)), j); err != nil {
				return err
			}
		}
		// Batch directories are named by day, so they sort by day.
		if err := os.Rename(tmp, filepath.Join(b.queueDir(), day)); err != nil {
			return err
		}
		if err := faultFn(nil).dirSync(b.queueDir()); err != nil {
			return err
		}
	}
	if err := writeFile(marker, []byte(sum)); err != nil {
		return err
	}
	for _, o := range merged {
		o.Job = "-"
		if err := b.logOutcome(o); err != nil {
			return err
		}
	}
	select {
	case b.wake <- struct{}{}:
	default:
	}
	return nil
}

// ErrDayTaken is returned for a batch that differs from the one already
// taken for its day.
var ErrDayTaken = errors.New("cleanroom: a different batch for a day already taken")

// daysKept is how long a day's record is kept: far past any resend, which
// comes at the emitter's next release after a failure.
const daysKept = 60

// batchSum identifies a batch's exact bytes.
func batchSum(batch [][]byte) string {
	h := sha256.New()
	for _, c := range batch {
		fmt.Fprintf(h, "%d:", len(c))
		h.Write(c)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// into is what a repeated hint coalesces into: a description for the log,
// and the artifact when it is one.
type into struct{ desc, artifact string }

// pruneDays drops day records more than daysKept days before day.
// Age is measured from the incoming day, not the clock.
func (b *Builder) pruneDays(day string) {
	t, _ := time.Parse("2006-01-02", day)
	cut := t.AddDate(0, 0, -daysKept).Format("2006-01-02")
	ents, _ := os.ReadDir(filepath.Join(b.cfg.Dir, "days"))
	for _, e := range ents {
		if e.Name() < cut {
			os.Remove(filepath.Join(b.cfg.Dir, "days", e.Name()))
		}
	}
}

func (b *Builder) queueDir() string { return filepath.Join(b.cfg.Dir, "queue") }

// queued lists waiting jobs, oldest batch first, in batch order.
func (b *Builder) queued() ([]*job, error) {
	batches, err := os.ReadDir(b.queueDir())
	if err != nil {
		return nil, err
	}
	var out []*job
	for _, d := range batches {
		if !d.IsDir() {
			continue
		}
		dir := filepath.Join(b.queueDir(), d.Name())
		ents, err := os.ReadDir(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(ents) == 0 {
			os.Remove(dir)
			continue
		}
		sort.Slice(ents, func(i, k int) bool { return ents[i].Name() < ents[k].Name() })
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			j := &job{}
			p := filepath.Join(dir, e.Name())
			if err := readJSON(p, j); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return nil, err
			}
			j.path = p
			out = append(out, j)
		}
	}
	return out, nil
}

func newID() string {
	var r [6]byte
	if _, err := rand.Read(r[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(r[:])
}

func writeJSON(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeFile(path, data)
}

// writeFile writes data durably: a synced temporary file renamed into place.
func writeFile(path string, data []byte) error { return writeFileWith(nil, path, data) }

func writeFileWith(fault faultFn, path string, data []byte) error {
	tmp := path + ".tmp"
	if err := writeSynced(fault, tmp, data); err != nil {
		return err
	}
	if err := fault.hit("rename", path); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return fault.dirSync(filepath.Dir(path))
}

// writeSynced creates path with data and syncs it.
func writeSynced(fault faultFn, path string, data []byte) error {
	if err := fault.hit("write", path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := fault.fileSync(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// faultFn, when set (tests only), is told of each file operation before it
// runs and may fail it.
type faultFn func(op, path string) error

func (f faultFn) hit(op, path string) error {
	if f == nil {
		return nil
	}
	return f(op, path)
}

// syncFile and syncDirFn make the package's only fsyncs, called only
// through fileSync and dirSync. Tests replace them with recorders that call
// the originals, so a test sees the syncs that ran, not only the hook
// (SR3-8-f2).
var (
	syncFile  = (*os.File).Sync
	syncDirFn = syncDir
)

// fileSync runs the hook, then syncs file. Every durable file sync goes
// through here.
func (f faultFn) fileSync(file *os.File) error {
	if err := f.hit("sync", file.Name()); err != nil {
		return err
	}
	return syncFile(file)
}

// dirSync runs the hook, then syncs dir. Every durable directory sync goes
// through here.
func (f faultFn) dirSync(dir string) error {
	if err := f.hit("syncdir", dir); err != nil {
		return err
	}
	return syncDirFn(dir)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
