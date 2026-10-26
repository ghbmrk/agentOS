package backup

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// entry is one live subject's data key in a key table. It is bound to its
// subject by the table's seal, never wrapped under the log key.
type entry struct {
	Subject string            `json:"subject"`
	Key     kernel.SubjectKey `json:"key"`
}

type table struct {
	BackupID   string  `json:"backup_id"`
	Generation uint64  `json:"generation"`
	Entries    []entry `json:"entries"`
}

const maxTable = 64 << 20

var (
	// ErrLiveKeyMissing is a live subject whose key the table does not
	// give: a backup without it would lose that subject's content.
	ErrLiveKeyMissing = errors.New("backup: a live subject's data key is missing")
	ErrNotEmpty       = errors.New("backup: the restore key table is not empty")
	ErrOtherBackup    = errors.New("backup: the key table belongs to another backup")
)

// live reports whether the log names subject and has not erased it.
func live(state Recaller, subject string) bool {
	r, ok := state.Recall(subject)
	return ok && !r.Erased
}

// liveEntries reads the key of each listed subject the log names and has
// not erased. An erased subject is left out even while its key delete is
// still owed, and a key no subject.opened names is left out too.
func liveEntries(subjects []string, keys kernel.Keys, state Recaller) ([]entry, error) {
	subjects = slices.Sorted(slices.Values(subjects))
	var out []entry
	for _, sub := range slices.Compact(subjects) {
		if !live(state, sub) {
			continue
		}
		k, ok, err := keys.Get(sub)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrLiveKeyMissing, sub, err)
		}
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrLiveKeyMissing, sub)
		}
		out = append(out, entry{sub, k})
	}
	return out, nil
}

func entrySubjects(es []entry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Subject
	}
	return out
}

// sealTable seals a key table to r: each seal is a fresh per-backup key.
func sealTable(r Recipient, id [idLen]byte, gen uint64, es []entry) ([]byte, error) {
	if es == nil {
		es = []entry{}
	}
	pt, err := json.Marshal(table{BackupID: hex.EncodeToString(id[:]), Generation: gen, Entries: es})
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := sealTo(&buf, r, header{kind: KindKeyTable, backupID: id, gen: gen})
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(pt); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Result names what a Rewrap did.
type Result int

const (
	// Unchanged: no listed subject was erased and the target lists only
	// the current table; nothing was written.
	Unchanged Result = iota
	// Rewrote: the target now lists only a table without the erased
	// subjects (a new one, confirmed by read-back, or the current one with
	// its strays deleted).
	Rewrote
	// The rest mean the backup may still hold an erased subject's key.
	AppendOnly       // the target cannot delete; nothing was written
	Offline          // a list, put or read-back failed
	ReadBackMismatch // the table read back is not what was put
	OldNotDeleted    // the new table is up, but an older one remains
	LiveKeyMissing   // refused: a live subject's key is missing
)

func (r Result) String() string {
	return [...]string{"unchanged", "rewrote", "append-only", "offline", "read-back-mismatch",
		"old-not-deleted", "live-key-missing"}[r]
}

// Outcome is a Rewrap's result, and the error behind it if any.
type Outcome struct {
	Result Result
	Err    error
}

// Rewrap re-seals rec's key table at t without the subjects erased since
// (D-168). The new table holds rec.Subjects that are still live, with
// their keys from the live table, sealed fresh to rec.Recipient (so a
// backup from before a recovery-key rotation still opens with the key
// that opens its content) as generation max(listed)+1. It is put, read
// back and compared, and then every other generation is deleted. It
// returns the new Record once the new table is confirmed, and rec
// otherwise; the caller persists what it returns.
func Rewrap(t Target, rec Record, keys kernel.Keys, state Recaller) (Record, Outcome) {
	id, err := parseID(rec.BackupID)
	if err != nil {
		return rec, Outcome{Offline, err}
	}
	gens, err := t.Tables(rec.BackupID)
	if err != nil {
		return rec, Outcome{Offline, err}
	}
	erased := slices.ContainsFunc(rec.Subjects, func(s string) bool { return !live(state, s) })
	current := slices.Contains(gens, rec.Generation)
	if !erased && current {
		if len(gens) == 1 {
			return rec, Outcome{Result: Unchanged}
		}
		// Only strays from an earlier run: delete them, keep rec.
		if t.AppendOnly() {
			return rec, Outcome{Result: AppendOnly}
		}
		return rec, dropOthers(t, rec.BackupID, rec.Generation, gens)
	}
	if t.AppendOnly() {
		return rec, Outcome{Result: AppendOnly}
	}
	keep := slices.DeleteFunc(slices.Clone(rec.Subjects), func(s string) bool { return !live(state, s) })
	es, err := liveEntries(keep, keys, state)
	if err != nil {
		return rec, Outcome{LiveKeyMissing, err}
	}
	gen := max(rec.Generation, slices.Max(append(slices.Clone(gens), 0))) + 1
	tb, err := sealTable(rec.Recipient, id, gen, es)
	if err != nil {
		return rec, Outcome{Offline, err}
	}
	if err := t.PutTable(rec.BackupID, gen, tb); err != nil {
		return rec, Outcome{Offline, err}
	}
	back, err := t.GetTable(rec.BackupID, gen)
	if err != nil {
		return rec, Outcome{Offline, err}
	}
	if !bytes.Equal(back, tb) {
		return rec, Outcome{Result: ReadBackMismatch}
	}
	next := rec
	next.Generation, next.Subjects, next.TableSum = gen, entrySubjects(es), sumHex(tb)
	return next, dropOthers(t, rec.BackupID, gen, gens)
}

// dropOthers deletes every listed generation but keep, then lists again
// to confirm only keep is left.
func dropOthers(t Target, backupID string, keep uint64, gens []uint64) Outcome {
	var errs []error
	for _, g := range gens {
		if g != keep {
			errs = append(errs, t.DeleteTable(backupID, g))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return Outcome{OldNotDeleted, err}
	}
	left, err := t.Tables(backupID)
	if err != nil {
		return Outcome{OldNotDeleted, err}
	}
	if len(left) != 1 || left[0] != keep {
		return Outcome{OldNotDeleted, fmt.Errorf("backup: generations %v still listed", left)}
	}
	return Outcome{Result: Rewrote}
}

func parseID(s string) ([idLen]byte, error) {
	var id [idLen]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != idLen || hex.EncodeToString(b) != s {
		return id, fmt.Errorf("backup: %q is not a backup id", s)
	}
	copy(id[:], b)
	return id, nil
}

// UnwrapTable opens a key-table object with the recovery key and puts
// every entry into dst, a fresh, empty table. It refuses a table of
// another backup. It does not drop erased subjects: OpenContent deletes
// the key of every subject the restored log has erased (D-167).
func UnwrapTable(r io.Reader, rk []byte, backupID string, dst kernel.Keys) (int, error) {
	h, body, err := openFrom(r, rk, KindKeyTable)
	if err != nil {
		return 0, err
	}
	if hex.EncodeToString(h.backupID[:]) != backupID {
		return 0, ErrOtherBackup
	}
	pt, err := io.ReadAll(io.LimitReader(body, maxTable+1))
	if err != nil {
		return 0, err
	}
	if len(pt) > maxTable {
		return 0, errors.New("backup: the key table is over 64 MiB")
	}
	var tb table
	dec := json.NewDecoder(bytes.NewReader(pt))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tb); err != nil {
		return 0, fmt.Errorf("backup: key table: %w", err)
	}
	if tb.BackupID != backupID || tb.Generation != h.gen {
		return 0, ErrOtherBackup
	}
	seen := map[string]bool{}
	for _, e := range tb.Entries {
		if !kernel.ValidSubject(e.Subject) || seen[e.Subject] {
			return 0, fmt.Errorf("backup: key table: bad or repeated subject %q", e.Subject)
		}
		seen[e.Subject] = true
	}
	have, err := dst.List()
	if err != nil {
		return 0, err
	}
	if len(have) != 0 {
		return 0, ErrNotEmpty
	}
	for i, e := range tb.Entries {
		if err := dst.Put(e.Subject, e.Key); err != nil {
			return i, err
		}
	}
	return len(tb.Entries), nil
}
