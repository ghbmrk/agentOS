package recovery

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// REQ: CAP-3, REC-1, REC-2, A8
// Acceptance: A8 (a restore onto a new drive with the recovery key does
// not bring back what the owner had the agent forget).

// pcCounter is one PC's counters, standing in for its TPM (as the vault's
// fakePC): a new counter starts at the highest value any counter on the
// PC has had, and nothing lowers one.
type pcCounter struct {
	host     string
	counters map[string]uint64
	auth     map[string][]byte
	max      uint64
	noIncr   bool
}

func newPCCounter(host string) *pcCounter {
	return &pcCounter{host: host, counters: map[string]uint64{}, auth: map[string][]byte{}, max: 40}
}

func (p *pcCounter) Host() string { return p.host }

func (p *pcCounter) Find(id []byte) ([]byte, bool, error) {
	_, ok := p.counters[hex.EncodeToString(id)]
	return id, ok, nil
}

func (p *pcCounter) Define(id, auth []byte) ([]byte, error) {
	if bytes.IndexByte(auth, 0) >= 0 {
		return nil, errors.New("auth holds a zero byte")
	}
	k := hex.EncodeToString(id)
	if _, ok := p.counters[k]; !ok {
		p.counters[k], p.auth[k] = p.max, append([]byte(nil), auth...)
	}
	return id, nil
}

func (p *pcCounter) Read(ref, auth []byte) (uint64, error) {
	k := hex.EncodeToString(ref)
	n, ok := p.counters[k]
	if !ok || !bytes.Equal(auth, p.auth[k]) {
		return 0, errors.New("tpm: bad counter")
	}
	return n, nil
}

func (p *pcCounter) Increment(ref, auth []byte) error {
	k := hex.EncodeToString(ref)
	if p.noIncr || !bytes.Equal(auth, p.auth[k]) {
		return errors.New("tpm: increment failed")
	}
	p.counters[k]++
	if p.counters[k] > p.max {
		p.max = p.counters[k]
	}
	return nil
}

func forget(t *testing.T, x *box, pc *pcCounter, goal string, at time.Time) []byte {
	t.Helper()
	cp, err := AppendForget(x.b, pc, ForgetEntry{Goal: goal, At: at, Since: at.Add(-time.Hour), Agent: true})
	must(t, err)
	return cp
}

func restoreWith(t *testing.T, bk []byte, rk RecoveryKey, opt Options) (Report, string) {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "new-drive")
	rep, err := Restore(bytes.NewReader(bk), rk, dst, lay, opt, t0.Add(48*time.Hour))
	must(t, err)
	return rep, dst
}

func restoredGoals(t *testing.T, rk RecoveryKey, dst string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dst, lay.ForgetLog))
	must(t, err)
	l, err := openForgetLog(forgetKey(rk), raw)
	must(t, err)
	var gs []string
	for _, e := range l.Entries {
		gs = append(gs, e.Goal)
	}
	return gs
}

func TestForgetLogAppendIsAuthenticatedAndAnchored(t *testing.T) {
	x := newBox(t)
	pc := newPCCounter("host-a")
	forget(t, x, pc, "goal-1", t0)
	cp := forget(t, x, pc, "goal-2", t0.Add(time.Minute))
	l, err := openForgetLog(forgetKey(x.rk), cp)
	must(t, err)
	if len(l.Entries) != 2 || l.Entries[1].Goal != "goal-2" || l.Host != "host-a" {
		t.Fatalf("log: %+v", l)
	}
	ref, ok, _ := pc.Find(l.ID)
	if !ok {
		t.Fatal("no counter defined for the log")
	}
	kv, _, _ := loadForgetKey(x.b.V)
	n, err := pc.Read(ref, kv.Auth)
	must(t, err)
	if l.head() != n || n != pc.max || n < 42 {
		t.Fatalf("head %d, counter %d", l.head(), n)
	}
	// The copy names goals only: no key, no record content.
	if bytes.Contains(cp, []byte(hex.EncodeToString(forgetKey(x.rk)))) {
		t.Fatal("copy holds its key")
	}
	// Another recovery key's derivation does not authenticate it.
	other, err := testGen(nil)
	must(t, err)
	ork, _ := ParseRecoveryKey(other.RecoveryKey)
	if _, err := openForgetLog(forgetKey(ork), cp); !errors.Is(err, errForeignLog) {
		t.Fatalf("other key: %v", err)
	}
	// The log key is not one of the box's other recovery-key derivations.
	if bytes.Equal(forgetKey(x.rk), hkdf(x.rk.b[:], nil, "agentos-backup-x25519-v1", 32)) {
		t.Fatal("log key reuses the backup key")
	}
}

// A8: the drive is lost; the owner restores, on the same PC, a backup made
// before a forget. The log copy at the backup's destination brings the
// forget back with it.
func TestRestoreReplaysTheForgetLogOnTheSamePC(t *testing.T) {
	x := newBox(t)
	pc := newPCCounter("host-a")
	forget(t, x, pc, "goal-1", t0)
	bk := x.backup()
	cp := forget(t, x, pc, "goal-2", t0.Add(time.Hour))
	rep, dst := restoreWith(t, bk, x.rk, Options{ForgetLogs: [][]byte{cp}, Counter: pc})
	if rep.Pending != "" {
		t.Fatalf("pending: %q", rep.Pending)
	}
	if gs := restoredGoals(t, x.rk, dst); strings.Join(gs, ",") != "goal-1,goal-2" {
		t.Fatalf("restored goals: %v", gs)
	}
	nb := openAt(t, dst, x.rk)
	if st := LoadState(nb.V); st.Pending != "" || !st.Restricted {
		t.Fatalf("state: %+v", st)
	}
	// The restored vault carries the whole log on: a later forget chains on.
	if _, err := AppendForget(nb, pc, ForgetEntry{Goal: "goal-3", At: t0.Add(49 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, lay.ForgetLog+PendingSuffix)); !os.IsNotExist(err) {
		t.Fatalf("pending marker: %v", err)
	}
}

// U1 on #409: a box that never forgot anything restores clean on its own
// PC, because its log is anchored when it is made; the empty log is then
// held to the counter like any other, so a later forget rolls it back.
func TestRestoreOfANeverForgotBoxOnItsOwnPC(t *testing.T) {
	pc := newPCCounter("host-a")
	x := newBoxOn(t, pc)
	bk := x.backup()
	rep, dst := restoreWith(t, bk, x.rk, Options{Counter: pc})
	if rep.Pending != "" {
		t.Fatalf("pending %q", rep.Pending)
	}
	if gs := restoredGoals(t, x.rk, dst); len(gs) != 0 {
		t.Fatalf("restored goals: %v", gs)
	}
	// Another PC still cannot check it.
	pendingRestore(t, bk, x.rk, Options{Counter: newPCCounter("host-b")}, PendingUnanchored)
	// After a forget, the empty log in the old backup is behind the counter.
	forget(t, x, pc, "goal-1", t0)
	pendingRestore(t, bk, x.rk, Options{Counter: pc}, PendingRolledBack)
}

func pendingRestore(t *testing.T, bk []byte, rk RecoveryKey, opt Options, want string) string {
	t.Helper()
	rep, dst := restoreWith(t, bk, rk, opt)
	if rep.Pending != want {
		t.Fatalf("pending %q, want %q", rep.Pending, want)
	}
	nb := openAt(t, dst, rk)
	if st := LoadState(nb.V); st.Pending != want || !st.Restricted {
		t.Fatalf("state: %+v", st)
	}
	// The marker gives agentosd the reason and the owner's notice.
	if b, err := os.ReadFile(filepath.Join(dst, lay.ForgetLog+PendingSuffix)); err != nil || string(b) != want+"\n"+PendingNotice(want)+"\n" {
		t.Fatalf("pending marker: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(dst, lay.ForgetLog)); !os.IsNotExist(err) {
		t.Fatalf("an unchecked log was handed on: %v", err)
	}
	return dst
}

// Threat check: an older destination copy restored in place of the
// newest, or the newest with its tail cut off.
func TestRestoreHoldsARolledBackOrTruncatedLog(t *testing.T) {
	x := newBox(t)
	pc := newPCCounter("host-a")
	bk := x.backup()
	old := forget(t, x, pc, "goal-1", t0)
	cp := forget(t, x, pc, "goal-2", t0.Add(time.Minute))
	pendingRestore(t, bk, x.rk, Options{ForgetLogs: [][]byte{old}, Counter: pc}, PendingRolledBack)

	var l forgetLog
	must(t, json.Unmarshal(cp, &l))
	l.Entries = l.Entries[:1]
	cut, _ := json.Marshal(l)
	pendingRestore(t, bk, x.rk, Options{ForgetLogs: [][]byte{cut}, Counter: pc}, PendingRolledBack)
	// No copy at all: the backup's own log is behind the counter.
	pendingRestore(t, bk, x.rk, Options{Counter: pc}, PendingRolledBack)
}

// Threat check: an entry changed, added without the key, cut from the
// middle, or replayed from another position.
func TestRestoreHoldsAForgedOrReplayedEntry(t *testing.T) {
	x := newBox(t)
	pc := newPCCounter("host-a")
	bk := x.backup()
	forget(t, x, pc, "goal-1", t0)
	cp := forget(t, x, pc, "goal-2", t0.Add(time.Minute))
	edit := func(f func(l *forgetLog)) []byte {
		var l forgetLog
		must(t, json.Unmarshal(cp, &l))
		f(&l)
		raw, _ := json.Marshal(l)
		return raw
	}
	for name, raw := range map[string][]byte{
		"changed": edit(func(l *forgetLog) { l.Entries[0].Goal = "goal-9" }),
		"appended": edit(func(l *forgetLog) {
			e := l.Entries[1]
			e.Seq, e.Goal, e.Count = 3, "goal-9", e.Count+1
			l.Entries = append(l.Entries, e)
		}),
		"cut": edit(func(l *forgetLog) { l.Entries = l.Entries[1:] }),
		"replayed": edit(func(l *forgetLog) {
			l.Entries = append(l.Entries, l.Entries[0])
		}),
	} {
		t.Run(name, func(t *testing.T) {
			pendingRestore(t, bk, x.rk, Options{ForgetLogs: [][]byte{cp, raw}, Counter: pc}, PendingForged)
		})
	}
}

// The ruling's no-anchor case: a restore on another PC, or with no counter
// at all, cannot tell an old copy from the newest, so it stays pending.
func TestRestoreWithNoAnchorStaysPending(t *testing.T) {
	x := newBox(t)
	pc := newPCCounter("host-a")
	bk := x.backup()
	cp := forget(t, x, pc, "goal-1", t0)
	pendingRestore(t, bk, x.rk, Options{ForgetLogs: [][]byte{cp}}, PendingUnanchored)
	pendingRestore(t, bk, x.rk, Options{ForgetLogs: [][]byte{cp}, Counter: newPCCounter("host-b")}, PendingUnanchored)
	n := PendingNotice(PendingUnanchored)
	if !strings.Contains(n, "original PC") || !isGSM7(n) || len(n) > 160 {
		t.Fatalf("notice: %q", n)
	}
	for _, r := range []string{PendingRolledBack, PendingForged, PendingMissing} {
		if n := PendingNotice(r); n == "" || !isGSM7(n) || len(n) > 160 {
			t.Fatalf("%s notice: %q", r, n)
		}
	}
}

// A backup made before this release has no log: fail closed.
func TestRestoreOfABackupWithoutALogStaysPending(t *testing.T) {
	x := newBox(t)
	must(t, x.b.V.Delete(ForgetLogName))
	bk := x.backup()
	pendingRestore(t, bk, x.rk, Options{Counter: newPCCounter("host-a")}, PendingMissing)
}

// A crash between the vault write and the counter's increment leaves the
// log one ahead: that restores, and the next forget catches the counter
// up, so dropping its entry later is still caught.
func TestForgetLogCrashBeforeIncrement(t *testing.T) {
	x := newBox(t)
	pc := newPCCounter("host-a")
	forget(t, x, pc, "goal-1", t0)
	bk := x.backup()
	pc.noIncr = true
	if _, err := AppendForget(x.b, pc, ForgetEntry{Goal: "goal-2", At: t0}); err == nil {
		t.Fatal("append reported success without the counter")
	}
	pc.noIncr = false
	cp, err := ExportForgetLog(x.b)
	must(t, err)
	rep, _ := restoreWith(t, bk, x.rk, Options{ForgetLogs: [][]byte{cp}, Counter: pc})
	if rep.Pending != "" {
		t.Fatalf("pending: %q", rep.Pending)
	}
	forget(t, x, pc, "goal-3", t0)
	pendingRestore(t, bk, x.rk, Options{ForgetLogs: [][]byte{cp}, Counter: pc}, PendingRolledBack)
}

// A rotation re-keys the log under the new recovery key; copies under the
// old key no longer authenticate and are ignored.
func TestRotationReKeysTheForgetLog(t *testing.T) {
	x := newBox(t)
	pc := newPCCounter("host-a")
	stale := forget(t, x, pc, "goal-1", t0)
	p, err := BeginRotate(x.b, AllParts, Auth{Recovery: x.rk}, Proof{}, testGen, nil, t0)
	must(t, err)
	nc, err := p.Commit(x.b, p.answer, t0.Add(time.Minute))
	must(t, err)
	nrk, err := ParseRecoveryKey(nc.RecoveryKey)
	must(t, err)
	cp, err := ExportForgetLog(x.b)
	must(t, err)
	if l, err := openForgetLog(forgetKey(nrk), cp); err != nil || len(l.Entries) != 1 {
		t.Fatalf("re-keyed log: %+v %v", l, err)
	}
	bk := x.backup()
	rep, dst := restoreWith(t, bk, nrk, Options{ForgetLogs: [][]byte{stale, cp}, Counter: pc})
	if rep.Pending != "" || strings.Join(restoredGoals(t, nrk, dst), ",") != "goal-1" {
		t.Fatalf("pending %q", rep.Pending)
	}
}

func isGSM7(s string) bool {
	for _, r := range s {
		if r > 0x7e || (r < 0x20 && r != '\n') || strings.ContainsRune("[]{}\\^~|`", r) {
			return false
		}
	}
	return true
}
