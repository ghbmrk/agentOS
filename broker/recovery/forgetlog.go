package recovery

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ghbmrk/agentos/broker/durable"
	"github.com/ghbmrk/agentos/broker/vault"
)

// The forget log carries the owner's forgets across a restore (CAP-3,
// security C3; Mark's ruling on #317 items 1–3). Each forget is an entry
// naming the goal, MACed under a key derived from the recovery key and
// chained to the one before, so an entry cannot be changed, added, cut
// from the middle or replayed without the card. The log lives in the
// vault; a copy goes to every backup destination and to the state dir
// (ExportForgetLog). Cutting the tail off a copy, or handing in an older
// one, is caught by a TPM NV counter on the PC (vault.Counter, as V6)
// that every append advances. A restore checks the log (checkForgetLog)
// and stays pending when it cannot (Pending*).
const (
	ForgetLogName = "recovery-forget-log"
	KindForgetLog = "forget_log"
	// ForgetKeyName holds the log's MAC key and its counter's
	// authorization; it is never exported.
	ForgetKeyName = "recovery-forget-key"
	KindForgetKey = "forget_log_key"

	forgetLogFmt = "agentos-forget-log-v1"
	forgetKeyFmt = "agentos-forget-key-v1"
)

// Why a restore is pending: agentosd refuses to start on the restored
// state dir while its marker is there, until the owner confirms the
// restore (W3-forget-b1-4).
const (
	// PendingUnanchored: no counter for the log on this PC, so an older
	// copy cannot be told from the newest.
	PendingUnanchored = "forget-log-unanchored"
	// PendingRolledBack: the newest authentic copy is behind the PC's
	// counter: forgets are missing from every copy at hand.
	PendingRolledBack = "forget-log-rolled-back"
	// PendingForged: a copy holds an entry the key did not make, or two
	// copies disagree.
	PendingForged = "forget-log-forged"
	// PendingMissing: the backup holds no log (made before this release).
	PendingMissing = "forget-log-missing"
)

// PendingSuffix names the marker a pending restore leaves beside
// Layout.ForgetLog: the reason, then the owner's notice (PendingNotice),
// one per line. agentosd refuses to start while it is there.
const PendingSuffix = ".pending"

// ErrNoForgetLog is an append to a vault that has no log yet: one made
// before this release, until its recovery key is next stored.
var ErrNoForgetLog = errors.New("recovery: no forget log yet")

var (
	errForeignLog = errors.New("recovery: forget log copy is not under this recovery key")
	errForgedLog  = errors.New("recovery: forget log copy holds an entry its key did not make")
)

// ForgetEntry is one forget. It names the goal, never its content.
type ForgetEntry struct {
	Seq  int       `json:"seq"`
	Goal string    `json:"goal"`
	At   time.Time `json:"at"`
	// Since is where the agent's machines were taken back to, when Agent.
	Since time.Time `json:"since,omitempty"`
	// Agent: the forget took the agent's own machines back too.
	Agent bool `json:"agent,omitempty"`
	// Count is the counter value this entry advanced the PC's counter to;
	// 0 for an entry made without one.
	Count uint64 `json:"count,omitempty"`
	Prev  string `json:"prev"`
	MAC   string `json:"mac"`
}

type forgetLog struct {
	Format string `json:"format"`
	ID     []byte `json:"id"`
	// Host is the PC whose counter anchors the log; Base is the counter's
	// value when it was defined, and AnchorSeq the last entry before it.
	Host      string        `json:"host,omitempty"`
	Base      uint64        `json:"base,omitempty"`
	AnchorSeq int           `json:"anchor_seq,omitempty"`
	MAC       string        `json:"mac"`
	Entries   []ForgetEntry `json:"entries"`
}

type forgetKeyValue struct {
	Format string `json:"format"`
	Key    []byte `json:"key"`
	Auth   []byte `json:"auth"`
}

// forgetKey derives the log's MAC key from the recovery key.
func forgetKey(rk RecoveryKey) []byte {
	return hkdf(rk.b[:], nil, "agentos-forget-log-v1", 32)
}

// head is the counter value the log's newest anchored entry advanced to.
func (l forgetLog) head() uint64 {
	if n := len(l.Entries); n > 0 && l.Entries[n-1].Seq > l.AnchorSeq {
		return l.Entries[n-1].Count
	}
	return l.Base
}

func (l forgetLog) headerMAC(key []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("agentos-forget-header-v1\x00"))
	m.Write([]byte(l.Format + "\x00"))
	m.Write(l.ID)
	m.Write([]byte("\x00" + l.Host + "\x00"))
	var n [16]byte
	binary.BigEndian.PutUint64(n[:8], l.Base)
	binary.BigEndian.PutUint64(n[8:], uint64(l.AnchorSeq))
	m.Write(n[:])
	return hex.EncodeToString(m.Sum(nil))
}

func entryMAC(key, id []byte, e ForgetEntry) string {
	e.MAC = ""
	enc, _ := json.Marshal(e)
	m := hmac.New(sha256.New, key)
	m.Write([]byte("agentos-forget-entry-v1\x00"))
	m.Write(id)
	m.Write(enc)
	return hex.EncodeToString(m.Sum(nil))
}

// chainStart is the first entry's Prev; each later one's is the hash of
// the entry before, MAC included.
func chainStart(key, id []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("agentos-forget-chain-v1\x00"))
	m.Write(id)
	return hex.EncodeToString(m.Sum(nil))
}

func chainNext(e ForgetEntry) string {
	enc, _ := json.Marshal(e)
	h := sha256.Sum256(enc)
	return hex.EncodeToString(h[:])
}

// sign recomputes every MAC and the chain under key.
func (l *forgetLog) sign(key []byte) {
	l.MAC = l.headerMAC(key)
	prev := chainStart(key, l.ID)
	for i := range l.Entries {
		l.Entries[i].Seq, l.Entries[i].Prev = i+1, prev
		l.Entries[i].MAC = entryMAC(key, l.ID, l.Entries[i])
		prev = chainNext(l.Entries[i])
	}
}

func decodeForgetLog(raw []byte) (forgetLog, error) {
	var l forgetLog
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&l); err != nil || l.Format != forgetLogFmt || len(l.ID) != 16 {
		return forgetLog{}, errForeignLog
	}
	return l, nil
}

// openForgetLog decodes a copy and checks it under key: a header the key
// did not make is another key's copy (errForeignLog); an entry it did not
// make, or out of chain, is forged (errForgedLog).
func openForgetLog(key, raw []byte) (forgetLog, error) {
	l, err := decodeForgetLog(raw)
	if err != nil {
		return l, err
	}
	if !hmac.Equal([]byte(l.MAC), []byte(l.headerMAC(key))) {
		return forgetLog{}, errForeignLog
	}
	prev := chainStart(key, l.ID)
	for i, e := range l.Entries {
		if e.Seq != i+1 || e.Prev != prev || !hmac.Equal([]byte(e.MAC), []byte(entryMAC(key, l.ID, e))) {
			return forgetLog{}, errForgedLog
		}
		prev = chainNext(e)
	}
	return l, nil
}

func loadForgetKey(v *vault.Vault) (forgetKeyValue, bool, error) {
	raw, ok, err := reserved(v, ForgetKeyName, KindForgetKey)
	if err != nil || !ok {
		return forgetKeyValue{}, ok, err
	}
	var kv forgetKeyValue
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&kv); err != nil || kv.Format != forgetKeyFmt || len(kv.Key) != 32 || len(kv.Auth) == 0 {
		return forgetKeyValue{}, true, errors.New("recovery: malformed forget log key")
	}
	return kv, true, nil
}

func loadForgetLog(v *vault.Vault) (forgetLog, bool, error) {
	raw, ok, err := reserved(v, ForgetLogName, KindForgetLog)
	if err != nil || !ok {
		return forgetLog{}, ok, err
	}
	l, err := decodeForgetLog(raw)
	if err != nil {
		return forgetLog{}, true, errors.New("recovery: malformed forget log")
	}
	return l, true, nil
}

func saveForgetLog(v *vault.Vault, l forgetLog) error {
	enc, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return v.Put(ForgetLogName, KindForgetLog, enc)
}

// ensureForgetLog stores the log key derived from rk and makes the log if
// there is none; after a rotation it re-keys the log. The vault's own
// copy is authenticated by the vault, so it is re-signed as it stands.
// The counter's authorization is random and kept across rotations. With
// c, this PC's counter, a log not anchored here is anchored at once, so a
// box that never forgets still restores on its own PC.
func ensureForgetLog(v *vault.Vault, rk RecoveryKey, c vault.Counter) error {
	kv, ok, err := loadForgetKey(v)
	if err != nil {
		return err
	}
	if !ok {
		a, err := random(nil, 16)
		if err != nil {
			return err
		}
		kv = forgetKeyValue{Format: forgetKeyFmt, Auth: []byte(hex.EncodeToString(a))}
	}
	kv.Key = forgetKey(rk)
	l, ok, err := loadForgetLog(v)
	if err != nil {
		return err
	}
	if !ok {
		id, err := random(nil, 16)
		if err != nil {
			return err
		}
		l = forgetLog{Format: forgetLogFmt, ID: id}
	}
	l.sign(kv.Key)
	enc, err := json.Marshal(kv)
	if err != nil {
		return err
	}
	if err := v.Put(ForgetKeyName, KindForgetKey, enc); err != nil {
		return err
	}
	if err := saveForgetLog(v, l); err != nil {
		return err
	}
	if c != nil && l.Host != c.Host() {
		_, err = anchorForgetLog(v, &l, kv, c)
	}
	return err
}

// AppendForget adds a forget to the log and returns the copy to write to
// the state dir and every reachable backup destination. With a counter
// (the vault process's TPM), the log is anchored to it: the vault is
// written first and the counter advanced after, so a crash between leaves
// the log one ahead, which the next append catches up. An error after the
// vault write leaves the entry in the log; the caller treats the forget as
// not logged.
func AppendForget(b *Box, c vault.Counter, e ForgetEntry) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	kv, ok, err := loadForgetKey(b.V)
	if err != nil {
		return nil, err
	}
	l, lok, err := loadForgetLog(b.V)
	if err != nil {
		return nil, err
	}
	if !ok || !lok {
		return nil, ErrNoForgetLog
	}
	var ref []byte
	if c != nil {
		if ref, err = anchorForgetLog(b.V, &l, kv, c); err != nil {
			return nil, err
		}
	}
	e.Seq, e.Count = len(l.Entries)+1, 0
	e.At, e.Since = e.At.UTC(), e.Since.UTC()
	if ref != nil {
		e.Count = l.head() + 1
	}
	l.Entries = append(l.Entries, e)
	l.sign(kv.Key)
	if err := saveForgetLog(b.V, l); err != nil {
		return nil, err
	}
	if ref != nil {
		if err := c.Increment(ref, kv.Auth); err != nil {
			return nil, fmt.Errorf("recovery: forget log counter: %w", err)
		}
	}
	return json.Marshal(l)
}

// anchorForgetLog defines the log's counter on this PC when the log has
// none here, or checks it: the log must be at the counter, or one ahead
// after a crash, which it catches up. It returns the counter's ref.
func anchorForgetLog(v *vault.Vault, l *forgetLog, kv forgetKeyValue, c vault.Counter) ([]byte, error) {
	if l.Host != c.Host() {
		// Not anchored yet, or a box now on another PC: a new counter.
		ref, err := c.Define(l.ID, kv.Auth)
		if err != nil {
			return nil, err
		}
		n, err := c.Read(ref, kv.Auth)
		if err != nil {
			return nil, err
		}
		l.Host, l.Base, l.AnchorSeq = c.Host(), n, len(l.Entries)
		l.sign(kv.Key)
		return ref, saveForgetLog(v, *l)
	}
	ref, found, err := c.Find(l.ID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, vault.ErrCounterMissing
	}
	n, err := c.Read(ref, kv.Auth)
	if err != nil {
		return nil, err
	}
	switch h := l.head(); {
	case h == n+1:
		if err := c.Increment(ref, kv.Auth); err != nil {
			return nil, err
		}
	case h != n:
		return nil, vault.ErrRolledBack
	}
	return ref, nil
}

// ExportForgetLog returns the log's copy for the state dir and the backup
// destinations.
func ExportForgetLog(b *Box) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	raw, ok, err := reserved(b.V, ForgetLogName, KindForgetLog)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNoForgetLog
	}
	return raw, nil
}

// checkForgetLog checks the restored vault's log against every copy at
// hand and the PC's counter. It returns the log to carry on, or why the
// restore stays pending; unanchored, it also returns the longest
// authentic log, for the owner to confirm (W3-forget-b1-4).
func checkForgetLog(v *vault.Vault, rk RecoveryKey, copies [][]byte, c vault.Counter) (forgetLog, string) {
	key := forgetKey(rk)
	defer wipe(key)
	raw, ok, err := reserved(v, ForgetLogName, KindForgetLog)
	if err != nil {
		return forgetLog{}, PendingForged
	}
	if !ok {
		return forgetLog{}, PendingMissing
	}
	best, err := openForgetLog(key, raw)
	if err != nil {
		return forgetLog{}, PendingForged
	}
	for _, cp := range copies {
		l, err := openForgetLog(key, cp)
		switch {
		case errors.Is(err, errForeignLog):
			continue // another key's copy, or not a log: as if absent
		case err != nil:
			return forgetLog{}, PendingForged
		case !bytes.Equal(l.ID, best.ID):
			continue
		}
		switch {
		case prefixOf(best, l):
			best = l
		case !prefixOf(l, best):
			return forgetLog{}, PendingForged
		}
	}
	kv, ok, err := loadForgetKey(v)
	// The anchor is the PC's counter for this log, whatever the copies
	// say: a copy from before the log was anchored here is behind it.
	if c == nil || !ok || err != nil {
		return best, PendingUnanchored
	}
	ref, found, err := c.Find(best.ID)
	if err != nil || !found {
		return best, PendingUnanchored
	}
	n, err := c.Read(ref, kv.Auth)
	if err != nil {
		return best, PendingUnanchored
	}
	h := best.head()
	if best.Host != c.Host() {
		h = 0 // its counts are another PC's
	}
	switch {
	case h == n || h == n+1:
		return best, ""
	case h < n:
		return forgetLog{}, PendingRolledBack
	}
	return forgetLog{}, PendingForged
}

// prefixOf reports whether a's entries begin b's.
func prefixOf(a, b forgetLog) bool {
	if len(a.Entries) > len(b.Entries) {
		return false
	}
	for i := range a.Entries {
		if a.Entries[i].MAC != b.Entries[i].MAC {
			return false
		}
	}
	return true
}

// settleForgetLog runs the check in a restore's extracted tree: a checked
// log goes into the vault and the state dir; otherwise the state dir's
// copy goes and a pending marker takes its place, with the owner's
// question beside it when the owner can confirm the restore. An
// unanchored log is authentic, so the vault keeps the longest copy: it
// only adds forgets, and the next append chains on from it.
func settleForgetLog(v *vault.Vault, rk RecoveryKey, tmp string, lay Layout, opt Options, created, now time.Time) (string, error) {
	copies := append([][]byte(nil), opt.ForgetLogs...)
	var path string
	if lay.ForgetLog != "" {
		path = filepath.Join(tmp, filepath.FromSlash(lay.ForgetLog))
		if raw, err := os.ReadFile(path); err == nil {
			copies = append(copies, raw)
		}
	}
	l, pending := checkForgetLog(v, rk, copies, opt.Counter)
	has := pending == "" || pending == PendingUnanchored
	if has {
		if err := saveForgetLog(v, l); err != nil {
			return "", err
		}
	}
	if path == "" {
		return pending, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if pending != "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		if Confirmable(pending) {
			f, err := newQuestion(pending, l, has, now, opt.Newer, created, decoyStream(rk, l, has))
			if err != nil {
				return "", err
			}
			if err := writeQuestion(path, f); err != nil {
				return "", err
			}
		} else if err := os.Remove(path + ConfirmSuffix); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		return pending, durable.WriteFile(path+PendingSuffix, []byte(pending+"\n"+PendingNotice(pending)+"\n"), 0o600)
	}
	for _, sfx := range []string{PendingSuffix, ConfirmSuffix} {
		if err := os.Remove(path + sfx); err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	enc, err := json.Marshal(l)
	if err != nil {
		return "", err
	}
	return "", durable.WriteFile(path, enc, 0o600)
}

// PendingNotice is the owner's text for a pending restore (CH-12: GSM-7,
// one segment, and what the owner can do).
func PendingNotice(reason string) string {
	switch reason {
	case PendingUnanchored:
		return "Restore on hold: this PC cannot check the list of things you had your agent forget. Restoring on your original PC still works."
	case PendingRolledBack:
		return "Restore on hold: the forget list in this backup is older than this PC's record. Restore again with every backup destination connected, or wait for an update."
	case PendingMissing:
		return "Restore on hold: this backup has no list of things you had your agent forget. Nothing can be done until an update."
	}
	return "Restore on hold: the list of things you had your agent forget was changed. Nothing can be done until an update."
}
