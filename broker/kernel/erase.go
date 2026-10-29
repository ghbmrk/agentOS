package kernel

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"
)

// Subjects, their data keys, and erase (SPEC LOG-4, KRN-erase, #2823). A
// subject is an opaque random ID with one random data key. The key lives in
// a table outside the log (Keys), since the log is append-only and goes into
// every backup, so nothing in it can be destroyed: the one exception to
// LOG-1's rebuilt key tables (Mark's card
// cmsg_01R91wiieBzMSvPKFsAJVvuKDAejf3f4MDFgLdQqe8UDkN). Content is sealed under the subject's key and
// named by the SHA-256 of its ciphertext, so the log holds no key, no name
// and no hash of a plaintext anyone could guess and confirm. A subject's name
// is content too, of class ClassLabel. Erase is one narrowing entry, then
// the key goes, then each store deletes the subject's items; every start
// re-applies the erases (OpenContent) and Tick retries the stores.

// Subject entry types.
const (
	TSubjectOpened  = "subject.opened"
	TContentStored  = "content.stored"
	TSubjectErased  = "subject.erased"
	TEraseConfirmed = "erase.confirmed"
	// TContentRead records that an agent session's lineage was given a
	// sealed item (ReadFor), so an erase can rewind it (D-169).
	TContentRead = "content.read"
)

// ClassLabel is the class of a subject's name: recall by name opens the
// labels of live subjects (Named).
const ClassLabel = "label"

// SubjectKey is a subject's data key, AES-256-GCM.
type SubjectKey [32]byte

// Keys is the subject-key table. Each call is durable when it returns, and
// Delete of an absent key succeeds.
type Keys interface {
	Put(subject string, k SubjectKey) error
	Get(subject string) (k SubjectKey, ok bool, err error)
	Delete(subject string) error
	List() ([]string, error)
}

// ContentStore holds sealed items by the hash of their ciphertext. Delete
// of an absent item succeeds.
type ContentStore interface {
	Put(h Hash, ct []byte) error
	Get(h Hash) ([]byte, error)
	Delete(h Hash) error
}

// MemKeys is a Keys in memory, for tests and the sim.
type MemKeys struct{ M map[string]SubjectKey }

func NewMemKeys() *MemKeys { return &MemKeys{M: map[string]SubjectKey{}} }

func (m *MemKeys) Put(s string, k SubjectKey) error { m.M[s] = k; return nil }
func (m *MemKeys) Get(s string) (SubjectKey, bool, error) {
	k, ok := m.M[s]
	return k, ok, nil
}
func (m *MemKeys) Delete(s string) error   { delete(m.M, s); return nil }
func (m *MemKeys) List() ([]string, error) { return slices.Sorted(maps.Keys(m.M)), nil }

// MemContent is a ContentStore in memory, for tests and the sim.
type MemContent struct{ M map[Hash][]byte }

func NewMemContent() *MemContent { return &MemContent{M: map[Hash][]byte{}} }

func (m *MemContent) Put(h Hash, ct []byte) error { m.M[h] = slices.Clone(ct); return nil }
func (m *MemContent) Get(h Hash) ([]byte, error) {
	ct, ok := m.M[h]
	if !ok {
		return nil, ErrItem
	}
	return slices.Clone(ct), nil
}
func (m *MemContent) Delete(h Hash) error { delete(m.M, h); return nil }

var (
	ErrContentClosed = errors.New("kernel: content stays closed until OpenContent has run")
	ErrSubject       = errors.New("kernel: no open subject by that id")
	ErrErased        = errors.New("kernel: that subject is erased")
	ErrStore         = errors.New("kernel: no content store by that name, or no such class")
	ErrSubjectKey    = errors.New("kernel: the subject's data key is missing, or not the one its subject.opened names")
	ErrItem          = errors.New("kernel: no readable item by that hash")
	ErrLineage       = errors.New("kernel: a lineage is 1 to 128 bytes of plain text")
	ErrLabel         = errors.New("kernel: a label to look for is visible text: valid UTF-8, not blank, no control or invisible character")
)

// ValidSubject reports whether s is a subject ID as OpenSubject draws them:
// 32 lowercase hex digits, so it is also a safe file name.
func ValidSubject(s string) bool {
	return len(s) == 32 && strings.Trim(s, "0123456789abcdef") == ""
}

// dataKeyID names a data key in the log without revealing it.
func dataKeyID(k SubjectKey) string {
	h := sha256.Sum256(append([]byte("agentos.subject-key.v1\x00"), k[:]...))
	return hex.EncodeToString(h[:16])
}

func contentAAD(subject, class string) []byte { return []byte(subject + "\x00" + class) }

// name is a store or class name: short, plain text.
func name(s string) bool { return s != "" && len(s) <= 64 && utf8.ValidString(s) && shown(s) }

// ValidStore reports whether s can name a content store: a name, and never
// the key table. A backup's content/<store> section names use it too.
func ValidStore(s string) bool { return name(s) && s != KeyTable }

// Item is one sealed item of a subject.
type Item struct {
	Store string `json:"store"`
	Hash  Hash   `json:"hash"`
	Class string `json:"class"`
	At    int64  `json:"at"`
}

type (
	subjectOpened struct {
		Subject string `json:"subject"`
		KeyID   string `json:"key_id"`
	}
	contentStored struct {
		Subject string `json:"subject"`
		Store   string `json:"store"`
		Hash    Hash   `json:"hash"`
		Class   string `json:"class"`
	}
	subjectErased struct {
		Subject string   `json:"subject"`
		Stores  []string `json:"stores"`
	}
	eraseConfirmed struct {
		Subject string `json:"subject"`
		Store   string `json:"store"`
	}
	contentRead struct {
		Hash    Hash   `json:"hash"`
		Lineage string `json:"lineage"`
	}
	subjectState struct {
		opened    int64
		seq       uint64 // of its subject.opened
		keyID     string
		items     []Item
		erased    bool
		erasedAt  int64
		stores    []string // the stores that held items at the erase
		confirmed map[string]bool
		reads     map[string]int64 // each lineage that read an item, at its first read
	}
	itemOf struct {
		subject string
		Item
	}
)

// KeyTable names the subject-key table among an erase's stores: its
// erase.confirmed records that the data key is gone, so an erase whose key
// delete failed stays in Unerased, across restarts, until it is. No
// content store takes the name.
const KeyTable = "key-table"

// holding is the sorted stores an erase must confirm: the key table and
// every store items are in.
func holding(items []Item) []string {
	out := []string{KeyTable}
	for _, it := range items {
		if !slices.Contains(out, it.Store) {
			out = append(out, it.Store)
		}
	}
	slices.Sort(out)
	return out
}

func (st *subjectState) unconfirmed() []string {
	var out []string
	for _, s := range st.stores {
		if !st.confirmed[s] {
			out = append(out, s)
		}
	}
	return out
}

func (s *State) applyErase(e Entry) error {
	switch e.Type {
	case TSubjectOpened:
		b, err := body[subjectOpened](e)
		if err != nil {
			return err
		}
		if ValidSubject(b.Subject) && s.subjects[b.Subject] == nil {
			s.subjects[b.Subject] = &subjectState{opened: e.At, seq: e.Seq, keyID: b.KeyID}
		}
	case TContentStored:
		b, err := body[contentStored](e)
		if err != nil {
			return err
		}
		if st := s.subjects[b.Subject]; st != nil && !st.erased && ValidStore(b.Store) && name(b.Class) && s.items[b.Hash].subject == "" {
			it := Item{Store: b.Store, Hash: b.Hash, Class: b.Class, At: e.At}
			st.items = append(st.items, it)
			s.items[b.Hash] = itemOf{b.Subject, it}
		}
	case TSubjectErased:
		b, err := body[subjectErased](e)
		if err != nil {
			return err
		}
		if st := s.subjects[b.Subject]; st != nil && !st.erased {
			st.erased, st.erasedAt, st.stores, st.confirmed = true, e.At, holding(st.items), map[string]bool{}
			s.owing[b.Subject] = true
		}
	case TEraseConfirmed:
		b, err := body[eraseConfirmed](e)
		if err != nil {
			return err
		}
		if st := s.subjects[b.Subject]; st != nil && st.erased && slices.Contains(st.stores, b.Store) {
			st.confirmed[b.Store] = true
			if len(st.unconfirmed()) == 0 {
				delete(s.owing, b.Subject)
			}
		}
	case TContentRead:
		b, err := body[contentRead](e)
		if err != nil {
			return err
		}
		if it, ok := s.items[b.Hash]; ok && validLineage(b.Lineage) {
			st := s.subjects[it.subject]
			if st.reads == nil {
				st.reads = map[string]int64{}
			}
			if _, ok := st.reads[b.Lineage]; !ok {
				st.reads[b.Lineage] = e.At
			}
		}
	}
	return nil
}

// validLineage reports whether s can name an agent session's lineage
// (vm.Machine.Lineage): short, plain text.
func validLineage(s string) bool { return s != "" && len(s) <= 128 && utf8.ValidString(s) && shown(s) }

// ErasedRead is a lineage that read an item of an erased subject, and
// when it first did: what an erase rewinds (D-169).
type ErasedRead struct {
	Subject string `json:"subject"`
	Lineage string `json:"lineage"`
	First   int64  `json:"first"`
}

// ErasedReads lists, for every erased subject, each lineage that read one
// of its items and the time of its first such read, by subject then
// lineage. It is a projection of the log, so it survives a restart and
// rebuilds from empty (LOG-1).
func (s *State) ErasedReads() []ErasedRead {
	var out []ErasedRead
	for _, sub := range slices.Sorted(maps.Keys(s.subjects)) {
		st := s.subjects[sub]
		if !st.erased {
			continue
		}
		for _, l := range slices.Sorted(maps.Keys(st.reads)) {
			out = append(out, ErasedRead{sub, l, st.reads[l]})
		}
	}
	return out
}

// Recall is what the box knows about a subject (LOG-4): while it is live,
// when it was opened and its items; once erased, only when, how many items
// it held and the stores that have not yet confirmed their delete.
type Recall struct {
	Subject     string   `json:"subject"`
	Opened      int64    `json:"opened"`
	Items       []Item   `json:"items,omitempty"`
	Erased      bool     `json:"erased"`
	ErasedAt    int64    `json:"erasedAt,omitempty"`
	Count       int      `json:"count,omitempty"`
	Unconfirmed []string `json:"unconfirmed,omitempty"`
}

func (s *State) Recall(subject string) (Recall, bool) {
	st := s.subjects[subject]
	if st == nil {
		return Recall{}, false
	}
	r := Recall{Subject: subject, Opened: st.opened}
	if !st.erased {
		r.Items = slices.Clone(st.items)
		return r, true
	}
	r.Erased, r.ErasedAt, r.Count, r.Unconfirmed = true, st.erasedAt, len(st.items), st.unconfirmed()
	return r, true
}

// ItemStore is the store the item named h is in, if the log names one: a
// content clerk reads only its own store's items (KRN-content).
func (s *State) ItemStore(h Hash) (string, bool) {
	it, ok := s.items[h]
	return it.Store, ok
}

// Unerased is an erased subject some store has not confirmed deleting.
type Unerased struct {
	Subject string   `json:"subject"`
	Items   int      `json:"items"`
	Stores  []string `json:"stores"`
}

// Unerased lists, by subject, every erase a store has not confirmed: the
// owner is told until it does (LOG-4 fails closed).
func (s *State) Unerased() []Unerased {
	var out []Unerased
	for _, sub := range slices.Sorted(maps.Keys(s.owing)) {
		st := s.subjects[sub]
		out = append(out, Unerased{Subject: sub, Items: len(st.items), Stores: st.unconfirmed()})
	}
	return out
}

// liveSubjects are the opened, unerased subjects, sorted.
func (s *State) liveSubjects() []string {
	var out []string
	for sub, st := range s.subjects {
		if !st.erased {
			out = append(out, sub)
		}
	}
	slices.Sort(out)
	return out
}

// ContentReport is what OpenContent found in the key table.
type ContentReport struct {
	// Missing are opened, unerased subjects whose key is missing or not
	// their own: their content does not open.
	Missing []string `json:"missing,omitempty"`
	// Unnamed are keys no subject.opened names: a crash between Put and
	// the log write, or a log older than the table. They are kept, since
	// the log alone cannot tell which, and nothing reads them.
	Unnamed []string `json:"unnamed,omitempty"`
}

// OpenContent opens the subject-key table and the content stores, after
// Boot, and re-applies every erase: it deletes the key of each erased
// subject still in the table and retries the stores. Seal and Read refuse
// until it has returned nil.
func (k *Kernel) OpenContent(keys Keys, stores map[string]ContentStore, now int64) (ContentReport, error) {
	var rep ContentReport
	listed, err := keys.List()
	if err != nil {
		return rep, err
	}
	slices.Sort(listed)
	for _, sub := range listed {
		switch st := k.s.subjects[sub]; {
		case st == nil:
			rep.Unnamed = append(rep.Unnamed, sub)
		case st.erased:
			// A delete still owed stays listed in Unerased under KeyTable
			// and is retried; a key back after its delete was confirmed
			// keeps content closed.
			if err := keys.Delete(sub); err != nil && st.confirmed[KeyTable] {
				return ContentReport{}, err
			}
		}
	}
	// A restore can bring back an item whose erase was confirmed after the
	// backup was taken: it is deleted again before any read.
	for _, st := range k.s.subjects {
		for _, it := range st.items {
			if cs := stores[it.Store]; st.erased && st.confirmed[it.Store] && cs != nil {
				if _, err := cs.Get(it.Hash); !errors.Is(err, ErrItem) {
					if err := cs.Delete(it.Hash); err != nil {
						return ContentReport{}, err
					}
				}
			}
		}
	}
	for _, sub := range k.s.liveSubjects() {
		dk, ok, err := keys.Get(sub)
		if err != nil {
			return ContentReport{}, err
		}
		if !ok || dataKeyID(dk) != k.s.subjects[sub].keyID {
			rep.Missing = append(rep.Missing, sub)
		}
	}
	k.keys, k.stores = keys, stores
	return rep, k.confirmErases(now)
}

// OpenSubject opens a new subject: a random ID and data key, the key put in
// the table before subject.opened is logged. An ID is never reopened.
func (k *Kernel) OpenSubject(now int64) (string, error) {
	if k.keys == nil {
		return "", ErrContentClosed
	}
	var id [16]byte
	var dk SubjectKey
	if _, err := io.ReadFull(k.log.cfg.Rand, id[:]); err != nil {
		return "", err
	}
	if _, err := io.ReadFull(k.log.cfg.Rand, dk[:]); err != nil {
		return "", err
	}
	sub := hex.EncodeToString(id[:])
	if k.s.subjects[sub] != nil {
		return "", ErrSubject
	}
	if err := k.keys.Put(sub, dk); err != nil {
		return "", err
	}
	// A key whose entry is not written is listed by the next OpenContent.
	if _, err := k.emit(now, TSubjectOpened, subjectOpened{sub, dataKeyID(dk)}); err != nil {
		return "", err
	}
	return sub, nil
}

// subjectKey is subject's data key, refusing an unknown or erased subject
// before any store is touched.
func (k *Kernel) subjectKey(subject string) (*subjectState, SubjectKey, error) {
	if k.keys == nil {
		return nil, SubjectKey{}, ErrContentClosed
	}
	st := k.s.subjects[subject]
	switch {
	case st == nil:
		return nil, SubjectKey{}, ErrSubject
	case st.erased:
		return nil, SubjectKey{}, ErrErased
	}
	dk, ok, err := k.keys.Get(subject)
	if err != nil {
		return nil, SubjectKey{}, err
	}
	if !ok || dataKeyID(dk) != st.keyID {
		return nil, SubjectKey{}, ErrSubjectKey
	}
	return st, dk, nil
}

// Seal encrypts plaintext under subject's key (AAD: subject and class),
// puts it in store under the hash of its ciphertext, then logs it. An item
// put but not logged is unreferenced, and unreadable once its subject's key
// goes.
func (k *Kernel) Seal(now int64, subject, store, class string, plaintext []byte) (Hash, error) {
	_, dk, err := k.subjectKey(subject)
	if err != nil {
		return Hash{}, err
	}
	cs := k.stores[store]
	if cs == nil || !ValidStore(store) || !name(class) {
		return Hash{}, ErrStore
	}
	a, err := newAEAD(dk)
	if err != nil {
		return Hash{}, err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := io.ReadFull(k.log.cfg.Rand, nonce); err != nil {
		return Hash{}, err
	}
	ct := a.Seal(nonce, nonce, plaintext, contentAAD(subject, class))
	h := Hash(sha256.Sum256(ct))
	if err := cs.Put(h, ct); err != nil {
		return Hash{}, err
	}
	if _, err := k.emit(now, TContentStored, contentStored{subject, store, h, class}); err != nil {
		return Hash{}, err
	}
	return h, nil
}

// Read opens the item named h. An erased or unknown subject is refused
// before its store is asked.
func (k *Kernel) Read(h Hash) ([]byte, error) {
	it, ok := k.s.items[h]
	if !ok {
		if k.keys == nil {
			return nil, ErrContentClosed
		}
		return nil, ErrItem
	}
	_, dk, err := k.subjectKey(it.subject)
	if err != nil {
		return nil, err
	}
	cs := k.stores[it.Store]
	if cs == nil {
		return nil, ErrStore
	}
	ct, err := cs.Get(h)
	if err != nil {
		return nil, err
	}
	a, err := newAEAD(dk)
	if err != nil {
		return nil, err
	}
	if Hash(sha256.Sum256(ct)) != h || len(ct) < a.NonceSize() {
		return nil, ErrItem
	}
	pt, err := a.Open(nil, ct[:a.NonceSize()], ct[a.NonceSize():], contentAAD(it.subject, it.Class))
	if err != nil {
		return nil, ErrItem
	}
	return pt, nil
}

// ReadFor opens the item named h for an agent session of lineage: the only
// way sealed content may reach one (LOG-4, D-169). It logs content.read
// first, so a delivery always leaves a record an erase can rewind; when the
// entry is not written nothing is returned. An erased or unknown item is
// refused before anything is logged.
func (k *Kernel) ReadFor(now int64, h Hash, lineage string) ([]byte, error) {
	if !validLineage(lineage) {
		return nil, ErrLineage
	}
	it, ok := k.s.items[h]
	if !ok {
		if k.keys == nil {
			return nil, ErrContentClosed
		}
		return nil, ErrItem
	}
	if _, _, err := k.subjectKey(it.subject); err != nil {
		return nil, err
	}
	if _, err := k.emit(now, TContentRead, contentRead{h, lineage}); err != nil {
		return nil, err
	}
	return k.Read(h)
}

// unlabelled is a character a label to look for may not hold: one invisible
// refuses, but for the two joiners (#2740).
func unlabelled(c rune) bool { return c != '‌' && c != '‍' && invisible(c) }

// sameLabel compares labels after folding case and collapsing runs of
// whitespace, so "alice  smith" reads "Alice Smith". Fuzzier matching is
// later (PLN-7).
func sameLabel(a, b string) bool {
	return strings.EqualFold(strings.Join(strings.Fields(a), " "), strings.Join(strings.Fields(b), " "))
}

// Named lists the live subjects one of whose labels reads label (sameLabel), and
// apart from them those with a label that could not be read (a missing key,
// a store down), so one fault does not hide every other subject. Before
// OpenContent it returns ErrContentClosed and no subjects, since none could
// be read. The log holds no name, so recall by name opens the labels. A
// blank or invalid-UTF-8 label, or one holding a character the owner cannot
// see (a control or the invisibles backup destinations refuse; the two
// joiners stay, as in STATUS lines, #2740), is ErrLabel: it would match
// labels the owner did not type (LOG-4, #3901).
func (k *Kernel) Named(label string) (found, unread []string, err error) {
	if strings.TrimSpace(label) == "" || !utf8.ValidString(label) || strings.ContainsFunc(label, unlabelled) {
		return nil, nil, ErrLabel
	}
	if k.keys == nil {
		return nil, nil, ErrContentClosed
	}
	for _, sub := range k.s.liveSubjects() {
		bad := false
		for _, it := range k.s.subjects[sub].items {
			if it.Class != ClassLabel {
				continue
			}
			pt, err := k.Read(it.Hash)
			if err != nil {
				bad = true
				continue
			}
			if sameLabel(string(pt), label) {
				found = append(found, sub)
				bad = false
				break
			}
		}
		if bad {
			unread = append(unread, sub)
		}
	}
	return found, unread, nil
}

// Confirmation is what an erase has reached.
type Confirmation struct {
	Subject string `json:"subject"`
	// Confirmed and Unconfirmed name the stores that have and have not
	// deleted the subject's items, and KeyTable once its key is or is not
	// destroyed. Unerased lists the unconfirmed ones and Tick retries them.
	Confirmed   []string `json:"confirmed"`
	Unconfirmed []string `json:"unconfirmed"`
	// Resealed and StillHeld name the older backups whose key table gave
	// the subject's key (D-168): Resealed now gives it no more at that
	// destination, and StillHeld may still, each with why. A backup that
	// never held the subject is in neither. Tick retries StillHeld.
	Resealed  []string     `json:"resealed,omitempty"`
	StillHeld []BackupHold `json:"stillHeld,omitempty"`
	// BackupsUnknown: no backup list is open (OpenBackups), so any older
	// backup may still hold the subject's items.
	BackupsUnknown bool `json:"backupsUnknown,omitempty"`
}

// BackupHold is an older backup that may still hold an erased subject's
// key, and why it was not re-sealed.
type BackupHold struct {
	Backup string `json:"backup"`
	Why    string `json:"why"`
}

// Backups is every older backup the box keeps a record of (BAK-1, D-168);
// broker/backup implements it. Subjects lists the subjects a backup's
// current key table gives keys for. Prepare takes what a re-seal of that
// table without every subject the state has erased needs and returns the
// re-seal's I/O. The kernel calls them under its lock; the I/O runs
// without it (Reseals), and the kernel checks Subjects after.
type Backups interface {
	List() []string
	Subjects(backup string) []string
	Prepare(backup string, keys Keys, s *State) (ResealIO, error)
}

// ResealIO does a re-seal's I/O at the backup's destination, without the
// kernel's lock, so a hung destination never holds STOP (KRN-7, #3317). It
// returns the commit, which runs under the lock and returns nil only once
// the re-seal is confirmed at the destination.
type ResealIO func() (commit func() error)

// OpenBackups gives the kernel the box's backups: from then on Reseals
// hands out a re-seal of each that gives an erased subject's key, and of
// one that failed, with the same backoff as a content store.
func (k *Kernel) OpenBackups(b Backups) { k.backups = b }

// Erase erases subject (LOG-4), an owner act the owner channel
// authenticates, like Stop. It logs subject.erased and anchors, then
// deletes the key, then asks each store holding the subject's items to
// delete them, logging erase.confirmed for the key table and for each store
// that does. Once the entry is logged the subject is erased whatever fails
// after: a narrowing entry that Open keeps, anchored or not, and re-applied
// at every start. A key delete that fails is returned, leaves KeyTable
// unconfirmed, and is retried, with backoff, by Tick and OpenContent. Before
// OpenContent the erase is logged and ErrContentClosed returned: the key
// goes when OpenContent runs. Every older backup that gives the subject's
// key is named StillHeld: the caller re-seals them without the lock
// (Reseals) and asks Confirm again.
func (k *Kernel) Erase(now int64, subject string) (Confirmation, error) {
	st := k.s.subjects[subject]
	switch {
	case st == nil:
		return Confirmation{}, ErrSubject
	case st.erased:
		return Confirmation{}, ErrErased
	}
	err := k.owner(now, TSubjectErased, subjectErased{subject, holding(st.items)})
	if !st.erased {
		return Confirmation{}, err
	}
	c := Confirmation{Subject: subject}
	if k.backups != nil {
		for _, b := range k.backups.List() {
			if slices.Contains(k.backups.Subjects(b), subject) {
				c.StillHeld = append(c.StillHeld, BackupHold{Backup: b})
			}
		}
	}
	if k.keys == nil {
		return k.Confirm(c), errors.Join(err, ErrContentClosed)
	}
	kerr, cerr := k.confirm(now, subject)
	return k.Confirm(c), errors.Join(err, kerr, cerr)
}

// Confirm is what the erase of c.Subject has reached now, for the backups
// c names: each that no longer gives the subject's key is Resealed, and
// each that still does StillHeld, with why.
func (k *Kernel) Confirm(c Confirmation) Confirmation {
	st := k.s.subjects[c.Subject]
	if st == nil || !st.erased {
		return c
	}
	out := Confirmation{Subject: c.Subject, Unconfirmed: st.unconfirmed()}
	for _, s := range st.stores {
		if st.confirmed[s] {
			out.Confirmed = append(out.Confirmed, s)
		}
	}
	if k.backups == nil {
		out.BackupsUnknown = true
		return out
	}
	held := slices.Clone(c.Resealed)
	for _, h := range c.StillHeld {
		held = append(held, h.Backup)
	}
	for _, b := range held {
		if !slices.Contains(k.backups.Subjects(b), c.Subject) {
			out.Resealed = append(out.Resealed, b)
			continue
		}
		why := errStillGiven
		if r, ok := k.retry[eraseRef{store: b}]; ok {
			why = r.err
		}
		out.StillHeld = append(out.StillHeld, BackupHold{b, why.Error()})
	}
	return out
}

var errStillGiven = errors.New("kernel: the backup's key table still gives the subject's key")

// Retried deletes back off, per subject and store, from RetryMin doubling
// to RetryMax, so a store that is down is not asked on every Tick. The
// backoff is kernel memory, not state: a restart asks every store again,
// and the erase stays in Unerased throughout.
const (
	RetryMin int64 = 1_000   // ms
	RetryMax int64 = 600_000 // ms
)

type (
	// eraseRef is one store's delete of one subject, or, with no subject,
	// one backup's re-seal, which covers every erased subject at once.
	eraseRef struct{ subject, store string }
	backoff  struct {
		last, wait int64 // the failed try's time and the wait after it
		err        error // what failed
	}
)

// held reports whether the delete of ref was tried and failed too recently.
// A now before that try (a wall clock stepped back) holds nothing, so a
// clock correction cannot keep a key on disk past RetryMax.
func (k *Kernel) held(ref eraseRef, now int64) bool {
	b, ok := k.retry[ref]
	return ok && b.last <= now && now < b.last+b.wait
}

// failed pushes the next try of ref back, doubling its wait.
func (k *Kernel) failed(ref eraseRef, now int64, err error) {
	if k.retry == nil {
		k.retry = map[eraseRef]backoff{}
	}
	w := RetryMin
	if b, ok := k.retry[ref]; ok {
		w = min(2*b.wait, RetryMax)
	}
	k.retry[ref] = backoff{now, w, err}
}

// confirm deletes subject's key and its items in each store not yet
// confirmed and not backing off, and logs each that does. One that fails
// stays unconfirmed and backs off: keyErr is the key delete's error, err a
// log error.
func (k *Kernel) confirm(now int64, subject string) (keyErr, err error) {
	st := k.s.subjects[subject]
	for _, store := range st.unconfirmed() {
		ref := eraseRef{subject, store}
		if k.held(ref, now) {
			continue
		}
		var derr error
		if store == KeyTable {
			keyErr = k.keys.Delete(subject)
			derr = keyErr
		} else if cs := k.stores[store]; cs == nil {
			derr = ErrStore
		} else {
			for _, it := range st.items {
				if it.Store != store {
					continue
				}
				if derr = cs.Delete(it.Hash); derr != nil {
					break
				}
			}
		}
		if derr != nil {
			k.failed(ref, now, derr)
			continue
		}
		delete(k.retry, ref)
		if _, err := k.emit(now, TEraseConfirmed, eraseConfirmed{subject, store}); err != nil {
			return keyErr, err
		}
	}
	return keyErr, nil
}

// confirmErases retries every erase not yet confirmed whose stores are not
// backing off. Only a log error is returned.
func (k *Kernel) confirmErases(now int64) error {
	for _, u := range k.s.Unerased() {
		if _, err := k.confirm(now, u.Subject); err != nil {
			return err
		}
	}
	return nil
}

// erased reports whether the log has erased subject.
func (s *State) erased(subject string) bool {
	st := s.subjects[subject]
	return st != nil && st.erased
}

// Reseal is one backup's re-seal that Reseals handed out: Run it without
// the kernel's lock, then pass it to Resealed under the lock.
type Reseal struct {
	Backup string
	io     ResealIO
	commit func() error
}

// Run does the re-seal's I/O at the backup's destination.
func (r *Reseal) Run() { r.commit = r.io() }

var errNotRun = errors.New("kernel: the re-seal did not run")

// Reseals hands out a re-seal of each backup that gives an erased
// subject's key and is neither backing off nor already handed out. One
// whose Prepare fails backs off.
func (k *Kernel) Reseals(now int64) []*Reseal {
	if k.backups == nil || k.keys == nil {
		return nil
	}
	var out []*Reseal
	for _, b := range k.backups.List() {
		ref := eraseRef{store: b}
		if _, out := k.resealing[b]; out || k.held(ref, now) || !slices.ContainsFunc(k.backups.Subjects(b), k.s.erased) {
			continue
		}
		io, err := k.backups.Prepare(b, k.keys, k.s)
		if err != nil {
			k.failed(ref, now, err)
			continue
		}
		if k.resealing == nil {
			k.resealing = map[string]bool{}
		}
		k.resealing[b] = false
		out = append(out, &Reseal{Backup: b, io: io})
	}
	return out
}

// Resealed commits r, which Run has run, and backs its backup off from
// now, the time Run finished, if that fails, unless RetryBackup ran
// while r was out (#3339).
func (k *Kernel) Resealed(now int64, r *Reseal) {
	moved := k.resealing[r.Backup]
	delete(k.resealing, r.Backup)
	ref, err := eraseRef{store: r.Backup}, errNotRun
	if r.commit != nil {
		err = r.commit()
	}
	if err != nil && !moved {
		k.failed(ref, now, err)
		return
	}
	delete(k.retry, ref)
}

// RetryBackup drops backup's backoff, so the next Reseals hands it out: its
// destination has changed since the re-seal that failed, or since the one
// out now, whose failure then sets none.
func (k *Kernel) RetryBackup(backup string) {
	delete(k.retry, eraseRef{store: backup})
	if _, out := k.resealing[backup]; out {
		k.resealing[backup] = true
	}
}

// ResealBackups runs every re-seal due in place, for a caller that holds
// no lock other callers wait on (Tick).
func (k *Kernel) ResealBackups(now int64) {
	for _, r := range k.Reseals(now) {
		r.Run()
		k.Resealed(now, r)
	}
}
