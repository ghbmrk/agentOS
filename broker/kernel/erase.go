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
	subjectState struct {
		opened    int64
		keyID     string
		items     []Item
		erased    bool
		erasedAt  int64
		stores    []string // the stores that held items at the erase
		confirmed map[string]bool
	}
	itemOf struct {
		subject string
		Item
	}
)

// holding is the sorted stores items are in.
func holding(items []Item) []string {
	var out []string
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
			s.subjects[b.Subject] = &subjectState{opened: e.At, keyID: b.KeyID}
		}
	case TContentStored:
		b, err := body[contentStored](e)
		if err != nil {
			return err
		}
		if st := s.subjects[b.Subject]; st != nil && !st.erased && name(b.Store) && name(b.Class) && s.items[b.Hash].subject == "" {
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
			if len(st.stores) > 0 {
				s.owing[b.Subject] = true
			}
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
	}
	return nil
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

// OpenContent opens the subject-key table and the content stores, after
// Boot, and re-applies every erase: it deletes the key of each erased
// subject still in the table and each key no subject.opened names (a crash
// between Put and the log write), and retries the stores. It returns the
// opened, unerased subjects whose key is missing or not their own. Seal and
// Read refuse until it has returned nil.
func (k *Kernel) OpenContent(keys Keys, stores map[string]ContentStore, now int64) ([]string, error) {
	listed, err := keys.List()
	if err != nil {
		return nil, err
	}
	slices.Sort(listed)
	for _, sub := range listed {
		if st := k.s.subjects[sub]; st == nil || st.erased {
			if err := keys.Delete(sub); err != nil {
				return nil, err
			}
		}
	}
	var missing []string
	for _, sub := range k.s.liveSubjects() {
		dk, ok, err := keys.Get(sub)
		if err != nil {
			return nil, err
		}
		if !ok || dataKeyID(dk) != k.s.subjects[sub].keyID {
			missing = append(missing, sub)
		}
	}
	k.keys, k.stores, k.keyOwed = keys, stores, map[string]bool{}
	return missing, k.confirmErases(now)
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
	// A key whose entry is not written is dropped by the next OpenContent.
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
	if cs == nil || !name(store) || !name(class) {
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

// Named lists the live subjects one of whose labels reads name. The log
// holds no name, so recall by name opens the labels.
func (k *Kernel) Named(label string) ([]string, error) {
	var out []string
	for _, sub := range k.s.liveSubjects() {
		for _, it := range k.s.subjects[sub].items {
			if it.Class != ClassLabel {
				continue
			}
			pt, err := k.Read(it.Hash)
			if err != nil {
				return nil, err
			}
			if string(pt) == label {
				out = append(out, sub)
				break
			}
		}
	}
	return out, nil
}

// Confirmation is what an erase has reached.
type Confirmation struct {
	Subject     string   `json:"subject"`
	Confirmed   []string `json:"confirmed"`   // stores that deleted the subject's items
	Unconfirmed []string `json:"unconfirmed"` // stores that have not: Unerased lists them and Tick retries
	// OlderBackups is always true: a backup taken before the erase may
	// still hold its items. The kernel has no backup list to name them by;
	// the backup slice names and re-wraps them (#2865).
	OlderBackups bool `json:"olderBackups"`
}

// Erase erases subject (LOG-4), an owner act the owner channel
// authenticates, like Stop. It logs subject.erased and anchors, then
// deletes the key, then asks each store holding the subject's items to
// delete them, logging erase.confirmed for each that does. Once the entry
// is logged the subject is erased whatever fails after: a narrowing entry
// that Open keeps, anchored or not, and re-applied at every start. A key
// delete that fails is returned and retried by Tick and OpenContent. Before
// OpenContent the erase is logged and ErrContentClosed returned: the key
// goes when OpenContent runs.
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
	if k.keys == nil {
		return k.confirmation(subject), errors.Join(err, ErrContentClosed)
	}
	if kerr := k.keys.Delete(subject); kerr != nil {
		k.keyOwed[subject] = true
		err = errors.Join(err, kerr)
	}
	if cerr := k.confirm(now, subject); cerr != nil {
		err = errors.Join(err, cerr)
	}
	return k.confirmation(subject), err
}

func (k *Kernel) confirmation(subject string) Confirmation {
	st := k.s.subjects[subject]
	c := Confirmation{Subject: subject, Unconfirmed: st.unconfirmed(), OlderBackups: true}
	for _, s := range st.stores {
		if st.confirmed[s] {
			c.Confirmed = append(c.Confirmed, s)
		}
	}
	return c
}

// confirm asks each store not yet confirmed for subject to delete its
// items, and logs each that does. A store that fails stays unconfirmed; only
// a log error is returned.
func (k *Kernel) confirm(now int64, subject string) error {
	st := k.s.subjects[subject]
	for _, store := range st.unconfirmed() {
		cs := k.stores[store]
		if cs == nil {
			continue
		}
		ok := true
		for _, it := range st.items {
			if it.Store == store && cs.Delete(it.Hash) != nil {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if _, err := k.emit(now, TEraseConfirmed, eraseConfirmed{subject, store}); err != nil {
			return err
		}
	}
	return nil
}

// confirmErases retries the key deletes Erase could not make and the store
// deletes not yet confirmed. Only a log error is returned.
func (k *Kernel) confirmErases(now int64) error {
	for _, sub := range slices.Sorted(maps.Keys(k.keyOwed)) {
		if k.keys.Delete(sub) == nil {
			delete(k.keyOwed, sub)
		}
	}
	for _, u := range k.s.Unerased() {
		if err := k.confirm(now, u.Subject); err != nil {
			return err
		}
	}
	return nil
}
