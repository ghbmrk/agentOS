// Package faces is the trusted side of face enrolment (VIS-core part c,
// VIS-faces): it keeps each enrolled person's template in a clerk.Secrets
// slot under vision-template/<id> (through Slots, which the wiring builds
// from the store, so this package calls no core write path), encrypted under a wrap key of its own,
// seals that wrap key as kernel content under the person's subject (LOG-4),
// and lends the templates to the untrusted vision service on its control
// socket. The service holds them in memory only and answers each face it
// sees with a name or unknown (DEV-7, D-207).
//
// Erase is by key: erasing the subject destroys the subject's key in the
// kernel, so the wrap key, and with it the template, can no longer be
// opened, even from a slot that survived. Every lend reads each wrap key
// again through ReadFor under the one service lineage, svc-vision, which
// the kernel logs first, so an erase rewinds it (D-169): a lend after an
// erase leaves that person out and removes the slot, and the service drops
// the template it held, since a lend replaces the whole set. A lend runs at
// every enrolment change, when Rewind is told of an erase, and every Every
// in Run, so a template outlives its subject's erase by at most Every.
//
// The content seam is the kernel's content socket (kernel/proc ContentSide,
// KRN-content), which admits one uid. That uid is this side's, the process
// that holds the slots, never the service's: a service that could seal
// could keep an unknown face's encoding as content (ASSUMPTIONS VIS-A13).
// Without a content seam there is no erase, so enrolment is refused
// (ErrNoErase) and no template is written.
//
// Enrolment is the owner's tier-4 step (DEV-7, CH-3), and the owner's page
// runs on the untrusted side, so this side does not take its word for it:
// Begin names the one enrolment (id, subject, the frame's digest, the
// consent notice and a fresh nonce) as a change for an anchor's passkey to
// co-sign, as the kernel's BackupTarget is, and Enrol makes a template only
// on that co-signature, once, within ApprovalTTL. Un-enrolment narrows, so
// it needs none.
package faces

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/vision"
)

// Hash names a sealed kernel item: the SHA-256 of its ciphertext.
type Hash [32]byte

// Content is the kernel's content seam for this side's own store: open a
// subject, seal an item under it, and read an item for a lineage, which
// the kernel logs before it answers. Part (f) adapts the content socket's
// client to it.
type Content interface {
	OpenSubject() (string, error)
	Seal(subject, class string, data []byte) (Hash, error)
	ReadFor(h Hash, lineage string) ([]byte, error)
}

// Control is the service's control socket (vision.ControlClient).
type Control interface {
	Enrol(ctx context.Context, f vision.Frame) ([]byte, error)
	Lend(ctx context.Context, ts []vision.Template) error
}

const (
	// Lineage is the one lineage every wrap-key read is logged under: the
	// vision service's, never an agent session's (comment 6459973175).
	Lineage = "svc-vision"
	// WrapClass is the wrap key's class as kernel content.
	WrapClass = "vision-wrap-key"
	// DefaultEvery is Run's period: the longest a template outlives its
	// subject's erase when no Rewind comes.
	DefaultEvery = 15 * time.Minute
	// ApprovalTTL is how long a Begin's change waits for its co-signature.
	ApprovalTTL = 10 * time.Minute
	// MaxPending bounds the enrolments begun and not yet signed; the
	// oldest is dropped for a new one.
	MaxPending = 8
)

// ConsentNotice is the page's own words before the tap (risk 23; comment
// 6459973175 point 3). Its digest is part of what the anchor signs, so a
// page that showed other words gets a signature Enrol refuses.
const ConsentNotice = "Enrolling someone else's face may need their consent under local law. " +
	"I keep their face template sealed until you remove them, and erasing them destroys it. " +
	"My backups don't keep templates yet, so after a restore they show as unknown until you enrol them again."

// Errors a caller tells apart.
var (
	ErrNoErase  = errors.New("faces: face enrolment needs erase, not yet available")
	ErrEnrolled = errors.New("faces: that id is already enrolled")
	ErrID       = errors.New("faces: an enrolment id is 1 to 32 of a-z, 0-9 and -")
	ErrFull     = errors.New("faces: no room for another enrolled person")
	// ErrApproval is an enrolment without a live anchor co-signature
	// over the change its Begin named: none, another change's, a used or
	// expired one, or a passkey that is not an anchor.
	ErrApproval = errors.New("faces: face enrolment needs your approval on the local page")
)

// Faces is the enrolled templates and the seams they move through.
type Faces struct {
	Slots Slots
	// Content is nil until the kernel serves this side a content store:
	// enrolment is refused until then.
	Content Content
	// Gone reports a ReadFor or Seal error that means the item can never
	// be read again: its subject erased or unknown, or the item unknown.
	// Any other error (the kernel not reached) keeps the slot and leaves
	// its template out of the lend until a later one reads it.
	Gone    func(error) bool
	Control Control
	// Anchors are the owner's anchor passkeys (the kernel's
	// State().Anchors): the only signers of an enrolment. Nil refuses
	// every enrolment.
	Anchors func() []key.PublicKey
	// Rand draws wrap keys and nonces; nil is crypto/rand.
	Rand io.Reader
	// Now is the clock for ApprovalTTL; nil is time.Now.
	Now func() time.Time

	pmu     sync.Mutex
	pending map[[32]byte]begun

	mu   sync.Mutex // one change or lend at a time
	lmu  sync.Mutex // lent alone, so Enrolled never waits on a lend
	lent map[string]bool
}

// Slots is the sealed store's surface for the template slots, built by the
// wiring from clerk.Secrets as clerk/devslot's Lend is: Names is
// Secrets.Names(clerk.VisionTemplateSlots), Put is Secrets.Put with
// clerk.KindStatic, Remove is Secrets.Remove, and Lend is
// Secrets.VisionTemplate, which opens a template slot alone, for one call,
// and wipes it after.
type Slots struct {
	Names  func() []string
	Put    func(slot string, rec []byte) error
	Remove func(slot string) error
	Lend   func(slot string) func(fn func(rec []byte) error) error
}

// SlotPrefix is clerk.VisionTemplateSlots: the only slots this package
// names.
const SlotPrefix = "vision-template/"

func (s Slots) has(slot string) bool { return slices.Contains(s.Names(), slot) }

// record is a slot's content: the subject and wrap-key item the template
// is bound to, and the template sealed under the wrap key.
type record struct {
	Subject string `json:"subject"`
	Item    string `json:"item"`
	Sealed  []byte `json:"sealed"`
}

func slot(id string) string { return SlotPrefix + id }

// templateAAD binds a sealed template to its id and subject, so a slot's
// blob cannot be moved to another person.
func templateAAD(id, subject string) []byte {
	return []byte("agentos/vision/template/" + id + "/" + subject)
}

// begun is an enrolment Begin named, waiting for its co-signature.
type begun struct {
	id, subject string
	frame       [32]byte
	exp         time.Time
}

// EnrolHash names one enrolment as a change a passkey co-signs
// (key.CosignMsg): the nonce, id, subject, the frame's digest and the
// consent notice's.
func EnrolHash(nonce [16]byte, id, subject string, frame [32]byte) [32]byte {
	notice := sha256.Sum256([]byte(ConsentNotice))
	h := sha256.New()
	h.Write([]byte("agentos.vision.enrol.v1\x00"))
	h.Write(nonce[:])
	for _, s := range []string{id, subject} {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(s))))
		h.Write([]byte(s))
	}
	h.Write(frame[:])
	h.Write(notice[:])
	return [32]byte(h.Sum(nil))
}

// FrameDigest is the digest of the frame the owner's page shows and the
// anchor approves.
func FrameDigest(fr vision.Frame) [32]byte {
	h := sha256.New()
	h.Write([]byte("agentos.vision.frame.v1\x00"))
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(fr.Format))))
	h.Write([]byte(fr.Format))
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(fr.Width)))
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(fr.Height)))
	h.Write(fr.Data)
	return [32]byte(h.Sum(nil))
}

// Begin names the enrolment of the face in frame as id, bound to subject
// (empty opens a new one), for an anchor's passkey to co-sign: the page
// asks for a tap over key.CosignMsg(what) after showing ConsentNotice. It
// refuses what Enrol would refuse before any signature, so the owner is
// not asked to approve an enrolment that cannot happen.
func (f *Faces) Begin(id, subject string, frame vision.Frame) (what [32]byte, err error) {
	if f.Content == nil {
		return what, ErrNoErase
	}
	if !vision.ValidEnrolledID(id) {
		return what, ErrID
	}
	var nonce [16]byte
	if _, err := io.ReadFull(f.rand(), nonce[:]); err != nil {
		return what, err
	}
	b := begun{id: id, subject: subject, frame: FrameDigest(frame), exp: f.now().Add(ApprovalTTL)}
	what = EnrolHash(nonce, id, subject, b.frame)
	f.pmu.Lock()
	defer f.pmu.Unlock()
	if f.pending == nil {
		f.pending = map[[32]byte]begun{}
	}
	for len(f.pending) >= MaxPending {
		var old [32]byte
		var at time.Time
		for w, p := range f.pending {
			if at.IsZero() || p.exp.Before(at) {
				old, at = w, p.exp
			}
		}
		delete(f.pending, old)
	}
	f.pending[what] = b
	return what, nil
}

// approved takes what's pending enrolment, once, and reports whether it
// is this one, unexpired, and c an anchor's co-signature over it.
func (f *Faces) approved(what [32]byte, id, subject string, frame vision.Frame, c key.Cosign) bool {
	f.pmu.Lock()
	b, ok := f.pending[what]
	delete(f.pending, what)
	f.pmu.Unlock()
	if !ok || !f.now().Before(b.exp) || b.id != id || b.subject != subject || b.frame != FrameDigest(frame) {
		return false
	}
	return f.Anchors != nil && key.In(f.Anchors(), c.By) && c.Over(what)
}

func (f *Faces) rand() io.Reader {
	if f.Rand == nil {
		return rand.Reader
	}
	return f.Rand
}

func (f *Faces) now() time.Time {
	if f.Now == nil {
		return time.Now()
	}
	return f.Now()
}

// Enrol makes the template of the one face in frame (the service's enrol
// call) and keeps it as id's, bound to subject; an empty subject opens a
// new one. It runs only on c, an anchor's co-signature over what, the
// change Begin named for this id, subject and frame: the owner's tier-4
// step, never a planner's. A what is used once, whatever the outcome. The
// wrap key is sealed in the kernel before the slot is written, so no slot
// exists whose template an erase cannot reach.
func (f *Faces) Enrol(ctx context.Context, id, subject string, frame vision.Frame, what [32]byte, c key.Cosign) error {
	if f.Content == nil {
		return ErrNoErase
	}
	if !vision.ValidEnrolledID(id) {
		return ErrID
	}
	if !f.approved(what, id, subject, frame, c) {
		return ErrApproval
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Slots.has(slot(id)) {
		return ErrEnrolled
	}
	if len(f.Slots.Names()) >= vision.MaxEnrolled {
		return ErrFull
	}
	tpl, err := f.Control.Enrol(ctx, frame)
	defer clear(tpl)
	if err != nil {
		return err
	}
	if subject == "" {
		if subject, err = f.Content.OpenSubject(); err != nil {
			return errors.Join(ErrNoErase, err)
		}
	}
	wk := make([]byte, 32)
	defer clear(wk)
	if _, err := io.ReadFull(f.rand(), wk); err != nil {
		return err
	}
	h, err := f.Content.Seal(subject, WrapClass, wk)
	if err != nil {
		return errors.Join(ErrNoErase, err)
	}
	sealed, err := seal(wk, tpl, templateAAD(id, subject))
	if err != nil {
		return err
	}
	rec, err := json.Marshal(record{Subject: subject, Item: hex.EncodeToString(h[:]), Sealed: sealed})
	if err != nil {
		return err
	}
	if err := f.Slots.Put(slot(id), rec); err != nil {
		return err
	}
	return f.lend(ctx)
}

// Unenrol empties id's slot and lends the rest, so the service drops the
// template. The wrap key stays in the kernel under the subject until the
// subject is erased; it opens nothing once the slot is gone.
func (f *Faces) Unenrol(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.Slots.Remove(slot(id)); err != nil {
		return err
	}
	return f.lend(ctx)
}

// Rewind is the D-169 rewind of svc-vision's reads of an erased subject:
// every slot bound to subject is removed, and the rest are lent, so the
// service drops that person's template at once.
func (f *Faces) Rewind(ctx context.Context, subject string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var errs []error
	for _, s := range f.Slots.Names() {
		var sub string
		err := f.Slots.Lend(s)(func(b []byte) error {
			var r record
			if err := json.Unmarshal(b, &r); err != nil {
				return err
			}
			sub = r.Subject
			return nil
		})
		if err == nil && sub == subject {
			errs = append(errs, f.Slots.Remove(s))
		}
	}
	return errors.Join(append(errs, f.lend(ctx))...)
}

// Sync lends the templates afresh, as a start does.
func (f *Faces) Sync(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lend(ctx)
}

// Run lends at once and then every every (DefaultEvery when zero) until
// ctx ends, so an erase no Rewind reported still reaches the service.
func (f *Faces) Run(ctx context.Context, every time.Duration, logf func(string, ...any)) {
	if every <= 0 {
		every = DefaultEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := f.Sync(ctx); err != nil && logf != nil {
			logf("vision: lending the enrolled templates failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Enrolled reports an id whose template the last lend carried, or, after
// a lend that failed, both the last two did: the client's own list
// (vision.Client.Enrolled), never the service's word.
func (f *Faces) Enrolled(id string) bool {
	f.lmu.Lock()
	defer f.lmu.Unlock()
	return f.lent[id]
}

// lend opens every slot's template through its wrap key, read for
// Lineage, and lends them all; the caller holds mu. A slot whose wrap key
// is gone is removed; one that cannot be read now is left out. Every
// opened template and wrap key is zeroed once the lend returns.
func (f *Faces) lend(ctx context.Context) error {
	var ts []vision.Template
	defer func() {
		for _, t := range ts {
			clear(t.Vec)
		}
	}()
	var errs []error
	for _, s := range f.Slots.Names() {
		id := strings.TrimPrefix(s, SlotPrefix)
		var tpl []byte
		gone := false
		err := f.Slots.Lend(s)(func(b []byte) error {
			var r record
			if err := json.Unmarshal(b, &r); err != nil {
				return err
			}
			defer clear(r.Sealed)
			var h Hash
			if n, err := hex.Decode(h[:], []byte(r.Item)); err != nil || n != len(h) {
				return errors.New("faces: a slot names no item")
			}
			if f.Content == nil {
				return ErrNoErase
			}
			wk, err := f.Content.ReadFor(h, Lineage)
			defer clear(wk)
			if err != nil {
				gone = f.Gone != nil && f.Gone(err)
				return err
			}
			tpl, err = open(wk, r.Sealed, templateAAD(id, r.Subject))
			return err
		})
		switch {
		case gone:
			errs = append(errs, f.Slots.Remove(s))
		case err != nil:
			errs = append(errs, err)
		case vision.ValidEnrolledID(id):
			ts = append(ts, vision.Template{ID: id, Vec: tpl})
		default:
			clear(tpl)
		}
	}
	err := f.Control.Lend(ctx, ts)
	lent := map[string]bool{}
	f.lmu.Lock()
	for _, t := range ts {
		// A lend that failed may or may not have landed, so Enrolled
		// keeps only the ids both sets hold: one just un-enrolled or
		// erased is refused at once, and one just enrolled waits for a
		// lend that lands (fails closed).
		if err == nil || f.lent[t.ID] {
			lent[t.ID] = true
		}
	}
	f.lent = lent
	f.lmu.Unlock()
	return errors.Join(append(errs, err)...)
}

func seal(key, plain, aad []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	n := make([]byte, g.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return g.Seal(n, n, plain, aad), nil
}

func open(key, blob, aad []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < g.NonceSize() {
		return nil, errors.New("faces: sealed template too short")
	}
	return g.Open(nil, blob[:g.NonceSize()], blob[g.NonceSize():], aad)
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("faces: a wrap key is 32 bytes")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}
