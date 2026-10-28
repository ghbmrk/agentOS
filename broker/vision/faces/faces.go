// Package faces is the trusted side of face enrolment (VIS-core part c,
// VIS-faces): it keeps each enrolled person's template in a clerk.Secrets
// slot under vision-template/<id>, encrypted under a wrap key of its own,
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
package faces

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
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
)

// Errors a caller tells apart.
var (
	ErrNoErase  = errors.New("faces: face enrolment needs erase, not yet available")
	ErrEnrolled = errors.New("faces: that id is already enrolled")
	ErrID       = errors.New("faces: an enrolment id is 1 to 32 of a-z, 0-9 and -")
	ErrFull     = errors.New("faces: no room for another enrolled person")
)

// Faces is the enrolled templates and the seams they move through.
type Faces struct {
	Secrets *clerk.Secrets
	// Content is nil until the kernel serves this side a content store:
	// enrolment is refused until then.
	Content Content
	// Gone reports a ReadFor or Seal error that means the item can never
	// be read again: its subject erased or unknown, or the item unknown.
	// Any other error (the kernel not reached) keeps the slot and leaves
	// its template out of the lend until a later one reads it.
	Gone    func(error) bool
	Control Control
	// Rand draws wrap keys; nil is crypto/rand.
	Rand io.Reader

	mu   sync.Mutex // one change or lend at a time
	lmu  sync.Mutex // lent alone, so Enrolled never waits on a lend
	lent map[string]bool
}

// record is a slot's content: the subject and wrap-key item the template
// is bound to, and the template sealed under the wrap key.
type record struct {
	Subject string `json:"subject"`
	Item    string `json:"item"`
	Sealed  []byte `json:"sealed"`
}

func slot(id string) string { return clerk.VisionTemplateSlots + id }

// templateAAD binds a sealed template to its id and subject, so a slot's
// blob cannot be moved to another person.
func templateAAD(id, subject string) []byte {
	return []byte("agentos/vision/template/" + id + "/" + subject)
}

// Enrol makes the template of the one face in f (the service's enrol
// call) and keeps it as id's, bound to subject; an empty subject opens a
// new one. The wrap key is sealed in the kernel before the slot is written,
// so no slot exists whose template an erase cannot reach. It runs only
// from the owner's tier-4 page step (part c2), never from a planner.
func (f *Faces) Enrol(ctx context.Context, id, subject string, frame vision.Frame) error {
	if f.Content == nil {
		return ErrNoErase
	}
	if !vision.ValidEnrolledID(id) {
		return ErrID
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Secrets.Has(slot(id)) {
		return ErrEnrolled
	}
	if len(f.Secrets.Names(clerk.VisionTemplateSlots)) >= vision.MaxEnrolled {
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
	r := f.Rand
	if r == nil {
		r = rand.Reader
	}
	if _, err := io.ReadFull(r, wk); err != nil {
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
	if err := f.Secrets.Put(slot(id), clerk.KindStatic, rec); err != nil {
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
	if err := f.Secrets.Remove(slot(id)); err != nil {
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
	for _, s := range f.Secrets.Names(clerk.VisionTemplateSlots) {
		var sub string
		err := f.Secrets.VisionTemplate(s)(func(b []byte) error {
			var r record
			if err := json.Unmarshal(b, &r); err != nil {
				return err
			}
			sub = r.Subject
			return nil
		})
		if err == nil && sub == subject {
			errs = append(errs, f.Secrets.Remove(s))
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

// Enrolled reports an id whose template the last lend carried: the
// client's own list (vision.Client.Enrolled), never the service's word.
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
	for _, s := range f.Secrets.Names(clerk.VisionTemplateSlots) {
		id := strings.TrimPrefix(s, clerk.VisionTemplateSlots)
		var tpl []byte
		gone := false
		err := f.Secrets.VisionTemplate(s)(func(b []byte) error {
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
			errs = append(errs, f.Secrets.Remove(s))
		case err != nil:
			errs = append(errs, err)
		case vision.ValidEnrolledID(id):
			ts = append(ts, vision.Template{ID: id, Vec: tpl})
		default:
			clear(tpl)
		}
	}
	if err := f.Control.Lend(ctx, ts); err != nil {
		// The service may still hold the last set; Enrolled keeps
		// naming it, since the service may still name those faces.
		return errors.Join(append(errs, err)...)
	}
	lent := map[string]bool{}
	for _, t := range ts {
		lent[t.ID] = true
	}
	f.lmu.Lock()
	f.lent = lent
	f.lmu.Unlock()
	return errors.Join(errs...)
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
