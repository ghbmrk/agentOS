package main

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// The owner page's Forget step (LOG-4, KRN-forget c, #3414; D-284): the
// owner types a name, sees what the box holds under it by count and kind,
// and taps a passkey over exactly that list; only then is forgetFlow's
// confirm called. The kernel does not authenticate an erase (KRN-erase
// design 4), so this tap is the proof that the owner asked: a passkey, not
// a texted code, so a SIM swap cannot erase the owner's data. Any of the
// owner's passkeys proves it, a hardware key or an enrolled phone passkey,
// since an erase only takes away. agentosd signs nothing and keeps nothing
// beyond forgetFlow's pending finds (localsrv.Erase).

// domainPageForget separates a Forget tap's message from every other a
// passkey signs (the key package's domains end the same way).
const domainPageForget = "agentos.page.forget.v1\x00"

// forgetMsg is what the Forget tap signs: the page session, the find's
// handle and exactly the subjects it found, each length-prefixed. A tap
// over one find, or in one session, does not verify for another.
func forgetMsg(session, handle string, subjects []string) []byte {
	b := []byte(domainPageForget)
	for _, s := range append([]string{session, handle}, subjects...) {
		b = binary.AppendUvarint(b, uint64(len(s)))
		b = append(b, s...)
	}
	return b
}

// shown is the subjects handle's live find holds, without taking it.
func (f *forgetFlow) shown(handle string) ([]string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for h, p := range f.pending {
		if subtle.ConstantTimeCompare([]byte(h), []byte(handle)) == 1 {
			return slices.Clone(p.subjects), f.now().Before(p.until)
		}
	}
	return nil, false
}

// pageForget serves the erase ops (localsrv.Erase) over the forget flow
// and the kernel's owner keys. Tell texts the owner (forgetTold, kept until
// sent) after each erase a tap confirmed, naming the passkey and the
// counts by kind but never the name: the passkey signs a challenge the
// owner cannot read, so a hacked page could put another find under the
// owner's tap, and the owner sees every page erase (as every passkey
// enrolled, #3228).
type pageForget struct {
	F    *forgetFlow
	K    keyReader
	Tell func(string)
	Now  func() time.Time // nil: time.Now
}

// forgetNotice is the owner's text after a page erase: what this erase
// took, by count and kind, never by name (an erased label is not kept),
// and when. STOP ends every page session's reach to the erase ops
// (localsrv), and a phone passkey can be cut off; a hardware key cannot
// on the page, so its text names STOP alone.
func forgetNotice(r forgetResult, by key.PublicKey, phone bool, at time.Time) string {
	n := 0
	for _, c := range r.ErasedKinds {
		n += c
	}
	what := plural(n, "item") + " (" + kindList(r.ErasedKinds) + ")"
	if n == 0 {
		what = "a name with nothing kept under it"
	}
	out := "I forgot " + what + " on my Wi-Fi page at " + at.Format("15:04") + " after a tap by passkey " + noticePrint(by) + "."
	if r.NotErased > 0 {
		out += " Some others found with them are still kept."
	}
	if phone {
		return out + " Not you? Text STOP, and cut that passkey off on the passkey page."
	}
	return out + " Not you? Text STOP."
}

// LogForgetUntold is logged when a page erase's notice could not be sent
// or saved; a saved one is sent again.
const LogForgetUntold = "forget: a page erase went through but the owner could not be told yet: %v"

// LogForgetFind is logged when a find did not reach the kernel; the page
// gets ErrEraseUnavailable and no kernel text.
const LogForgetFind = "forget: a name could not be looked up: %v"

func (p pageForget) Find(ctx context.Context, session, name string) (localapi.EraseFound, error) {
	found, err := p.F.find(ctx, name)
	if err != nil {
		log.Printf(LogForgetFind, err)
		return localapi.EraseFound{}, sockets.Code(localapi.ErrEraseUnavailable)
	}
	out := localapi.EraseFound{Text: found.Text()}
	if found.Handle == "" {
		return out, nil
	}
	subjects, ok := p.F.shown(found.Handle)
	if !ok {
		return localapi.EraseFound{}, sockets.Code(localapi.ErrEraseUnavailable)
	}
	c := key.Challenge(forgetMsg(session, found.Handle, subjects))
	out.Handle, out.Challenge = found.Handle, c[:]
	return out, nil
}

// Confirm erases what handle's find showed once one of the owner's
// passkeys tapped over it in this session. Every refusal erases nothing
// and, but for ErrEraseStale, leaves the find to tap again.
func (p pageForget) Confirm(ctx context.Context, session, handle string, authData, clientData, sig []byte) (localapi.EraseDone, error) {
	subjects, ok := p.F.shown(handle)
	if !ok {
		return localapi.EraseDone{}, sockets.Code(localapi.ErrEraseStale)
	}
	anchors, live, _, err := ownerKeys(ctx, p.K)
	if err != nil {
		return localapi.EraseDone{}, sockets.Code(localapi.ErrEraseUnavailable)
	}
	by, phone, ok := ownerTapped(forgetMsg(session, handle, subjects), anchors, live, authData, clientData, sig)
	if !ok {
		return localapi.EraseDone{}, sockets.Code(localapi.ErrEraseBadAssertion)
	}
	r, err := p.F.confirm(ctx, handle)
	if errors.Is(err, ErrForgetHandle) {
		// Another confirm of the same find took it first.
		return localapi.EraseDone{}, sockets.Code(localapi.ErrEraseStale)
	}
	if err != nil {
		return localapi.EraseDone{}, sockets.Code(localapi.ErrEraseUnavailable)
	}
	if r.Erased > 0 && p.Tell != nil {
		now := time.Now
		if p.Now != nil {
			now = p.Now
		}
		p.Tell(forgetNotice(r, by, phone, now()))
	}
	return localapi.EraseDone{Text: r.Text(), Kept: r.kept()}, nil
}

// ownerTapped is the owner's passkey, an anchor or a live phone passkey
// (phone), that made this assertion over msg (KEY-7's one encoding), if
// any.
func ownerTapped(msg []byte, anchors []key.PublicKey, live []key.Enrollment, authData, clientData, sig []byte) (by key.PublicKey, phone, ok bool) {
	canon, err := key.AssertionSig(key.Assertion{AuthenticatorData: authData, ClientDataJSON: clientData, Signature: sig})
	if err != nil {
		return key.PublicKey{}, false, false
	}
	for _, a := range anchors {
		if a.Verify(msg, canon) {
			return a, false, true
		}
	}
	for _, e := range live {
		if e.Passkey.Verify(msg, canon) {
			return e.Passkey, true, true
		}
	}
	return key.PublicKey{}, false, false
}

// forgetTold is the page erases' notices not yet sent, saved in the state
// directory before each is sent, so a failed send or a restart does not
// lose one (KRN-forget-c-3 rests on the owner hearing every page erase).
// Each goes in order; a failed send leaves it and those after it for the
// next try.
type forgetTold struct {
	path string
	send func(string) error

	mu    sync.Mutex
	texts []string
}

const (
	// forgetToldFile holds forgetTold's notices in the state directory.
	forgetToldFile = "forget-untold.json"
	// forgetToldEvery is how often an unsent notice is tried again.
	forgetToldEvery = time.Minute
)

// openForgetTold reads the notices a past run did not send. A corrupt
// record is set aside (a durable copy, as erase-rewound.json's) and
// logged; one that cannot be read is logged.
func openForgetTold(path string, send func(string) error) *forgetTold {
	t := &forgetTold{path: path, send: send}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		log.Printf(LogForgetUntold, fmt.Errorf("the unsent record is unreadable: %v", err))
	case json.Unmarshal(b, &t.texts) != nil:
		t.texts = nil
		log.Printf(LogForgetUntold, fmt.Errorf("the unsent record is corrupt, set aside: %v", writeSynced(path+".corrupt", b)))
	}
	return t
}

// tell saves text, then sends what is saved.
func (t *forgetTold) tell(text string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.texts = append(t.texts, text)
	if err := t.saveLocked(); err != nil {
		log.Printf(LogForgetUntold, err)
	}
	t.flushLocked()
}

// flushLocked sends the saved notices in order until one fails.
func (t *forgetTold) flushLocked() {
	sent := 0
	for _, text := range t.texts {
		if err := t.send(text); err != nil {
			log.Printf(LogForgetUntold, err)
			break
		}
		sent++
	}
	if sent == 0 {
		return
	}
	t.texts = t.texts[sent:]
	if err := t.saveLocked(); err != nil {
		log.Printf(LogForgetUntold, err)
	}
}

func (t *forgetTold) saveLocked() error {
	b, err := json.Marshal(append([]string{}, t.texts...))
	if err != nil {
		return err
	}
	return writeSynced(t.path, b)
}

// run retries the saved notices every every until ctx ends, first at
// once, so a restart sends what an earlier run could not.
func (t *forgetTold) run(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		t.mu.Lock()
		if len(t.texts) > 0 {
			t.flushLocked()
		}
		t.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
