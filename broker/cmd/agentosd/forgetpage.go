package main

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"log"
	"slices"

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
// and the kernel's owner keys. Tell texts the owner (alertOwner, never
// held) after each erase a tap confirmed, naming the passkey but never
// the name: the passkey signs a challenge the owner cannot read, so a
// hacked page could put another find under the owner's tap, and the owner
// sees every page erase (as every passkey enrolled, #3228).
type pageForget struct {
	F    *forgetFlow
	K    keyReader
	Tell func(string) error
}

// forgetNotice is the owner's text after a page erase: by count, never by
// name (an erased label is not kept).
// A partial erase says so: its count of items erased is not known here.
func forgetNotice(r forgetResult, by key.PublicKey) string {
	what := plural(r.Items, "item")
	if r.NotErased > 0 {
		what = "some of " + plural(r.Items, "item") + ", not all,"
	}
	return "I forgot " + what + " on my Wi-Fi page after a tap by passkey " + noticePrint(by) + ". Not you? Text STOP."
}

// LogForgetUntold is logged when a page erase's notice could not be sent.
const LogForgetUntold = "forget: a page erase went through but the owner could not be told: %v"

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
func (p pageForget) Confirm(ctx context.Context, session, handle string, authData, clientData, sig []byte) (string, error) {
	subjects, ok := p.F.shown(handle)
	if !ok {
		return "", sockets.Code(localapi.ErrEraseStale)
	}
	anchors, live, _, err := ownerKeys(ctx, p.K)
	if err != nil {
		return "", sockets.Code(localapi.ErrEraseUnavailable)
	}
	by, ok := ownerTapped(forgetMsg(session, handle, subjects), anchors, live, authData, clientData, sig)
	if !ok {
		return "", sockets.Code(localapi.ErrEraseBadAssertion)
	}
	r, err := p.F.confirm(ctx, handle)
	if errors.Is(err, ErrForgetHandle) {
		// Another confirm of the same find took it first.
		return "", sockets.Code(localapi.ErrEraseStale)
	}
	if err != nil {
		return "", sockets.Code(localapi.ErrEraseUnavailable)
	}
	if r.Erased > 0 && p.Tell != nil {
		if err := p.Tell(forgetNotice(r, by)); err != nil {
			log.Printf(LogForgetUntold, err)
		}
	}
	return r.Text(), nil
}

// ownerTapped is the owner's passkey, an anchor or a live phone passkey,
// that made this assertion over msg (KEY-7's one encoding), if any.
func ownerTapped(msg []byte, anchors []key.PublicKey, live []key.Enrollment, authData, clientData, sig []byte) (key.PublicKey, bool) {
	canon, err := key.AssertionSig(key.Assertion{AuthenticatorData: authData, ClientDataJSON: clientData, Signature: sig})
	if err != nil {
		return key.PublicKey{}, false
	}
	for _, a := range anchors {
		if a.Verify(msg, canon) {
			return a, true
		}
	}
	for _, e := range live {
		if e.Passkey.Verify(msg, canon) {
			return e.Passkey, true
		}
	}
	return key.PublicKey{}, false
}
