package heads

// REQ: STO-1, KEY-7, STO-4

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/channel"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The channel's Heads and Revoked hooks are this package.
var (
	_ channel.Heads = (*Store)(nil)
	_               = channel.Config{Revoked: (*Store)(nil).Revoked}
)

// klog is a real kernel log, so every head and entry here is in the
// kernel's own encoding (kernel.SignHead, kernel.Entry), not a copy of it.
type klog struct {
	t    *testing.T
	priv ed25519.PrivateKey
	log  *kernel.Log
	at   int64
}

func newKlog(t *testing.T, priv ed25519.PrivateKey) *klog {
	t.Helper()
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{},
		Pub: priv.Public().(ed25519.PublicKey), Sign: priv, Rand: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	return &klog{t: t, priv: priv, log: l}
}

func (k *klog) add(typ string, v int, body any) wire.Entry {
	k.t.Helper()
	k.at++
	e, err := k.log.Append(k.at, typ, v, body)
	if err != nil {
		k.t.Fatal(err)
	}
	b, err := json.Marshal(e)
	if err != nil {
		k.t.Fatal(err)
	}
	return wire.Entry{ID: e.Seq, Body: b}
}

func (k *klog) head() wire.Head {
	es := k.log.Entries()
	last := es[len(es)-1]
	return toWire(kernel.SignHead(k.priv, last.Seq, last.Hash()))
}

func toWire(h kernel.Head) wire.Head {
	w := wire.Head{ID: h.Seq, Seq: h.Seq}
	copy(w.Hash[:], h.Hash[:])
	copy(w.Sig[:], h.Sig)
	return w
}

type journal struct{ b []byte }

func (j *journal) Load() ([]byte, error) { return j.b, nil }
func (j *journal) Append(b []byte) error { j.b = append(j.b, b...); return nil }
func (j *journal) Truncate(n int) error  { j.b = j.b[:n]; return nil }

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func open(t *testing.T, pub ed25519.PublicKey, j *journal) *Store {
	t.Helper()
	s, err := Open(Config{Kernel: pub, Journal: j})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestKeepsEveryHeadRefusesFork (STO-1): the enforcer keeps every head the
// kernel sends, across a restart, not only the newest; a second head at a
// seq it holds with another hash, a head below its newest, and an entry
// whose hash differs from the head at its seq are refused and reported, and
// none of them replaces what it holds. Catches a rollback anchor that
// forgets: an anchor keeping only the latest head, or overwriting one,
// lets a rolled-back core re-grow past it unseen.
func TestKeepsEveryHeadRefusesFork(t *testing.T) {
	pub, priv := keys(t)
	k := newKlog(t, priv)
	j := &journal{}
	forked := make(chan uint64, 8)
	s, err := Open(Config{Kernel: pub, Journal: j, Fork: func(seq uint64) { forked <- seq }})
	if err != nil {
		t.Fatal(err)
	}
	var sent []wire.Head
	for i := 0; i < 3; i++ {
		e := k.add(kernel.TKeyPaused, 1, map[string]key.ID{"ID": {byte(i)}})
		h := k.head()
		if err := s.Head(h); err != nil {
			t.Fatalf("head %d: %v", h.Seq, err)
		}
		if err := s.Entry(e); err != nil {
			t.Fatalf("entry %d: %v", e.ID, err)
		}
		sent = append(sent, h)
	}
	// A resend after a resume is no change.
	if err := s.Head(sent[1]); err != nil {
		t.Fatalf("resent head: %v", err)
	}

	// A rolled-back core: the same seq 3 with another history.
	rb := newKlog(t, priv)
	rb.add(kernel.TKeyPaused, 1, map[string]key.ID{"ID": {0}})
	rb.add(kernel.TKeyPaused, 1, map[string]key.ID{"ID": {1}})
	forged := rb.add(kernel.TKeyResumed, 1, map[string]key.ID{"ID": {0}})
	if err := s.Head(rb.head()); !errors.Is(err, ErrFork) {
		t.Fatalf("forked head: %v, want ErrFork", err)
	}
	if err := s.Entry(forged); !errors.Is(err, ErrFork) {
		t.Fatalf("forked entry: %v, want ErrFork", err)
	}
	// The rolled-back core's head at an earlier seq the store holds.
	rb2 := newKlog(t, priv)
	rb2.add(kernel.TKeyResumed, 1, map[string]key.ID{"ID": {0}})
	if err := s.Head(rb2.head()); !errors.Is(err, ErrFork) {
		t.Fatalf("head below the newest: %v, want ErrFork", err)
	}
	var forks []uint64
	for range 3 {
		select {
		case seq := <-forked:
			forks = append(forks, seq)
		case <-time.After(5 * time.Second):
			t.Fatal("fork not reported")
		}
	}
	slices.Sort(forks)
	if !slices.Equal(forks, []uint64{1, 3, 3}) {
		t.Fatalf("forks reported %v, want [1 3 3]", forks)
	}
	// A head signed by another key is not the kernel's.
	_, other := keys(t)
	ok := newKlog(t, other)
	for range 4 {
		ok.add(kernel.TKeyPaused, 1, map[string]key.ID{"ID": {9}})
	}
	if err := s.Head(ok.head()); !errors.Is(err, ErrBadSig) {
		t.Fatalf("head from another key: %v, want ErrBadSig", err)
	}

	check := func(s *Store) {
		t.Helper()
		if got := s.Heads(); !slices.Equal(got, sent) {
			t.Fatalf("heads %v, want every sent head %v", got, sent)
		}
		if l, ok := s.Latest(); !ok || l != sent[2] {
			t.Fatalf("latest %v %v", l, ok)
		}
		if n := len(s.Entries()); n != 3 {
			t.Fatalf("%d entries kept, want 3", n)
		}
		if !s.Paused(key.ID{0}) {
			t.Fatal("the forged resume was applied")
		}
	}
	check(s)
	check(open(t, pub, j)) // a restart keeps every head and entry
}

// The head-domain message is the kernel's byte for byte: a head the kernel
// signs verifies here, and a key derivation's signature by the same
// sub-key over the same bytes in another domain does not (KEY-3).
func TestHeadDomain(t *testing.T) {
	pub, priv := keys(t)
	s := open(t, pub, &journal{})
	k := newKlog(t, priv)
	k.add(kernel.TKeyPaused, 1, map[string]key.ID{"ID": {1}})
	h := k.head()
	bad := h
	copy(bad.Sig[:], ed25519.Sign(priv, append([]byte(key.DomainLink), h.Hash[:]...)))
	if err := s.Head(bad); !errors.Is(err, ErrBadSig) {
		t.Fatalf("other-domain signature: %v", err)
	}
	if err := s.Head(h); err != nil {
		t.Fatalf("kernel head: %v", err)
	}
}

// Entries are the closed key-change and erase set, in the kernel's one
// encoding; anything else, or the same entry re-encoded, is refused.
func TestEntryStrict(t *testing.T) {
	pub, priv := keys(t)
	s := open(t, pub, &journal{})
	k := newKlog(t, priv)
	step := k.add(kernel.TStop, 1, map[string]string{})
	if err := s.Entry(step); !errors.Is(err, ErrType) {
		t.Fatalf("stop entry: %v, want ErrType", err)
	}
	e := k.add(kernel.TKeyRevoked, 1, map[string]key.ID{"ID": {7}})
	var m map[string]any
	if err := json.Unmarshal(e.Body, &m); err != nil {
		t.Fatal(err)
	}
	re, _ := json.MarshalIndent(m, "", " ")
	if err := s.Entry(wire.Entry{ID: e.ID, Body: re}); !errors.Is(err, ErrEncoding) {
		t.Fatalf("re-encoded entry: %v, want ErrEncoding", err)
	}
	if err := s.Entry(e); err != nil {
		t.Fatal(err)
	}
	if !s.RevokedID(key.ID{7}) {
		t.Fatal("key.revoked not applied")
	}
	for _, body := range []string{`{"ID":"zz"}`, `{"ID":"07","x":1}`, `{}`} {
		e := k.add(kernel.TKeyRevoked, 1, json.RawMessage(body))
		if err := s.Entry(e); err == nil {
			t.Fatalf("body %s kept", body)
		}
	}
}

// authenticator is the owner's enforcer passkey, as the policy tests make
// one: an ES256 credential on the enforcer's own RP ID.
type authenticator struct {
	t    *testing.T
	priv *ecdsa.PrivateKey
	rpID string
}

func newAuthenticator(t *testing.T, rpID string) *authenticator {
	t.Helper()
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &authenticator{t: t, priv: p, rpID: rpID}
}

func (a *authenticator) Public() key.PublicKey {
	point, err := a.priv.PublicKey.Bytes()
	if err != nil {
		a.t.Fatal(err)
	}
	pk, err := key.ES256(a.rpID, point)
	if err != nil {
		a.t.Fatal(err)
	}
	return pk
}

func (a *authenticator) Sign(msg []byte) []byte {
	c := key.Challenge(msg)
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(c[:]),
		"origin": "https://" + a.rpID, "crossOrigin": false})
	h := sha256.Sum256([]byte(a.rpID))
	ad := append(h[:], 0x01|0x04, 0, 0, 0, 0)
	cdh := sha256.Sum256(cd)
	m := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, m[:])
	if err != nil {
		a.t.Fatal(err)
	}
	b, err := key.AssertionSig(key.Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig})
	if err != nil {
		a.t.Fatal(err)
	}
	return b
}

// TestRevokedSubKeyRefused (KEY-7, STO-1): once the owner revokes the
// kernel's sub-key with the enforcer passkey, the revocation set refuses
// it (the channel's hello and every frame check it), and the store keeps
// no head or entry it signs, across a restart. Nothing the stolen core
// sends, and no other credential, revokes or un-revokes. Catches a stolen
// core's key still working.
func TestRevokedSubKeyRefused(t *testing.T) {
	pub, priv := keys(t)
	j := &journal{}
	s := open(t, pub, j)
	k := newKlog(t, priv)
	if err := s.Entry(k.add(kernel.TKeyPaused, 1, map[string]key.ID{"ID": {1}})); err != nil {
		t.Fatal(err)
	}
	if err := s.Head(k.head()); err != nil {
		t.Fatal(err)
	}

	owner := newAuthenticator(t, "enforcer.home.arpa")
	thief := newAuthenticator(t, "enforcer.home.arpa")
	root := SubKeyRoot(owner.Public(), pub)
	if err := s.RevokeSubKey(owner.Public(), pub, thief.Sign(key.RootMsg(root))); !errors.Is(err, ErrBadSig) {
		t.Fatalf("another passkey's revocation: %v", err)
	}
	ed := key.Ed25519(pub)
	if err := s.RevokeSubKey(ed, pub, ed25519.Sign(priv, key.RootMsg(SubKeyRoot(ed, pub)))); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("the sub-key revoking itself as owner: %v", err)
	}
	other, _ := keys(t)
	if err := s.RevokeSubKey(owner.Public(), other, owner.Sign(key.RootMsg(root))); !errors.Is(err, ErrBadSig) {
		t.Fatalf("a signature for one key revoking another: %v", err)
	}
	if s.Revoked(pub) {
		t.Fatal("revoked before the owner signed")
	}
	if err := s.RevokeSubKey(owner.Public(), pub, owner.Sign(key.RootMsg(root))); err != nil {
		t.Fatal(err)
	}

	for _, s := range []*Store{s, open(t, pub, j)} {
		if !s.Revoked(pub) {
			t.Fatal("the sub-key is not in the revocation set")
		}
		k.add(kernel.TKeyResumed, 1, map[string]key.ID{"ID": {1}})
		e := k.add(kernel.TKeyResumed, 1, map[string]key.ID{"ID": {1}})
		if err := s.Head(k.head()); !errors.Is(err, ErrRevoked) {
			t.Fatalf("head from the revoked sub-key: %v", err)
		}
		if err := s.Entry(e); !errors.Is(err, ErrRevoked) {
			t.Fatalf("entry from the revoked sub-key: %v", err)
		}
		if !s.Paused(key.ID{1}) || len(s.Heads()) != 1 {
			t.Fatal("the stolen core changed the store")
		}
	}
}

// Kernel-logged revocations fill the set too: key IDs (and pauses until
// resumed), edge keys and passkeys. A revocation is final: no later entry
// lifts it.
func TestEntriesFillRevocationSet(t *testing.T) {
	pub, priv := keys(t)
	j := &journal{}
	s := open(t, pub, j)
	k := newKlog(t, priv)
	edge, _ := keys(t)
	pk := newAuthenticator(t, "core.home.arpa").Public()
	for _, e := range []wire.Entry{
		k.add(kernel.TKeyRevoked, 1, map[string]key.ID{"ID": {1}}),
		k.add(kernel.TKeyPaused, 1, map[string]key.ID{"ID": {2}}),
		k.add(kernel.TKeyPaused, 1, map[string]key.ID{"ID": {3}}),
		k.add(kernel.TKeyResumed, 1, map[string]key.ID{"ID": {3}}),
		k.add(kernel.TKeyResumed, 1, map[string]key.ID{"ID": {1}}),
		k.add(kernel.TEdgeRevoked, 1, map[string]ed25519.PublicKey{"key": edge}),
		k.add(kernel.TUnenrolled, 1, key.Unenrollment{Passkey: pk, By: key.Ed25519(pub), Sig: []byte{1}}),
		k.add(kernel.TSubjectErased, 1, map[string]any{"subject": "s1", "stores": []string{"mail"}}),
	} {
		if err := s.Entry(e); err != nil {
			t.Fatalf("entry %d: %v", e.ID, err)
		}
	}
	for _, s := range []*Store{s, open(t, pub, j)} {
		if !s.RevokedID(key.ID{1}) || s.RevokedID(key.ID{2}) || !s.Paused(key.ID{2}) || s.Paused(key.ID{3}) {
			t.Fatal("key IDs")
		}
		if !s.Revoked(edge) || s.Revoked(pub) || !s.RevokedPasskey(pk) {
			t.Fatal("public keys")
		}
	}
}

// After a core trip the enforcer keeps no head or entry (STO-1, KRN-12);
// the trip survives a restart.
func TestTripKeepsNone(t *testing.T) {
	pub, priv := keys(t)
	j := &journal{}
	s := open(t, pub, j)
	if err := s.Trip(); err != nil {
		t.Fatal(err)
	}
	k := newKlog(t, priv)
	e := k.add(kernel.TKeyRevoked, 1, map[string]key.ID{"ID": {1}})
	for _, s := range []*Store{s, open(t, pub, j)} {
		if err := s.Head(k.head()); !errors.Is(err, ErrTripped) {
			t.Fatalf("head after a trip: %v", err)
		}
		if err := s.Entry(e); !errors.Is(err, ErrTripped) {
			t.Fatalf("entry after a trip: %v", err)
		}
	}
}

// A failed journal write keeps nothing, so the channel answers "not kept"
// and the kernel resends; a torn last record is dropped at open.
func TestJournal(t *testing.T) {
	pub, priv := keys(t)
	j := &failing{}
	s := open(t, pub, &j.journal)
	s.cfg.Journal = j
	k := newKlog(t, priv)
	k.add(kernel.TKeyPaused, 1, map[string]key.ID{"ID": {1}})
	j.fail = true
	if err := s.Head(k.head()); err == nil || len(s.Heads()) != 0 {
		t.Fatal("kept a head the journal refused")
	}
	j.fail = false
	if err := s.Head(k.head()); err != nil {
		t.Fatal(err)
	}
	j.b = append(j.b, `{"head":{"seq":`...) // a power cut mid-append
	s = open(t, pub, &j.journal)
	if got := s.Heads(); len(got) != 1 {
		t.Fatalf("after a torn record: %v", got)
	}
	k.add(kernel.TKeyPaused, 1, map[string]key.ID{"ID": {2}})
	if err := s.Head(k.head()); err != nil { // the next append is clean
		t.Fatal(err)
	}
	if got := open(t, pub, &j.journal).Heads(); len(got) != 2 {
		t.Fatalf("append after a torn record, reopened: %v", got)
	}
	j.b = append(j.b, "\n{}\n"...)
	if _, err := Open(Config{Kernel: pub, Journal: &j.journal}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt journal: %v", err)
	}
}

type failing struct {
	journal
	fail bool
}

func (f *failing) Append(b []byte) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.journal.Append(b)
}

// Heads only rise: a new head below the newest held is a rewound log, and
// an entry whose Prev is not the hash of the entry held before it forks.
func TestHeadsOnlyRise(t *testing.T) {
	pub, priv := keys(t)
	s := open(t, pub, &journal{})
	k := newKlog(t, priv)
	k.add(kernel.TKeyPaused, 1, map[string]key.ID{"ID": {1}})
	low := k.head()
	e2 := k.add(kernel.TKeyPaused, 1, map[string]key.ID{"ID": {2}})
	if err := s.Head(k.head()); err != nil {
		t.Fatal(err)
	}
	if err := s.Head(low); !errors.Is(err, ErrFork) {
		t.Fatalf("head below the newest: %v, want ErrFork", err)
	}
	if err := s.Entry(e2); err != nil {
		t.Fatal(err)
	}
	other := newKlog(t, priv)
	o1 := other.add(kernel.TKeyRevoked, 1, map[string]key.ID{"ID": {9}})
	if err := s.Entry(o1); !errors.Is(err, ErrFork) {
		t.Fatalf("entry the next held entry does not chain from: %v, want ErrFork", err)
	}
	if s.RevokedID(key.ID{9}) || len(s.Heads()) != 1 {
		t.Fatal("a fork changed the store")
	}
}
