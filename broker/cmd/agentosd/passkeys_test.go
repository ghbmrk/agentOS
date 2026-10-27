package main

// REQ: KEY-4, ID-1, CH-3, REC-3

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
	"github.com/ghbmrk/agentos/broker/sockets"
)

const testRP = "agentos.internal"

// authenticator is a software WebAuthn ES256 credential on testRP: no
// real secret and no hardware.
type authenticator struct {
	k     *ecdsa.PrivateKey
	highS bool   // return the high-S twin of each signature
	rp    string // the RP ID it is made on and taps on; testRP when empty
}

func (a *authenticator) rpID() string {
	if a.rp == "" {
		return testRP
	}
	return a.rp
}

func newAuthenticator(t *testing.T) *authenticator {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &authenticator{k: k}
}

// point is what the page's create() hands agentosd.
func (a *authenticator) point(t *testing.T) []byte {
	t.Helper()
	b, err := a.k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (a *authenticator) public(t *testing.T) key.PublicKey {
	t.Helper()
	pk, err := key.ES256(a.rpID(), a.point(t))
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

// get is the browser's get() over challenge, from https://testRP, user
// present and verified.
func (a *authenticator) get(t *testing.T, challenge []byte) (authData, clientData, sig []byte) {
	t.Helper()
	rp := sha256.Sum256([]byte(a.rpID()))
	authData = append(rp[:], 0x05, 0, 0, 0, 0)
	clientData, _ = json.Marshal(map[string]any{"type": "webauthn.get", "origin": "https://" + a.rpID(),
		"challenge": base64.RawURLEncoding.EncodeToString(challenge), "crossOrigin": false})
	cdh := sha256.Sum256(clientData)
	h := sha256.Sum256(append(append([]byte{}, authData...), cdh[:]...))
	r, s, err := ecdsa.Sign(rand.Reader, a.k, h[:])
	if err != nil {
		t.Fatal(err)
	}
	half := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	if (s.Cmp(half) > 0) != a.highS {
		s.Sub(elliptic.P256().Params().N, s)
	}
	sig, err = asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	return authData, clientData, sig
}

// testKernel is a real kernel behind the owner seam as kernelsock answers
// it: ErrAnchor and a setup-only kernel's refusal typed, every other
// refusal in the kernel's words.
type testKernel struct {
	k         *kernel.Kernel
	enrolls   int
	unenrolls int
	err       error // when set, every call answers it
	refuse    bool  // Enroll answers the kernel's refusal in its words
	enrollErr error // when set, Enroll alone answers it

	mu      sync.Mutex
	entered chan struct{} // when set, Enroll signals it on entry
	gate    chan struct{} // when set, Enroll waits for it to close

	taken []kernelsock.BackupView // the backups Backup took (backupchoice_test.go)
}

func (k *testKernel) setupOnly() bool { return len(k.k.State().Anchors) == 0 }

func (k *testKernel) answer(err error) error {
	switch {
	case k.err != nil:
		return k.err
	case k.setupOnly():
		return kernelsock.ErrSetupOnly
	case errors.Is(err, kernel.ErrAnchor):
		return kernelsock.ErrAnchor
	case err != nil:
		return kernelsock.Refused{Text: err.Error()}
	}
	return nil
}

func (k *testKernel) Anchors(context.Context) ([]key.PublicKey, error) {
	if err := k.answer(nil); err != nil {
		return nil, err
	}
	return slices.Clone(k.k.State().Anchors), nil
}

func (k *testKernel) Enrollments(context.Context) ([]key.Enrollment, []key.PublicKey, error) {
	if err := k.answer(nil); err != nil {
		return nil, nil, err
	}
	es, un := k.k.State().Enrollments()
	return slices.Clone(es), slices.Clone(un), nil
}

func (k *testKernel) Enroll(_ context.Context, e key.Enrollment) error {
	k.mu.Lock()
	k.enrolls++
	k.mu.Unlock()
	if k.entered != nil {
		k.entered <- struct{}{}
	}
	if k.gate != nil {
		<-k.gate
	}
	if err := k.answer(nil); err != nil {
		return err
	}
	if k.enrollErr != nil {
		return k.enrollErr
	}
	if k.refuse {
		return kernelsock.Refused{Text: kernel.ErrNotEnrolled.Error()}
	}
	return k.answer(k.k.Enroll(time.Now().UnixMilli(), e))
}

func (k *testKernel) Unenroll(_ context.Context, u key.Unenrollment) error {
	k.unenrolls++
	if err := k.answer(nil); err != nil {
		return err
	}
	return k.answer(k.k.Unenroll(time.Now().UnixMilli(), u))
}

// bootKernel boots a kernel over store with anchors (none: setup-only).
func bootKernel(t *testing.T, store *kernel.MemStore, anchors []key.PublicKey) *testKernel {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	l, err := kernel.Open(kernel.Config{Store: store, Anchor: &kernel.MemAnchor{}, Key: [32]byte{7}, Pub: pub, Sign: priv, Rand: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	k, err := kernel.Boot(l, anchors, nil, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	return &testKernel{k: k}
}

type passkeyRig struct {
	t       *testing.T
	anchors []*authenticator
	store   *kernel.MemStore
	k       *testKernel
	p       *passkeys
	now     time.Time
}

func newPasskeyRig(t *testing.T) *passkeyRig {
	r := &passkeyRig{t: t, anchors: []*authenticator{newAuthenticator(t), newAuthenticator(t)}, now: time.Unix(1_800_000_000, 0)}
	r.store = &kernel.MemStore{}
	r.k = bootKernel(t, r.store, r.anchorKeys())
	r.p = newPasskeys(r.k, testRP)
	r.p.Now = func() time.Time { return r.now }
	return r
}

func (r *passkeyRig) anchorKeys() []key.PublicKey {
	return []key.PublicKey{r.anchors[0].public(r.t), r.anchors[1].public(r.t)}
}

// enrol runs the ceremony: the phone's point, then by's tap over the
// challenge.
func (r *passkeyRig) enrol(session string, phone, by *authenticator) error {
	r.t.Helper()
	c, err := r.p.Begin(context.Background(), session, phone.point(r.t))
	if err != nil {
		return err
	}
	ad, cd, sig := by.get(r.t, c)
	return r.p.Finish(context.Background(), session, ad, cd, sig)
}

// cut cuts phone off on by's tap over its listed CutChallenge (#3209).
func (r *passkeyRig) cut(phone, by *authenticator) error {
	r.t.Helper()
	id := keyID(phone.public(r.t))
	c := key.Challenge(key.UnenrollMsg(phone.public(r.t)))
	ad, cd, sig := by.get(r.t, c[:])
	return r.p.CutOff(context.Background(), id, ad, cd, sig)
}

func (r *passkeyRig) enrolled() []key.Enrollment {
	es, _ := r.k.k.State().Enrollments()
	return es
}

func code(err error) string {
	var c sockets.Code
	if errors.As(err, &c) {
		return string(c)
	}
	if err == nil {
		return ""
	}
	return "uncoded: " + err.Error()
}

// A phone's create() point and a hardware key's get() over the returned
// challenge enrol the phone passkey on the configured RP ID, and the list
// shows it under that hardware key.
func TestEnrolsAPhonePasskeyFromTheCeremony(t *testing.T) {
	r := newPasskeyRig(t)
	phone := newAuthenticator(t)
	c, err := r.p.Begin(context.Background(), "s1", phone.point(t))
	if err != nil {
		t.Fatal(err)
	}
	want := key.Challenge(key.EnrollMsg(phone.public(t)))
	if string(c) != string(want[:]) {
		t.Fatal("the challenge is not over EnrollMsg of the phone's key")
	}
	ad, cd, sig := r.anchors[0].get(t, c)
	if err := r.p.Finish(context.Background(), "s1", ad, cd, sig); err != nil {
		t.Fatal(err)
	}
	es := r.enrolled()
	if len(es) != 1 || es[0].Passkey != phone.public(t) || es[0].By != r.anchors[0].public(t) {
		t.Fatalf("enrolled %+v", es)
	}
	if !key.In(r.k.k.State().Passkeys(), phone.public(t)) {
		t.Fatal("the kernel's owner set lacks the phone")
	}
	l, err := r.p.List(context.Background())
	if err != nil || len(l.Anchors) != 2 || len(l.Enrolled) != 1 || len(l.CutOff) != 0 {
		t.Fatalf("list %+v, %v", l, err)
	}
	if e := l.Enrolled[0]; e.ID != keyID(phone.public(t)) || e.Alg != key.AlgES256 || e.By != fingerprint(r.anchors[0].public(t)) {
		t.Fatalf("listed %+v", e)
	}
	// The begun point is spent: finishing again is stale.
	if err := r.p.Finish(context.Background(), "s1", ad, cd, sig); code(err) != localapi.ErrPasskeyStale {
		t.Fatalf("a second finish: %v", err)
	}
}

// The hardware key signed EnrollMsg(X), but the session's begun point is
// Y: nothing is enrolled (KEY-4), so a page cannot swap the key being
// enrolled under the owner's tap.
func TestAnAssertionForAnotherPasskeyEnrolsNothing(t *testing.T) {
	r := newPasskeyRig(t)
	x, y := newAuthenticator(t), newAuthenticator(t)
	cx := key.Challenge(key.EnrollMsg(x.public(t)))
	if _, err := r.p.Begin(context.Background(), "s1", y.point(t)); err != nil {
		t.Fatal(err)
	}
	ad, cd, sig := r.anchors[0].get(t, cx[:])
	if err := r.p.Finish(context.Background(), "s1", ad, cd, sig); code(err) != localapi.ErrPasskeyBadAssertion {
		t.Fatalf("finish: %v", err)
	}
	if len(r.enrolled()) != 0 || r.k.enrolls != 0 {
		t.Fatalf("enrolled %+v after %d calls", r.enrolled(), r.k.enrolls)
	}
	// The kernel refuses the swap too, without agentosd's check.
	sigX, _ := key.AssertionSig(key.Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig})
	if err := r.k.Enroll(context.Background(), key.Enrollment{Passkey: y.public(t), By: r.anchors[0].public(t), Sig: sigX}); !errors.As(err, new(kernelsock.Refused)) {
		t.Fatalf("the kernel took a swapped enrollment: %v", err)
	}
}

// An authenticator's high-S signature is enrolled once, in AssertionSig's
// form, so one tap is one enrollment (KEY-7).
func TestAHighSAssertionIsAttachedLowS(t *testing.T) {
	r := newPasskeyRig(t)
	r.anchors[0].highS = true
	phone := newAuthenticator(t)
	c, err := r.p.Begin(context.Background(), "s1", phone.point(t))
	if err != nil {
		t.Fatal(err)
	}
	ad, cd, sig := r.anchors[0].get(t, c)
	if err := r.p.Finish(context.Background(), "s1", ad, cd, sig); err != nil {
		t.Fatal(err)
	}
	canon, _ := key.AssertionSig(key.Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig})
	es := r.enrolled()
	if len(es) != 1 || string(es[0].Sig) != string(canon) {
		t.Fatalf("enrolled %+v", es)
	}
	var a key.Assertion
	if json.Unmarshal(es[0].Sig, &a) != nil || string(a.Signature) == string(sig) {
		t.Fatal("the high-S signature was attached as sent")
	}
}

// A tap by an enrolled phone passkey enrols nothing: only a hardware key
// widens the owner's set.
func TestAPhonePasskeyCannotEnrolAnother(t *testing.T) {
	r := newPasskeyRig(t)
	phone, other := newAuthenticator(t), newAuthenticator(t)
	if err := r.enrol("s1", phone, r.anchors[0]); err != nil {
		t.Fatal(err)
	}
	calls := r.k.enrolls
	if err := r.enrol("s1", other, phone); code(err) != localapi.ErrPasskeyNotAnchor {
		t.Fatalf("a phone enrolling another: %v", err)
	}
	if len(r.enrolled()) != 1 || r.k.enrolls != calls {
		t.Fatalf("enrolled %+v", r.enrolled())
	}
}

// With two hardware keys, a tap by the second is enrolled under the
// second. A garbage assertion is ErrPasskeyBadAssertion and calls no
// Enroll.
func TestTheAnchorThatSignedIsFound(t *testing.T) {
	r := newPasskeyRig(t)
	phone := newAuthenticator(t)
	if err := r.enrol("s1", phone, r.anchors[1]); err != nil {
		t.Fatal(err)
	}
	if es := r.enrolled(); len(es) != 1 || es[0].By != r.anchors[1].public(t) {
		t.Fatalf("enrolled %+v", es)
	}
	calls := r.k.enrolls
	if _, err := r.p.Begin(context.Background(), "s2", newAuthenticator(t).point(t)); err != nil {
		t.Fatal(err)
	}
	for _, f := range [][3][]byte{{{1}, {2}, {3}}, {make([]byte, 37), []byte("{}"), {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}}} {
		if err := r.p.Finish(context.Background(), "s2", f[0], f[1], f[2]); code(err) != localapi.ErrPasskeyBadAssertion {
			t.Fatalf("garbage: %v", err)
		}
	}
	// A tap by a key not in the owner's set at all.
	stranger := newAuthenticator(t)
	if err := r.enrol("s2", newAuthenticator(t), stranger); code(err) != localapi.ErrPasskeyBadAssertion {
		t.Fatalf("a stranger's tap: %v", err)
	}
	if r.k.enrolls != calls {
		t.Fatal("a bad assertion reached Enroll")
	}
}

// Cutting off a hardware key is ErrPasskeyAnchor before the kernel is
// called; a phone is cut off for good, stays cut off across a restart of
// both agentosd and the kernel, and is listed so.
func TestCutOffAnAnchorIsRefusedBeforeTheKernel(t *testing.T) {
	r := newPasskeyRig(t)
	if err := r.p.CutOff(context.Background(), keyID(r.anchors[0].public(t)), nil, nil, nil); code(err) != localapi.ErrPasskeyAnchor {
		t.Fatalf("cut off an anchor: %v", err)
	}
	if r.k.unenrolls != 0 {
		t.Fatal("unenroll sent for an anchor")
	}
	// The kernel's own refusal of an anchor maps to the same code.
	if err := passkeyCode(r.k.Unenroll(context.Background(), key.Unenrollment{Passkey: r.anchors[0].public(t)}), localapi.ErrPasskeyRefused); code(err) != localapi.ErrPasskeyAnchor {
		t.Fatalf("the kernel's ErrAnchor: %v", err)
	}
	phone := newAuthenticator(t)
	if err := r.enrol("s1", phone, r.anchors[0]); err != nil {
		t.Fatal(err)
	}
	id := keyID(phone.public(t))
	if err := r.cut(phone, r.anchors[0]); err != nil {
		t.Fatal(err)
	}
	if key.In(r.k.k.State().Passkeys(), phone.public(t)) {
		t.Fatal("the phone is still in the owner's set")
	}
	if err := r.p.CutOff(context.Background(), id, nil, nil, nil); err != nil {
		t.Fatalf("cutting off again: %v", err)
	}
	if err := r.p.CutOff(context.Background(), keyID(newAuthenticator(t).public(t)), nil, nil, nil); code(err) != localapi.ErrPasskeyStale {
		t.Fatalf("a key not listed: %v", err)
	}
	// A phone cut off cannot be enrolled again.
	if err := r.enrol("s1", phone, r.anchors[0]); code(err) != localapi.ErrPasskeyRefused {
		t.Fatalf("enrolling a cut-off phone: %v", err)
	}
	// Restart both: the list is the log's.
	p2 := newPasskeys(bootKernel(t, r.store, r.anchorKeys()), testRP)
	l, err := p2.List(context.Background())
	if err != nil || len(l.Enrolled) != 0 || len(l.CutOff) != 1 || l.CutOff[0].ID != id {
		t.Fatalf("after restart %+v, %v", l, err)
	}
}

// A begun enrolment lapses after five minutes, and only the session that
// began it can finish it.
func TestAPendingEnrolmentLapsesAndIsBoundToItsSession(t *testing.T) {
	r := newPasskeyRig(t)
	phone := newAuthenticator(t)
	c, err := r.p.Begin(context.Background(), "s1", phone.point(t))
	if err != nil {
		t.Fatal(err)
	}
	ad, cd, sig := r.anchors[0].get(t, c)
	if err := r.p.Finish(context.Background(), "s2", ad, cd, sig); code(err) != localapi.ErrPasskeyStale {
		t.Fatalf("another session: %v", err)
	}
	r.now = r.now.Add(passkeyPending)
	if err := r.p.Finish(context.Background(), "s1", ad, cd, sig); code(err) != localapi.ErrPasskeyStale {
		t.Fatalf("after five minutes: %v", err)
	}
	if len(r.enrolled()) != 0 {
		t.Fatal("enrolled")
	}
	// A new begin replaces the old one in its session.
	other := newAuthenticator(t)
	if _, err := r.p.Begin(context.Background(), "s1", phone.point(t)); err != nil {
		t.Fatal(err)
	}
	c2, _ := r.p.Begin(context.Background(), "s1", other.point(t))
	ad, cd, sig = r.anchors[0].get(t, c2)
	if err := r.p.Finish(context.Background(), "s1", ad, cd, sig); err != nil {
		t.Fatal(err)
	}
	if es := r.enrolled(); len(es) != 1 || es[0].Passkey != other.public(t) {
		t.Fatalf("enrolled %+v", es)
	}
	// The begun points are bounded: the oldest is evicted.
	for i := range maxPending + 1 {
		if _, err := r.p.Begin(context.Background(), string(rune('a'+i)), phone.point(t)); err != nil {
			t.Fatal(err)
		}
		r.now = r.now.Add(time.Second)
	}
	if len(r.p.pending) != maxPending {
		t.Fatalf("%d kept", len(r.p.pending))
	}
	if _, ok := r.p.pending["a"]; ok {
		t.Fatal("the oldest was kept")
	}
}

// Every failure the page can see is one of the closed codes: a
// setup-only kernel, an unreachable one, a lost answer and every kernel
// refusal, whatever its words.
func TestNoKernelTextReachesThePage(t *testing.T) {
	allowed := append(slices.Clone(localapi.PasskeyCodes), localapi.ErrBadArgs, "")
	check := func(what string, err error) {
		t.Helper()
		if !slices.Contains(allowed, code(err)) {
			t.Errorf("%s: %v", what, err)
		}
	}
	setup := bootKernel(t, &kernel.MemStore{}, nil)
	p := newPasskeys(setup, testRP)
	phone := newAuthenticator(t)
	_, err := p.List(context.Background())
	if code(err) != localapi.ErrPasskeySetup {
		t.Fatalf("a setup-only kernel's list: %v", err)
	}
	if _, err := p.Begin(context.Background(), "s", phone.point(t)); code(err) != localapi.ErrPasskeySetup {
		t.Fatalf("a setup-only kernel's begin: %v", err)
	}
	if err := p.CutOff(context.Background(), keyID(phone.public(t)), nil, nil, nil); code(err) != localapi.ErrPasskeySetup {
		t.Fatalf("a setup-only kernel's cut off: %v", err)
	}
	if _, err := p.Begin(context.Background(), "s", make([]byte, 65)); code(err) != localapi.ErrBadArgs {
		t.Fatalf("a point off the curve: %v", err)
	}
	for _, kerr := range []error{kernelsock.ErrUnreachable, kernelsock.ErrLost, kernelsock.Refused{Text: "kernel: anything at all"},
		errors.New("run: the socket has no call anchors")} {
		r := newPasskeyRig(t)
		c, err := r.p.Begin(context.Background(), "s", phone.point(t))
		if err != nil {
			t.Fatal(err)
		}
		r.k.err = kerr
		_, err = r.p.List(context.Background())
		check("list", err)
		ad, cd, sig := r.anchors[0].get(t, c)
		check("finish", r.p.Finish(context.Background(), "s", ad, cd, sig))
		check("cut off", r.p.CutOff(context.Background(), keyID(phone.public(t)), nil, nil, nil))
		_, err = r.p.Begin(context.Background(), "s", phone.point(t))
		check("begin", err)
	}
	// The kernel refusing what passed the pre-checks is ErrPasskeyRefused,
	// never its words.
	r := newPasskeyRig(t)
	r.k.refuse = true
	if err := r.enrol("s", phone, r.anchors[0]); code(err) != localapi.ErrPasskeyRefused {
		t.Fatalf("the kernel's refusal: %v", err)
	}
}

func TestRPIDIsADomain(t *testing.T) {
	for rp, ok := range map[string]bool{testRP: true, "box.example.org": true, "": false, "internal": false, "10.42.0.1": false,
		"Agentos.internal": false, "a..b": false, "-a.b": false, "a.b:443": false, "a b.c": false} {
		if validRPID(rp) != ok {
			t.Errorf("%q: want %v", rp, ok)
		}
	}
}

// A phone passkey is cut off only on a hardware key's tap over its listed
// CutChallenge (#3209): no tap, the phone's own, another phone's, a
// stranger's, or a hardware key's over another key's challenge is refused
// before the kernel; the hardware key's cuts it off.
func TestCutOffAPhoneNeedsAHardwareKeyTap(t *testing.T) {
	r := newPasskeyRig(t)
	phone, other := newAuthenticator(t), newAuthenticator(t)
	if err := r.enrol("s1", phone, r.anchors[0]); err != nil {
		t.Fatal(err)
	}
	if err := r.enrol("s2", other, r.anchors[1]); err != nil {
		t.Fatal(err)
	}
	l, err := r.p.List(context.Background())
	c := key.Challenge(key.UnenrollMsg(phone.public(t)))
	if err != nil || len(l.Enrolled) != 2 || string(l.Enrolled[0].CutChallenge) != string(c[:]) || l.Anchors[0].CutChallenge != nil {
		t.Fatalf("listed cut-off challenges: %+v %v", l, err)
	}
	id := keyID(phone.public(t))
	overOther := key.Challenge(key.UnenrollMsg(other.public(t)))
	ad, cd, sig := r.anchors[0].get(t, overOther[:])
	if err := r.p.CutOff(context.Background(), id, nil, nil, nil); code(err) != localapi.ErrPasskeyBadAssertion {
		t.Fatalf("no tap: %v", err)
	}
	if err := r.cut(phone, phone); code(err) != localapi.ErrPasskeyNotAnchor {
		t.Fatalf("the phone's own tap: %v", err)
	}
	if err := r.cut(phone, other); code(err) != localapi.ErrPasskeyNotAnchor {
		t.Fatalf("another phone's tap: %v", err)
	}
	if err := r.cut(phone, newAuthenticator(t)); code(err) != localapi.ErrPasskeyBadAssertion {
		t.Fatalf("a stranger's tap: %v", err)
	}
	if err := r.p.CutOff(context.Background(), id, ad, cd, sig); code(err) != localapi.ErrPasskeyBadAssertion {
		t.Fatalf("a hardware key's tap over another key: %v", err)
	}
	if r.k.unenrolls != 0 || !key.In(r.k.k.State().Passkeys(), phone.public(t)) {
		t.Fatal("a refused cut-off reached the kernel")
	}
	if err := r.cut(phone, r.anchors[1]); err != nil {
		t.Fatal(err)
	}
	if key.In(r.k.k.State().Passkeys(), phone.public(t)) || !key.In(r.k.k.State().Passkeys(), other.public(t)) {
		t.Fatal("the hardware key's tap: the phone stays, or the other phone went")
	}
}

// Two finishes of one begun point in parallel reach the kernel once: the
// second waits for the first and gets its answer (#3175 item 1).
func TestTwoFinishesInOneSessionEnrolOnce(t *testing.T) {
	r := newPasskeyRig(t)
	phone := newAuthenticator(t)
	c, err := r.p.Begin(context.Background(), "s1", phone.point(t))
	if err != nil {
		t.Fatal(err)
	}
	ad, cd, sig := r.anchors[0].get(t, c)
	r.k.entered, r.k.gate = make(chan struct{}, 2), make(chan struct{})
	errs := make(chan error, 2)
	finish := func() { errs <- r.p.Finish(context.Background(), "s1", ad, cd, sig) }
	go finish()
	<-r.k.entered
	go finish()
	time.Sleep(50 * time.Millisecond) // the second reaches Finish while the first is in Enroll
	close(r.k.gate)
	first, second := <-errs, <-errs
	if r.k.enrolls != 1 {
		t.Fatalf("%d Enroll calls", r.k.enrolls)
	}
	if first != nil || (second != nil && code(second) != localapi.ErrPasskeyStale) {
		t.Fatalf("answers %v, %v", first, second)
	}
	if es := r.enrolled(); len(es) != 1 || es[0].Passkey != phone.public(t) {
		t.Fatalf("enrolled %+v", es)
	}
}

// A refused tap or an unreachable kernel leaves the begun point live, so
// the owner can tap again; the kernel's own refusal spends it (#3175
// items 1, 2).
func TestAFailedFinishCanBeRetried(t *testing.T) {
	r := newPasskeyRig(t)
	phone := newAuthenticator(t)
	c, err := r.p.Begin(context.Background(), "s1", phone.point(t))
	if err != nil {
		t.Fatal(err)
	}
	ad, cd, sig := phone.get(t, c) // the phone's own new passkey, picked at the tap
	if err := r.p.Finish(context.Background(), "s1", ad, cd, sig); code(err) != localapi.ErrPasskeyBadAssertion {
		t.Fatalf("the phone's own tap: %v", err)
	}
	ad, cd, sig = r.anchors[0].get(t, c)
	r.k.enrollErr = kernelsock.ErrUnreachable
	if err := r.p.Finish(context.Background(), "s1", ad, cd, sig); code(err) != localapi.ErrPasskeyUnavailable {
		t.Fatalf("an unreachable kernel: %v", err)
	}
	r.k.enrollErr = nil
	if err := r.p.Finish(context.Background(), "s1", ad, cd, sig); err != nil {
		t.Fatalf("the retry: %v", err)
	}
	if es := r.enrolled(); len(es) != 1 || es[0].Passkey != phone.public(t) {
		t.Fatalf("enrolled %+v", es)
	}
	other := newAuthenticator(t)
	c, err = r.p.Begin(context.Background(), "s1", other.point(t))
	if err != nil {
		t.Fatal(err)
	}
	ad, cd, sig = r.anchors[0].get(t, c)
	r.k.refuse = true
	if err := r.p.Finish(context.Background(), "s1", ad, cd, sig); code(err) != localapi.ErrPasskeyRefused {
		t.Fatalf("the kernel's refusal: %v", err)
	}
	r.k.refuse = false
	if err := r.p.Finish(context.Background(), "s1", ad, cd, sig); code(err) != localapi.ErrPasskeyStale {
		t.Fatalf("after the kernel's refusal: %v", err)
	}
}

// A page on another RP ID than agentosd's enrols nothing: the phone's
// credential would be bound to agentosd's and never verify (#3175 item 4).
func TestAPageOnAnotherRPIDEnrolsNothing(t *testing.T) {
	const pageRP = "box.example.org"
	anchor := newAuthenticator(t)
	anchor.rp = pageRP
	k := bootKernel(t, &kernel.MemStore{}, []key.PublicKey{anchor.public(t)})
	p := newPasskeys(k, testRP)
	phone := newAuthenticator(t)
	phone.rp = pageRP
	c, err := p.Begin(context.Background(), "s1", phone.point(t))
	if err != nil {
		t.Fatal(err)
	}
	ad, cd, sig := anchor.get(t, c)
	if err := p.Finish(context.Background(), "s1", ad, cd, sig); code(err) != localapi.ErrPasskeyUnavailable {
		t.Fatalf("a page on %s: %v", pageRP, err)
	}
	if es, _ := k.k.State().Enrollments(); k.enrolls != 0 || len(es) != 0 {
		t.Fatalf("enrolled %+v (%d calls)", es, k.enrolls)
	}
}
