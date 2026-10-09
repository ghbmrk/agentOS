package main

import (
	"encoding/base32"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-8, ONB-3, ONB-6, CH-6

// newSetupRig is a box whose vault was made in setup mode (`init -setup`):
// the setup-open entry is in the vault, so enrollment is open until one
// confirmation seals it.
func newSetupRig(t *testing.T) *fastRig {
	t.Helper()
	r := newFastRig(t, true)
	v, err := vault.Open(r.path, r.key)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err := v.Put(SetupOpenName, KindSetupOpen, []byte(synthetic(t, "open-"))); err != nil {
		t.Fatal(err)
	}
	return r
}

// enrolledSeed reads the seed back out of an otpauth:// link, as the
// owner's phone does when it scans it.
func enrolledSeed(t *testing.T, uri string) []byte {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("not an otpauth link: %q", uri)
	}
	q := u.Query()
	if q.Get("issuer") != "AgentOS" || q.Get("digits") != "6" || q.Get("period") != "30" || q.Get("algorithm") != "SHA1" {
		t.Fatalf("parameters: %q", uri)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(q.Get("secret"))
	if err != nil || len(seed) != 20 {
		t.Fatalf("secret: %v %d", err, len(seed))
	}
	return seed
}

// Security L7 on the P2-2w plan: the seed is made inside the vault process
// and goes out once, in the answer that made it. A second enroll makes a
// new seed, so no seed is ever handed out twice, and the one shown before
// no longer confirms. The confirmed seed is untouched until confirmation.
func TestEnrollMakesTheSeedInTheVaultAndHandsItOutOnce(t *testing.T) {
	r := newSetupRig(t)
	if _, err := r.c.enroll(); err != errLocked {
		t.Fatalf("locked vault: %v", err)
	}
	r.c.confirm(r.unlock(t), r.code())

	first, err := r.c.enroll()
	if err != nil {
		t.Fatal(err)
	}
	s1 := enrolledSeed(t, first)
	got, ok := r.c.v.Secret(PendingSeedName)
	if !ok || got.Reveal() != string(s1) || !hasKind(r.c.v, PendingSeedName, vault.KindTOTPSeed) {
		t.Fatal("the handed-out seed is not the vault's pending seed")
	}
	second, err := r.c.enroll()
	if err != nil {
		t.Fatal(err)
	}
	s2 := enrolledSeed(t, second)
	if string(s1) == string(s2) {
		t.Fatal("the same seed was handed out twice")
	}

	r.clk.add(30 * time.Second)
	if ok, err := r.c.confirmEnroll(totp(s1, r.clk.now())); ok || err != nil {
		t.Fatalf("a replaced seed confirmed: %v %v", ok, err)
	}
	// Until confirmation the channel's seed is still the old one.
	if _, ok, err := r.c.verify(r.code(), 0, true); !ok || err != nil {
		t.Fatalf("old seed before confirmation: %v %v", ok, err)
	}
}

// ONB-3, P2-2w P4: one entered code from the new seed confirms it and
// the seed becomes the channel's, the old one stops working; setup's
// finish then seals the enrollment for good, across a restart: no later
// call makes or hands out a seed (re-enrollment is REC-3's, with the
// recovery key).
func TestOneCodeConfirmsTheEnrollmentAndSealsIt(t *testing.T) {
	r := newSetupRig(t)
	if _, err := r.c.confirmEnroll("000000"); err != errLocked {
		t.Fatalf("locked vault: %v", err)
	}
	r.c.confirm(r.unlock(t), r.code())
	if ok, err := r.c.confirmEnroll("000000"); ok || err != errNoEnrollment {
		t.Fatalf("nothing enrolled: %v %v", ok, err)
	}
	uri, err := r.c.enroll()
	if err != nil {
		t.Fatal(err)
	}
	seed := enrolledSeed(t, uri)
	r.clk.add(30 * time.Second)
	if ok, err := r.c.confirmEnroll("000000"); ok || err != nil {
		t.Fatalf("wrong code: %v %v", ok, err)
	}
	code := totp(seed, r.clk.now())
	if ok, err := r.c.confirmEnroll(code); !ok || err != nil {
		t.Fatalf("right code: %v %v", ok, err)
	}
	if _, ok := r.c.v.Secret(PendingSeedName); ok {
		t.Fatal("pending seed kept after confirmation")
	}
	if err := r.c.sealEnroll(); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.c.v.Secret(SetupOpenName); ok {
		t.Fatal("setup-open entry kept after the seal")
	}
	if _, ok := r.c.v.Secret(ConfirmedName); ok {
		t.Fatal("confirmed marker kept after the seal")
	}
	if n := r.notes[len(r.notes)-1]; n != noteEnrolled {
		t.Fatalf("owner not told of the new code generator: %q", n)
	}
	// The confirming code is spent; the next one from the new seed works
	// for the channel, and the old seed's does not.
	if _, ok, _ := r.c.verify(code, 0, true); ok {
		t.Fatal("the confirming code was accepted again")
	}
	r.clk.add(30 * time.Second)
	if _, ok, _ := r.c.verify(r.code(), 0, true); ok {
		t.Fatal("the old seed still works")
	}
	if _, ok, err := r.c.verify(totp(seed, r.clk.now()), 0, true); !ok || err != nil {
		t.Fatalf("new seed: %v %v", ok, err)
	}

	if _, err := r.c.enroll(); err != errEnrolled {
		t.Fatalf("enroll after confirmation: %v", err)
	}
	if _, err := r.c.confirmEnroll("000000"); err != errEnrolled {
		t.Fatalf("confirm after confirmation: %v", err)
	}
	if err := r.c.sealEnroll(); err != errEnrolled {
		t.Fatalf("seal after the seal: %v", err)
	}
	r.c.lock()
	r.build(t)
	r.seed = seed
	r.clk.add(30 * time.Second)
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.enroll(); err != errEnrolled {
		t.Fatalf("enroll after a restart: %v", err)
	}
}

// L3 on #367 (CRED-8, ONB-6): a confirmation does not outlive the pairing
// it was made under. Phone A confirms, setup starts over and phone B
// enrolls: B's enroll replaces A's confirmed seed as the one setup waits
// on, the seal refuses until B confirms, and once sealed only B's seed
// works. A seal with nothing confirmed seals nothing.
func TestARestartedSetupsSeedReplacesAnEarlierConfirmation(t *testing.T) {
	r := newSetupRig(t)
	if err := r.c.sealEnroll(); err != errLocked {
		t.Fatalf("locked vault: %v", err)
	}
	r.c.confirm(r.unlock(t), r.code())
	if err := r.c.sealEnroll(); err != errNotConfirmed {
		t.Fatalf("seal with nothing confirmed: %v", err)
	}

	uriA, err := r.c.enroll()
	if err != nil {
		t.Fatal(err)
	}
	seedA := enrolledSeed(t, uriA)
	r.clk.add(30 * time.Second)
	if ok, err := r.c.confirmEnroll(totp(seedA, r.clk.now())); !ok || err != nil {
		t.Fatalf("A confirms: %v %v", ok, err)
	}
	if hasKind(r.c.v, EnrolledName, KindEnrolled) || !hasKind(r.c.v, SetupOpenName, KindSetupOpen) {
		t.Fatal("a confirmation sealed the enrollment before finish")
	}

	// Setup starts over; B's step asks for a new seed.
	uriB, err := r.c.enroll()
	if err != nil {
		t.Fatalf("enroll after an unsealed confirmation: %v", err)
	}
	seedB := enrolledSeed(t, uriB)
	if err := r.c.sealEnroll(); err != errNotConfirmed {
		t.Fatalf("seal with B's seed unconfirmed: %v", err)
	}
	r.clk.add(30 * time.Second)
	if ok, err := r.c.confirmEnroll(totp(seedB, r.clk.now())); !ok || err != nil {
		t.Fatalf("B confirms: %v %v", ok, err)
	}
	if err := r.c.sealEnroll(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if n := r.notes[len(r.notes)-1]; n != noteEnrolled {
		t.Fatalf("owner not told of the new code generator: %q", n)
	}
	r.clk.add(30 * time.Second)
	if _, ok, _ := r.c.verify(totp(seedA, r.clk.now()), 0, true); ok {
		t.Fatal("A's codes still verify")
	}
	if _, ok, err := r.c.verify(totp(seedB, r.clk.now()), 0, true); !ok || err != nil {
		t.Fatalf("B's codes: %v %v", ok, err)
	}
	if _, err := r.c.enroll(); err != errEnrolled {
		t.Fatalf("enroll after the seal: %v", err)
	}
}

// Wrong confirmations count in the same bucket as the channel's counted
// codes, so a confirm route cannot be used to grind codes past the cap.
func TestWrongConfirmationsAreBounded(t *testing.T) {
	r := newSetupRig(t)
	r.c.confirm(r.unlock(t), r.code())
	uri, err := r.c.enroll()
	if err != nil {
		t.Fatal(err)
	}
	seed := enrolledSeed(t, uri)
	r.clk.add(30 * time.Second)
	for i := 0; i < MaxWrongCounted; i++ {
		if ok, err := r.c.confirmEnroll("000000"); ok || err != nil {
			t.Fatalf("wrong %d: %v %v", i, ok, err)
		}
	}
	var p *pausedError
	if _, err := r.c.confirmEnroll(totp(seed, r.clk.now())); !errors.As(err, &p) {
		t.Fatalf("after %d wrong: %v", MaxWrongCounted, err)
	}
	if _, _, err := r.c.verify(r.code(), 0, true); !errors.As(err, &p) {
		t.Fatalf("channel bucket not shared: %v", err)
	}
}

// The verify socket (agentosd's uid only) carries enroll and its
// confirmation; agentosd's client reads the link once and the
// confirmation's answer carries no seed.
func TestEnrollOverTheVerifySocket(t *testing.T) {
	r := newSetupRig(t)
	run := filepath.Join(t.TempDir(), "run")
	srvs, err := serve(run, r.c, testRouter(t), nil, nil, os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, s := range srvs {
			s.Close()
		}
	}()
	v := modelroute.NewVerifier(filepath.Join(run, VerifySocket))
	if _, err := v.Enroll(); err != modelroute.ErrVaultLocked {
		t.Fatalf("locked: %v", err)
	}
	r.c.confirm(r.unlock(t), r.code())
	uri, err := v.Enroll()
	if err != nil {
		t.Fatal(err)
	}
	seed := enrolledSeed(t, uri)
	r.clk.add(30 * time.Second)
	if ok, err := v.ConfirmEnroll("000000"); ok || err != nil {
		t.Fatalf("wrong: %v %v", ok, err)
	}
	if ok, err := v.ConfirmEnroll(totp(seed, r.clk.now())); !ok || err != nil {
		t.Fatalf("right: %v %v", ok, err)
	}
	if err := v.SealEnroll(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := v.SealEnroll(); err != modelroute.ErrEnrolled {
		t.Fatalf("seal twice: %v", err)
	}
	if _, err := v.Enroll(); err != modelroute.ErrEnrolled {
		t.Fatalf("sealed: %v", err)
	}

	w := httptest.NewRecorder()
	verifyHandler(r.c).ServeHTTP(w, httptest.NewRequest("POST", "/enroll/confirm", strings.NewReader(`{"code":"000000"}`)))
	if b := w.Body.String(); strings.Contains(b, "secret") || strings.Contains(b, "otpauth") {
		t.Fatalf("confirm answer: %s", b)
	}
	for _, p := range []string{"/enroll", "/enroll/confirm", "/enroll/seal"} {
		w = httptest.NewRecorder()
		verifyHandler(r.c).ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s: %d", p, w.Code)
		}
	}
}

// Enrollment is closed unless the vault was made in setup mode: a vault
// from plain `init`, from REC-3's re-enroll or from before c1 has no
// setup-open entry, so a taken-over agentosd cannot swap the owner's seed
// for one it holds (CRED-8, CH-6).
//
// P2-2w c2 r1: such a vault answers "not open" (412), apart from "sealed"
// (410), so setup can tell the owner it cannot finish on this box.
func TestEnrollIsClosedOutsideSetupMode(t *testing.T) {
	r := openRig(t)
	if _, err := r.c.enroll(); err != errNotOpen {
		t.Fatalf("enroll without setup mode: %v", err)
	}
	if _, err := r.c.confirmEnroll(r.code()); err != errNotOpen {
		t.Fatalf("confirm without setup mode: %v", err)
	}
	if err := r.c.sealEnroll(); err != errNotOpen {
		t.Fatalf("seal without setup mode: %v", err)
	}
	if _, ok := r.c.v.Secret(PendingSeedName); ok {
		t.Fatal("a pending seed was written")
	}
	r.clk.add(30 * time.Second)
	if _, ok, err := r.c.verify(r.code(), 0, true); !ok || err != nil {
		t.Fatalf("the owner's seed changed: %v %v", ok, err)
	}

	// init writes the setup-open entry only with -setup, and then leaves
	// the seed hand-out to setup.
	for _, setup := range []bool{false, true} {
		dir := t.TempDir()
		vp, kp := filepath.Join(dir, "vault"), filepath.Join(dir, "vault.keys")
		args := []string{"-vault", vp, "-keys", kp}
		if setup {
			args = append(args, "-setup")
		}
		var out strings.Builder
		if err := initCmd(args, &out); err != nil {
			t.Fatal(err)
		}
		_, rest, _ := strings.Cut(out.String(), "Vault passphrase: ")
		pass, _, _ := strings.Cut(rest, "\n")
		v, err := vault.OpenSealed(vp, kp, vault.Passphrase(pass))
		if err != nil {
			t.Fatal(err)
		}
		open := hasKind(v, SetupOpenName, KindSetupOpen)
		v.Close()
		if open != setup {
			t.Fatalf("init -setup=%v: setup-open entry %v", setup, open)
		}
		if printed := strings.Contains(out.String(), "otpauth://"); printed == setup {
			t.Fatalf("init -setup=%v: seed printed %v", setup, printed)
		}
	}
}

// P2-2w c2 r1 (L3 on #367): "sealed by setup" and "not open" are told
// apart over the socket, and only a seal entry of its own kind counts as
// sealed; anything else in its place is not open, never sealed.
func TestNotOpenIsAnsweredApartFromSealed(t *testing.T) {
	r := openRig(t)
	run := filepath.Join(t.TempDir(), "run")
	srvs, err := serve(run, r.c, testRouter(t), nil, nil, os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, s := range srvs {
			s.Close()
		}
	}()
	v := modelroute.NewVerifier(filepath.Join(run, VerifySocket))
	if _, err := v.Enroll(); err != modelroute.ErrEnrollNotOpen {
		t.Fatalf("enroll on a vault never opened: %v", err)
	}
	if _, err := v.ConfirmEnroll("000000"); err != modelroute.ErrEnrollNotOpen {
		t.Fatalf("confirm on a vault never opened: %v", err)
	}
	if err := v.SealEnroll(); err != modelroute.ErrEnrollNotOpen {
		t.Fatalf("seal on a vault never opened: %v", err)
	}

	// A seal entry of the wrong kind, beside an open entry, is not a seal.
	if err := r.c.v.Put(SetupOpenName, KindSetupOpen, []byte(synthetic(t, "open-"))); err != nil {
		t.Fatal(err)
	}
	if err := r.c.v.Put(EnrolledName, KindSetupOpen, []byte(synthetic(t, "mark-"))); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Enroll(); err != modelroute.ErrEnrollNotOpen {
		t.Fatalf("enroll beside a wrong-kind seal: %v", err)
	}
	if err := r.c.v.Delete(EnrolledName); err != nil {
		t.Fatal(err)
	}
	if err := r.c.putMark(EnrolledName, KindEnrolled); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Enroll(); err != modelroute.ErrEnrolled {
		t.Fatalf("enroll on a sealed vault: %v", err)
	}
	if err := v.SealEnroll(); err != modelroute.ErrEnrolled {
		t.Fatalf("seal on a sealed vault: %v", err)
	}
}
