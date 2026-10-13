package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/recovery"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: HW-1, HW-10, ONB-6, ONB-7

// newInitSetupRig is a box as `init -setup` leaves it, started as serve
// starts it: the vault process opens the setup vault with the setup key
// (CTRL-setup-open), with no passphrase typed.
func newInitSetupRig(t *testing.T) *setupCardRig {
	t.Helper()
	dir := t.TempDir()
	x := &setupCardRig{vp: filepath.Join(dir, "vault"), kp: filepath.Join(dir, "vault.keys")}
	x.fastRig = &fastRig{clk: &clock{t: time.Unix(1_800_000_000, 0)}, path: x.vp, state: filepath.Join(dir, "unlock.json")}
	if err := initCmd([]string{"-vault", x.vp, "-keys", x.kp, "-claim", claimedBox(t, dir), "-setup"}, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	x.start(t)
	return x
}

// claimedBox is the claim state of a box whose owner has claimed it, in
// dir; its path is init's -claim.
func claimedBox(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "claim.json")
	if err := os.WriteFile(p, []byte(`{"claimed":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// start is the vault process starting over the same files.
func (x *setupCardRig) start(t *testing.T) {
	t.Helper()
	x.build(t)
	x.c.startSetup()
}

func setupKey(t *testing.T, kp string) recovery.RecoveryKey {
	t.Helper()
	raw, err := os.ReadFile(setupKeyFor(kp))
	if err != nil {
		t.Fatal(err)
	}
	rk, err := recovery.ParseRecoveryKey(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return rk
}

func readState(t *testing.T, path string) unlockState {
	t.Helper()
	st, err := loadState(path)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// HW-10, HW-1: init -setup prints no secret. The setup vault opens with a
// setup key kept root-only beside the keys, and the state file marks the
// box as in setup mode.
func TestInitSetupKeepsASetupKeyAndPrintsNoSecret(t *testing.T) {
	dir := t.TempDir()
	vp, kp := filepath.Join(dir, "vault"), filepath.Join(dir, "vault.keys")
	var out strings.Builder
	cp := claimedBox(t, dir)
	if err := initCmd([]string{"-vault", vp, "-keys", kp, "-claim", cp, "-setup"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "passphrase:") || strings.Contains(out.String(), "otpauth://") {
		t.Fatalf("init -setup printed a secret: %q", out.String())
	}
	fi, err := os.Stat(setupKeyFor(kp))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("setup key: %v %v", err, fi)
	}
	v, err := vault.OpenSealed(vp, kp, recovery.Factor(setupKey(t, kp)))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if !hasKind(v, SetupOpenName, KindSetupOpen) || !hasKind(v, SeedName, vault.KindTOTPSeed) {
		t.Fatal("the setup vault lacks its setup-open entry or seed")
	}
	if st := readState(t, statePathFor(kp)); !st.Setup || st.Sealed || st.Provisioned {
		t.Fatalf("state: %+v", st)
	}
	// A second init over the same box is refused and leaves the key.
	if err := initCmd([]string{"-vault", vp, "-keys", kp, "-claim", cp, "-setup"}, &out); err == nil {
		t.Fatal("init ran twice")
	}
	if _, err := vault.OpenSealed(vp, kp, recovery.Factor(setupKey(t, kp))); err != nil {
		t.Fatalf("the second init changed the key: %v", err)
	}
}

// ONB-6, ONB-7, HW-1: the vault process opens the setup vault at start
// with no typed passphrase, so step 3 enrolls and the card's confirm
// provisions; once provisioned, the setup key is gone and the key it held
// opens nothing, so nothing from before the claim opens the card's vault
// (HW-10).
func TestStartOpensTheSetupVaultUntilProvision(t *testing.T) {
	x := newInitSetupRig(t)
	if x.phase() != open {
		t.Fatalf("setup vault not opened at start: %v", x.phase())
	}
	before := setupKey(t, x.kp)
	x.enrollCodes(t)
	card := newCard(t)
	if code, out := x.call(http.MethodPost, "/card/provision", provisionBody(card)); code != http.StatusOK {
		t.Fatalf("provision: %d %v", code, out)
	}
	absent(t, setupKeyFor(x.kp))
	if _, err := vault.OpenSealed(x.vp, x.kp, recovery.Factor(before)); !errors.Is(err, vault.ErrNoSlotOpens) {
		t.Fatalf("the setup key opens the card's vault: %v", err)
	}
	// A restart leaves the card's vault locked: only the card opens it.
	x.c.lock()
	x.start(t)
	if x.phase() != locked {
		t.Fatalf("card's vault opened at start: %v", x.phase())
	}
	// Even a setup key put back opens nothing.
	if err := os.WriteFile(setupKeyFor(x.kp), []byte(before.Text()), 0o600); err != nil {
		t.Fatal(err)
	}
	x.c.lock()
	x.start(t)
	if x.phase() != locked {
		t.Fatalf("a put-back setup key opened the vault: %v", x.phase())
	}
}

// HW-1, A1: once finish sealed the seed the setup vault never opens at
// start, even with its key put back, and the key is removed.
func TestStartNeverOpensASealedVault(t *testing.T) {
	x := newInitSetupRig(t)
	key := setupKey(t, x.kp)
	x.enrollCodes(t)
	x.seal(t)
	absent(t, setupKeyFor(x.kp))
	x.c.lock()
	if err := os.WriteFile(setupKeyFor(x.kp), []byte(key.Text()), 0o600); err != nil {
		t.Fatal(err)
	}
	x.start(t)
	if x.phase() != locked {
		t.Fatalf("a sealed vault opened at start: %v", x.phase())
	}
	absent(t, setupKeyFor(x.kp))

	// The seal entry alone is enough, should the state's mark be lost.
	y := newInitSetupRig(t)
	key = setupKey(t, y.kp)
	y.enrollCodes(t)
	y.seal(t)
	y.c.lock()
	if err := os.WriteFile(y.state, []byte(`{"setup":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(setupKeyFor(y.kp), []byte(key.Text()), 0o600); err != nil {
		t.Fatal(err)
	}
	y.start(t)
	if y.phase() != locked {
		t.Fatalf("a vault with the seal entry opened at start: %v", y.phase())
	}
	absent(t, setupKeyFor(y.kp))
}

// remadeSetup checks the vault on disk is a fresh setup vault, open: a
// new seed, enrollment open, no card and no confirmation, so finish sends
// the owner back to step 3 (localsrv: EnrollNone at the seal clears
// setup's record).
func remadeSetup(t *testing.T, x *setupCardRig, oldSeed []byte, oldKey recovery.RecoveryKey) {
	t.Helper()
	if x.phase() != open {
		t.Fatalf("remade setup vault not open: %v", x.phase())
	}
	if secret(t, x.c.v, SeedName) == string(oldSeed) {
		t.Fatal("the old seed was kept")
	}
	if _, ok := x.c.v.Secret(recovery.CardName); ok {
		t.Fatal("a card is in the remade vault")
	}
	x.c.mu.Lock()
	err := x.c.closedLocked()
	x.c.mu.Unlock()
	if err != nil {
		t.Fatalf("enrollment not open on the remade vault: %v", err)
	}
	if err := x.c.sealEnroll(); err != errNotConfirmed {
		t.Fatalf("finish on the remade vault: %v", err)
	}
	if st := readState(t, x.state); !st.Setup || st.Sealed || st.Provisioned {
		t.Fatalf("state: %+v", st)
	}
	if _, err := vault.OpenSealed(x.vp, x.kp, recovery.Factor(oldKey)); !errors.Is(err, vault.ErrNoSlotOpens) {
		t.Fatalf("the old setup key opens the remade vault: %v", err)
	}
	if _, err := vault.OpenSealed(x.vp, x.kp, recovery.Factor(setupKey(t, x.kp))); err != nil {
		t.Fatalf("the setup key does not open the remade vault: %v", err)
	}
	absent(t, x.vp+cardTemp, x.kp+cardTemp, x.vp+".init", x.kp+".init")
}

// HW-1 test 2, ONB-7, F10 (R1 on #1199): a reset that removed the card's
// vault leaves a fresh setup vault, open, so step 3 and the next card's
// provision can run; open or after a restart.
func TestResetRemakesTheSetupVault(t *testing.T) {
	for _, restart := range []bool{false, true} {
		x := newInitSetupRig(t)
		key := setupKey(t, x.kp)
		x.enrollCodes(t)
		old := x.seed
		card := newCard(t)
		if err := x.c.provisionCard(card); err != nil {
			t.Fatal(err)
		}
		if restart {
			x.c.lock()
			x.start(t)
		}
		code, out := x.call(http.MethodPost, "/card/reset", map[string]any{})
		if code != http.StatusOK || out["ok"] != true || out["remade"] != true {
			t.Fatalf("restart %v: reset %d %v", restart, code, out)
		}
		remadeSetup(t, x, old, key)
		if _, err := vault.OpenSealed(x.vp, x.kp, vault.Passphrase(card.VaultPassphrase)); err == nil {
			t.Fatalf("restart %v: the old card opens the remade vault", restart)
		}
		// Step 3 again, then the next card's provision.
		x.enrollCodes(t)
		if err := x.c.provisionCard(newCard(t)); err != nil {
			t.Fatalf("restart %v: provision after the remake: %v", restart, err)
		}
	}
}

// HW-1 test 2, F10: a start in setup mode, unsealed, that finds no keys
// file (removed, or a stop before init's or a remake's last rename)
// remakes the setup vault and removes what is left of the old one.
func TestStartRemakesAMissingSetupVault(t *testing.T) {
	for _, gone := range [][]string{{"keys"}, {"keys", "vault"}} {
		x := newInitSetupRig(t)
		key := setupKey(t, x.kp)
		x.enrollCodes(t)
		old := x.seed
		x.c.lock()
		for _, g := range gone {
			p := map[string]string{"keys": x.kp, "vault": x.vp}[g]
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		}
		os.WriteFile(x.vp+cardTemp, []byte("left"), 0o600)
		os.WriteFile(x.kp+".init", []byte("left"), 0o600)
		x.start(t)
		remadeSetup(t, x, old, key)
	}

	// A stop between provision's two renames: the card's vault is in
	// place but its keys are not; the reset the start runs remakes it.
	y := newInitSetupRig(t)
	key := setupKey(t, y.kp)
	y.enrollCodes(t)
	old := y.seed
	if err := y.c.provisionCard(newCard(t)); err != nil {
		t.Fatal(err)
	}
	y.c.lock()
	if err := os.Remove(y.kp); err != nil {
		t.Fatal(err)
	}
	y.start(t)
	if err := y.c.resetCard(); err != nil {
		t.Fatal(err)
	}
	remadeSetup(t, y, old, key)
}

// HW-1, A1, HW-10: no remake once finish sealed, outside setup mode, or
// when the state file is missing (fail closed).
func TestNoRemakeOutsideUnsealedSetup(t *testing.T) {
	for _, state := range []string{`{"setup":true,"sealed":true}`, `{}`, ""} {
		x := newInitSetupRig(t)
		x.c.lock()
		if err := os.Remove(x.kp); err != nil {
			t.Fatal(err)
		}
		if state == "" {
			os.Remove(x.state)
		} else if err := os.WriteFile(x.state, []byte(state), 0o600); err != nil {
			t.Fatal(err)
		}
		x.start(t)
		if x.phase() != locked {
			t.Fatalf("state %q: opened", state)
		}
		absent(t, x.kp)
		if _, err := os.Lstat(x.vp); err != nil {
			t.Fatalf("state %q: the vault file was removed: %v", state, err)
		}
		if err := x.c.resetCard(); err != nil && !errors.Is(err, errSealedReset) {
			t.Fatalf("state %q: reset: %v", state, err)
		}
		absent(t, x.kp)
	}

	// A sealed box's reset is refused and remakes nothing.
	y := newInitSetupRig(t)
	y.enrollCodes(t)
	if err := y.c.provisionCard(newCard(t)); err != nil {
		t.Fatal(err)
	}
	y.seal(t)
	raw, _ := os.ReadFile(y.state)
	var st unlockState
	if json.Unmarshal(raw, &st) != nil || !st.Sealed {
		t.Fatalf("state after seal: %s", raw)
	}
	if code, _ := y.call(http.MethodPost, "/card/reset", map[string]any{}); code != http.StatusGone {
		t.Fatalf("sealed reset: %d", code)
	}
	absent(t, setupKeyFor(y.kp))
}

// HW-10, claim K5 (R2 on #1203): init -setup makes nothing before the
// claim. A sealed box nobody has claimed, a box with no claim state (fail
// closed: the download path's pairing gate is not built) and an unreadable
// state are refused before any file is written; once the owner's phone
// has claimed the box, init -setup makes the setup vault.
func TestInitSetupWaitsForTheClaim(t *testing.T) {
	dir := t.TempDir()
	vp, kp := filepath.Join(dir, "vault"), filepath.Join(dir, "vault.keys")
	cp := filepath.Join(dir, "claim.json")
	run := func() error {
		return initCmd([]string{"-vault", vp, "-keys", kp, "-claim", cp, "-setup"}, &strings.Builder{})
	}
	none := func(when string) {
		t.Helper()
		for _, p := range []string{vp, kp, setupKeyFor(kp), statePathFor(kp), vp + ".init", kp + ".init"} {
			if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s: %s exists", when, p)
			}
		}
	}
	if err := run(); err == nil {
		t.Fatal("init -setup ran with no claim state")
	}
	none("no claim state")
	for _, bad := range []string{"{", "null", `{"claimed":false}`} {
		if err := os.WriteFile(cp, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := run(); err == nil {
			t.Fatalf("init -setup ran over claim state %q", bad)
		}
		none(bad)
	}
	st := change.FileStore{Path: cp}
	code, err := claim.NewCode(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cp); err != nil {
		t.Fatal(err)
	}
	if err := claim.Seal(st, code, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil {
		t.Fatal("init -setup ran before the claim")
	}
	none("sealed, unclaimed")
	cl, err := claim.Open(claim.Config{Store: st, BootID: func() (string, error) { return "boot-1", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Try(code); err != nil {
		t.Fatal(err)
	}
	if err := run(); err != nil {
		t.Fatalf("init -setup after the claim: %v", err)
	}
	if _, err := vault.OpenSealed(vp, kp, recovery.Factor(setupKey(t, kp))); err != nil {
		t.Fatal(err)
	}
}

// HW-1 test 2, ONB-7, F10 (R1 on #1203): the card's provision needs a code
// generator confirmed on this vault, so a remade setup vault, whose seed
// nobody was shown, never carries into a card's vault. The refusal
// writes nothing; after step 3 again the next card provisions.
func TestProvisionWaitsForAConfirmedCodeGenerator(t *testing.T) {
	// A fresh setup vault: no code generator yet.
	x := newInitSetupRig(t)
	if code, out := x.call(http.MethodPost, "/card/provision", provisionBody(newCard(t))); code != http.StatusPreconditionFailed {
		t.Fatalf("provision before step 3: %d %v", code, out)
	}
	// Enrolled but not confirmed.
	if _, err := x.c.enroll(); err != nil {
		t.Fatal(err)
	}
	if err := x.c.provisionCard(newCard(t)); !errors.Is(err, errCodesUnconfirmed) {
		t.Fatalf("provision with a pending seed: %v", err)
	}
	// Confirmed, then a newer seed handed out: the vault's seed is not
	// the one the phone now shows.
	x.enrollCodes(t)
	if _, err := x.c.enroll(); err != nil {
		t.Fatal(err)
	}
	if err := x.c.provisionCard(newCard(t)); !errors.Is(err, errCodesUnconfirmed) {
		t.Fatalf("provision after a re-enroll: %v", err)
	}

	// The issue's path: card 1, a reset that remakes the setup vault,
	// card 2, then a restart.
	y := newInitSetupRig(t)
	key := setupKey(t, y.kp)
	y.enrollCodes(t)
	old := y.seed
	if err := y.c.provisionCard(newCard(t)); err != nil {
		t.Fatal(err)
	}
	y.c.lock()
	y.start(t)
	if code, out := y.call(http.MethodPost, "/card/reset", map[string]any{}); code != http.StatusOK || out["remade"] != true {
		t.Fatalf("reset: %d %v", code, out)
	}
	card2 := newCard(t)
	code, out := y.call(http.MethodPost, "/card/provision", provisionBody(card2))
	if code != http.StatusPreconditionFailed || out["error"] != errCodesUnconfirmed.Error() {
		t.Fatalf("card 2 on the remade vault: %d %v", code, out)
	}
	absent(t, y.vp+cardTemp, y.kp+cardTemp)
	if st := readState(t, y.state); st.Provisioned || st.Sealed || !st.Setup {
		t.Fatalf("state after the refusal: %+v", st)
	}
	y.c.lock()
	y.start(t)
	remadeSetup(t, y, old, key)
	if _, err := vault.OpenSealed(y.vp, y.kp, vault.Passphrase(card2.VaultPassphrase)); err == nil {
		t.Fatal("card 2 opens the vault")
	}
	// Step 3 again, then card 2.
	y.enrollCodes(t)
	if err := y.c.provisionCard(card2); err != nil {
		t.Fatalf("card 2 after step 3: %v", err)
	}
	y.seal(t)
}
