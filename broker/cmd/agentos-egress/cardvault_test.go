package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/recovery"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: HW-1, ONB-7, A1

// setupCardRig is a vault process over a sealed vault made in setup mode,
// as `init -setup` leaves it (the code-generator seed and the setup-open
// entry), for the Owner Card ops (cardvault.go). The setup vault opens
// with a recovery-kind factor here so the tests pay no passphrase
// derivation for it; the card's vault opens with its passphrase. All
// values are synthetic canaries.
type setupCardRig struct {
	*fastRig
	vp, kp string
	setup  recovery.RecoveryKey // opens the setup vault
	call   func(method, path string, body any) (int, map[string]any)
}

func newSetupCardRig(t *testing.T, setupOpen bool) *setupCardRig {
	t.Helper()
	dir := t.TempDir()
	x := &setupCardRig{vp: filepath.Join(dir, "vault"), kp: filepath.Join(dir, "vault.keys")}
	var err error
	if x.setup, err = recovery.NewRecoveryKey(nil); err != nil {
		t.Fatal(err)
	}
	v, err := vault.CreateSealed(x.vp, x.kp, recovery.Factor(x.setup))
	if err != nil {
		t.Fatal(err)
	}
	x.fastRig = &fastRig{clk: &clock{t: time.Unix(1_800_000_000, 0)}, seed: []byte(synthetic(t, "seed-")),
		path: x.vp, state: filepath.Join(dir, "unlock.json")}
	v.Put(SeedName, vault.KindTOTPSeed, x.seed)
	if setupOpen {
		v.Put(SetupOpenName, KindSetupOpen, []byte(synthetic(t, "open-")))
	}
	v.Close()
	if err := os.WriteFile(x.state, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.build(t)
	return x
}

// build makes (or, after a restart, remakes) the vault process over the
// same files.
func (x *setupCardRig) build(t *testing.T) {
	t.Helper()
	c, err := newCustody(&custody{
		open: func(p string) (*vault.Vault, error) {
			if p == goodPass {
				return vault.OpenSealed(x.vp, x.kp, recovery.Factor(x.setup))
			}
			return vault.OpenSealed(x.vp, x.kp, vault.Passphrase(p))
		},
		build: func(v *vault.Vault) (*egress.Proxy, error) {
			return newProxy(v, map[string][]string{"agent": {"openai"}}, nil, nil)
		},
		ttl:       15 * time.Minute,
		now:       x.clk.now,
		notify:    func(s string) { x.notes = append(x.notes, s) },
		statePath: x.state,
		vaultPath: x.vp,
		keysPath:  x.kp,
	})
	if err != nil {
		t.Fatal(err)
	}
	x.c = c
	t.Cleanup(c.lock)
	x.call = handlerCall(t, c)
}

// open unlocks the setup vault with its passphrase and a code.
func (x *setupCardRig) open(t *testing.T) {
	t.Helper()
	if err := x.c.confirm(x.unlock(t), x.code()); err != nil {
		t.Fatal(err)
	}
}

// enrollCodes is setup's step 3: a new code generator enrolled and
// confirmed, so the seed in the vault is the owner's phone's.
func (x *setupCardRig) enrollCodes(t *testing.T) {
	t.Helper()
	uri, err := x.c.enroll()
	if err != nil {
		t.Fatal(err)
	}
	x.seed = enrolledSeed(t, uri)
	x.clk.add(30 * time.Second)
	if ok, err := x.c.confirmEnroll(x.code()); !ok || err != nil {
		t.Fatalf("confirm codes: %v %v", ok, err)
	}
}

// seal is setup's finish: the confirmed seed is sealed.
func (x *setupCardRig) seal(t *testing.T) {
	t.Helper()
	ensureCard(t, x.c)
	if err := x.c.sealEnroll(); err != nil {
		t.Fatal(err)
	}
}

// newCard is an Owner Card as the box generates it (card.Generate).
func newCard(t *testing.T) recovery.Card {
	t.Helper()
	rk, err := recovery.NewRecoveryKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := synthCard(t, rk)
	c.VaultPassphrase = synthetic(t, "pass-canary-")
	return c
}

func provisionBody(c recovery.Card) map[string]any {
	return map[string]any{"setup_secret": c.SetupSecret,
		"setup_code": c.SetupCode, "vault_passphrase": c.VaultPassphrase, "grid_seed": c.GridSeed, "recovery_key": c.RecoveryKey}
}

func secret(t *testing.T, v *vault.Vault, name string) string {
	t.Helper()
	s, ok := v.Secret(name)
	if !ok {
		t.Fatalf("%s missing", name)
	}
	return s.Reveal()
}

func absent(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s left: %v", p, err)
		}
	}
}

// HW-1, ONB-7 (security S2 on #1073): provisioning from the confirmed
// card makes the card's vault, which opens with the card's passphrase and
// recovery key and no longer with the setup vault's, and carries the
// code-generator seed the owner enrolled at step 3 into it, so setup
// finishes with that seed and the phone keeps working.
func TestProvisionCarriesTheCodeSeedIntoTheCardsVault(t *testing.T) {
	x := newSetupCardRig(t, true)
	card := newCard(t)
	if code, _ := x.call(http.MethodPost, "/card/provision", provisionBody(card)); code != http.StatusConflict {
		t.Fatalf("locked vault provisioned: %d", code)
	}
	x.open(t)
	x.enrollCodes(t)
	if code, _ := x.call(http.MethodGet, "/card/provision", nil); code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", code)
	}
	code, out := x.call(http.MethodPost, "/card/provision", provisionBody(card))
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("provision: %d %v", code, out)
	}
	for _, v := range out {
		if s, _ := v.(string); s != "" && strings.Contains(card.VaultPassphrase+card.RecoveryKey+card.SetupSecret, s) {
			t.Fatal("the answer echoes the card")
		}
	}
	if x.phase() != open {
		t.Fatalf("phase %v after provisioning", x.phase())
	}
	if secret(t, x.c.v, SeedName) != string(x.seed) || !hasKind(x.c.v, ConfirmedName, KindConfirmed) ||
		!hasKind(x.c.v, SetupOpenName, KindSetupOpen) {
		t.Fatal("the setup vault's entries did not carry into the card's vault")
	}
	if got, err := (&recovery.Box{V: x.c.v}).LoadCard(); err != nil || got.SetupSecret != card.SetupSecret {
		t.Fatalf("card not stored: %v", err)
	}

	// On disk: the card's passphrase and recovery key open it, the setup
	// vault's factor does not, and the seed is in it.
	if _, err := vault.OpenSealed(x.vp, x.kp, recovery.Factor(x.setup)); err == nil {
		t.Fatal("the setup vault's factor still opens the card's vault")
	}
	rk, _ := recovery.ParseRecoveryKey(card.RecoveryKey)
	for name, f := range map[string]vault.Factor{"passphrase": vault.Passphrase(card.VaultPassphrase), "recovery key": recovery.Factor(rk)} {
		v, err := vault.OpenSealed(x.vp, x.kp, f)
		if err != nil {
			t.Fatalf("%s does not open the card's vault: %v", name, err)
		}
		if secret(t, v, SeedName) != string(x.seed) {
			t.Fatalf("%s: seed not carried", name)
		}
		v.Close()
	}
	absent(t, x.vp+cardTemp, x.kp+cardTemp)

	// Finish seals the carried seed; the phone's codes keep working, and
	// card rotation now finds the card.
	x.seal(t)
	x.clk.add(30 * time.Second)
	if _, ok, err := x.c.verify(x.code(), 0, true); !ok || err != nil {
		t.Fatalf("the enrolled seed does not verify after provisioning: %v %v", ok, err)
	}
	x.c.rot.mu.Lock()
	_, err := x.c.rotBox()
	x.c.rot.mu.Unlock()
	if err != nil {
		t.Fatalf("rotation finds no card: %v", err)
	}

	// A restart opens the card's vault with the card's passphrase.
	x.c.lock()
	x.build(t)
	x.clk.add(MinAttemptGap)
	tk, err := x.c.unlock(card.VaultPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	x.clk.add(30 * time.Second)
	if err := x.c.confirm(tk, x.code()); err != nil {
		t.Fatalf("unlock with the card: %v", err)
	}
}

// HW-1 (firstboot F10): the card step retries Provision with the same card
// when saving the latch fails, so a retry is a no-op; a different card is
// refused and changes nothing.
func TestProvisionRetriesTheSameCardAndRefusesAnother(t *testing.T) {
	x := newSetupCardRig(t, true)
	x.open(t)
	x.enrollCodes(t)
	card := newCard(t)
	if err := x.c.provisionCard(card); err != nil {
		t.Fatal(err)
	}
	keys, _ := os.ReadFile(x.kp)
	if err := x.c.provisionCard(card); err != nil {
		t.Fatalf("retry with the same card: %v", err)
	}
	if again, _ := os.ReadFile(x.kp); string(again) != string(keys) {
		t.Fatal("a retry rewrote the keys file")
	}
	other := newCard(t)
	if err := x.c.provisionCard(other); err != errCardOther {
		t.Fatalf("another card: %v", err)
	}
	// The same operating values with another passphrase are another card.
	forged := card
	forged.VaultPassphrase = synthetic(t, "pass-canary-")
	if err := x.c.provisionCard(forged); err != errCardOther {
		t.Fatalf("another passphrase: %v", err)
	}
	if _, err := vault.OpenSealed(x.vp, x.kp, vault.Passphrase(other.VaultPassphrase)); err == nil {
		t.Fatal("another card opens the vault")
	}
	if secret(t, x.c.v, SeedName) != string(x.seed) {
		t.Fatal("the seed changed")
	}
}

// HW-1, A1 (security S1 on #1073): only a vault in setup mode is
// provisioned from a card; once finish sealed the seed, or on a vault
// setup mode never opened, nothing is made and the files are untouched.
func TestProvisionIsRefusedOutsideSetupMode(t *testing.T) {
	x := newSetupCardRig(t, true)
	x.open(t)
	x.enrollCodes(t)
	x.seal(t)
	keys, _ := os.ReadFile(x.kp)
	if err := x.c.provisionCard(newCard(t)); err != errEnrolled {
		t.Fatalf("after the seal: %v", err)
	}
	if again, _ := os.ReadFile(x.kp); string(again) != string(keys) {
		t.Fatal("the keys file changed")
	}

	y := newSetupCardRig(t, false)
	y.open(t)
	if err := y.c.provisionCard(newCard(t)); err != errNotOpen {
		t.Fatalf("not in setup mode: %v", err)
	}
	if _, err := vault.OpenSealed(y.vp, y.kp, recovery.Factor(y.setup)); err != nil {
		t.Fatalf("the vault changed: %v", err)
	}
	absent(t, y.vp+cardTemp, y.kp+cardTemp)
}

// HW-1, ONB-7 (firstboot F10; security S2 on #1073): a vault made from a
// card whose latch was never saved is reset, open or after a restart,
// and the seed goes with it: nothing opens afterwards.
func TestResetDiscardsTheUnlatchedVaultAndItsSeed(t *testing.T) {
	for _, restart := range []bool{false, true} {
		x := newSetupCardRig(t, true)
		x.open(t)
		x.enrollCodes(t)
		card := newCard(t)
		if err := x.c.provisionCard(card); err != nil {
			t.Fatal(err)
		}
		if restart {
			x.c.lock()
			x.build(t)
		}
		if code, out := x.call(http.MethodPost, "/card/reset", map[string]any{}); code != http.StatusOK || out["ok"] != true {
			t.Fatalf("restart %v: reset %d %v", restart, code, out)
		}
		if x.phase() != locked || x.c.v != nil {
			t.Fatalf("restart %v: vault still held", restart)
		}
		absent(t, x.vp, x.kp, x.vp+cardTemp, x.kp+cardTemp)
		x.clk.add(MinAttemptGap)
		if _, err := x.c.unlock(card.VaultPassphrase); err == nil {
			t.Fatalf("restart %v: the reset vault still opens", restart)
		}
		// A reset with nothing left to remove is a no-op.
		if err := x.c.resetCard(); err != nil {
			t.Fatalf("restart %v: second reset: %v", restart, err)
		}
	}
}

// HW-1, A1 (security S1 on #1073): once finish sealed a seed the vault is
// never reset, even locked after a restart where nothing inside it can be
// read, and an open vault outside setup mode is not reset either.
func TestResetIsRefusedOnceASeedIsSealed(t *testing.T) {
	x := newSetupCardRig(t, true)
	x.open(t)
	x.enrollCodes(t)
	card := newCard(t)
	if err := x.c.provisionCard(card); err != nil {
		t.Fatal(err)
	}
	x.seal(t)
	if err := x.c.resetCard(); err != errSealedReset {
		t.Fatalf("open, sealed: %v", err)
	}
	x.c.lock()
	x.build(t)
	if code, _ := x.call(http.MethodPost, "/card/reset", map[string]any{}); code != http.StatusGone {
		t.Fatalf("locked, sealed: %d", code)
	}
	if _, err := vault.OpenSealed(x.vp, x.kp, vault.Passphrase(card.VaultPassphrase)); err != nil {
		t.Fatalf("the sealed vault was touched: %v", err)
	}

	// A vault sealed before the seal was also kept outside it (or whose
	// mark was lost) gets the mark the first time it opens.
	y := newSetupCardRig(t, true)
	y.open(t)
	y.enrollCodes(t)
	y.seal(t)
	y.c.lock()
	if err := os.WriteFile(y.state, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	y.build(t)
	y.clk.add(30 * time.Second)
	y.open(t)
	y.c.lock()
	y.build(t)
	if err := y.c.resetCard(); err != errSealedReset {
		t.Fatalf("mark not restored on open: %v", err)
	}

	// An open vault setup mode never opened is not a setup vault.
	z := newSetupCardRig(t, false)
	z.open(t)
	if err := z.c.resetCard(); err != errNotOpen {
		t.Fatalf("not in setup mode: %v", err)
	}
	if _, err := vault.OpenSealed(z.vp, z.kp, recovery.Factor(z.setup)); err != nil {
		t.Fatalf("the vault was touched: %v", err)
	}
}

// HW-1 (firstboot F10): every start before the card's confirm latches runs
// the reset, the first one included; a setup vault no card made yet holds
// the seed enrolled at step 3 and is kept, open or locked.
func TestResetKeepsTheSetupVaultNoCardMade(t *testing.T) {
	x := newSetupCardRig(t, true)
	if err := x.c.resetCard(); err != nil {
		t.Fatalf("locked: %v", err)
	}
	x.open(t)
	x.enrollCodes(t)
	if err := x.c.resetCard(); err != nil {
		t.Fatalf("open: %v", err)
	}
	if x.phase() != open || secret(t, x.c.v, SeedName) != string(x.seed) {
		t.Fatal("the setup vault was discarded")
	}
	x.c.lock()
	x.build(t)
	if err := x.c.resetCard(); err != nil {
		t.Fatalf("locked after a restart: %v", err)
	}
	if _, err := vault.OpenSealed(x.vp, x.kp, recovery.Factor(x.setup)); err != nil {
		t.Fatalf("the setup vault was removed: %v", err)
	}
}

// F10, #1115: the page routes the owner back to step 3 on the provision
// refusal for an unconfirmed code generator, so that refusal carries a
// stable reason. Other 412s (no setup-open entry, errNotOpen) carry none,
// so the page never routes on the status alone.
func TestTheCodesRefusalCarriesAReason(t *testing.T) {
	x := newInitSetupRig(t)
	code, out := x.call(http.MethodPost, "/card/provision", provisionBody(newCard(t)))
	if code != http.StatusPreconditionFailed || out["reason"] != reasonCodesUnconfirmed {
		t.Fatalf("provision before step 3: %d %v", code, out)
	}
	if out["error"] != errCodesUnconfirmed.Error() {
		t.Fatalf("message: %v", out["error"])
	}
	y := newSetupCardRig(t, false)
	y.open(t)
	code, out = y.call(http.MethodPost, "/card/provision", provisionBody(newCard(t)))
	if code != http.StatusPreconditionFailed {
		t.Fatalf("not in setup mode: %d %v", code, out)
	}
	if _, ok := out["reason"]; ok {
		t.Fatalf("errNotOpen carries a reason: %v", out)
	}
}

// ensureCard stands in for the card step's provision where a test is not
// about the card: the open vault holds a card entry, as finish needs.
func ensureCard(t *testing.T, c *custody) {
	t.Helper()
	if _, ok := c.v.Secret(recovery.CardName); ok {
		return
	}
	if err := c.v.Put(recovery.CardName, recovery.KindCard, []byte(synthetic(t, "card-"))); err != nil {
		t.Fatal(err)
	}
}
