package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/recovery"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: REC-4, CRED-1, CH-3, HW-1

// cardRig is an open vault process over a drive set up with an Owner
// Card (recovery.Provision), as the controller's is after setup: the
// rotation ops on the unlock socket run against the real recovery
// package and vault. All values are synthetic canaries.
type cardRig struct {
	*fastRig
	rk    recovery.RecoveryKey
	card  recovery.Card
	box   *recovery.Box // a second view of the drive, for checks
	call  func(method, path string, body any) (int, map[string]any)
	id    string // the latest begun rotation's ID (S-R1)
	tmu   sync.Mutex
	fires []func()
	ttls  []time.Duration
}

func synthCard(t *testing.T, rk recovery.RecoveryKey) recovery.Card {
	t.Helper()
	seed := make([]byte, 32)
	rand.Read(seed)
	return recovery.Card{
		SetupSecret: synthetic(t, "setup-canary-"), SetupCode: "TEST-CODE", GridSeed: seed, RecoveryKey: rk.Text()}
}

func newCardRig(t *testing.T) *cardRig {
	t.Helper()
	dir := t.TempDir()
	vp, kp := filepath.Join(dir, "vault"), filepath.Join(dir, "vault.keys")
	rk, err := recovery.NewRecoveryKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.CreateSealed(vp, kp, recovery.Factor(rk))
	if err != nil {
		t.Fatal(err)
	}
	x := &cardRig{rk: rk, card: synthCard(t, rk)}
	b := &recovery.Box{VaultPath: vp, KeysPath: kp, V: v}
	if err := recovery.Provision(b, x.card, recovery.Factor(rk)); err != nil {
		t.Fatal(err)
	}
	r := &fastRig{clk: &clock{t: time.Unix(1_800_000_000, 0)}, seed: []byte(synthetic(t, "seed-")), path: vp,
		state: filepath.Join(dir, "unlock.json")}
	v.Put(SeedName, vault.KindTOTPSeed, r.seed)
	v.Put("openai", vault.KindAPIKey, []byte(synthetic(t, "sk-canary-")))
	v.Close()
	c, err := newCustody(&custody{
		open: func(p string) (*vault.Vault, error) {
			if p != goodPass {
				return nil, vault.ErrNoSlotOpens
			}
			return vault.OpenSealed(vp, kp, recovery.Factor(rk))
		},
		build: func(v *vault.Vault) (*egress.Proxy, error) {
			return newProxy(v, map[string][]string{"agent": {"openai"}}, nil, nil)
		},
		ttl:       15 * time.Minute,
		now:       r.clk.now,
		notify:    func(s string) { r.notes = append(r.notes, s) },
		statePath: r.state,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.vaultPath, c.keysPath = vp, kp
	c.afterFunc = func(d time.Duration, f func()) func() bool {
		x.tmu.Lock()
		defer x.tmu.Unlock()
		x.fires, x.ttls = append(x.fires, f), append(x.ttls, d)
		return func() bool { return true }
	}
	r.c = c
	t.Cleanup(c.lock)
	x.fastRig = r
	x.call = handlerCall(t, c)
	return x
}

// open unlocks the vault with the passphrase and a code.
func (x *cardRig) open(t *testing.T) {
	t.Helper()
	tk := x.unlock(t)
	if err := x.c.confirm(tk, x.code()); err != nil {
		t.Fatal(err)
	}
}

// stored reads the Owner Card the drive holds now, through a view of its
// own opened with rk.
func (x *cardRig) stored(t *testing.T, rk recovery.RecoveryKey) recovery.Card {
	t.Helper()
	b := &recovery.Box{VaultPath: x.c.vaultPath, KeysPath: x.c.keysPath}
	var err error
	b.V, err = vault.OpenSealed(b.VaultPath, b.KeysPath, recovery.Factor(rk))
	if err != nil {
		t.Fatal(err)
	}
	defer b.V.Close()
	c, err := b.LoadCard()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// newRotationID is a rotation ID as the page draws one (S-R1).
func newRotationID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// begin starts a rotation; a body naming no ID gets a fresh one, which
// commit and cancel then carry.
func (x *cardRig) begin(t *testing.T, body map[string]any) (int, map[string]any) {
	t.Helper()
	if _, ok := body["id"]; !ok {
		body["id"] = newRotationID()
	}
	x.id, _ = body["id"].(string)
	return x.call("POST", "/rotate/begin", body)
}

func (x *cardRig) commit(t *testing.T, next rotateCommit) (int, map[string]any) {
	t.Helper()
	if next.ID == "" {
		next.ID = x.id
	}
	return x.call("POST", "/rotate/commit", next)
}

// nextSetup is a new card's setup secret and code.
func nextSetup(t *testing.T) rotateCommit {
	return rotateCommit{SetupSecret: synthetic(t, "setup-next-"), SetupCode: "NEXT-CODE"}
}

// nextSetupGrid is a new card's setup secret and code, and grid.
func nextSetupGrid(t *testing.T) rotateCommit {
	n := nextSetup(t)
	n.GridSeed = make([]byte, 32)
	rand.Read(n.GridSeed)
	return n
}

// REC-4, CH-3: with the vault open and a fresh approval code, the vault
// process rotates the chosen parts through the recovery package; the
// stored card changes only once the commit arrives.
func TestRotateSetupAndGridOverTheSocket(t *testing.T) {
	x := newCardRig(t)
	x.open(t)
	code, out := x.begin(t, map[string]any{"code": x.next(), "parts": []string{"setup", "grid"}})
	if code != http.StatusOK {
		t.Fatalf("begin: %d %v", code, out)
	}
	if out["wifi_name"] != nil || out["expires"] == nil {
		t.Fatalf("begin reply: %v", out)
	}
	if got := x.stored(t, x.rk); got.SetupSecret != x.card.SetupSecret {
		t.Fatal("begin changed the card")
	}
	next := nextSetupGrid(t)
	code, out = x.commit(t, next)
	if code != http.StatusOK {
		t.Fatalf("commit: %d %v", code, out)
	}
	got := x.stored(t, x.rk)
	if got.SetupSecret != next.SetupSecret || got.SetupCode != next.SetupCode || string(got.GridSeed) != string(next.GridSeed) {
		t.Fatal("the stored card is not the new one")
	}
	if notes, _ := out["notes"].([]any); len(notes) == 0 {
		t.Fatalf("no done notes: %v", out)
	}
	if _, ok := out["enrollment"]; ok {
		t.Fatal("a setup and grid rotation replaced the code generator")
	}
	// The pending rotation is spent.
	if code, _ := x.commit(t, nextSetupGrid(t)); code != http.StatusGone {
		t.Fatalf("second commit: %d", code)
	}
}

// CH-3: rotation is tier 4. A locked vault refuses; a wrong code is
// refused, counted and told to the owner; a code works once.
func TestRotateBeginNeedsTheOpenVaultAndACode(t *testing.T) {
	x := newCardRig(t)
	if code, _ := x.begin(t, map[string]any{"code": x.code(), "parts": []string{"setup"}}); code != http.StatusConflict {
		t.Fatalf("locked: %d", code)
	}
	x.open(t)
	x.notes = nil
	if code, _ := x.begin(t, map[string]any{"code": "000000", "parts": []string{"setup"}}); code != http.StatusForbidden {
		t.Fatalf("wrong code: %d", code)
	}
	if len(x.notes) != 1 || !strings.Contains(x.notes[0], "card rotation") {
		t.Fatalf("owner not told of the wrong code: %v", x.notes)
	}
	if len(x.c.st.Wrong) != 1 {
		t.Fatalf("wrong code not counted: %v", x.c.st.Wrong)
	}
	c := x.next()
	if code, _ := x.begin(t, map[string]any{"code": c, "parts": []string{"setup"}}); code != http.StatusOK {
		t.Fatalf("good code: %d", code)
	}
	if code, _ := x.begin(t, map[string]any{"code": c, "parts": []string{"setup"}}); code == http.StatusOK {
		t.Fatal("a code was used twice")
	}
	for _, parts := range [][]string{nil, {"wifi"}, {"setup", "keyboard"}} {
		if code, _ := x.begin(t, map[string]any{"code": x.next(), "parts": parts}); code != http.StatusBadRequest {
			t.Fatalf("parts %v: %d", parts, code)
		}
	}
}

// #1090 review R1: the wire maps the recovery package's outcomes to what
// the display needs. A lapsed or cancelled pending rotation is 410 (the
// display discards the card); a new card that does not fit the parts is
// 400 and the rotation stays for a retry.
func TestRotateCommitOutcomes(t *testing.T) {
	x := newCardRig(t)
	x.open(t)
	if code, _ := x.commit(t, nextSetupGrid(t)); code != http.StatusGone {
		t.Fatalf("no rotation: %d", code)
	}
	begin := func() {
		t.Helper()
		if code, out := x.begin(t, map[string]any{"code": x.next(), "parts": []string{"setup", "grid"}}); code != http.StatusOK {
			t.Fatalf("begin: %d %v", code, out)
		}
	}
	// A card that does not fit: kept for a retry.
	begin()
	if code, _ := x.commit(t, nextSetup(t)); code != http.StatusBadRequest {
		t.Fatalf("misfit: %d", code)
	}
	if code, _ := x.commit(t, nextSetupGrid(t)); code != http.StatusOK {
		t.Fatalf("retry after misfit: %d", code)
	}
	// Cancelled.
	begin()
	if code := x.cancel(t); code != http.StatusNoContent {
		t.Fatalf("cancel: %d", code)
	}
	if code, _ := x.commit(t, nextSetupGrid(t)); code != http.StatusGone {
		t.Fatalf("after cancel: %d", code)
	}
	// Lapsed by the clock (Pending's own expiry).
	begin()
	x.clk.add(recovery.PendingTTL + time.Second)
	if code, out := x.commit(t, nextSetupGrid(t)); code != http.StatusGone || !strings.Contains(out["error"].(string), "lapsed") {
		t.Fatalf("lapsed: %d %v", code, out)
	}
	if code, _ := x.commit(t, nextSetupGrid(t)); code != http.StatusGone {
		t.Fatal("a lapsed rotation stayed")
	}
}

func (x *cardRig) cancel(t *testing.T) int {
	t.Helper()
	code, _ := x.call("POST", "/rotate/cancel", map[string]any{"id": x.id})
	return code
}

// #1090 review R2, CRED-1: the typed passphrase never stays without a
// limit. A timer armed for PendingTTL drops an unused rotation; locking
// the vault drops it too.
func TestRotateTimerAndLockDropThePendingRotation(t *testing.T) {
	x := newCardRig(t)
	x.open(t)
	if code, out := x.begin(t, map[string]any{"code": x.next(), "parts": []string{"setup"}}); code != http.StatusOK {
		t.Fatalf("begin: %d %v", code, out)
	}
	if len(x.fires) != 1 || x.ttls[0] != recovery.PendingTTL {
		t.Fatalf("timer: %v", x.ttls)
	}
	x.c.rot.mu.Lock()
	p := x.c.rot.p
	x.c.rot.mu.Unlock()
	x.fires[0]()
	if x.c.rot.p != nil {
		t.Fatal("the timer left the rotation")
	}
	// The dropped Pending itself is cancelled, not only forgotten.
	if _, err := p.Commit(&recovery.Box{V: nil}, recovery.Card{}, x.clk.now()); !errors.Is(err, recovery.ErrPendingLapsed) {
		t.Fatalf("dropped Pending: %v", err)
	}
	if code, _ := x.commit(t, nextSetup(t)); code != http.StatusGone {
		t.Fatalf("after timer: %d", code)
	}

	// A timer from an earlier rotation does not drop a later one.
	if code, _ := x.begin(t, map[string]any{"code": x.next(), "parts": []string{"setup"}}); code != http.StatusOK {
		t.Fatal("begin again")
	}
	x.fires[0]()
	if x.c.rot.p == nil {
		t.Fatal("a stale timer dropped a later rotation")
	}

	x.c.lock()
	if x.c.rot.p != nil || x.c.rot.box != nil {
		t.Fatal("lock left the rotation")
	}
	x.clk.add(30 * time.Second) // a new code step: each code opens once
	x.open(t)
	if code, _ := x.commit(t, nextSetup(t)); code != http.StatusGone {
		t.Fatalf("after lock: %d", code)
	}
}

// REC-4: a recovery-key rotation, authorized by the current recovery key,
// re-encrypts and replaces the code generator; the new seed's enrollment
// comes back for the page, and a code from it confirms it.
func TestRotateRecoveryKeyReturnsTheEnrollment(t *testing.T) {
	x := newCardRig(t)
	x.open(t)
	x.wantPending(t, false)
	if code, out := x.begin(t, map[string]any{"recovery": "AAAA-BBBB", "parts": []string{"recovery"}}); code != http.StatusForbidden {
		t.Fatalf("malformed key: %d %v", code, out)
	}
	other, _ := recovery.NewRecoveryKey(nil)
	x.notes = nil
	if code, _ := x.begin(t, map[string]any{"recovery": other.Text(), "parts": []string{"recovery"}}); code != http.StatusForbidden {
		t.Fatalf("wrong key: %d", code)
	}
	if len(x.notes) != 1 {
		t.Fatalf("owner not told of a wrong recovery key: %v", x.notes)
	}
	if code, out := x.begin(t, map[string]any{"recovery": x.rk.Text(), "parts": []string{"recovery"}}); code != http.StatusOK {
		t.Fatalf("begin: %d %v", code, out)
	}
	nk, _ := recovery.NewRecoveryKey(nil)
	code, out := x.commit(t, rotateCommit{RecoveryKey: nk.Text()})
	if code != http.StatusOK {
		t.Fatalf("commit: %d %v", code, out)
	}
	uri, _ := out["enrollment"].(string)
	seed := seedOf(t, uri)
	if string(seed) == string(x.seed) {
		t.Fatal("the code generator was not replaced")
	}
	x.wantPending(t, true) // #1175 UX U-R1: the page can offer the show form
	_ = x.stored(t, nk)    // the new key opens the drive
	if _, err := vault.OpenSealed(x.c.vaultPath, x.c.keysPath, recovery.Factor(x.rk)); err == nil {
		t.Fatal("the old recovery key still opens the drive")
	}
	if code, out := x.call("POST", "/rotate/enroll", map[string]any{"code": "000000"}); code != http.StatusOK || out["confirmed"] != false {
		t.Fatalf("wrong enrollment code: %d %v", code, out)
	}
	if code, out := x.call("POST", "/rotate/show-enrollment", map[string]any{"recovery": x.rk.Text()}); code != http.StatusForbidden {
		t.Fatalf("show with the old key: %d %v", code, out)
	}
	if code, out := x.call("POST", "/rotate/show-enrollment", map[string]any{"recovery": nk.Text()}); code != http.StatusOK || out["enrollment"] != uri {
		t.Fatalf("show again: %d", code)
	}
	if code, out := x.call("POST", "/rotate/enroll", map[string]any{"code": totp(seed, x.clk.now())}); code != http.StatusOK || out["confirmed"] != true {
		t.Fatalf("enroll: %d %v", code, out)
	}
	x.wantPending(t, false)
	if code, _ := x.call("POST", "/rotate/enroll", map[string]any{"code": totp(seed, x.clk.now())}); code != http.StatusConflict {
		t.Fatalf("enroll again: %d", code)
	}
}

func seedOf(t *testing.T, uri string) []byte {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "otpauth" {
		t.Fatalf("enrollment %q", uri)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
	if err != nil {
		t.Fatal(err)
	}
	return seed
}

// failReencrypt is this PC's TPM with re-encryption failing.
type failReencrypt struct {
	trustedHost
	err error
}

func (f failReencrypt) reencrypt(*vault.Vault, string, []vault.Factor) (int, error) { return 0, f.err }

// #1090 review R1: a commit that stops after a slot was rewritten is 409
// (ErrCardNotStored), which the display treats as a card in effect, and
// the owner is told; nothing else maps to 409.
func TestRotateCommitPartWayIsInEffect(t *testing.T) {
	x := newCardRig(t)
	x.open(t)
	if code, out := x.begin(t, map[string]any{"recovery": x.rk.Text(), "parts": []string{"recovery"}}); code != http.StatusOK {
		t.Fatalf("begin: %d %v", code, out)
	}
	x.c.mu.Lock()
	x.c.host = failReencrypt{nil, errors.New("tpm: synthetic failure")}
	x.c.mu.Unlock()
	x.notes = nil
	nk, _ := recovery.NewRecoveryKey(nil)
	code, out := x.commit(t, rotateCommit{RecoveryKey: nk.Text()})
	if code != http.StatusConflict {
		t.Fatalf("part way: %d %v", code, out)
	}
	if strings.Contains(out["error"].(string), "synthetic") {
		t.Fatal("the internal error reached the page")
	}
	if len(x.notes) == 0 || !strings.Contains(strings.Join(x.notes, "\n"), "part way") {
		t.Fatalf("owner not told: %v", x.notes)
	}
	if x.c.rot.p != nil {
		t.Fatal("a part-way rotation stayed pending")
	}
	x.c.mu.Lock()
	x.c.host = nil
	x.c.mu.Unlock()
	// The next rotation must replace what is owed.
	code, out = x.begin(t, map[string]any{"recovery": nk.Text(), "parts": []string{"setup"}})
	if code != http.StatusConflict || !strings.Contains(out["error"].(string), "also replace") {
		t.Fatalf("owed: %d %v", code, out)
	}
}

// A drive set up without an Owner Card has nothing to rotate.
func TestRotateWithoutACard(t *testing.T) {
	r := newFastRig(t, true)
	r.c.afterFunc = func(time.Duration, func()) func() bool { return func() bool { return true } }
	tk := r.unlock(t)
	if err := r.c.confirm(tk, r.code()); err != nil {
		t.Fatal(err)
	}
	code, out := handlerCall(t, r.c)("POST", "/rotate/begin", map[string]any{"id": newRotationID(), "code": r.next(), "parts": []string{"setup"}})
	if code != http.StatusConflict {
		t.Fatalf("no card: %d %v", code, out)
	}
}

// wantPending checks /rotate/status: whether a replaced code generator
// waits for its first code (#1175 UX U-R1).
func (x *cardRig) wantPending(t *testing.T, want bool) {
	t.Helper()
	code, out := x.call("POST", "/rotate/status", map[string]any{})
	if code != http.StatusOK || out["enrollment_pending"] != want {
		t.Fatalf("status: %d %v, want enrollment_pending %v", code, out, want)
	}
}

// #1175 security S-R1: commit and cancel carry the ID their begin named.
// A late commit or a stale cancel from an older rotation answers 410 and
// leaves the newer rotation waiting; a cancel that arrived before its own
// begin keeps that begin from dropping the newer one.
func TestRotateOpsCarryTheirRotationID(t *testing.T) {
	x := newCardRig(t)
	x.open(t)
	for _, id := range []any{nil, "", "short", strings.Repeat("G", 32), strings.Repeat("A", 32)} {
		body := map[string]any{"code": x.next(), "parts": []string{"setup"}}
		if id != nil {
			body["id"] = id
		}
		code, _ := x.call("POST", "/rotate/begin", body)
		if code != http.StatusBadRequest {
			t.Fatalf("begin with id %v: %d", id, code)
		}
	}
	if code, _ := x.begin(t, map[string]any{"code": x.next(), "parts": []string{"setup"}}); code != http.StatusOK {
		t.Fatal("begin A")
	}
	a := x.id
	code, out := x.begin(t, map[string]any{"code": x.next(), "parts": []string{"setup"}})
	if code != http.StatusOK || out["id"] != x.id {
		t.Fatalf("begin B: %d %v", code, out)
	}
	b := x.id
	late := nextSetup(t)
	late.ID = a
	if code, _ := x.commit(t, late); code != http.StatusGone {
		t.Fatalf("late commit: %d", code)
	}
	if code, _ := x.commit(t, rotateCommit{ID: strings.Repeat("0", 32), SetupSecret: synthetic(t, "setup-next-"), SetupCode: "NEXT-CODE"}); code != http.StatusGone {
		t.Fatalf("unknown id commit: %d", code)
	}
	if code, _ := x.call("POST", "/rotate/cancel", map[string]any{"id": a}); code != http.StatusGone {
		t.Fatalf("stale cancel: %d", code)
	}
	if code, _ := x.call("POST", "/rotate/cancel", map[string]any{}); code != http.StatusGone {
		t.Fatalf("cancel without id: %d", code)
	}
	if got := x.stored(t, x.rk); got.SetupSecret != x.card.SetupSecret {
		t.Fatal("a stale op changed the card")
	}
	// B still waits, and its own commit lands B's values.
	next := rotateCommit{ID: b, SetupSecret: synthetic(t, "setup-next-"), SetupCode: "NEXT-CODE"}
	if code, out := x.commit(t, next); code != http.StatusOK {
		t.Fatalf("commit B: %d %v", code, out)
	}
	if got := x.stored(t, x.rk); got.SetupSecret != next.SetupSecret {
		t.Fatal("B's commit did not land")
	}

	// The page gave up on begin D and cancelled it before D arrived; C
	// is waiting. D must not drop C.
	if code, _ := x.begin(t, map[string]any{"code": x.next(), "parts": []string{"setup"}}); code != http.StatusOK {
		t.Fatal("begin C")
	}
	c := x.id
	d := newRotationID()
	if code, _ := x.call("POST", "/rotate/cancel", map[string]any{"id": d}); code != http.StatusGone {
		t.Fatalf("early cancel: %d", code)
	}
	if code, out := x.begin(t, map[string]any{"id": d, "code": x.next(), "parts": []string{"setup"}}); code != http.StatusGone {
		t.Fatalf("begin after its cancel: %d %v", code, out)
	}
	x.c.rot.mu.Lock()
	still := x.c.rot.p != nil && x.c.rot.id == c
	x.c.rot.mu.Unlock()
	if !still {
		t.Fatal("a cancelled begin dropped the waiting rotation")
	}
	x.id = c
	if code := x.cancel(t); code != http.StatusNoContent {
		t.Fatalf("cancel C: %d", code)
	}
}
