package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-8, CRED-9, HW-5a, A8, HW-8

// cardFactor stands in for the Owner Card's passphrase slot, so the
// trusted-host rules run without paying Argon2id on every test; the real
// passphrase slot is exercised in server_test.go.
type cardFactor struct{}

func (cardFactor) Kind() string { return vault.SlotRecovery }
func (cardFactor) Enroll() (vault.Slot, []byte, error) {
	return vault.Slot{Kind: vault.SlotRecovery}, bytes.Repeat([]byte{7}, vault.KeySize), nil
}
func (cardFactor) KEK(vault.Slot) ([]byte, error) { return bytes.Repeat([]byte{7}, vault.KeySize), nil }

// The trusted host's boot path, measured as S7's Type #1 boot does:
// Secure Boot state into PCR 7, initrd into 9, kernel command line (with
// the /usr root hash) into 12.
var testPCRs = []uint{7, 9, 12}

// secureBoot is the PC's Secure Boot state (db, dbx) as PCR 7 measures it.
const secureBoot = "sb-db-2026"

func bootPC(s *swtpm.TPM, initrd, cmdline string) { bootSB(s, secureBoot, initrd, cmdline) }

func bootSB(s *swtpm.TPM, sb, initrd, cmdline string) {
	s.Reboot()
	s.Measure(7, sb)
	s.Measure(9, initrd)
	s.Measure(12, cmdline)
}

func bootGood(s *swtpm.TPM) { bootPC(s, "initrd-A", "usrhash=aaaa quiet") }

// pcRig is one drive (vault, keys, policies, unlock state) and the PC it
// is plugged into.
type pcRig struct {
	dir   string
	vault string
	keys  string
	clk   *clock
	seed  []byte
	tpm   *swtpm.TPM
	c     *custody
	notes []string
	// release is the image version this boot runs (os-release).
	release string
}

func newPCRig(t *testing.T) *pcRig {
	t.Helper()
	dir := t.TempDir()
	r := &pcRig{
		dir:   dir,
		vault: filepath.Join(dir, "vault"),
		keys:  filepath.Join(dir, "vault.keys"),
		clk:   &clock{t: time.Unix(1_800_000_000, 0)},
		seed:  []byte(synthetic(t, "seed-")),
		tpm:   swtpm.Start(t),

		release: "2026.10.1",
	}
	v, err := vault.CreateSealed(r.vault, r.keys, cardFactor{})
	if err != nil {
		t.Fatal(err)
	}
	v.Put(SeedName, vault.KindTOTPSeed, r.seed)
	v.Put("openai", vault.KindAPIKey, []byte(synthetic(t, "sk-canary-")))
	v.Close()
	bootGood(r.tpm)
	r.start(t, r.tpm)
	return r
}

// start runs the vault process on pc (a restart, or the drive moved).
func (r *pcRig) start(t *testing.T, pc *swtpm.TPM) {
	t.Helper()
	if r.c != nil {
		r.c.lock()
	}
	var host trustedHost
	if pc != nil {
		host = &tpmHost{
			openTPM:    pc.Open,
			vaultPath:  r.vault,
			keysPath:   r.keys,
			policyPath: filepath.Join(r.dir, "vault.pcrpolicy"),
			pcrs:       testPCRs,
			name:       "Test PC",
			release:    func() string { return r.release },
			now:        r.clk.now,
			notify:     func(s string) { r.notes = append(r.notes, s) },
		}
	}
	c, err := newCustody(&custody{
		open: func(p string) (*vault.Vault, error) {
			if p != goodPass {
				return nil, vault.ErrNoSlotOpens
			}
			return vault.OpenSealed(r.vault, r.keys, cardFactor{})
		},
		build: func(v *vault.Vault) (*egress.Proxy, error) {
			return newProxy(v, map[string][]string{"agent": {"openai"}}, nil)
		},
		host:      host,
		ttl:       15 * time.Minute,
		now:       r.clk.now,
		notify:    func(s string) { r.notes = append(r.notes, s) },
		statePath: filepath.Join(r.dir, "unlock.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	r.c = c
	t.Cleanup(c.lock)
	c.bootTrusted()
}

func (r *pcRig) phase() phase { p, _ := r.c.status(); return p }

// code is the owner's current code; each call moves the clock to the next
// 30 s step, since a code works once (O6).
func (r *pcRig) code() string {
	r.clk.add(30 * time.Second)
	return totp(r.seed, r.clk.now())
}

// unknownHostUnlock is the CRED-8 unknown-host flow.
func (r *pcRig) unknownHostUnlock(t *testing.T) {
	t.Helper()
	r.clk.add(MinAttemptGap)
	tk, err := r.c.unlock(goodPass)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.c.confirm(tk, r.code()); err != nil {
		t.Fatal(err)
	}
}

func (r *pcRig) tpmSlots(t *testing.T) int {
	t.Helper()
	slots, err := vault.ReadSlots(r.keys)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, s := range slots {
		if s.Kind == vault.SlotTPM {
			n++
		}
	}
	return n
}

func (r *pcRig) noted(sub string) bool {
	for _, n := range r.notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

// CRED-8, A8: the drive starts as an unknown host; after the owner makes
// this PC trusted (approval code on the local page, CRED-9), a restart on
// the same boot path opens the vault with no owner input at all.
func TestTrustedHostRestartsUnattended(t *testing.T) {
	r := newPCRig(t)
	if r.phase() != locked || !r.noted("unknown host") {
		t.Fatalf("fresh drive: phase %v, notes %q", r.phase(), r.notes)
	}
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatalf("trust: %v", err)
	}
	if r.tpmSlots(t) != 1 {
		t.Fatal("no trusted-host slot after trust")
	}

	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.phase() != open || r.c.model() == nil {
		t.Fatalf("trusted host after restart: phase %v, notes %q", r.phase(), r.notes)
	}
}

// CRED-9: adding a trusted host needs the vault open and an approval code
// from the code generator, used once; a wrong code counts toward the cap.
func TestTrustNeedsAnApprovalCode(t *testing.T) {
	r := newPCRig(t)
	if _, err := r.c.trust(r.code(), ""); err != errLocked {
		t.Fatalf("trust while locked: %v", err)
	}
	r.unknownHostUnlock(t)
	if _, err := r.c.trust("000000", ""); err == nil || !strings.HasPrefix(err.Error(), "wrong code") {
		t.Fatalf("wrong code: %v", err)
	}
	if _, err := r.c.trust("", ""); err == nil {
		t.Fatal("no code accepted")
	}
	if r.tpmSlots(t) != 0 {
		t.Fatal("slot added without a valid code")
	}
	c := r.code()
	if _, err := r.c.trust(c, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.trust(c, ""); err == nil {
		t.Fatal("the same code worked twice")
	}
}

// HW-5a, A8: a modified initrd or kernel command line does not unlock on
// the trusted host. The owner is told the boot path changed, and can
// still unlock as on an unknown host.
func TestModifiedBootPathDoesNotUnlockUnattended(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatal(err)
	}
	for _, b := range [][2]string{
		{"initrd-A-plus-keylogger", "usrhash=aaaa quiet"},
		{"initrd-A", "usrhash=aaaa quiet init=/bin/sh"},
	} {
		bootPC(r.tpm, b[0], b[1])
		r.notes = nil
		r.start(t, r.tpm)
		if r.phase() != locked || r.c.model() != nil {
			t.Fatalf("modified boot path %q unlocked", b)
		}
		if !r.noted("started the box in a way it hasn't before") || !r.noted("tampered") {
			t.Fatalf("owner not told: %q", r.notes)
		}
	}
	r.unknownHostUnlock(t)
	if r.phase() != open {
		t.Fatal("passphrase and code no longer unlock after a boot path change")
	}
}

// CRED-8: the drive moved to another PC is an unknown host there, even
// though it carries the first PC's slot.
func TestOtherPCIsAnUnknownHost(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatal(err)
	}
	other := swtpm.Start(t)
	bootGood(other)
	r.notes = nil
	r.start(t, other)
	if r.phase() != locked || !r.noted("unknown host") {
		t.Fatalf("other PC: phase %v, notes %q", r.phase(), r.notes)
	}
	r.unknownHostUnlock(t)
	// Trusting the second PC keeps the first.
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatal(err)
	}
	if r.tpmSlots(t) != 2 {
		t.Fatalf("trusted-host slots: %d, want 2", r.tpmSlots(t))
	}
	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.phase() != open {
		t.Fatal("first PC no longer trusted after trusting a second")
	}
}

// CRED-8: the optional boot PIN. The PC restarts locked and waits for the
// PIN on the local page; a wrong PIN opens nothing; the right one opens
// the vault without the card or a code.
func TestBootPIN(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), "12"); err != errBadPIN {
		t.Fatalf("short PIN: %v", err)
	}
	// Six characters at least (arbitrator), counted as characters: five
	// letters are too short in any script.
	if _, err := r.c.trust(r.code(), "äöüäö"); err != errBadPIN {
		t.Fatalf("five-character PIN: %v", err)
	}
	if _, err := r.c.trust(r.code(), "12345"); err != errBadPIN {
		t.Fatalf("five-digit PIN: %v", err)
	}
	if _, err := r.c.trust(r.code(), "246810"); err != nil {
		t.Fatal(err)
	}
	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.phase() != locked || !r.c.pinWanted() {
		t.Fatalf("PIN host after restart: phase %v, wants PIN %v", r.phase(), r.c.pinWanted())
	}
	r.clk.add(MinAttemptGap)
	if err := r.c.unlockPIN("135711"); err != errWrongPIN {
		t.Fatalf("wrong PIN: %v", err)
	}
	if r.phase() != locked {
		t.Fatal("wrong PIN opened the vault")
	}
	if err := r.c.unlockPIN("246810"); err != errTooSoon {
		t.Fatalf("PIN tries not spaced: %v", err)
	}
	r.clk.add(MinAttemptGap)
	if err := r.c.unlockPIN("246810"); err != nil {
		t.Fatalf("right PIN: %v", err)
	}
	if r.phase() != open || r.c.pinWanted() {
		t.Fatal("right PIN did not open the vault")
	}
}

// CRED-9: removing a trusted host needs a code too; afterwards the PC is
// an unknown host.
func TestRemoveTrustedHost(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatal(err)
	}
	hosts, err := r.c.hosts()
	if err != nil || len(hosts) != 1 || !hosts[0].This || hosts[0].Host != "Test PC" || hosts[0].PIN {
		t.Fatalf("hosts: %+v, %v", hosts, err)
	}
	if want := "Test PC, trusted " + r.clk.now().Local().Format("Jan 2"); hosts[0].Label != want {
		t.Fatalf("host label %q, want %q", hosts[0].Label, want)
	}
	if _, err := r.c.untrust("000000", hosts[0].ID); err == nil {
		t.Fatal("untrust with a wrong code")
	}
	if n, err := r.c.untrust(r.code(), hosts[0].ID); err != nil || n != 1 {
		t.Fatalf("untrust: %d, %v", n, err)
	}
	if r.tpmSlots(t) != 0 {
		t.Fatal("slot left after untrust")
	}
	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.phase() != locked {
		t.Fatal("removed host still unlocks unattended")
	}
}

// Without a TPM (the cloud box) every boot is an unknown host, and making
// the PC trusted is refused rather than half done.
func TestNoTPM(t *testing.T) {
	r := newPCRig(t)
	r.start(t, nil)
	if r.phase() != locked {
		t.Fatal("opened without a TPM")
	}
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), ""); err != errNoTPM {
		t.Fatalf("trust without a TPM: %v", err)
	}
}

// HW-5a: the policy key lives only inside the vault. Neither the keys
// file nor the policy file holds it, the proxy cannot inject it, and the
// credential socket cannot overwrite it.
func TestPolicyKeyStaysInTheVault(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatal(err)
	}
	sec, ok := r.c.v.Secret(PolicyKeyName)
	if !ok {
		t.Fatal("no policy key in the vault")
	}
	der := []byte(sec.Reveal())
	k, err := tpmseal.ParsePolicyKey(der)
	if err != nil {
		t.Fatal(err)
	}
	priv := k.D.Bytes()
	entries, _ := os.ReadDir(r.dir)
	for _, e := range entries {
		raw, _ := os.ReadFile(filepath.Join(r.dir, e.Name()))
		if bytes.Contains(raw, der) || bytes.Contains(raw, priv) {
			t.Fatalf("%s holds the policy key", e.Name())
		}
	}
	if _, ok := (apiKeysOnly{r.c.v}).Secret(PolicyKeyName); ok {
		t.Fatal("proxy can inject the policy key")
	}
	if err := r.c.put(PolicyKeyName, []byte(synthetic(t, "sk-"))); !errors.Is(err, errBadCredential) {
		t.Fatalf("put over the policy key: %v", err)
	}
}

// The local UI drives trusted hosts over the unlock socket: /trust with a
// code (and PIN), /hosts, and after a restart /status asks for the PIN and
// /unlock-pin opens the vault.
func TestTrustedHostOverTheUnlockSocket(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	call := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rd = bytes.NewReader(raw)
		}
		w := httptest.NewRecorder()
		unlockHandler(r.c).ServeHTTP(w, httptest.NewRequest(method, path, rd))
		out := map[string]any{}
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, out := call("POST", "/trust", map[string]string{"code": "000000"}); code != http.StatusForbidden {
		t.Fatalf("trust with a wrong code: %d %v", code, out)
	}
	if code, out := call("POST", "/trust", map[string]string{"code": r.code(), "pin": "864213"}); code != http.StatusOK || out["host"] != "Test PC" {
		t.Fatalf("trust: %d %v", code, out)
	}
	code, out := call("GET", "/hosts", nil)
	hosts, _ := out["hosts"].([]any)
	if code != http.StatusOK || len(hosts) != 1 {
		t.Fatalf("hosts: %d %v", code, out)
	}

	bootGood(r.tpm)
	r.start(t, r.tpm)
	if _, out := call("GET", "/status", nil); out["state"] != "locked" || out["pin"] != true {
		t.Fatalf("status on a PIN host: %v", out)
	}
	r.clk.add(MinAttemptGap)
	if code, out := call("POST", "/unlock-pin", map[string]string{"pin": "864213"}); code != http.StatusOK || out["state"] != "open" {
		t.Fatalf("unlock-pin: %d %v", code, out)
	}
	id, _ := hosts[0].(map[string]any)["id"].(string)
	if code, _ := call("POST", "/untrust", map[string]string{"code": r.code(), "id": id}); code != http.StatusNoContent {
		t.Fatalf("untrust: %d", code)
	}
}

// CRED-8: a PIN slot takes the TPM's lockout hierarchy with an
// authorization kept only in the vault, so a thief cannot reset the TPM's
// guess counter with the factory-empty lockout password. Turning the PIN
// off gives the hierarchy back (arbitrator: reversible).
func TestBootPINTakesTheLockoutHierarchy(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), "246810"); err != nil {
		t.Fatal(err)
	}
	name := r.lockoutEntry()
	if name == "" {
		t.Fatal("no lockout authorization in the vault")
	}
	if _, ok := (apiKeysOnly{r.c.v}).Secret(name); ok {
		t.Fatal("proxy can inject the lockout authorization")
	}
	if err := r.c.put(name, []byte(synthetic(t, "sk-"))); !errors.Is(err, errBadCredential) {
		t.Fatalf("put over the lockout authorization: %v", err)
	}
	if err := r.c.put(lockoutAuthPrefix+"x", []byte(synthetic(t, "sk-"))); !errors.Is(err, errBadCredential) {
		t.Fatalf("put under the reserved prefix: %v", err)
	}
	// Re-trusting the PC (say, to change the PIN) keeps the same one.
	if _, err := r.c.trust(r.code(), "135799"); err != nil {
		t.Fatalf("re-trust with a new PIN: %v", err)
	}
	if r.lockoutEntry() != name {
		t.Fatal("changing the PIN replaced the lockout authorization")
	}
	// PIN off: the lockout password is empty again and the vault forgets it.
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatal(err)
	}
	if r.lockoutEntry() != "" {
		t.Fatal("lockout authorization kept after the PIN was turned off")
	}
	if err := r.tpm.ThiefLockReset(); err != nil {
		t.Fatalf("lockout not given back after the PIN was turned off: %v", err)
	}
	// PIN on again: a thief's empty-password reset fails.
	if _, err := r.c.trust(r.code(), "246810"); err != nil {
		t.Fatal(err)
	}
	if err := r.tpm.ThiefLockReset(); err == nil {
		t.Fatal("empty lockout password still resets the PIN guess counter")
	}
}

// Removing this PC from the trusted hosts gives the lockout hierarchy back.
func TestUntrustGivesTheLockoutBack(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), "246810"); err != nil {
		t.Fatal(err)
	}
	hosts, _ := r.c.hosts()
	if _, err := r.c.untrust(r.code(), hosts[0].ID); err != nil {
		t.Fatal(err)
	}
	if r.lockoutEntry() != "" {
		t.Fatal("lockout authorization kept after untrust")
	}
	if err := r.tpm.ThiefLockReset(); err != nil {
		t.Fatalf("lockout not given back after untrust: %v", err)
	}
}

// After a wrong lockout password the TPM refuses the box's own for a day,
// so turning the PIN off then cannot give the hierarchy back at once. The
// vault keeps the authorization, the owner is told, and the box retries
// at each unattended start.
func TestLockoutReleaseRetried(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), "246810"); err != nil {
		t.Fatal(err)
	}
	r.tpm.ThiefLockReset()
	r.notes = nil
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatalf("PIN off while the lockout hierarchy is locked: %v", err)
	}
	if r.lockoutEntry() == "" {
		t.Fatal("lockout authorization dropped before it was given back")
	}
	if !r.noted("give the TPM's lockout back") {
		t.Fatalf("owner not told: %q", r.notes)
	}
}

func (r *pcRig) lockoutEntry() string {
	for _, e := range r.c.v.List() {
		if e.Kind == vault.KindTPMLockoutAuth {
			return e.Name
		}
	}
	return ""
}

// When other software already set the lockout password, the box cannot
// vouch for the PIN's guess limit: a PIN is refused, and nothing guesses
// that password. Trusting the PC without a PIN still works.
func TestBootPINRefusedWhenLockoutIsOwned(t *testing.T) {
	r := newPCRig(t)
	other, _ := tpmseal.NewLockoutAuth()
	if err := tpmseal.TakeLockout(r.tpm.TPM(), other, false); err != nil {
		t.Fatal(err)
	}
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), "246810"); err != errLockoutOwned {
		t.Fatalf("PIN with a foreign lockout password: %v", err)
	}
	if r.tpmSlots(t) != 0 {
		t.Fatal("slot added anyway")
	}
	if r.lockoutEntry() != "" {
		t.Fatal("unused lockout authorization left in the vault")
	}
	// The settings are another system's: nothing is kept to put back.
	if n, _ := r.daEntry(); n != "" {
		t.Fatal("another system's settings kept as this PC's originals")
	}
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatalf("trust without a PIN: %v", err)
	}
}

// After the box's own update the trusted PC is refused like any changed
// boot path (no signed policy yet), but the owner is told it is the
// update, not tampering.
func TestBoxUpdateIsNotCalledTampering(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatal(err)
	}
	r.release = "2026.11.1"
	bootPC(r.tpm, "initrd-B", "usrhash=bbbb quiet")
	r.notes = nil
	r.start(t, r.tpm)
	if r.phase() != locked {
		t.Fatal("unapproved release unlocked unattended")
	}
	if !r.noted("Box updated. Unlock once with your passphrase and a code; this PC stays trusted after that.") || r.noted("tampered") {
		t.Fatalf("update notes: %q", r.notes)
	}
	if ch, upd, _ := r.c.bootChange(); !ch || !upd {
		t.Fatalf("boot change %v, update %v", ch, upd)
	}
}

// "Keep this PC trusted": after a changed boot path, the fallback unlock's
// own proof (passphrase, code, local page) approves the new boot path, so
// the next restart is unattended again, and a PIN slot keeps its PIN.
func TestKeepThisPCTrusted(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), "246810"); err != nil {
		t.Fatal(err)
	}
	r.release = "2026.11.1"
	newPath := func() { bootPC(r.tpm, "initrd-B", "usrhash=bbbb quiet") }
	newPath()
	r.start(t, r.tpm)
	r.clk.add(MinAttemptGap)
	if err := r.c.unlockPIN("246810"); err != errBootChanged {
		t.Fatalf("PIN on a changed boot path: %v", err)
	}

	r.clk.add(MinAttemptGap)
	tk, err := r.c.unlock(goodPass)
	if err != nil {
		t.Fatal(err)
	}
	kept, err := r.c.confirmKeep(tk, r.code(), true)
	if err != nil || !kept {
		t.Fatalf("keep trusted: %v, %v", kept, err)
	}
	if r.tpmSlots(t) != 1 {
		t.Fatal("keeping the PC trusted resealed its slot")
	}
	newPath()
	r.start(t, r.tpm)
	if !r.c.pinWanted() {
		t.Fatalf("kept PC: wants PIN %v, notes %q", r.c.pinWanted(), r.notes)
	}
	r.clk.add(MinAttemptGap)
	if err := r.c.unlockPIN("246810"); err != nil {
		t.Fatalf("PIN after keeping the PC trusted: %v", err)
	}
	if ch, _, _ := r.c.bootChange(); ch {
		t.Fatal("boot change still reported after unlocking")
	}
}

// Unticking "Keep this PC trusted" approves nothing, and keep has no
// effect when the boot path did not change (an unknown host stays one).
func TestKeepTrustedOnlyWhenAsked(t *testing.T) {
	r := newPCRig(t)
	r.clk.add(MinAttemptGap)
	tk, _ := r.c.unlock(goodPass)
	if kept, err := r.c.confirmKeep(tk, r.code(), true); err != nil || kept {
		t.Fatalf("unknown host kept: %v, %v", kept, err)
	}
	if r.tpmSlots(t) != 0 {
		t.Fatal("unknown host became trusted without /trust")
	}
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatal(err)
	}
	bootPC(r.tpm, "initrd-B", "usrhash=bbbb quiet")
	r.start(t, r.tpm)
	r.clk.add(MinAttemptGap)
	tk, _ = r.c.unlock(goodPass)
	if kept, err := r.c.confirmKeep(tk, r.code(), false); err != nil || kept {
		t.Fatalf("unticked: %v, %v", kept, err)
	}
	bootPC(r.tpm, "initrd-B", "usrhash=bbbb quiet")
	r.start(t, r.tpm)
	if r.phase() != locked {
		t.Fatal("changed boot path approved without the owner asking")
	}
}

// The local page learns of a changed boot path from /status and sends
// "Keep this PC trusted" with /confirm.
func TestKeepTrustedOverTheUnlockSocket(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatal(err)
	}
	call := func(method, path string, body any) map[string]any {
		t.Helper()
		var rd io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rd = bytes.NewReader(raw)
		}
		w := httptest.NewRecorder()
		unlockHandler(r.c).ServeHTTP(w, httptest.NewRequest(method, path, rd))
		out := map[string]any{}
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	bootPC(r.tpm, "initrd-A", "usrhash=aaaa quiet init=/bin/sh")
	r.start(t, r.tpm)
	if out := call("GET", "/status", nil); out["boot_changed"] != true || out["updated"] != false {
		t.Fatalf("status after a changed boot path: %v", out)
	}
	r.clk.add(MinAttemptGap)
	tk, _ := call("POST", "/unlock", map[string]string{"passphrase": goodPass})["ticket"].(string)
	if out := call("POST", "/confirm", map[string]any{"ticket": tk, "code": r.code(), "keep_trusted": true}); out["state"] != "open" || out["kept_trusted"] != true {
		t.Fatalf("confirm keeping the PC trusted: %v", out)
	}
	if out := call("GET", "/status", nil); out["boot_changed"] != nil {
		t.Fatalf("status once open: %v", out)
	}
}

// PCR 7 (arbitrator): a Secure Boot change made outside the box (say, a
// firmware update that changed db) stops the unattended unlock, and the
// owner is told what changed rather than warned of tampering.
func TestSecureBootChangeIsNamed(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatal(err)
	}
	bootSB(r.tpm, "sb-db-2027", "initrd-A", "usrhash=aaaa quiet")
	r.notes = nil
	r.start(t, r.tpm)
	if r.phase() != locked {
		t.Fatal("changed Secure Boot state unlocked unattended")
	}
	if !r.noted("Secure Boot settings on this PC changed. If you updated firmware, unlock with your card to keep this PC trusted.") || r.noted("tampered") {
		t.Fatalf("Secure Boot notes: %q", r.notes)
	}
	if _, _, sb := r.c.bootChange(); !sb {
		t.Fatal("status does not report the Secure Boot change")
	}
	// A change beyond PCR 7 is not called a Secure Boot change.
	bootSB(r.tpm, "sb-db-2027", "initrd-evil", "usrhash=aaaa quiet")
	r.notes = nil
	r.start(t, r.tpm)
	if r.noted("Secure Boot") || !r.noted("tampered") {
		t.Fatalf("mixed change notes: %q", r.notes)
	}
}

// A lockout authorization the TPM has proved stale (say, other software
// re-keyed it) is dropped rather than retried at every start, which would
// re-arm the TPM's day-long lockout each time.
func TestStaleLockoutEntryIsDropped(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), "246810"); err != nil {
		t.Fatal(err)
	}
	sec, _ := r.c.v.Secret(r.lockoutEntry())
	if err := tpmseal.ReleaseLockout(r.tpm.TPM(), []byte(sec.Reveal())); err != nil {
		t.Fatal(err)
	}
	other, _ := tpmseal.NewLockoutAuth()
	if err := tpmseal.TakeLockout(r.tpm.TPM(), other, false); err != nil {
		t.Fatal(err)
	}
	r.notes = nil
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatal(err)
	}
	if r.lockoutEntry() != "" {
		t.Fatal("stale lockout authorization kept for retries")
	}
	if !r.noted("Another system on this PC now controls the TPM") {
		t.Fatalf("owner not told: %q", r.notes)
	}
	// The settings the stale lockout guarded are the other system's now:
	// their kept originals go too, without a second message (HOST-1f).
	if n, _ := r.daEntry(); n != "" || r.noted("security chip") {
		t.Fatalf("originals entry %q, notes %q", n, r.notes)
	}
}

// The CLI's "Keep this PC trusted" prompt is never ticked by default: the
// update and Secure Boot hints come from files on the drive (Security
// lens, #50), so an empty answer keeps nothing.
func TestUnlockCLIKeepTrustedDefault(t *testing.T) {
	for _, tc := range []struct {
		name    string
		boot    func(r *pcRig)
		prompt  string
		kept    bool
		release string
	}{
		{"update", func(r *pcRig) { bootPC(r.tpm, "initrd-B", "usrhash=bbbb quiet") }, "[y/N]", false, "2026.11.1"},
		{"secure boot", func(r *pcRig) { bootSB(r.tpm, "sb-db-2027", "initrd-A", "usrhash=aaaa quiet") }, "[y/N]", false, ""},
		{"unexplained", func(r *pcRig) { bootPC(r.tpm, "initrd-A", "usrhash=aaaa init=/bin/sh") }, "[y/N]", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPCRig(t)
			r.unknownHostUnlock(t)
			if _, err := r.c.trust(r.code(), ""); err != nil {
				t.Fatal(err)
			}
			if tc.release != "" {
				r.release = tc.release
			}
			tc.boot(r)
			r.start(t, r.tpm)
			run := filepath.Join(r.dir, "run")
			os.Mkdir(run, 0o700)
			ln, err := net.Listen("unix", filepath.Join(run, UnlockSocket))
			if err != nil {
				t.Fatal(err)
			}
			srv := &http.Server{Handler: unlockHandler(r.c)}
			go srv.Serve(ln)
			defer srv.Close()
			r.clk.add(MinAttemptGap)
			in := strings.NewReader("\n" + goodPass + "\n" + totp(r.seed, r.clk.now().Add(30*time.Second)) + "\n")
			r.clk.add(30 * time.Second)
			var out bytes.Buffer
			if err := unlockCmd([]string{"-run", run}, in, &out); err != nil {
				t.Fatalf("unlock: %v\n%s", err, out.String())
			}
			if !strings.Contains(out.String(), "Keep this PC trusted? "+tc.prompt) {
				t.Fatalf("prompt: %s", out.String())
			}
			// Kept means the next restart on this boot path is unattended.
			tc.boot(r)
			r.start(t, r.tpm)
			if got := r.phase() == open; got != tc.kept {
				t.Fatalf("kept %v, want %v", got, tc.kept)
			}
		})
	}
}

// daEntry is the vault's kept dictionary-attack originals entry, if any.
func (r *pcRig) daEntry() (name, value string) {
	for _, e := range r.c.v.List() {
		if e.Kind == vault.KindTPMDAOriginal {
			s, _ := r.c.v.Secret(e.Name)
			return e.Name, s.Reveal()
		}
	}
	return "", ""
}

func (r *pcRig) readDA(t *testing.T) tpmseal.DAParams {
	t.Helper()
	p, err := tpmseal.ReadDA(r.tpm.TPM())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// pcDA is a PC's own dictionary-attack settings, unlike the PIN slot's.
var pcDA = tpmseal.DAParams{MaxTries: 7, Interval: 600, Recovery: 3600}

func (r *pcRig) setPCDA(t *testing.T) {
	t.Helper()
	if err := tpmseal.RestoreDA(r.tpm.TPM(), pcDA); err != nil {
		t.Fatal(err)
	}
}

// HOST-1f (HW-8, D7): turning a boot PIN on keeps the PC's own
// dictionary-attack settings in the vault before the TPM is changed, and
// turning it off puts them back exactly; the entry then goes, so a later
// PIN reads the PC's settings afresh (Security H3).
func TestPINOffGivesTheDASettingsBack(t *testing.T) {
	r := newPCRig(t)
	r.setPCDA(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), "246810"); err != nil {
		t.Fatal(err)
	}
	name, val := r.daEntry()
	if name != daOriginalPrefix+strings.TrimPrefix(r.lockoutEntry(), lockoutAuthPrefix) || val != daValuePrefix+pcDA.String() {
		t.Fatalf("kept originals %q = %q (lockout entry %q)", name, val, r.lockoutEntry())
	}
	if got := r.readDA(t); got != tpmseal.PINDA {
		t.Fatalf("PIN settings %+v", got)
	}
	if _, ok := (apiKeysOnly{r.c.v}).Secret(name); ok {
		t.Fatal("proxy can read the kept settings")
	}
	// Changing the PIN keeps the first originals, not the PIN's own.
	if _, err := r.c.trust(r.code(), "135799"); err != nil {
		t.Fatal(err)
	}
	if _, v := r.daEntry(); v != daValuePrefix+pcDA.String() {
		t.Fatalf("originals replaced: %q", v)
	}
	r.notes = nil
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatal(err)
	}
	if got := r.readDA(t); got != pcDA {
		t.Fatalf("after PIN off %+v, want %+v", got, pcDA)
	}
	if n, _ := r.daEntry(); n != "" || r.lockoutEntry() != "" {
		t.Fatalf("entries left: %q, %q", n, r.lockoutEntry())
	}
	if r.noted("security chip") || r.noted("lockout") {
		t.Fatalf("owner told about a clean give-back: %q", r.notes)
	}
}

// Security H3: a take cut off after the PIN's settings were written but
// before the lockout authorization was set leaves the originals entry;
// the next take keeps it, and PIN off restores the true settings.
func TestDAOriginalsSurviveAPartialTake(t *testing.T) {
	r := newPCRig(t)
	r.setPCDA(t)
	r.unknownHostUnlock(t)
	id, err := tpmseal.Identity(r.tpm.TPM())
	if err != nil {
		t.Fatal(err)
	}
	if err := keepDAOriginal(r.c.v, r.tpm.TPM(), id); err != nil {
		t.Fatal(err)
	}
	if err := tpmseal.RestoreDA(r.tpm.TPM(), tpmseal.PINDA); err != nil { // the cut-off midpoint
		t.Fatal(err)
	}
	if _, err := r.c.trust(r.code(), "246810"); err != nil {
		t.Fatal(err)
	}
	if _, v := r.daEntry(); v != daValuePrefix+pcDA.String() {
		t.Fatalf("originals after the retried take: %q", v)
	}
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatal(err)
	}
	if got := r.readDA(t); got != pcDA {
		t.Fatalf("after PIN off %+v, want %+v", got, pcDA)
	}
}

// Security H5, D4: originals left with no lockout entry (a restore that
// failed after the release, or a crash before the take) are restored at
// the next unattended start and then forgotten.
func TestPendingDARestoreIsRetriedAtStart(t *testing.T) {
	r := newPCRig(t)
	r.setPCDA(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatal(err)
	}
	id, _ := tpmseal.Identity(r.tpm.TPM())
	if err := keepDAOriginal(r.c.v, r.tpm.TPM(), id); err != nil {
		t.Fatal(err)
	}
	if err := tpmseal.RestoreDA(r.tpm.TPM(), tpmseal.PINDA); err != nil {
		t.Fatal(err)
	}
	r.notes = nil
	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.phase() != open {
		t.Fatalf("phase %v, notes %q", r.phase(), r.notes)
	}
	if got := r.readDA(t); got != pcDA {
		t.Fatalf("after start %+v, want %+v", got, pcDA)
	}
	if n, _ := r.daEntry(); n != "" {
		t.Fatal("restored entry kept")
	}
}

// Security H1, H6: when another system has set the lockout authorization
// since, nothing is tried against it (a wrong one would lock its lockout
// hierarchy for a day at every start), the entry is dropped, and the
// owner is told once, in the guide's words.
func TestDARestoreNeverProbesAForeignLockout(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatal(err)
	}
	id, _ := tpmseal.Identity(r.tpm.TPM())
	if err := keepDAOriginal(r.c.v, r.tpm.TPM(), id); err != nil {
		t.Fatal(err)
	}
	other, _ := tpmseal.NewLockoutAuth()
	if err := tpmseal.TakeLockout(r.tpm.TPM(), other, false); err != nil {
		t.Fatal(err)
	}
	before := r.readDA(t)
	r.notes = nil
	bootGood(r.tpm)
	r.start(t, r.tpm)
	if err := tpmseal.TakeLockout(r.tpm.TPM(), other, true); err != nil {
		t.Fatalf("the other system's lockout authorization was disturbed: %v", err)
	}
	if got := r.readDA(t); got != before {
		t.Fatalf("settings changed under a foreign lockout: %+v", got)
	}
	if n, _ := r.daEntry(); n != "" {
		t.Fatal("unrestorable entry kept for retries")
	}
	const msg = "Another system on this PC, probably Windows, now controls its security chip's lockout, so I couldn't put back the chip's limit on wrong guesses. Nothing to do: your PIN is off and the box works as before."
	told := 0
	for _, n := range r.notes {
		if strings.Contains(n, "security chip") {
			if n != msg {
				t.Fatalf("note %q", n)
			}
			told++
		}
	}
	if told != 1 {
		t.Fatalf("notes %q", r.notes)
	}
	r.notes = nil
	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.noted("security chip") {
		t.Fatal("told twice")
	}
}

// Security H2, H4: originals kept for another PC's TPM are never written
// into this one, and a malformed entry is never written at all; both stay.
func TestDAOriginalsOnlyForTheirOwnTPM(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatal(err)
	}
	before := r.readDA(t)
	otherPC := daOriginalName([]byte("\x00\x0bsome-other-pcs-srk-name"))
	if err := r.c.v.Put(otherPC, vault.KindTPMDAOriginal, []byte(daValuePrefix+"1,1,1")); err != nil {
		t.Fatal(err)
	}
	bootGood(r.tpm)
	r.start(t, r.tpm)
	if got := r.readDA(t); got != before {
		t.Fatalf("another PC's settings written here: %+v", got)
	}
	if n, _ := r.daEntry(); n != otherPC {
		t.Fatal("another PC's entry dropped")
	}
	r.c.v.Delete(otherPC)
	id, _ := tpmseal.Identity(r.tpm.TPM())
	for _, bad := range []string{daValuePrefix + "1,1", daValuePrefix + "1, 1,1", "tpm-da-v2 1,1,1", daValuePrefix + "01,1,1"} {
		if err := r.c.v.Put(daOriginalName(id), vault.KindTPMDAOriginal, []byte(bad)); err != nil {
			t.Fatal(err)
		}
		bootGood(r.tpm)
		r.start(t, r.tpm)
		if got := r.readDA(t); got != before {
			t.Fatalf("malformed %q written: %+v", bad, got)
		}
		if _, v := r.daEntry(); v != bad {
			t.Fatalf("malformed %q dropped or changed: %q", bad, v)
		}
	}
}

// D5: a vault whose PIN was turned on before HOST-1f has no originals;
// PIN off gives the lockout back and leaves the settings, saying nothing.
func TestLegacyPINOffLeavesTheDASettings(t *testing.T) {
	r := newPCRig(t)
	r.setPCDA(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), "246810"); err != nil {
		t.Fatal(err)
	}
	n, _ := r.daEntry()
	r.c.v.Delete(n)
	r.notes = nil
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatal(err)
	}
	if got := r.readDA(t); got != tpmseal.PINDA {
		t.Fatalf("legacy settings %+v", got)
	}
	if r.lockoutEntry() != "" || r.noted("security chip") || r.noted("lockout") {
		t.Fatalf("lockout %q, notes %q", r.lockoutEntry(), r.notes)
	}
}
