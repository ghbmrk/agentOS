package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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

// REQ: CRED-8, CRED-9, HW-5a, A8

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
// initrd into PCR 9, kernel command line (with the /usr root hash) into 12.
var testPCRs = []uint{9, 12}

func bootPC(s *swtpm.TPM, initrd, cmdline string) {
	s.Reboot()
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
		if !r.noted("boot path changed") {
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
	if _, err := r.c.trust(r.code(), "2468"); err != nil {
		t.Fatal(err)
	}
	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.phase() != locked || !r.c.pinWanted() {
		t.Fatalf("PIN host after restart: phase %v, wants PIN %v", r.phase(), r.c.pinWanted())
	}
	r.clk.add(MinAttemptGap)
	if err := r.c.unlockPIN("1357"); err != errWrongPIN {
		t.Fatalf("wrong PIN: %v", err)
	}
	if r.phase() != locked {
		t.Fatal("wrong PIN opened the vault")
	}
	if err := r.c.unlockPIN("2468"); err != errTooSoon {
		t.Fatalf("PIN tries not spaced: %v", err)
	}
	r.clk.add(MinAttemptGap)
	if err := r.c.unlockPIN("2468"); err != nil {
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
	if code, out := call("POST", "/trust", map[string]string{"code": r.code(), "pin": "8642"}); code != http.StatusOK || out["host"] != "Test PC" {
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
	if code, out := call("POST", "/unlock-pin", map[string]string{"pin": "8642"}); code != http.StatusOK || out["state"] != "open" {
		t.Fatalf("unlock-pin: %d %v", code, out)
	}
	id, _ := hosts[0].(map[string]any)["id"].(string)
	if code, _ := call("POST", "/untrust", map[string]string{"code": r.code(), "id": id}); code != http.StatusNoContent {
		t.Fatalf("untrust: %d", code)
	}
}
