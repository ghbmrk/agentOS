package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"

	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/vault"
)

// PolicyKeyName is the vault entry holding the box's PCR policy key
// (HW-5a): it signs the boot paths this box approves, and never leaves
// the vault.
const PolicyKeyName = "pcr-policy-key"

// lockoutAuthPrefix names the vault entries holding a trusted PC's TPM
// lockout authorization, one per TPM, followed by part of its SRK name.
const lockoutAuthPrefix = "tpm-lockout-"

// daOriginalPrefix names the vault entries keeping a trusted PC's own TPM
// dictionary-attack settings while a boot PIN slot has replaced them
// (HOST-1f); daValuePrefix versions their value and gives it the vault's
// minimum length.
const (
	daOriginalPrefix = "tpm-da-"
	daValuePrefix    = "tpm-da-v1 "
)

// maxPolicies bounds the approved boot paths kept; the oldest go first.
const maxPolicies = 16

// hostInfo describes one trusted PC for the local UI.
type hostInfo struct {
	// ID is the PC's TPM identity (its storage root key's name, hex).
	ID string `json:"id"`
	// Host is the PC's product name when it was trusted.
	Host string `json:"host"`
	// This is the PC the box is running on.
	This bool `json:"this"`
	// PIN: this PC's slot needs the boot PIN.
	PIN bool `json:"pin"`
	// Trusted is when the owner trusted the PC (RFC 3339), if known.
	Trusted string `json:"trusted,omitempty"`
	// Label is what the owner sees, such as "GEEKOM Air12, trusted Oct 5".
	Label string `json:"label"`
}

// trustedHost is this PC's TPM as custody sees it (CRED-8 trusted host).
type trustedHost interface {
	// open opens the vault through this PC's slot; pin is the boot PIN
	// when the slot has one.
	open(pin string) (*vault.Vault, error)
	// enroll approves the running boot path and seals a slot for this PC
	// on the open vault, replacing any slot it had. It returns the PC's
	// name.
	enroll(v *vault.Vault, pin string) (string, error)
	// remove drops the slot of the PC with the given ID.
	remove(v *vault.Vault, id string) (int, error)
	// list describes the trusted PCs.
	list() ([]hostInfo, error)
	// anchor binds the open vault to this PC's rollback counter, making
	// the counter if needed (V6); trust calls it before enroll.
	anchor(v *vault.Vault) error
	// reencrypt moves the open vault to a fresh data key (vault.Reencrypt,
	// proving owner) and a new policy key, and seals fresh slots for this
	// PC (with pin if its slot has one) and for every other trusted PC it
	// can reach without that PC. It returns how many other PCs must be
	// trusted again.
	reencrypt(v *vault.Vault, pin string, owner []vault.Factor) (int, error)
	// bind checks an open vault against this PC's rollback counter and
	// binds it, so every later write advances the counter (V6). It
	// returns vault.ErrRolledBack for an old copy of the drive.
	bind(v *vault.Vault) error
	// approve adds the running boot path to the approved ones, without
	// touching any slot ("Keep this PC trusted" after a fallback unlock).
	approve(v *vault.Vault) error
	// updated reports whether this boot runs another release of the box
	// than the last one this PC unlocked on, and secureBootChanged whether
	// only the Secure Boot state (PCR 7) differs from the boot path last
	// approved. Both read files an attacker with the drive could write,
	// so they only pick the owner's wording.
	updated() bool
	secureBootChanged() bool
	// updateCounter is this PC's TPM as the counter that anchors the
	// update store's outside-attestor record (SR3-6f-2b).
	updateCounter() (vault.Counter, error)
}

// tpmHost is trustedHost over the PC's TPM (package tpmseal). Approved
// boot paths are in policyPath beside the keys file: signatures, no
// secrets.
type tpmHost struct {
	openTPM    func() (transport.TPMCloser, error)
	vaultPath  string
	keysPath   string
	policyPath string
	pcrs       []uint
	// name is this PC's product name, shown to the owner.
	name string
	// release is the running image's version (os-release IMAGE_VERSION).
	release func() string
	now     func() time.Time
	// notify tells the owner (as custody.notify).
	notify func(string)

	mu sync.Mutex // one TPM conversation at a time
	// daWarned: the owner was told this run that the chip's limit on
	// wrong guesses could not be put back yet (HOST-1f).
	daWarned bool
}

// openTPMAt opens the TPM at path: the kernel's resource manager
// (/dev/tpmrm0) on the box, or a socket for a software TPM.
func openTPMAt(path string) func() (transport.TPMCloser, error) {
	return func() (transport.TPMCloser, error) {
		if fi, err := os.Stat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return linuxudstpm.Open(path)
		}
		return linuxtpm.Open(path)
	}
}

// productName reads the PC's vendor and model from DMI, for the owner.
func productName() string {
	var parts []string
	for _, f := range []string{"/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/product_name"} {
		if b, err := os.ReadFile(f); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				parts = append(parts, s)
			}
		}
	}
	if len(parts) == 0 {
		return "this PC"
	}
	return strings.Join(parts, " ")
}

type policyFile struct {
	Version  int              `json:"version"`
	Policies []tpmseal.Policy `json:"policies"`
	// Release is the image version this PC last unlocked or was approved
	// on: a hint for the owner's wording only (tpmHost.updated).
	Release string `json:"release,omitempty"`
	// Values are the PCR values (hex, by index) of the boot path approved
	// last: a hint for the owner's wording only (secureBootChanged).
	Values map[string]string `json:"values,omitempty"`
}

func (h *tpmHost) readFile() (policyFile, error) {
	pf := policyFile{Version: 1}
	raw, err := os.ReadFile(h.policyPath)
	if errors.Is(err, os.ErrNotExist) {
		return pf, nil
	}
	if err != nil {
		return pf, err
	}
	if err := json.Unmarshal(raw, &pf); err != nil || pf.Version != 1 {
		return pf, errors.New("PCR policy file unreadable")
	}
	return pf, nil
}

func (h *tpmHost) writeFile(pf policyFile) error {
	raw, err := json.Marshal(pf)
	if err != nil {
		return err
	}
	return writeFileAtomic(h.policyPath, raw)
}

func (h *tpmHost) readPolicies() ([]tpmseal.Policy, error) {
	pf, err := h.readFile()
	return pf.Policies, err
}

// addPolicy keeps p among the approved boot paths, newest last, and
// records the running release and the PCR values p approves.
func (h *tpmHost) addPolicy(p tpmseal.Policy, vals [][]byte) error {
	pf, err := h.readFile()
	if err != nil {
		return err
	}
	out := make([]tpmseal.Policy, 0, len(pf.Policies)+1)
	for _, q := range pf.Policies {
		if !bytes.Equal(q.Digest, p.Digest) || !samePCRs(q.PCRs, p.PCRs) {
			out = append(out, q)
		}
	}
	out = append(out, p)
	if len(out) > maxPolicies {
		out = out[len(out)-maxPolicies:]
	}
	pf.Policies, pf.Release = out, h.releaseNow()
	pf.Values = map[string]string{}
	for i, pcr := range p.PCRs {
		if i < len(vals) {
			pf.Values[strconv.Itoa(int(pcr))] = hex.EncodeToString(vals[i])
		}
	}
	return h.writeFile(pf)
}

func (h *tpmHost) releaseNow() string {
	if h.release == nil {
		return ""
	}
	return h.release()
}

// noteRelease records the running release after a trusted unlock.
func (h *tpmHost) noteRelease() {
	pf, err := h.readFile()
	if rel := h.releaseNow(); err == nil && rel != "" && pf.Release != rel {
		pf.Release = rel
		h.writeFile(pf)
	}
}

// secureBootChanged reports whether, of the PCRs the last approved boot
// path recorded, only PCR 7 (Secure Boot state: db, dbx) reads otherwise
// now, as after a firmware update made outside the box.
func (h *tpmHost) secureBootChanged() bool {
	pf, err := h.readFile()
	if err != nil || len(pf.Values) == 0 {
		return false
	}
	var pcrs []uint
	for k := range pf.Values {
		n, err := strconv.Atoi(k)
		if err != nil || n < 0 || n > 23 {
			return false
		}
		pcrs = append(pcrs, uint(n))
	}
	sort.Slice(pcrs, func(i, j int) bool { return pcrs[i] < pcrs[j] })
	h.mu.Lock()
	defer h.mu.Unlock()
	t, err := h.openTPM()
	if err != nil {
		return false
	}
	defer t.Close()
	now, err := tpmseal.ReadPCRs(t, pcrs)
	if err != nil {
		return false
	}
	sb := false
	for i, pcr := range pcrs {
		if hex.EncodeToString(now[i]) == pf.Values[strconv.Itoa(int(pcr))] {
			continue
		}
		if pcr != 7 {
			return false
		}
		sb = true
	}
	return sb
}

func (h *tpmHost) updated() bool {
	pf, err := h.readFile()
	rel := h.releaseNow()
	return err == nil && rel != "" && pf.Release != "" && rel != pf.Release
}

// imageVersion reads IMAGE_VERSION from os-release, which the image build
// (P2-1) sets per release.
func imageVersion() string {
	for _, f := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if v, ok := strings.CutPrefix(line, "IMAGE_VERSION="); ok {
				return strings.Trim(strings.TrimSpace(v), `"'`)
			}
		}
		return ""
	}
	return ""
}

func samePCRs(a, b []uint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// tpmFactor is the trusted-host slot as a vault factor. For a slot sealed
// on another PC it answers vault.ErrSkipSlot.
type tpmFactor struct {
	t        transport.TPM
	pin      string
	pub      *ecdsa.PublicKey // Enroll
	name     string           // Enroll
	now      time.Time        // Enroll
	policies []tpmseal.Policy // KEK
}

func (*tpmFactor) Kind() string { return vault.SlotTPM }

func (f *tpmFactor) Enroll() (vault.Slot, []byte, error) {
	kek := make([]byte, vault.KeySize)
	if _, err := rand.Read(kek); err != nil {
		return vault.Slot{}, nil, err
	}
	s, err := tpmseal.Seal(f.t, kek, f.pub, f.pin, f.name)
	if err != nil {
		return vault.Slot{}, nil, err
	}
	if !f.now.IsZero() {
		s.Trusted = f.now.Unix()
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return vault.Slot{}, nil, err
	}
	return vault.Slot{Kind: vault.SlotTPM, Sealed: raw}, kek, nil
}

func (f *tpmFactor) KEK(s vault.Slot) ([]byte, error) {
	sealed, err := sealedOf(s)
	if err != nil {
		return nil, vault.ErrSkipSlot
	}
	kek, err := tpmseal.Unseal(f.t, sealed, f.policies, f.pin)
	if errors.Is(err, tpmseal.ErrOtherTPM) {
		return nil, vault.ErrSkipSlot
	}
	return kek, err
}

func sealedOf(s vault.Slot) (*tpmseal.Sealed, error) {
	var sealed tpmseal.Sealed
	if err := json.Unmarshal(s.Sealed, &sealed); err != nil {
		return nil, err
	}
	return &sealed, nil
}

func (h *tpmHost) open(pin string) (*vault.Vault, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	pols, err := h.readPolicies()
	if err != nil {
		return nil, err
	}
	v, err := func() (*vault.Vault, error) {
		t, err := h.openTPM()
		if err != nil {
			return nil, err
		}
		defer t.Close()
		return vault.OpenSealed(h.vaultPath, h.keysPath, &tpmFactor{t: t, pin: pin, policies: pols})
	}()
	if err != nil {
		return nil, err
	}
	// The TPM connection is closed: the counter opens its own.
	if err := h.bindLocked(v); err != nil {
		v.Close()
		return nil, err
	}
	h.noteRelease()
	// Opened without a PIN, so this PC's slot has none: give back a
	// lockout hierarchy an earlier PIN-off could not (giveBack).
	if pin == "" {
		if t, err := h.openTPM(); err == nil {
			if id, err := tpmseal.Identity(t); err == nil {
				h.giveBack(v, t, id)
			}
			t.Close()
		}
	}
	return v, nil
}

// tpmCounter is this PC's TPM as the vault's rollback counter (V6,
// tpmseal/counter.go). Each call opens its own TPM connection, so callers
// must not hold one while writing the vault.
type tpmCounter struct {
	openTPM func() (transport.TPMCloser, error)
	srk     []byte // this TPM's storage root key name, pinned
}

func (c *tpmCounter) Host() string { return hex.EncodeToString(c.srk) }

func (c *tpmCounter) with(f func(transport.TPM) error) error {
	t, err := c.openTPM()
	if err != nil {
		return err
	}
	defer t.Close()
	return f(t)
}

func (c *tpmCounter) Find(id []byte) (ref []byte, ok bool, err error) {
	err = c.with(func(t transport.TPM) (err error) {
		ok, err = tpmseal.FindCounter(t, id)
		return err
	})
	return nil, ok, err
}

func (c *tpmCounter) Define(id, auth []byte) (ref []byte, err error) {
	err = c.with(func(t transport.TPM) error {
		r, err := tpmseal.DefineCounter(t, c.srk, id, auth)
		ref = r.Marshal()
		return err
	})
	return ref, err
}

func (c *tpmCounter) Read(ref, auth []byte) (n uint64, err error) {
	r, err := tpmseal.ParseCounterRef(ref)
	if err != nil {
		return 0, err
	}
	err = c.with(func(t transport.TPM) (err error) {
		n, err = tpmseal.ReadCounter(t, c.srk, r, auth)
		return err
	})
	return n, err
}

func (c *tpmCounter) Increment(ref, auth []byte) error {
	r, err := tpmseal.ParseCounterRef(ref)
	if err != nil {
		return err
	}
	return c.with(func(t transport.TPM) error { return tpmseal.IncrementCounter(t, c.srk, r, auth) })
}

// offlineFactor seals a fresh slot for another trusted PC while it is
// away (tpmseal.SealTo), from the SRK public area its old slot recorded.
type offlineFactor struct {
	srkPublic []byte
	pub       *ecdsa.PublicKey
	host      string
	trusted   int64
}

func (*offlineFactor) Kind() string { return vault.SlotTPM }

func (f *offlineFactor) Enroll() (vault.Slot, []byte, error) {
	kek := make([]byte, vault.KeySize)
	if _, err := rand.Read(kek); err != nil {
		return vault.Slot{}, nil, err
	}
	s, err := tpmseal.SealTo(f.srkPublic, kek, f.pub, f.host)
	if err != nil {
		return vault.Slot{}, nil, err
	}
	s.Trusted = f.trusted
	raw, err := json.Marshal(s)
	if err != nil {
		return vault.Slot{}, nil, err
	}
	return vault.Slot{Kind: vault.SlotTPM, Sealed: raw}, kek, nil
}

func (*offlineFactor) KEK(vault.Slot) ([]byte, error) { return nil, vault.ErrSkipSlot }

// errWrongPINReencrypt: this PC's slot has a boot PIN and the one given
// does not open it, so nothing was changed.
var errWrongPINReencrypt = errors.New("this PC's boot PIN did not open its slot")

// reencrypt is V7 with the review of #45 (B5) and the arbitrator's
// ruling. Whoever kept the old data key may also hold the old policy key
// and every slot's old key-encryption key, so no slot keeps either: the
// vault moves to a new data key with every trusted-host slot dropped,
// then gets a new policy key, the approved boot paths are re-signed under
// it, and each trusted PC gets a slot with a fresh key-encryption key.
// This PC is sealed on its TPM; another PC is sealed from its recorded
// SRK public area, so it needs no visit. A PC with a boot PIN, or whose
// slot predates the recorded SRK, cannot be sealed while away and is
// counted for the owner to trust again. A crash part way leaves fewer
// trusted PCs, never a slot under an old key: those PCs fall back to the
// owner's unlock.
func (h *tpmHost) reencrypt(v *vault.Vault, pin string, owner []vault.Factor) (_ int, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	oldKey, err := policyKey(v)
	if err != nil {
		return 0, err
	}
	pf, err := h.readFile()
	if err != nil {
		return 0, err
	}
	slots, err := vault.ReadSlots(h.keysPath)
	if err != nil {
		return 0, err
	}
	t, err := h.openTPM()
	if err != nil {
		return 0, err
	}
	id, err := tpmseal.Identity(t)
	t.Close()
	if err != nil {
		return 0, err
	}
	var here *tpmseal.Sealed
	var away []*tpmseal.Sealed
	dropped := 0
	for _, sl := range slots {
		if sl.Kind != vault.SlotTPM {
			continue
		}
		sealed, err := sealedOf(sl)
		switch {
		case err != nil:
			dropped++
		case bytes.Equal(sealed.SRKName, id):
			here = sealed
		case !sealed.HasPIN() && tpmseal.SameSRK(sealed.SRKPublic, sealed.SRKName):
			away = append(away, sealed)
		default:
			dropped++
		}
	}
	if here != nil && here.HasPIN() {
		// The PIN is sealed into the new slot too, so prove it first
		// rather than set a mistyped one.
		t, err := h.openTPM()
		if err != nil {
			return 0, err
		}
		kek, err := tpmseal.Unseal(t, here, pf.Policies, pin)
		t.Close()
		if err != nil {
			return 0, fmt.Errorf("%w: %v", errWrongPINReencrypt, err)
		}
		clear(kek)
	}

	if _, err := v.Reencrypt(owner...); err != nil {
		return 0, err
	}
	// From here every trusted-host slot is gone; a failure leaves the
	// PCs not yet sealed again for the owner to trust again by name.
	pending := append([]*tpmseal.Sealed(nil), away...)
	if here != nil {
		pending = append([]*tpmseal.Sealed{here}, pending...)
	}
	defer func() {
		if err != nil && len(pending) > 0 {
			names := make([]string, len(pending))
			for i, p := range pending {
				names[i] = p.Host
				if names[i] == "" {
					names[i] = "a trusted PC"
				}
			}
			h.say("The vault's new key is in place, but these PCs must be trusted again: " + strings.Join(names, ", "))
		}
	}()
	newKey, err := tpmseal.NewPolicyKey()
	if err != nil {
		return 0, err
	}
	der, err := tpmseal.MarshalPolicyKey(newKey)
	if err != nil {
		return 0, err
	}
	if err := v.Put(PolicyKeyName, vault.KindPCRPolicyKey, der); err != nil {
		return 0, err
	}
	var resigned []tpmseal.Policy
	for _, p := range pf.Policies {
		if !tpmseal.SignedBy(p, &oldKey.PublicKey) {
			continue
		}
		q, err := tpmseal.Resign(newKey, p)
		if err != nil {
			return 0, err
		}
		resigned = append(resigned, q)
	}
	pf.Policies = resigned
	if err := h.writeFile(pf); err != nil {
		return 0, err
	}
	if here != nil {
		t, err := h.openTPM()
		if err != nil {
			return dropped + len(away), err
		}
		err = v.AddSlot(&tpmFactor{t: t, pin: pin, pub: &newKey.PublicKey, name: here.Host, now: time.Unix(here.Trusted, 0)}, func(s vault.Slot) bool {
			sealed, err := sealedOf(s)
			return err == nil && bytes.Equal(sealed.SRKName, id)
		})
		t.Close()
		if err != nil {
			return dropped + len(away), err
		}
		pending = pending[1:]
	}
	for i, a := range away {
		if err := v.AddSlot(&offlineFactor{srkPublic: a.SRKPublic, pub: &newKey.PublicKey, host: a.Host, trusted: a.Trusted}, func(s vault.Slot) bool {
			sealed, err := sealedOf(s)
			return err == nil && bytes.Equal(sealed.SRKName, a.SRKName)
		}); err != nil {
			return dropped + len(away) - i, err
		}
		pending = pending[1:]
	}
	return dropped, nil
}

// counter returns this PC's TPM as a rollback counter. Caller holds mu.
func (h *tpmHost) counter() (*tpmCounter, error) {
	t, err := h.openTPM()
	if err != nil {
		return nil, err
	}
	id, err := tpmseal.Identity(t)
	t.Close()
	if err != nil {
		return nil, err
	}
	return &tpmCounter{openTPM: h.openTPM, srk: id}, nil
}

func (h *tpmHost) updateCounter() (vault.Counter, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.counter()
}

func (h *tpmHost) bind(v *vault.Vault) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.bindLocked(v)
}

// bindLocked binds v to this PC's counter. A TPM that cannot even name
// itself binds nothing: v.Bind then has no anchor to check, which is the
// unknown-host case the owner unlocks in person. Caller holds mu.
func (h *tpmHost) bindLocked(v *vault.Vault) error {
	c, err := h.counter()
	if err != nil {
		if len(v.Anchors()) > 0 {
			// The vault is anchored somewhere; whether here cannot be
			// told without the TPM, so refuse rather than guess.
			return fmt.Errorf("%w: %v", errRollbackCheck, err)
		}
		return nil
	}
	err = v.Bind(c)
	if err != nil && !errors.Is(err, vault.ErrRolledBack) && !errors.Is(err, vault.ErrCounterMissing) {
		return fmt.Errorf("%w: %v", errRollbackCheck, err)
	}
	if err == nil && len(v.Anchors()) > 0 && !anchoredTo(v, c.Host()) {
		h.say(noteUnanchored)
	}
	return err
}

// noteUnanchored tells the owner that this PC cannot check the drive for
// an older copy, because only other PCs hold its counter (V6 limit a).
const noteUnanchored = "This drive is trusted on another PC, so this PC can't tell whether it's an older copy. Unlock here only if the drive has stayed with you."

func anchoredTo(v *vault.Vault, host string) bool {
	for _, a := range v.Anchors() {
		if a.Host == host {
			return true
		}
	}
	return false
}

// errRollbackCheck marks a rollback check the TPM did not answer; the
// owner sees noteTPMSilent and the detail goes to the log (UX-45-3).
var errRollbackCheck = errors.New("this PC's TPM did not answer the rollback check")

// policyKey returns the vault's policy key, making it on first use.
func policyKey(v *vault.Vault) (*ecdsa.PrivateKey, error) {
	if s, ok := v.Secret(PolicyKeyName); ok {
		if !hasKind(v, PolicyKeyName, vault.KindPCRPolicyKey) {
			return nil, errors.New("policy key entry has the wrong kind")
		}
		return tpmseal.ParsePolicyKey([]byte(s.Reveal()))
	}
	k, err := tpmseal.NewPolicyKey()
	if err != nil {
		return nil, err
	}
	der, err := tpmseal.MarshalPolicyKey(k)
	if err != nil {
		return nil, err
	}
	if err := v.Put(PolicyKeyName, vault.KindPCRPolicyKey, der); err != nil {
		return nil, err
	}
	return k, nil
}

func (h *tpmHost) enroll(v *vault.Vault, pin string) (_ string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key, err := policyKey(v)
	if err != nil {
		return "", err
	}
	t, err := h.openTPM()
	if err != nil {
		return "", err
	}
	defer t.Close()
	// Approve the boot path running now: the owner is making this PC
	// trusted as it is (CRED-9).
	vals, err := tpmseal.ReadPCRs(t, h.pcrs)
	if err != nil {
		return "", err
	}
	p, err := tpmseal.Sign(key, h.pcrs, vals)
	if err != nil {
		return "", err
	}
	if err := h.addPolicy(p, vals); err != nil {
		return "", err
	}
	id, err := tpmseal.Identity(t)
	if err != nil {
		return "", err
	}
	tookNew := false
	if pin != "" {
		had := hasKind(v, lockoutAuthName(id), vault.KindTPMLockoutAuth)
		if err := takeLockout(v, t, id); err != nil {
			return "", err
		}
		tookNew = !had
	}
	defer func() {
		// PIN off gives the lockout back; so does a PIN slot that was
		// never saved, when this call took the lockout.
		if (pin == "" && err == nil) || (tookNew && err != nil) {
			h.giveBack(v, t, id)
		}
	}()
	if err := v.AddSlot(&tpmFactor{t: t, pin: pin, pub: &key.PublicKey, name: h.name, now: h.clock()}, func(s vault.Slot) bool {
		sealed, err := sealedOf(s)
		return err == nil && bytes.Equal(sealed.SRKName, id)
	}); err != nil {
		return "", err
	}
	return h.name, nil
}

// anchor binds the vault to this PC's rollback counter, making the
// counter if this PC has none for the vault (V6). trust calls it before
// enroll, so a PC is never trusted without the counter.
func (h *tpmHost) anchor(v *vault.Vault) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	c, err := h.counter()
	if err != nil {
		return err
	}
	return v.Anchor(c)
}

// takeLockout makes the TPM's lockout hierarchy the vault's before a PIN
// slot is sealed (tpmseal.TakeLockout). The authorization is stored in the
// vault first, so it is never set on the TPM without being kept; if the
// TPM refuses, a new entry is removed again.
func takeLockout(v *vault.Vault, t transport.TPM, id []byte) error {
	name := lockoutAuthName(id)
	var auth []byte
	held := false
	for _, e := range v.List() {
		if e.Name != name {
			continue
		}
		if e.Kind != vault.KindTPMLockoutAuth {
			return errors.New("lockout authorization entry has the wrong kind")
		}
		s, _ := v.Secret(name)
		auth, held = []byte(s.Reveal()), true
	}
	// The PC's own settings go into the vault, durably, before the TPM
	// is changed (Security H3 on HOST-1f).
	if err := keepDAOriginal(v, t, id); err != nil {
		return err
	}
	if !held {
		var err error
		if auth, err = tpmseal.NewLockoutAuth(); err != nil {
			return err
		}
		if err := v.Put(name, vault.KindTPMLockoutAuth, auth); err != nil {
			return err
		}
	}
	err := tpmseal.TakeLockout(t, auth, held)
	clear(auth)
	// Forget a new entry only when the TPM certainly never took it: any
	// other failure may have come after the change, and losing the value
	// would lock the box out of the lockout hierarchy.
	if errors.Is(err, tpmseal.ErrLockoutOwned) && !held {
		v.Delete(name)
	}
	return err
}

// lockoutAuthName is the vault entry for the TPM whose SRK name is id: the
// first 16 bytes of the name's digest, in hex.
func lockoutAuthName(id []byte) string { return lockoutAuthPrefix + tpmTag(id) }

// daOriginalName is the entry keeping that TPM's own dictionary-attack
// settings. It is bound to the TPM as the lockout entry is, so one PC's
// settings are never written into another's (Security H2 on HOST-1f).
func daOriginalName(id []byte) string { return daOriginalPrefix + tpmTag(id) }

func tpmTag(id []byte) string {
	d := id
	if len(d) > 2 {
		d = d[2:] // drop the name's hash algorithm
	}
	if len(d) > 16 {
		d = d[:16]
	}
	return hex.EncodeToString(d)
}

// keepDAOriginal keeps the TPM's dictionary-attack settings in the vault
// while they are still the PC's own: only while the lockout authorization
// is empty, since the box sets its own settings only then, and never over
// an entry already kept, which holds the first, true originals (a take cut
// off midway would otherwise replace them with the box's). A TPM clear
// changes the SRK name, so an entry kept before it no longer matches this
// TPM: it is never applied, and stays in the vault (tpmseal T12).
func keepDAOriginal(v *vault.Vault, t transport.TPM, id []byte) error {
	name := daOriginalName(id)
	for _, e := range v.List() {
		if e.Name != name {
			continue
		}
		if e.Kind != vault.KindTPMDAOriginal {
			return errors.New("dictionary-attack settings entry has the wrong kind")
		}
		return nil
	}
	set, err := tpmseal.LockoutAuthSet(t)
	if err != nil || set {
		return err
	}
	p, err := tpmseal.ReadDA(t)
	if err != nil {
		return err
	}
	return v.Put(name, vault.KindTPMDAOriginal, []byte(daValuePrefix+p.String()))
}

func (h *tpmHost) clock() time.Time {
	if h.now == nil {
		return time.Now()
	}
	return h.now()
}

func (h *tpmHost) approve(v *vault.Vault) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	key, err := policyKey(v)
	if err != nil {
		return err
	}
	t, err := h.openTPM()
	if err != nil {
		return err
	}
	defer t.Close()
	vals, err := tpmseal.ReadPCRs(t, h.pcrs)
	if err != nil {
		return err
	}
	p, err := tpmseal.Sign(key, h.pcrs, vals)
	if err != nil {
		return err
	}
	return h.addPolicy(p, vals)
}

func (h *tpmHost) remove(v *vault.Vault, id string) (int, error) {
	want, err := hex.DecodeString(id)
	if err != nil || len(want) == 0 {
		return 0, errors.New("bad host id")
	}
	n, err := v.RemoveSlots(vault.SlotTPM, func(s vault.Slot) bool {
		sealed, err := sealedOf(s)
		return err == nil && bytes.Equal(sealed.SRKName, want)
	})
	if err != nil || n == 0 {
		return n, err
	}
	// This PC no longer trusted: give its lockout hierarchy back. Another
	// PC's TPM is not reachable from here; its entry stays in the vault
	// until that PC is trusted again without a PIN.
	h.mu.Lock()
	defer h.mu.Unlock()
	if t, err := h.openTPM(); err == nil {
		if me, err := tpmseal.Identity(t); err == nil && bytes.Equal(me, want) {
			h.giveBack(v, t, me)
		}
		t.Close()
	}
	return n, nil
}

// giveBack returns the TPM's lockout hierarchy (tpmseal.ReleaseLockout)
// once this PC has no PIN slot, and the vault forgets the authorization.
// After a wrong lockout password the TPM refuses even the right one for a
// day, so a failure keeps the authorization, tells the owner, and is
// retried at each unattended start. Caller holds mu.
func (h *tpmHost) giveBack(v *vault.Vault, t transport.TPM, id []byte) {
	name := lockoutAuthName(id)
	if hasKind(v, name, vault.KindTPMLockoutAuth) {
		s, _ := v.Secret(name)
		auth := []byte(s.Reveal())
		err := tpmseal.ReleaseLockout(t, auth)
		clear(auth)
		switch {
		case errors.Is(err, tpmseal.ErrLockoutOwned):
			// Proved stale: retrying would only re-arm the TPM's lockout.
			// The settings it guards are the other system's now.
			h.say("Another system on this PC, probably Windows, now controls its security chip's lockout, so I've dropped my copy of that setting. The limit on wrong guesses stays as I set it. Nothing to do.")
			if hasKind(v, daOriginalName(id), vault.KindTPMDAOriginal) {
				v.Delete(daOriginalName(id))
			}
		case err != nil:
			h.say("couldn't give the TPM's lockout back to this PC yet; the box will try again at each restart")
			return
		}
		if err := v.Delete(name); err != nil {
			h.sayErr(lockoutForgetFailed, err)
			return
		}
	}
	h.restoreDA(v, t, id)
}

// restoreDA puts this TPM's own dictionary-attack settings back once the
// lockout authorization is given back (HOST-1f). tpmseal.RestoreDA reads
// whether the authorization is empty before sending anything, so a lockout
// another system set since is never tried (Security H1); the entry is then
// dropped and the owner told once. A malformed entry is never written and
// stays (H4); any other failure stays for the next unattended start (D4).
// Caller holds mu.
func (h *tpmHost) restoreDA(v *vault.Vault, t transport.TPM, id []byte) {
	name := daOriginalName(id)
	if !hasKind(v, name, vault.KindTPMDAOriginal) {
		return
	}
	s, _ := v.Secret(name)
	raw, ok := strings.CutPrefix(s.Reveal(), daValuePrefix)
	p, err := tpmseal.ParseDA(raw)
	if !ok || err != nil {
		h.warnDA()
		return
	}
	switch err := tpmseal.RestoreDA(t, p); {
	case errors.Is(err, tpmseal.ErrLockoutSet):
		h.say("Another system on this PC, probably Windows, now controls its security chip's lockout, so I couldn't put back the chip's limit on wrong guesses. Nothing to do: your PIN is off and the box works as before.")
	case err != nil:
		h.warnDA()
		return
	}
	if err := v.Delete(name); err != nil {
		h.sayErr(daForgetFailed, err)
	}
}

// warnDA tells the owner, once per run, that a restore is still pending:
// the guide promises the settings come back as they were.
func (h *tpmHost) warnDA() {
	if !h.daWarned {
		h.daWarned = true
		h.say("I couldn't put back this PC's security chip limit on wrong guesses yet; I'll try again at each restart. Nothing to do.")
	}
}

func (h *tpmHost) say(s string) {
	if h.notify != nil {
		h.notify(s)
	}
}

// The texts for a vault that can't forget an entry after the lockout or the
// chip's settings were given back. The next unattended start retries, so
// the owner has nothing to do (CH-12).
const (
	lockoutForgetFailed = "I couldn't clear the box's saved copy of this PC's security chip lockout; I'll try again at each restart. Nothing to do."
	daForgetFailed      = "I couldn't clear the box's saved copy of this PC's security chip limits; I'll try again at each restart. Nothing to do."
)

// sayErr tells the owner a fixed sentence. The error can name a vault
// path, so it goes to the log and not into the text (CH-12).
func (h *tpmHost) sayErr(sentence string, err error) {
	log.Printf("custody: %s: %v", sentence, err)
	h.say(sentence)
}

func (h *tpmHost) list() ([]hostInfo, error) {
	slots, err := vault.ReadSlots(h.keysPath)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	var me []byte
	if t, err := h.openTPM(); err == nil {
		me, _ = tpmseal.Identity(t)
		t.Close()
	}
	h.mu.Unlock()
	out := []hostInfo{}
	for _, s := range slots {
		if s.Kind != vault.SlotTPM {
			continue
		}
		sealed, err := sealedOf(s)
		if err != nil {
			continue
		}
		hi := hostInfo{
			ID:    hex.EncodeToString(sealed.SRKName),
			Host:  sealed.Host,
			This:  me != nil && bytes.Equal(me, sealed.SRKName),
			PIN:   sealed.HasPIN(),
			Label: sealed.Host,
		}
		if hi.Label == "" {
			hi.Label = "a PC"
		}
		if sealed.Trusted > 0 {
			at := time.Unix(sealed.Trusted, 0)
			hi.Trusted = at.UTC().Format(time.RFC3339)
			hi.Label += ", trusted " + at.Local().Format("Jan 2")
		}
		out = append(out, hi)
	}
	return out, nil
}

// newTPMHost returns this PC's TPM as a trusted host, or nil when the PC
// has none (every boot is then an unknown host).
func newTPMHost(tpmPath, vaultPath, keysPath, policyPath string, pcrs []uint) trustedHost {
	if tpmPath == "" {
		return nil
	}
	if _, err := os.Stat(tpmPath); err != nil {
		return nil
	}
	return &tpmHost{
		openTPM:    openTPMAt(tpmPath),
		vaultPath:  vaultPath,
		keysPath:   keysPath,
		policyPath: policyPath,
		pcrs:       pcrs,
		name:       productName(),
		release:    imageVersion,
		now:        time.Now,
		notify:     func(s string) { log.Print(s) },
	}
}

// parsePCRs reads a comma-separated PCR list such as "4,7,9,12".
func parsePCRs(s string) ([]uint, error) {
	var out []uint
	for _, f := range strings.Split(s, ",") {
		n, err := strconv.ParseUint(strings.TrimSpace(f), 10, 8)
		if err != nil || n > 23 {
			return nil, fmt.Errorf("-pcrs: bad PCR %q", f)
		}
		out = append(out, uint(n))
	}
	if len(out) == 0 || len(out) > tpmseal.MaxPCRs {
		return nil, fmt.Errorf("-pcrs: select 1 to %d PCRs", tpmseal.MaxPCRs)
	}
	return out, nil
}
