package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	// approve adds the running boot path to the approved ones, without
	// touching any slot ("Keep this PC trusted" after a fallback unlock).
	approve(v *vault.Vault) error
	// updated reports whether this boot runs another release of the box
	// than the last one this PC unlocked on. It reads files an attacker
	// with the drive could write, so it only picks the owner's wording.
	updated() bool
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

	mu sync.Mutex // one TPM conversation at a time
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
// records the running release.
func (h *tpmHost) addPolicy(p tpmseal.Policy) error {
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
	t, err := h.openTPM()
	if err != nil {
		return nil, err
	}
	defer t.Close()
	v, err := vault.OpenSealed(h.vaultPath, h.keysPath, &tpmFactor{t: t, pin: pin, policies: pols})
	if err == nil {
		h.noteRelease()
	}
	return v, err
}

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

func (h *tpmHost) enroll(v *vault.Vault, pin string) (string, error) {
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
	p, err := tpmseal.SignCurrent(t, key, h.pcrs)
	if err != nil {
		return "", err
	}
	if err := h.addPolicy(p); err != nil {
		return "", err
	}
	id, err := tpmseal.Identity(t)
	if err != nil {
		return "", err
	}
	if pin != "" {
		if err := takeLockout(v, t, id); err != nil {
			return "", err
		}
	}
	if err := v.AddSlot(&tpmFactor{t: t, pin: pin, pub: &key.PublicKey, name: h.name, now: h.clock()}, func(s vault.Slot) bool {
		sealed, err := sealedOf(s)
		return err == nil && bytes.Equal(sealed.SRKName, id)
	}); err != nil {
		return "", err
	}
	return h.name, nil
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
	if err != nil && !held {
		v.Delete(name)
	}
	return err
}

// lockoutAuthName is the vault entry for the TPM whose SRK name is id: the
// first 16 bytes of the name's digest, in hex.
func lockoutAuthName(id []byte) string {
	d := id
	if len(d) > 2 {
		d = d[2:] // drop the name's hash algorithm
	}
	if len(d) > 16 {
		d = d[:16]
	}
	return lockoutAuthPrefix + hex.EncodeToString(d)
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
	p, err := tpmseal.SignCurrent(t, key, h.pcrs)
	if err != nil {
		return err
	}
	return h.addPolicy(p)
}

func (h *tpmHost) remove(v *vault.Vault, id string) (int, error) {
	want, err := hex.DecodeString(id)
	if err != nil || len(want) == 0 {
		return 0, errors.New("bad host id")
	}
	return v.RemoveSlots(vault.SlotTPM, func(s vault.Slot) bool {
		sealed, err := sealedOf(s)
		return err == nil && bytes.Equal(sealed.SRKName, want)
	})
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
	}
}

// parsePCRs reads a comma-separated PCR list such as "4,9,12".
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
