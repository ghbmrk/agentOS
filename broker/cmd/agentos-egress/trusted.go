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
}

func (h *tpmHost) readPolicies() ([]tpmseal.Policy, error) {
	raw, err := os.ReadFile(h.policyPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var pf policyFile
	if err := json.Unmarshal(raw, &pf); err != nil || pf.Version != 1 {
		return nil, errors.New("PCR policy file unreadable")
	}
	return pf.Policies, nil
}

// addPolicy keeps p among the approved boot paths, newest last.
func (h *tpmHost) addPolicy(p tpmseal.Policy) error {
	old, err := h.readPolicies()
	if err != nil {
		return err
	}
	out := make([]tpmseal.Policy, 0, len(old)+1)
	for _, q := range old {
		if !bytes.Equal(q.Digest, p.Digest) || !samePCRs(q.PCRs, p.PCRs) {
			out = append(out, q)
		}
	}
	out = append(out, p)
	if len(out) > maxPolicies {
		out = out[len(out)-maxPolicies:]
	}
	raw, err := json.Marshal(policyFile{Version: 1, Policies: out})
	if err != nil {
		return err
	}
	return writeFileAtomic(h.policyPath, raw)
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
	return vault.OpenSealed(h.vaultPath, h.keysPath, &tpmFactor{t: t, pin: pin, policies: pols})
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
	if err := v.AddSlot(&tpmFactor{t: t, pin: pin, pub: &key.PublicKey, name: h.name}, func(s vault.Slot) bool {
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
		out = append(out, hostInfo{
			ID:   hex.EncodeToString(sealed.SRKName),
			Host: sealed.Host,
			This: me != nil && bytes.Equal(me, sealed.SRKName),
			PIN:  sealed.HasPIN(),
		})
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
