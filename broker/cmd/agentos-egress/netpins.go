package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/vault"
)

// Owner pins (DEV-2, BAK-1): a backup target, a private hosted route or a
// compute host the owner has chosen. Each is one vault entry named
// "netpin:<label>" of kind pinEntryKind, holding
// {"kind":"backup|hosted|compute","name":"host","addr":"ip:port","key":"<sha256 hex of the TLS public key>"}.
// The vault is the owner-settings store: it is sealed, so a pin cannot be
// planted or read while the box is locked. No entry, no pin. Only the
// tier-4 pin command (pin, unpin) writes these entries; custody.put, the
// local page's credential write, refuses them (N12).
const (
	pinEntryKind   = "netguard-pin"
	pinEntryPrefix = "netpin:"
)

type pinRecord struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	Addr string `json:"addr"`
	Key  string `json:"key"`
}

// loadPins reads the owner pins from v. A record that does not parse, names
// an unknown kind or lacks a name or address or a 32-byte key is skipped;
// the problems name the entry label only, never a value.
func loadPins(v *vault.Vault) ([]netguard.Pin, []string) {
	var pins []netguard.Pin
	var problems []string
	for _, e := range v.List() {
		if e.Kind != pinEntryKind || !strings.HasPrefix(e.Name, pinEntryPrefix) {
			continue
		}
		s, ok := v.Secret(e.Name)
		if !ok {
			continue
		}
		p, err := parsePin(s.Reveal())
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", e.Name, err))
			continue
		}
		pins = append(pins, p)
	}
	return pins, problems
}

func parsePin(raw string) (netguard.Pin, error) {
	var r pinRecord
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return netguard.Pin{}, errors.New("not a pin record")
	}
	var p netguard.Pin
	switch r.Kind {
	case "backup":
		p.Kind = netguard.PinBackup
	case "hosted":
		p.Kind = netguard.PinHosted
	case "compute":
		p.Kind = netguard.PinCompute
	default:
		return p, errors.New("unknown pin kind")
	}
	p.Name = r.Name
	if r.Addr != "" {
		ap, err := netip.ParseAddrPort(r.Addr)
		if err != nil {
			return p, errors.New("address is not ip:port")
		}
		p.Addr = ap
	}
	k, err := hex.DecodeString(r.Key)
	if err != nil || len(k) != len(p.Key) {
		return p, errors.New("key is not a SHA-256 hex")
	}
	copy(p.Key[:], k)
	if p.Name == "" && !p.Addr.IsValid() {
		return p, errors.New("pin needs a name or an address")
	}
	if p.Key == ([32]byte{}) {
		return p, errors.New("pin needs a key hash")
	}
	return p, nil
}

// applyPins sets the guard's pins from the open vault. Skipped records are
// logged by label. No guard (tests) is a no-op.
func (c *custody) applyPins(v *vault.Vault) {
	if c.guard == nil {
		return
	}
	pins, problems := loadPins(v)
	for _, pr := range problems {
		log.Printf("netguard: owner pin skipped: %s", pr)
	}
	if err := c.guard.SetPins(pins); err != nil {
		log.Printf("netguard: owner pins refused: %v", err)
		_ = c.guard.SetPins(nil)
	}
}

// clearPins drops every pin: a locked box reaches no pinned endpoint.
func (c *custody) clearPins() {
	if c.guard != nil {
		_ = c.guard.SetPins(nil)
	}
}

var (
	pinLabelRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	pinNameRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

	errNoSuchPin = uerr(http.StatusNotFound, "no pinned endpoint with that label")
)

func errBadPin(why string) error { return uerr(http.StatusBadRequest, "pin refused: "+why) }

// checkPin validates a pin command before its code is spent, and returns
// the record as stored. The refusal names the problem, never a value.
func checkPin(label string, r pinRecord) ([]byte, error) {
	if !pinLabelRE.MatchString(label) {
		return nil, errBadPin("the label is 1 to 32 lower-case letters, digits or '-'")
	}
	r.Name = strings.ToLower(strings.TrimSuffix(r.Name, "."))
	if r.Name != "" && (len(r.Name) > 253 || !pinNameRE.MatchString(r.Name)) {
		return nil, errBadPin("the name is not a host name")
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, errBadPin("not a pin record")
	}
	if _, err := parsePin(string(raw)); err != nil {
		return nil, errBadPin(err.Error())
	}
	return raw, nil
}

// pin writes the owner pin label (CRED-9 tier 4: an approval code plus
// local confirmation, which is this request arriving on the unlock
// socket). An existing pin of that label is replaced: that is the re-pin
// flow when an endpoint's key or address changes, and replaced reports
// it. The guard takes the new pin list before pin returns.
func (c *custody) pin(code, label string, r pinRecord) (replaced bool, err error) {
	raw, err := checkPin(label, r)
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return false, errLocked
	}
	name := pinEntryPrefix + label
	if hasOtherKind(c.v, name, pinEntryKind) {
		return false, errBadPin("a vault entry of another kind has that label")
	}
	if err := c.approvedLocked(code, "an owner pin change"); err != nil {
		return false, err
	}
	replaced = hasKind(c.v, name, pinEntryKind)
	if err := c.v.Put(name, pinEntryKind, raw); err != nil {
		if errors.Is(err, vault.ErrRolledBack) {
			c.notify(noteRolledBack)
			return false, errRolledBack
		}
		return false, uerr(http.StatusInternalServerError, "the pin was not saved")
	}
	c.applyPins(c.v)
	if replaced {
		c.notify(fmt.Sprintf("owner pin replaced: %s (%s)", label, r.Kind))
	} else {
		c.notify(fmt.Sprintf("owner pin added: %s (%s)", label, r.Kind))
	}
	return replaced, nil
}

// unpin removes the owner pin label (tier 4, as pin).
func (c *custody) unpin(code, label string) error {
	if !pinLabelRE.MatchString(label) {
		return errNoSuchPin
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return errLocked
	}
	name := pinEntryPrefix + label
	if err := c.approvedLocked(code, "an owner pin change"); err != nil {
		return err
	}
	if !hasKind(c.v, name, pinEntryKind) {
		return errNoSuchPin
	}
	if err := c.v.Delete(name); err != nil {
		return uerr(http.StatusInternalServerError, "the pin was not removed")
	}
	c.applyPins(c.v)
	c.notify("owner pin removed: " + label)
	return nil
}

type pinInfo struct {
	Label string `json:"label"`
	pinRecord
}

// pins lists the owner pins by label while the vault is open. A pin is
// an endpoint and a public-key hash, not a secret, so it is shown in full
// for the owner to check against the endpoint.
func (c *custody) pins() ([]pinInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return nil, errLocked
	}
	var out []pinInfo
	for _, e := range c.v.List() {
		if e.Kind != pinEntryKind || !strings.HasPrefix(e.Name, pinEntryPrefix) {
			continue
		}
		s, ok := c.v.Secret(e.Name)
		if !ok {
			continue
		}
		var r pinRecord
		if json.Unmarshal([]byte(s.Reveal()), &r) != nil {
			continue
		}
		out = append(out, pinInfo{strings.TrimPrefix(e.Name, pinEntryPrefix), r})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out, nil
}
