package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"

	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/vault"
)

// Owner pins (DEV-2, BAK-1): a backup target, a private hosted route or a
// compute host the owner has chosen. Each is one vault entry named
// "netpin:<label>" of kind pinEntryKind, holding
// {"kind":"backup|hosted|compute","name":"host","addr":"ip:port","key":"<sha256 hex of the TLS public key>"}.
// The vault is the owner-settings store: it is sealed, so a pin cannot be
// planted or read while the box is locked. No entry, no pin.
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
