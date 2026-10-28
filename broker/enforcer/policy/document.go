// Package policy is the enforcer's owner-signed policy (SPEC STO-4, NET-4;
// briefs/ENF.md slice a). A policy version is one canonical document and
// one KEY-1 root over it, signed by the owner's passkey and checked with
// broker/kernel/key, with no second rule system. Versions only rise.
// Classify decides whether a change is on the closed tightening list; every
// other change is a loosening, which waits 10 minutes after the owner's
// assertion and can be cancelled in that time (Engine).
//
// It is enforcer code: it imports the standard library and
// broker/kernel/key only (broker/daemon/arc2_test.go). Its assumptions are
// in ASSUMPTIONS.md.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// The networks NET-2 Segments names. A device sits on one of the last two;
// the rest are listed so a document that names them reads, and so a device
// moved onto one is a change Classify sees.
const (
	NetOwner     = "owner"
	NetHousehold = "household"
	NetGuests    = "guests"
	NetDevices   = "devices"
	NetCore      = "core"
	NetEdge      = "edge"
)

var networks = []string{NetCore, NetDevices, NetEdge, NetGuests, NetHousehold, NetOwner}

// Hold kinds (NET-4 Loosening: holding back a security fix, freezing
// firmware).
const (
	HoldFix      = "hold-fix"
	HoldFirmware = "freeze-firmware"
)

var (
	ErrMalformed = errors.New("policy: malformed document")
	ErrNotRising = errors.New("policy: version does not rise")
)

// Document is one policy version: everything the enforcer enforces besides
// the devices' secrets. Its canonical form (Encode) is what a version's key
// commits to.
type Document struct {
	Version uint64 `json:"version"`
	// Destinations is the core's signed destination list (NET-2 The core's
	// list): host names the core may reach.
	Destinations []string       `json:"destinations"`
	Devices      []Device       `json:"devices"`
	Pairs        []Pair         `json:"pairs"`
	Standing     []StandingRule `json:"standing"`
	Holds        []Hold         `json:"holds"`
	// Drone is the SHA-256, in hex, of the owner-signed drone flight policy
	// (broker/drone), or empty when there is none.
	Drone string `json:"drone"`
}

// Device is one device on the home network.
type Device struct {
	ID      string `json:"id"`
	Network string `json:"network"`
	// WiFi is the device's own Wi-Fi identity (brief decision 8); empty for
	// a wired device.
	WiFi string `json:"wifi"`
	// Allow is the device's allow list: the host names it may reach.
	Allow []string `json:"allow"`
	// VendorCloud allows the device's vendor cloud at the network.
	VendorCloud bool `json:"vendor_cloud"`
	// Isolated cuts the device off from everything, its allow list and
	// pairs included, without forgetting them.
	Isolated bool `json:"isolated"`
	// Everyday takes the device off the safety list (NET-2 Safety
	// devices). The zero value is on it, so a device nobody classified
	// fails safe; setting it is a loosening, so only the owner can.
	Everyday bool `json:"everyday"`
	// Secure names a safety-list device's one secure-direction command,
	// such as a lock's "lock" (NET-2 Safety devices); empty for none.
	Secure string `json:"secure"`
	// Label is how far the enforcer can contain the device (NET-1), from
	// qualification and the enforcer's observation, never from what the
	// device reports: LabelContained, LabelExceptRadio, or empty for not
	// containable, so a device nobody labelled promises nothing.
	Label string `json:"label"`
}

// The NET-1 labels a device can carry; the empty label is not containable.
const (
	LabelContained   = "contained"
	LabelExceptRadio = "contained-except-radio"
)

// Pair is a signed device-to-device path. A sorts before B.
type Pair struct {
	A string `json:"a"`
	B string `json:"b"`
}

// StandingRule is a rule the owner signed once that the enforcer applies by
// itself inside its window (NET-4 Standing rules), such as a visitor's
// keypad code on a lock. The code itself is the device's secret, held
// beside the policy, not in it.
type StandingRule struct {
	ID     string `json:"id"`
	Device string `json:"device"`
	Action string `json:"action"`
	FromMS int64  `json:"from_ms"`
	ToMS   int64  `json:"to_ms"` // exclusive
}

// Hold holds back a security fix or freezes a device's firmware.
type Hold struct {
	Device string `json:"device"`
	Kind   string `json:"kind"`
}

// Encode is d's canonical form: sorted and checked, then encoding/json's
// marshalling, which is byte for byte what a version's key commits to.
func Encode(d Document) ([]byte, error) {
	d = d.normal()
	if err := d.check(); err != nil {
		return nil, err
	}
	return json.Marshal(d)
}

// Decode reads a canonical document: unknown fields, trailing data and any
// form that Encode would not write are refused, so one document has one
// encoding and one hash.
func Decode(b []byte) (Document, error) {
	var d Document
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil || dec.More() {
		return Document{}, ErrMalformed
	}
	canon, err := Encode(d)
	if err != nil {
		return Document{}, err
	}
	if !bytes.Equal(canon, b) {
		return Document{}, fmt.Errorf("%w: not canonical", ErrMalformed)
	}
	return d, nil
}

// Hash is the SHA-256 of d's canonical form, in hex.
func Hash(d Document) (string, error) {
	b, err := Encode(d)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// Device is the device with id, or nil.
func (d Document) Device(id string) *Device {
	for i := range d.Devices {
		if d.Devices[i].ID == id {
			return &d.Devices[i]
		}
	}
	return nil
}

// Active is the standing rules for device that apply at now: inside their
// window only.
func (d Document) Active(device string, nowMS int64) []StandingRule {
	var out []StandingRule
	for _, r := range d.Standing {
		if r.Device == device && r.FromMS <= nowMS && nowMS < r.ToMS {
			out = append(out, r)
		}
	}
	return out
}

// SecureCommand reports whether cmd is device's named secure-direction
// command, such as a lock's lock or relock: the one command for a
// safety-list device that applies at once (NET-4 Tightening; NET-2 Safety
// devices). Engine.Secure rate-limits it.
func (d Document) SecureCommand(device, cmd string) bool {
	dev := d.Device(device)
	return dev != nil && !dev.Everyday && dev.Secure != "" && dev.Secure == cmd
}

// normal is d with every list sorted and deduplicated and every nil list
// empty, so equal documents encode equally. It copies, never aliasing d.
func (d Document) normal() Document {
	d.Destinations = sorted(d.Destinations)
	devs := make([]Device, len(d.Devices))
	for i, dev := range d.Devices {
		dev.Allow = sorted(dev.Allow)
		devs[i] = dev
	}
	slices.SortFunc(devs, func(a, b Device) int { return strings.Compare(a.ID, b.ID) })
	d.Devices = devs
	pairs := make([]Pair, len(d.Pairs))
	for i, p := range d.Pairs {
		if p.B < p.A {
			p.A, p.B = p.B, p.A
		}
		pairs[i] = p
	}
	slices.SortFunc(pairs, func(a, b Pair) int {
		return strings.Compare(a.A+"\x00"+a.B, b.A+"\x00"+b.B)
	})
	d.Pairs = slices.Compact(pairs)
	d.Standing = append([]StandingRule{}, d.Standing...)
	slices.SortFunc(d.Standing, func(a, b StandingRule) int { return strings.Compare(a.ID, b.ID) })
	d.Holds = append([]Hold{}, d.Holds...)
	slices.SortFunc(d.Holds, func(a, b Hold) int {
		return strings.Compare(a.Device+"\x00"+a.Kind, b.Device+"\x00"+b.Kind)
	})
	d.Holds = slices.Compact(d.Holds)
	return d
}

func sorted(s []string) []string {
	out := append([]string{}, s...)
	slices.Sort(out)
	return slices.Compact(out)
}

// check refuses a document with a nameless or duplicate device, an unknown
// network or label, a pair, rule or hold naming no device, or an empty window.
func (d Document) check() error {
	bad := func(f string, a ...any) error { return fmt.Errorf("%w: "+f, append([]any{ErrMalformed}, a...)...) }
	for i, dev := range d.Devices {
		if !name(dev.ID) {
			return bad("device id %q", dev.ID)
		}
		if i > 0 && d.Devices[i-1].ID == dev.ID {
			return bad("device %q twice", dev.ID)
		}
		if !slices.Contains(networks, dev.Network) {
			return bad("device %q on network %q", dev.ID, dev.Network)
		}
		for _, h := range dev.Allow {
			if !name(h) {
				return bad("device %q allows %q", dev.ID, h)
			}
		}
		if dev.Label != "" && dev.Label != LabelContained && dev.Label != LabelExceptRadio {
			return bad("device %q label %q", dev.ID, dev.Label)
		}
		if dev.Secure != "" && (dev.Everyday || !name(dev.Secure)) {
			return bad("device %q: a secure command %q needs a safety-list device", dev.ID, dev.Secure)
		}
	}
	for _, h := range d.Destinations {
		if !name(h) {
			return bad("destination %q", h)
		}
	}
	for _, p := range d.Pairs {
		if p.A == p.B || d.Device(p.A) == nil || d.Device(p.B) == nil {
			return bad("pair %q-%q", p.A, p.B)
		}
	}
	for i, r := range d.Standing {
		if !name(r.ID) || !name(r.Action) || d.Device(r.Device) == nil || r.FromMS >= r.ToMS {
			return bad("standing rule %q", r.ID)
		}
		if i > 0 && d.Standing[i-1].ID == r.ID {
			return bad("standing rule %q twice", r.ID)
		}
	}
	for _, h := range d.Holds {
		if d.Device(h.Device) == nil || (h.Kind != HoldFix && h.Kind != HoldFirmware) {
			return bad("hold %q on %q", h.Kind, h.Device)
		}
	}
	return nil
}

// name is a non-empty token with no space, control character or slash, so
// it cannot split a serial or a rendered line.
func name(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, c := range s {
		if c <= ' ' || c == 0x7f || c == '/' {
			return false
		}
	}
	return true
}
