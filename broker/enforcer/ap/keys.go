// Package ap is the enforcer's Wi-Fi access point (SPEC NET-3, HW-10;
// briefs/ENF.md slice g): the OpenWrt access point's configuration, built
// from the owner-signed policy, the enforcer's own layout and the Wi-Fi
// passwords the enforcer generates, and those passwords themselves.
//
// The access point does Wi-Fi only. It bridges each network onto its own
// VLAN toward the enforcer and holds an address only on its admin VLAN, so
// nothing on Wi-Fi reaches it. Each Devices-network device joins with its
// own password, which puts it on its own VLAN (D-225); the enforcer then
// knows a device by the VLAN tag it sees, never by anything the access
// point reports. The passwords are generated here, kept beside the policy,
// never in it, and shown only on the enforcer's page (Card), so agentOS
// never holds one.
//
// ap renders text only; ap/push carries it to the access point over SSH
// with a pinned host key. It is enforcer code: it imports the standard
// library, enforcer/policy and enforcer/nft (broker/daemon/arc2_test.go).
// Its assumptions are in ASSUMPTIONS.md.
package ap

import (
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

var (
	ErrKeys   = errors.New("ap: bad keys")
	ErrLayout = errors.New("ap: bad layout")
	ErrPolicy = errors.New("ap: policy does not fit the access point")
)

// Keys is every Wi-Fi password the access point uses. It lives on the
// enforcer beside the policy and never in it: the channel's reads, the
// policy document and the core see none of it.
type Keys struct {
	// Setup is the setup network's password, the one secret made before
	// enrolment (HW-10): the seller's sticker or the flasher made it. The
	// access point broadcasts the setup network only until Owner is set.
	Setup string
	// Owner, Household and Guests are each network's one password, made
	// at enrolment (Enrol).
	Owner, Household, Guests string
	// Devices is the Devices network's own password. It puts a device on
	// no VLAN, so the access point refuses it (dynamic_vlan 2); it is
	// never shown, and exists only because hostapd needs one.
	Devices string
	// Device is each Devices-network device's own password and VLAN, by
	// device id.
	Device map[string]DeviceKey
}

// DeviceKey is one device's Wi-Fi password and the VLAN it puts the device
// on.
type DeviceKey struct {
	VLAN     int
	Password string
}

// Enrolled reports whether enrolment has replaced the setup network with
// the four networks (HW-10, NET-3).
func (k Keys) Enrolled() bool { return k.Owner != "" }

// Enrol makes the four networks' passwords, replacing the setup network.
// The setup password is kept only so a reader can tell which secret the
// sticker printed; it opens nothing once Owner is set.
func (k *Keys) Enrol() error {
	if k.Enrolled() {
		return fmt.Errorf("%w: already enrolled", ErrKeys)
	}
	for _, p := range []*string{&k.Owner, &k.Household, &k.Guests, &k.Devices} {
		*p = password()
	}
	return k.distinct()
}

// Sync gives every Devices-network device with a VLAN in d a password of
// its own and drops every other device's, so removing a device revokes
// its password and touches no other. A device keeps its password only
// while it keeps both its id and its VLAN; a device moved to another VLAN
// is a new pairing with a new password. Sync returns the ids that got a
// new password, for the page to show.
func (k *Keys) Sync(d policy.Document) ([]string, error) {
	if !k.Enrolled() {
		return nil, fmt.Errorf("%w: devices before enrolment", ErrKeys)
	}
	want, err := vlans(d)
	if err != nil {
		return nil, err
	}
	next := make(map[string]DeviceKey, len(want))
	var fresh []string
	for id, v := range want {
		if old, ok := k.Device[id]; ok && old.VLAN == v {
			next[id] = old
			continue
		}
		next[id] = DeviceKey{VLAN: v, Password: password()}
		fresh = append(fresh, id)
	}
	k.Device = next
	slices.Sort(fresh)
	return fresh, k.distinct()
}

// Rekey replaces one device's password, as when the owner revokes it
// because it leaked: that device is paired again and no other is.
func (k *Keys) Rekey(id string) error {
	dk, ok := k.Device[id]
	if !ok {
		return fmt.Errorf("%w: no device %q", ErrKeys, id)
	}
	dk.Password = password()
	k.Device[id] = dk
	return k.distinct()
}

// Card is what the enforcer's page shows the owner for one network or
// device: the network name, the password, and a Wi-Fi QR code's text.
// Shown is the password as the page prints it, in groups of four with a
// space between them so a person typing it into a device's app or with a
// remote keeps their place; the key and the QR text use Password. Note,
// when set, is a sentence the page prints under the card.
type Card struct {
	SSID, Password, QR string
	Shown, Note        string
}

// DeviceCard is the card for one device's password, for the enforcer's
// page only (NET-3: shown only on its own page). Its note names the one
// band devices join on (ENF-g-7), so an owner pairing a device that lacks
// that band sees why it never joins.
func (k Keys) DeviceCard(l Layout, id string) (Card, bool) {
	dk, ok := k.Device[id]
	if !ok {
		return Card{}, false
	}
	c := card(l.SSID.Devices, dk.Password)
	if len(l.Radios) > 0 {
		b := band(l.Radios[0].Band)
		c.Note = "Devices join on " + b + " Wi-Fi only: a device without " + b + " cannot join."
	}
	return c, true
}

// NetworkCard is the card for the setup network before enrolment, or for
// Owner, Household or Guests after it.
func (k Keys) NetworkCard(l Layout, network string) (Card, bool) {
	if !k.Enrolled() {
		return card(l.SSID.Setup, k.Setup), network == NetSetup
	}
	switch network {
	case policy.NetOwner:
		return card(l.SSID.Owner, k.Owner), true
	case policy.NetHousehold:
		return card(l.SSID.Household, k.Household), true
	case policy.NetGuests:
		return card(l.SSID.Guests, k.Guests), true
	}
	return Card{}, false
}

// NetSetup names the setup network for NetworkCard.
const NetSetup = "setup"

// card is the Wi-Fi QR text that phones read (the WIFI: URI form), with
// the SSID's and the password's special characters escaped: generated
// passwords are base32 and have none, but the setup password is the
// sticker's.
func card(ssid, pw string) Card {
	esc := strings.NewReplacer(`\`, `\\`, `;`, `\;`, `,`, `\,`, `:`, `\:`, `"`, `\"`).Replace
	return Card{SSID: ssid, Password: pw, QR: "WIFI:T:WPA;S:" + esc(ssid) + ";P:" + esc(pw) + ";;", Shown: grouped(pw)}
}

// grouped is pw in groups of four separated by spaces. A password that
// already holds a space is shown as it is, since regrouping it would hide
// which spaces are part of it.
func grouped(pw string) string {
	if strings.Contains(pw, " ") {
		return pw
	}
	r := []rune(pw)
	var parts []string
	for len(r) > 4 {
		parts = append(parts, string(r[:4]))
		r = r[4:]
	}
	return strings.Join(append(parts, string(r)), " ")
}

// band is an OpenWrt radio band as the owner reads it.
func band(b string) string {
	switch b {
	case "2g":
		return "2.4 GHz"
	case "5g":
		return "5 GHz"
	case "6g":
		return "6 GHz"
	case "60g":
		return "60 GHz"
	}
	return b
}

// password is 26 base32 characters (130 bits) from the system's random
// source: within WPA's 8 to 63, needing no quoting anywhere, and easy to
// type into a device's app.
func password() string { return rand.Text() }

// distinct refuses keys where two passwords are equal. hostapd tries a
// joining device's password against each entry in turn, so two equal
// ones would put a device on whichever VLAN comes first.
func (k Keys) distinct() error {
	seen := map[string]bool{}
	all := []string{k.Owner, k.Household, k.Guests, k.Devices}
	for _, dk := range k.Device {
		all = append(all, dk.Password)
	}
	for _, p := range all {
		if p == "" {
			continue
		}
		if seen[p] {
			return fmt.Errorf("%w: two passwords are equal", ErrKeys)
		}
		seen[p] = true
	}
	return nil
}

// vlans is each Devices-network device's VLAN, by id, read with the
// firewall's own rule (nft.VLAN), so both sides agree on every number.
func vlans(d policy.Document) (map[string]int, error) {
	out := map[string]int{}
	seen := map[int]string{}
	for _, dev := range d.Devices {
		if dev.WiFi == "" {
			continue // a radio or wired device: no Wi-Fi password
		}
		v, ok := nft.VLAN(dev.WiFi)
		if !ok || dev.Network != policy.NetDevices {
			return nil, fmt.Errorf("%w: device %q has Wi-Fi identity %q on %q", ErrPolicy, dev.ID, dev.WiFi, dev.Network)
		}
		if other, dup := seen[v]; dup {
			return nil, fmt.Errorf("%w: devices %q and %q share VLAN %d", ErrPolicy, other, dev.ID, v)
		}
		seen[v] = dev.ID
		out[dev.ID] = v
	}
	return out, nil
}
