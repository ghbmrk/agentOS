package claim

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// SetupNetPath is where a preloaded box keeps its setup network: the
// Wi-Fi the phone joins before the Owner Card exists (§8.1 step 4,
// CTRL-claim-ap). The seller flow writes it into the image root-owned
// 0600 beside StatePath and prints it on the sticker; firstboot serves it
// until the card is confirmed, then burns it. It is in the access point
// loader's own directory (apnet.Dir, #2626); a test keeps the two equal.
const SetupNetPath = "/var/lib/agentos/ap/setup-net.json"

// SetupSSIDPrefix starts every setup network's name. The card's network
// is "AgentOS-" and four symbols, so the two never look alike.
const SetupSSIDPrefix = "AgentOS-Setup-"

// setupSSIDSymbols is the random part of a setup network's name: enough
// that two boxes on one street do not share it; the password, not the
// name, keeps others out.
const setupSSIDSymbols = 4

// SetupNet is a preloaded box's setup network. The password is kept in
// the clear, since WPA3-SAE needs it (CH-7); it is per box, 80 bits, and
// opens only the claim and setup pages, behind the claim (HW-10).
type SetupNet struct {
	SSID     string `json:"ssid"`
	Password string `json:"password"`
	// Rotated is set once the claim has replaced the sticker's password
	// (Rotate): the sticker no longer opens the network. A seller's file
	// leaves it unset.
	Rotated bool `json:"rotated,omitempty"`
}

// ErrRotated is Rotate's refusal for a network the claim already rotated:
// the password changes once, at the claim (HW-10).
var ErrRotated = errors.New("claim: setup network already rotated")

// NewSetupPassword is a new setup network password in the claim code's
// format, for the claim's rotation (HW-10).
func NewSetupPassword(r io.Reader) (string, error) { return NewCode(r) }

// Rotate is n with the sticker's password replaced by password: the same
// name, Rotated set. It refuses a network already rotated and a password
// NewSetupPassword would not make.
func (n SetupNet) Rotate(password string) (SetupNet, error) {
	if n.Rotated {
		return SetupNet{}, ErrRotated
	}
	if err := n.Validate(); err != nil {
		return SetupNet{}, err
	}
	r := SetupNet{SSID: n.SSID, Password: password, Rotated: true}
	if err := r.Validate(); err != nil {
		return SetupNet{}, err
	}
	return r, nil
}

// NewSetupNet makes a setup network for the seller flow: a name from
// SetupSSIDPrefix and four card symbols, and a password in the claim
// code's format, drawn independently of the code.
func NewSetupNet(r io.Reader) (SetupNet, error) {
	name, err := NewCode(r)
	if err != nil {
		return SetupNet{}, err
	}
	pw, err := NewCode(r)
	if err != nil {
		return SetupNet{}, err
	}
	n := SetupNet{SSID: SetupSSIDPrefix + name[:setupSSIDSymbols], Password: pw}
	return n, n.Validate()
}

// Validate refuses anything but a name NewSetupNet makes and a password of
// CodeSymbols card symbols in the code's grouping.
func (n SetupNet) Validate() error {
	sym := strings.TrimPrefix(n.SSID, SetupSSIDPrefix)
	if sym == n.SSID || len(sym) != setupSSIDSymbols || strings.Trim(sym, alphabet) != "" {
		return errors.New("claim: not a setup network name")
	}
	if p := Normalize(n.Password); len(p) != CodeSymbols || strings.Trim(p, alphabet) != "" || group(p) != n.Password {
		return errors.New("claim: not a setup network password")
	}
	return nil
}

// Marshal is the setup file's content.
func (n SetupNet) Marshal() ([]byte, error) {
	if err := n.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(n)
}

// ParseSetupNet reads a setup file. Anything but one valid setup network
// is an error: the box brings up no network nobody printed.
func ParseSetupNet(b []byte) (SetupNet, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var n SetupNet
	if err := d.Decode(&n); err != nil {
		return SetupNet{}, fmt.Errorf("claim: setup network: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return SetupNet{}, errors.New("claim: setup network: trailing data")
	}
	return n, n.Validate()
}

// group is a normalized code as NewCode prints it, XXXX-XXXX-XXXX-XXXX.
func group(s string) string {
	var parts []string
	for len(s) > 4 {
		parts = append(parts, s[:4])
		s = s[4:]
	}
	return strings.Join(append(parts, s), "-")
}
