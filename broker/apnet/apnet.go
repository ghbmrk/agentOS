// Package apnet is the card's network file: the Owner Card's Wi-Fi name
// and password as the access point serves them once the card is confirmed
// (CTRL-claim-ap u1, #1185; HW-1, CH-7). The page writes it through
// agentosd's setup op before the confirm latches; agentos-ap reads it and
// serves it at the confirm and at every later start. It imports nothing
// of the card's code, so agentosd may link it (ARC-2).
package apnet

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Path is where the box keeps the card's network, root-owned 0600 beside
// the setup network (claim.SetupNetPath). The password is held in the
// clear, as WPA3-SAE needs it, and never logged (ARC-1).
const Path = "/var/lib/agentos/ap-net.json"

// Prefix starts the card's network name; the setup network's is
// "AgentOS-Setup-", so the two never look alike.
const Prefix = "AgentOS-"

// alphabet is the card's (card.Alphabet; a test keeps them equal).
const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

const (
	nameSymbols     = 4
	passwordSymbols = 16
	groupSymbols    = 4
)

// Network is the card's network: the name and password printed on it.
type Network struct {
	SSID     string `json:"ssid"`
	Password string `json:"password"`
}

// String and GoString keep the password out of logs.
func (Network) String() string   { return "[card Wi-Fi network]" }
func (Network) GoString() string { return "[card Wi-Fi network]" }

// Validate refuses anything but a network the card prints: a name of
// Prefix and four card symbols, and a password of sixteen card symbols
// in groups of four (XXXX-XXXX-XXXX-XXXX).
func (n Network) Validate() error {
	sym := strings.TrimPrefix(n.SSID, Prefix)
	if sym == n.SSID || len(sym) != nameSymbols || strings.Trim(sym, alphabet) != "" {
		return errors.New("apnet: not a card network name")
	}
	return ValidPassword(n.Password)
}

// ValidPassword refuses anything but sixteen card symbols in groups of
// four (XXXX-XXXX-XXXX-XXXX): the card's network password, and the shape
// the claim gives the setup network's (claim.NewSetupPassword, HW-10).
func ValidPassword(pw string) error {
	p := strings.ReplaceAll(pw, "-", "")
	if len(p) != passwordSymbols || strings.Trim(p, alphabet) != "" || group(p) != pw {
		return errors.New("apnet: not a card network password")
	}
	return nil
}

// Marshal is the file's content.
func (n Network) Marshal() ([]byte, error) {
	if err := n.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		SSID     string `json:"ssid"`
		Password string `json:"password"`
	}(n))
}

// Parse reads the file. Anything but one valid card network is an error:
// the box serves no network the card did not print.
func Parse(b []byte) (Network, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var n Network
	if err := d.Decode(&n); err != nil {
		return Network{}, fmt.Errorf("apnet: card network: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return Network{}, errors.New("apnet: card network: trailing data")
	}
	if err := n.Validate(); err != nil {
		return Network{}, err
	}
	return n, nil
}

func group(s string) string {
	var parts []string
	for len(s) > groupSymbols {
		parts = append(parts, s[:groupSymbols])
		s = s[groupSymbols:]
	}
	return strings.Join(append(parts, s), "-")
}
