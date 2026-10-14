package main

import (
	"errors"
	"os"

	"github.com/ghbmrk/agentos/broker/apnet"
	"github.com/ghbmrk/agentos/broker/durable"
)

// errRotateAPNet is every refusal of a rotated network. It names neither
// network: the password must stay out of errors and logs (CH-7).
var errRotateAPNet = errors.New("rotate Wi-Fi network: refused")

// rotateAPNet writes a rotated card's Wi-Fi network for agentos-ap to serve
// (REC-4, #1191): root-only, 0600, by durable rename, validated by apnet.
// A rotation keeps the card's network name, so a network for another name
// is refused, as is a rotation before setup wrote the first one. Nil path,
// nil hook: the page's op is then refused.
func rotateAPNet(path string) func(apnet.Network) error {
	if path == "" {
		return nil
	}
	return func(n apnet.Network) error {
		b, err := os.ReadFile(path)
		if err != nil {
			return errRotateAPNet
		}
		cur, err := apnet.Parse(b)
		if err != nil || cur.SSID != n.SSID {
			return errRotateAPNet
		}
		out, err := n.Marshal()
		if err != nil {
			return errRotateAPNet
		}
		if durable.WriteFile(path, out, 0o600) != nil {
			return errRotateAPNet
		}
		return nil
	}
}
