package main

import (
	"errors"
	"os"

	"github.com/ghbmrk/agentos/broker/apnet"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/durable"
	"github.com/ghbmrk/agentos/broker/modelroute"
)

// errRotateAPNet is every refusal of a rotated network. It names neither
// network: the password must stay out of errors and logs (CH-7).
var errRotateAPNet = errors.New("rotate Wi-Fi network: refused")

// writeAPNetFile is the write; a var only so a test proves it is the
// durable one (#1524).
var writeAPNetFile = durable.WriteFile

// rotateAPNet writes a rotated card's Wi-Fi network for agentos-ap to serve
// (REC-4, #1191): root-only, 0600, by durable rename, validated by apnet.
// The network comes from take, the vault process's one-shot hold of the
// latest Wi-Fi commit (#1522), never from the page: without a commit
// there is nothing to take, and a second write needs a second commit. A
// rotation keeps the card's network name, so a network for another name
// is refused, as is a rotation before setup wrote the first one. A
// directory sync that fails after the rename still put the new network
// on the air, so it is a success. Nil path or taker, nil hook: the page's
// op is then refused.
func rotateAPNet(path string, take func() (apnet.Network, error)) func() error {
	if path == "" || take == nil {
		return nil
	}
	return func() error {
		n, err := take()
		if err != nil {
			return errRotateAPNet
		}
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
		if err := writeAPNetFile(path, out, 0o600); err != nil && !errors.Is(err, durable.ErrDirSync) {
			return errRotateAPNet
		}
		return nil
	}
}

// pageSocket is the local UI's socket main serves, with the rotated
// network taken from the vault process's verify socket.
func pageSocket(uid, gid int, apNetPath, verifySocket string) *daemon.PageSocket {
	var take func() (apnet.Network, error)
	if verifySocket != "" {
		v := modelroute.NewVerifier(verifySocket)
		take = func() (apnet.Network, error) {
			w, err := v.TakeRotatedWiFi()
			return apnet.Network{SSID: w.SSID, Password: w.Password}, err
		}
	}
	return &daemon.PageSocket{UID: uid, GID: &gid, RotateAPNet: rotateAPNet(apNetPath, take)}
}
