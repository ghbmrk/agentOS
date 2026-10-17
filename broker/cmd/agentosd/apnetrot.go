package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

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

// apNetMu keeps a page rotation and a reconcile from interleaving: each
// reads the vault and writes ap-net.json under it, so a reconcile that
// read the vault before a commit cannot overwrite the rotation's write.
var apNetMu sync.Mutex

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
		apNetMu.Lock()
		defer apNetMu.Unlock()
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

// errReconcileAPNet is every refusal to put the vault's network back. It
// names neither network (CH-7).
var errReconcileAPNet = errors.New("reconcile Wi-Fi network: refused")

// reconcileAPNet puts the Owner Card's committed Wi-Fi network, read from
// the open vault by committed, in ap-net.json when the file holds another
// (#1696): a rotation whose one-shot permit lapsed while agentosd was down
// left the access point on the old network. As with a rotation, only a
// network of the file's own name is written, validated by apnet, 0600 by
// durable rename; a file that already matches is not rewritten. An error
// from committed is returned wrapped, not as errReconcileAPNet, so the
// caller can tell an unanswered read from a refusal.
func reconcileAPNet(path string, committed func() (apnet.Network, error)) error {
	apNetMu.Lock()
	defer apNetMu.Unlock()
	n, err := committed()
	if err != nil {
		return fmt.Errorf("reconcile Wi-Fi network: %w", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return errReconcileAPNet
	}
	cur, err := apnet.Parse(b)
	if err != nil || cur.SSID != n.SSID {
		return errReconcileAPNet
	}
	if cur == n {
		return nil
	}
	out, err := n.Marshal()
	if err != nil {
		return errReconcileAPNet
	}
	if err := writeAPNetFile(path, out, 0o600); err != nil && !errors.Is(err, durable.ErrDirSync) {
		return errReconcileAPNet
	}
	return nil
}

// reconcileAPNetLoop reconciles at start and on each locked-to-open change
// of the vault, which it sees by asking on every tick (#1696). While the
// vault stays open after a reconcile, nothing more is written: a rotation
// then comes with its own permit. Until the vault process answers a
// network (not up yet, no card, a rotation owing its Wi-Fi part) it asks
// again on the next tick. logf hears each new error but a locked vault.
func reconcileAPNetLoop(ctx context.Context, path string, committed func() (apnet.Network, error), tick <-chan time.Time, logf func(error)) {
	reconciled := false
	last := ""
	for {
		var err error
		if reconciled {
			_, err = committed()
		} else {
			err = reconcileAPNet(path, committed)
		}
		switch {
		case errors.Is(err, modelroute.ErrVaultLocked):
			reconciled = false
			err = nil
		case err == nil, errors.Is(err, errReconcileAPNet):
			// Written, already matching, or refused on the file or the
			// network: done for this open.
			reconciled = true
		}
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		if msg != last && msg != "" {
			logf(err)
		}
		last = msg
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
	}
}

// committedNetwork reads the committed network over the vault process's
// verify socket; nil without one.
func committedNetwork(verifySocket string) func() (apnet.Network, error) {
	if verifySocket == "" {
		return nil
	}
	v := modelroute.NewVerifier(verifySocket)
	return func() (apnet.Network, error) {
		w, err := v.CommittedWiFi()
		return apnet.Network{SSID: w.SSID, Password: w.Password}, err
	}
}

// watchCommittedWiFi is the reconcile main runs, every apUpEvery.
func watchCommittedWiFi(ctx context.Context, path, verifySocket string) {
	committed := committedNetwork(verifySocket)
	if path == "" || committed == nil {
		return
	}
	t := time.NewTicker(apUpEvery)
	defer t.Stop()
	reconcileAPNetLoop(ctx, path, committed, t.C, func(err error) { log.Printf("access point network: %v", err) })
}
