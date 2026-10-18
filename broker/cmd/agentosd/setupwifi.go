package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"

	"github.com/ghbmrk/agentos/broker/apnet"
	"github.com/ghbmrk/agentos/broker/durable"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// defaultSetupNet is claim.SetupNetPath, which agentosd may not link
// (ARC-2); a test keeps them equal.
const defaultSetupNet = "/var/lib/agentos/setup-net.json"

// setupWiFi is the setup network's file as agentosd reads and rewrites it
// for the claim's rotation (HW-10, #1692): claim.SetupNet's fields, which
// agentosd may not link (ARC-2). agentos-ap parses the result with
// claim.ParseSetupNet; a test keeps the two in step.
type setupWiFi struct {
	SSID     string `json:"ssid"`
	Password string `json:"password"`
	Rotated  bool   `json:"rotated,omitempty"`
}

// readSetupWiFi reads the setup network at path: ErrNoSetupWiFi when the
// file is absent or empty (no setup network, or burned at the confirm),
// ErrFailed when it cannot be read or parsed.
func readSetupWiFi(path string) (setupWiFi, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) || err == nil && len(b) == 0 {
		return setupWiFi{}, sockets.Code(localapi.ErrNoSetupWiFi)
	}
	if err != nil {
		return setupWiFi{}, sockets.Code(localapi.ErrFailed)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var n setupWiFi
	if d.Decode(&n) != nil || n.SSID == "" {
		return setupWiFi{}, sockets.Code(localapi.ErrFailed)
	}
	if _, err := d.Token(); err != io.EOF {
		return setupWiFi{}, sockets.Code(localapi.ErrFailed)
	}
	return n, nil
}

// setupWiFiNameOp is OpSetupWiFiName: the setup network's name and whether
// it is rotated, never its password.
func setupWiFiNameOp(path string) sockets.Handler {
	return func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
		n, err := readSetupWiFi(path)
		if err != nil {
			return nil, err
		}
		return localapi.SetupWiFiName{SSID: n.SSID, Rotated: n.Rotated}, nil
	}
}

// setupWiFiOp is OpSetupWiFi: it replaces the sticker's password with the
// page's, once, keeping the name, and writes the file 0600 by a durable
// rename for agentos-ap, which brings the network back up with it (Down
// then Up). It logs nothing of either password (ARC-1). A burn that races
// it can leave the rotated file behind; agentos-ap burns it again at its
// next poll, since the latch or the owner state still says so.
func setupWiFiOp(path string) sockets.Handler {
	return func(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
		var r localapi.SetupWiFi
		if json.Unmarshal(args, &r) != nil || apnet.ValidPassword(r.Password) != nil {
			return nil, sockets.Code(localapi.ErrBadArgs)
		}
		n, err := readSetupWiFi(path)
		if err != nil {
			return nil, err
		}
		if n.Rotated {
			return nil, sockets.Code(localapi.ErrWiFiRotated)
		}
		if r.Password == n.Password {
			return nil, sockets.Code(localapi.ErrBadArgs)
		}
		b, err := json.Marshal(setupWiFi{SSID: n.SSID, Password: r.Password, Rotated: true})
		if err != nil || durable.WriteFile(path, b, 0o600) != nil {
			return nil, sockets.Code(localapi.ErrFailed)
		}
		return nil, nil
	}
}
