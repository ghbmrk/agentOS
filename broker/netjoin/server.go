package netjoin

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/ghbmrk/agentos/broker/sockets"
)

// Endpoint is the helper's one socket (L8.3): only peerUID (agentosd's)
// may connect, checked with SO_PEERCRED before a request is read, with
// sockets' request cap, and at most two connections that each idle out.
func Endpoint(j *Joiner, peerUID int) sockets.Endpoint {
	uid := peerUID
	return sockets.Endpoint{
		Name:        Socket,
		Peer:        sockets.Peer{Kind: "agentosd"},
		Ops:         map[string]sockets.Handler{OpJoin: j.handle},
		MaxConns:    2,
		IdleTimeout: 10 * time.Second,
		PeerUID:     &uid,
	}
}

// handle answers every request with a code. Args that are not exactly a
// Request (missing, extra fields, trailing data, wrong types) are refused
// without a D-Bus call.
func (j *Joiner) handle(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var r Request
	d := json.NewDecoder(bytes.NewReader(args))
	d.DisallowUnknownFields()
	if len(args) == 0 || d.Decode(&r) != nil || d.More() {
		return Answer{Code: Refused}, nil
	}
	return Answer{Code: j.Join(ctx, r.SSID, r.PSK)}, nil
}
