package main

import (
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"github.com/ghbmrk/agentos/broker/sockets"
)

// Kernel is what the link asks the kernel, on the kernel process's link
// socket (decisions 4, 5 and 8). The link holds no key and keeps no answer:
// every connection asks again.
type Kernel interface {
	// LinkKey is the public half of the core's link key.
	LinkKey() (ed25519.PublicKey, error)
	// LinkSign signs a TLS 1.3 server CertificateVerify input with the
	// link key; the kernel refuses any other input (linksign).
	LinkSign(msg []byte) ([]byte, error)
	// EdgeKey is what the log says of an edge key now (edgekey).
	EdgeKey(k ed25519.PublicKey) (Edge, error)
	// EdgeCandidate reports a hello read in hello mode (edgecandidate).
	EdgeCandidate(k ed25519.PublicKey, nonce, sig []byte) error
}

// Edge is the kernel's answer for one key.
type Edge struct {
	Live    bool `json:"live"`    // the key is LiveEdge: serve it
	Revoked bool `json:"revoked"` // revoked or replaced in this log: drop its hello
}

// The wire the kernel's link side speaks (kernel/proc's Conn, written out
// here as owner/kernelsock writes out the owner side's, so the link links
// no kernel process code): one call per connection, {op, args}, answered
// {result} or {error}. The kernel's side serves these names.
type (
	wireCall struct {
		Op   string `json:"op"`
		Args any    `json:"args"`
	}
	wireAnswer struct {
		Result  json.RawMessage `json:"result,omitempty"`
		Refusal json.RawMessage `json:"refusal,omitempty"`
		Error   string          `json:"error,omitempty"`
	}
	signArgs struct {
		Msg []byte `json:"msg"`
	}
	keyArgs struct {
		Key ed25519.PublicKey `json:"key"`
	}
	candidateArgs struct {
		Key   ed25519.PublicKey `json:"key"`
		Nonce []byte            `json:"nonce"`
		Sig   []byte            `json:"sig"`
	}
	none struct{}
)

const (
	maxAnswer = 1 << 16
	callFor   = 10 * time.Second
)

var (
	// ErrUnreachable: no kernel listens on the socket, or another uid
	// holds it. Nothing was sent.
	ErrUnreachable = errors.New("agentos-link: the kernel's link socket could not be reached")
	// ErrLost: the answer never came.
	ErrLost = errors.New("agentos-link: the kernel's answer was lost")
)

// Refused is a call the kernel answered with an error, by its text.
type Refused struct{ Text string }

func (r Refused) Error() string { return "agentos-link: the kernel refused: " + r.Text }

// kernelConn is the link socket's client.
type kernelConn struct {
	socket string
	uid    int // the kernel's uid: the only peer the link calls
}

func (c kernelConn) call(op string, args, out any) error {
	if args == nil {
		args = none{}
	}
	b, err := json.Marshal(wireCall{op, args})
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("unix", c.socket, callFor)
	if err != nil {
		return ErrUnreachable
	}
	defer conn.Close()
	if uid, ok := sockets.PeerUID(conn); !ok || uid != c.uid {
		return ErrUnreachable
	}
	conn.SetDeadline(time.Now().Add(callFor))
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return ErrLost
	}
	var a wireAnswer
	if json.NewDecoder(io.LimitReader(conn, maxAnswer)).Decode(&a) != nil {
		return ErrLost
	}
	switch {
	case a.Error != "":
		return Refused{a.Error}
	case len(a.Refusal) > 0:
		return Refused{string(a.Refusal)}
	case out != nil:
		if json.Unmarshal(a.Result, out) != nil {
			return ErrLost
		}
	}
	return nil
}

func (c kernelConn) LinkKey() (k ed25519.PublicKey, err error) {
	if err = c.call("linkkey", nil, &k); err == nil && len(k) != ed25519.PublicKeySize {
		err = ErrLost
	}
	return k, err
}

func (c kernelConn) LinkSign(msg []byte) (sig []byte, err error) {
	if err = c.call("linksign", signArgs{msg}, &sig); err == nil && len(sig) != ed25519.SignatureSize {
		err = ErrLost
	}
	return sig, err
}

func (c kernelConn) EdgeKey(k ed25519.PublicKey) (e Edge, err error) {
	err = c.call("edgekey", keyArgs{k}, &e)
	return e, err
}

func (c kernelConn) EdgeCandidate(k ed25519.PublicKey, nonce, sig []byte) error {
	return c.call("edgecandidate", candidateArgs{k, nonce, sig}, nil)
}

// linkSigner is the TLS server's signer: the public half the kernel named,
// and every signature made by the kernel's linksign (decision 4), so this
// process never holds the link key.
type linkSigner struct {
	k   Kernel
	pub ed25519.PublicKey
}

func (s linkSigner) Public() crypto.PublicKey { return s.pub }

func (s linkSigner) Sign(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != 0 {
		return nil, errors.New("agentos-link: the link key signs Ed25519 only")
	}
	return s.k.LinkSign(msg)
}
