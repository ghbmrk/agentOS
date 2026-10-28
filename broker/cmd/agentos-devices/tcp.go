package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// Transport errors. None carries text from the device, and devhost sends
// the driver only "failed" for any of them (DEVSLOT-host-lib-5).
var (
	errWrongKey  = errors.New("devices: the device's key is not the pinned one")
	errNotPinned = errors.New("devices: a frame for another device or channel")
	// errNoRelay is GATT until the enforcer's relay (DEVSLOT part c).
	errNoRelay = errors.New("devices: no GATT relay")
)

// dialWait bounds one TCP connection and its handshake.
const dialWait = 10 * time.Second

// tcpTransport is a TCP device's one stream (DEV-3): a TLS connection to
// the pin's home address on the declaration's one port, kept only if the
// device's key, the SHA-256 of its certificate's public key, is the pin's.
// It ignores the certificate's names, issuer and dates: the pin is the
// device's whole identity. A failed call drops the connection, and the next
// call connects again.
type tcpTransport struct {
	pin     devslot.Pin
	ch      devslot.Channel
	maxRead int

	// guard is the process's address policy (DEV-2): the stream is dialled
	// only through it, as a device executor's dial (PurposeDevice) to a
	// PinDevice pin, which devicePins gives each TCP device.
	guard *netguard.Policy

	mu   sync.Mutex // one call at a time on the stream
	conn net.Conn
}

func newTCPTransport(d devslot.Declaration, pin devslot.Pin, guard *netguard.Policy) (*tcpTransport, error) {
	if d.Link != devslot.TCP || len(d.Channels) != 1 || pin.Key == ([32]byte{}) || !pin.Host.IsValid() || guard == nil {
		return nil, errors.New("devices: a TCP transport needs a TCP declaration with one channel, a keyed pin and the address guard")
	}
	return &tcpTransport{pin: pin, ch: d.Channels[0], maxRead: d.MaxRead, guard: guard}, nil
}

func (t *tcpTransport) addrPort() netip.AddrPort {
	return netip.AddrPortFrom(t.pin.Host.Unmap(), t.ch.Port)
}

// devicePin is the guard's pin for a TCP device: its one address and port,
// and its key, which tlsConfig checks at the handshake.
func devicePin(d devslot.Declaration, pin devslot.Pin) (netguard.Pin, bool) {
	if d.Link != devslot.TCP || len(d.Channels) != 1 {
		return netguard.Pin{}, false
	}
	return netguard.Pin{Kind: netguard.PinDevice, Addr: netip.AddrPortFrom(pin.Host.Unmap(), d.Channels[0].Port), Key: pin.Key}, true
}

// tlsConfig checks the device's key against the pin, and nothing else.
func (t *tcpTransport) tlsConfig() *tls.Config {
	want := t.pin.Key
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// The chain is not checked against any root: VerifyConnection runs
		// even so, and checks the one thing that names the device.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errWrongKey
			}
			if sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo) != want {
				return errWrongKey
			}
			return nil
		},
	}
}

// stream is the connection, made if there is none. t.mu is held.
func (t *tcpTransport) stream(ctx context.Context) (net.Conn, error) {
	if t.conn != nil {
		return t.conn, nil
	}
	ctx, cancel := context.WithTimeout(ctx, dialWait)
	defer cancel()
	raw, err := t.guard.DialContext(netguard.WithPurpose(ctx, netguard.PurposeDevice), "tcp", t.addrPort().String())
	if err != nil {
		return nil, err
	}
	c := tls.Client(raw, t.tlsConfig())
	if err := c.HandshakeContext(ctx); err != nil {
		raw.Close()
		if errors.Is(err, errWrongKey) {
			return nil, errWrongKey
		}
		return nil, err
	}
	t.conn = c
	return c, nil
}

// call runs fn on the stream with ctx's end as its deadline, and drops the
// stream if fn fails.
func (t *tcpTransport) call(ctx context.Context, tg devslot.Target, fn func(net.Conn) error) error {
	if tg.Pin != t.pin || tg.Channel != t.ch {
		return errNotPinned
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	c, err := t.stream(ctx)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Unix(1, 0)) })
	err = fn(c)
	if !stop() || err != nil {
		c.Close()
		t.conn = nil
		if err == nil {
			err = ctx.Err()
		}
	}
	return err
}

func (t *tcpTransport) Write(ctx context.Context, tg devslot.Target, frame []byte) error {
	return t.call(ctx, tg, func(c net.Conn) error {
		_, err := c.Write(frame)
		return err
	})
}

// Read returns what one read of the stream gives, at most the declaration's
// MaxRead bytes: a TCP device's frame is what arrives together.
func (t *tcpTransport) Read(ctx context.Context) (devslot.Target, []byte, error) {
	tg := devslot.Target{Pin: t.pin, Channel: t.ch}
	buf := make([]byte, max(t.maxRead, 1))
	var n int
	err := t.call(ctx, tg, func(c net.Conn) error {
		var err error
		n, err = c.Read(buf)
		return err
	})
	if err != nil {
		return devslot.Target{}, nil, err
	}
	return tg, buf[:n], nil
}

// gattTransport is GATT until the enforcer's relay (DEVSLOT part c): every
// call fails with errNoRelay.
type gattTransport struct{}

func (gattTransport) Write(context.Context, devslot.Target, []byte) error { return errNoRelay }
func (gattTransport) Read(context.Context) (devslot.Target, []byte, error) {
	return devslot.Target{}, nil, errNoRelay
}

// transportFor is the transport for a declaration's link kind.
func transportFor(d devslot.Declaration, pin devslot.Pin, guard *netguard.Policy) (devslot.Transport, error) {
	switch d.Link {
	case devslot.TCP:
		return newTCPTransport(d, pin, guard)
	case devslot.GATT:
		return gattTransport{}, nil
	}
	return nil, errors.New("devices: unknown link kind")
}
