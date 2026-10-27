package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/edgelink"
	"github.com/ghbmrk/agentos/broker/kernel"
)

// The link's timings (decision 5).
const (
	handshakeFor = 10 * time.Second
	helloFor     = 5 * time.Second        // an edge that is not live sends its hello within this
	trailFor     = 200 * time.Millisecond // how long a hello connection is watched for a second frame
	recheckEvery = 250 * time.Millisecond // a revoke or cut closes a served connection within a second
	recheckFor   = 500 * time.Millisecond // a recheck the kernel has not answered by then reads as not live
	handshakeCap = 16                     // handshakes in flight at once; a connection over it is refused (#3462)
)

// slots bounds the handshakes in flight on one listener: a connection takes
// a slot before its handshake and gives it back once it is served or
// closed, so a hostile edge opening connections without limit costs the
// kernel at most handshakeCap linksign and edgekey calls at a time.
type slots chan struct{}

func newSlots() slots { return make(slots, handshakeCap) }

// take takes a slot, or reports false when every slot is held.
func (s slots) take() bool {
	select {
	case s <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s slots) give() { <-s }

// errFault is every reason a connection closes that the edge caused. It
// carries nothing the edge sent.
var errFault = errors.New("agentos-link: the edge broke the link's framing or handshake")

// hello is one verified hello: the edge's key, the connection's exporter
// value and the key's signature, the record the kernel logs as a candidate
// and the pre-store capture writes (kernel.HelloMsg).
type hello struct {
	key   ed25519.PublicKey
	nonce []byte
	sig   []byte
}

// capture is the capture file's bytes: key, nonce, signature (agentos-enroll
// readCapture).
func (h hello) capture() []byte {
	return append(append(append([]byte(nil), h.key...), h.nonce...), h.sig...)
}

// readHello reads hello mode's one frame from conn, whose handshake key is
// key: a hello within helloFor that verifies over this connection's
// exporter value, from a key that is not of small order, and nothing after
// it. Anything else is errFault.
func readHello(conn *tls.Conn, key ed25519.PublicKey, wait time.Duration) (hello, error) {
	conn.SetReadDeadline(time.Now().Add(wait))
	f, err := edgelink.ReadFrame(conn, edgelink.Hello)
	if err != nil {
		return hello{}, errFault
	}
	nonce, err := edgelink.HelloNonce(conn.ConnectionState())
	if err != nil || kernel.SmallOrder(key) || edgelink.VerifyHello(key, nonce, f.Body) != nil {
		return hello{}, errFault
	}
	// The connection carries exactly one frame: a byte after the hello is
	// a fault, and the hello is not taken.
	conn.SetReadDeadline(time.Now().Add(trailFor))
	var b [1]byte
	if n, _ := conn.Read(b[:]); n > 0 {
		return hello{}, errFault
	}
	return hello{key, nonce, f.Body}, nil
}

// handshake completes conn's TLS 1.3 handshake under cfg and returns the
// key the edge proved.
func handshake(raw net.Conn, cfg *tls.Config) (*tls.Conn, ed25519.PublicKey, error) {
	conn := tls.Server(raw, cfg)
	conn.SetDeadline(time.Now().Add(handshakeFor))
	if err := conn.Handshake(); err != nil {
		return conn, nil, errFault
	}
	conn.SetDeadline(time.Time{})
	key, err := edgelink.PeerKey(conn.ConnectionState())
	if err != nil {
		return conn, nil, errFault
	}
	return conn, key, nil
}

// Item is one frame the live edge delivered, with the label its kind gives
// it at the core (decision 6), never one the edge chose.
type Item struct {
	Kind   edgelink.Kind
	Origin string
	Body   []byte
	Label  edgelink.Label
}

// server is the served mode (decision 5): the live edge's frames go to the
// consumer, any other key gets one hello read and reported.
type server struct {
	kernel Kernel
	cfg    *tls.Config
	items  chan Item // to the consumer; unbuffered, so a slow consumer slows the edge
	log    io.Writer // counts only, never content

	faults  atomic.Int64
	refused atomic.Int64 // connections refused over handshakeCap
	slots   slots
	wait    time.Duration // helloFor, shorter in tests
	every   time.Duration // recheckEvery, shorter in tests
	limit   time.Duration // recheckFor

	mu   sync.Mutex
	live *served // the connection outbound frames go to
}

// served is one connection of the live edge.
type served struct {
	conn *tls.Conn
	wmu  sync.Mutex
	done chan struct{}
	once sync.Once
}

func (c *served) close() {
	c.once.Do(func() {
		close(c.done)
		c.conn.Close()
	})
}

func newServer(k Kernel, log io.Writer) (*server, error) {
	pub, err := k.LinkKey()
	if err != nil {
		return nil, fmt.Errorf("agentos-link: the kernel names no link key: %w", err)
	}
	cfg, err := edgelink.ServerConfig(linkSigner{k, pub})
	if err != nil {
		return nil, err
	}
	return &server{kernel: k, cfg: cfg, items: make(chan Item), log: log, slots: newSlots(), wait: helloFor, every: recheckEvery, limit: recheckFor}, nil
}

// serve handles each connection ln accepts until ln closes.
func (s *server) serve(ln net.Listener) error {
	for {
		raw, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if !s.slots.take() {
			raw.Close()
			n := s.refused.Add(1)
			fmt.Fprintf(s.log, "agentos-link: refused a connection over the handshake cap (%d so far)\n", n)
			continue
		}
		go s.handle(raw)
	}
}

// fault counts one connection closed on the edge's fault and says the count.
func (s *server) fault() {
	n := s.faults.Add(1)
	fmt.Fprintf(s.log, "agentos-link: closed a connection on a fault (%d so far)\n", n)
}

// handle runs one connection, which holds a slot (serve) until it is
// served live or closed.
func (s *server) handle(raw net.Conn) {
	held := true
	release := func() {
		if held {
			held = false
			s.slots.give()
		}
	}
	defer release()
	conn, key, err := handshake(raw, s.cfg)
	if err != nil {
		conn.Close()
		s.fault()
		return
	}
	// Asked on every connection, never cached across one (decision 5).
	e, err := s.kernel.EdgeKey(key)
	if err != nil {
		conn.Close()
		fmt.Fprintf(s.log, "agentos-link: the kernel did not answer for an edge key: %v\n", err)
		return
	}
	if e.Live {
		release() // a served connection is no longer a handshake
		s.serveLive(conn, key)
		return
	}
	defer conn.Close()
	h, err := readHello(conn, key, s.wait)
	if err != nil {
		s.fault()
		return
	}
	if e.Revoked {
		return // read and dropped: a revoked key never comes back
	}
	if err := s.kernel.EdgeCandidate(h.key, h.nonce, h.sig); err != nil {
		// A candidate within the minute, or one the kernel refuses
		// otherwise, logs nothing; the text is the kernel's, not the edge's.
		fmt.Fprintf(s.log, "agentos-link: the kernel took no candidate: %v\n", err)
	}
}

// serveLive carries the live edge's frames to the consumer until the
// connection ends, a frame breaks the framing, or the kernel stops naming
// key live.
func (s *server) serveLive(conn *tls.Conn, key ed25519.PublicKey) {
	c := &served{conn: conn, done: make(chan struct{})}
	s.mu.Lock()
	if s.live != nil {
		s.live.close() // the edge reconnected: the newest connection is served
	}
	s.live = c
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.live == c {
			s.live = nil
		}
		s.mu.Unlock()
		c.close()
	}()
	go s.recheck(c, key)
	for {
		f, err := edgelink.ReadFrame(conn, edgelink.FromEdge)
		if err != nil {
			select {
			case <-c.done: // closed here: by a revoke, a cut or a newer connection
			default:
				if err != io.EOF {
					s.fault()
				}
			}
			return
		}
		select {
		case s.items <- Item{f.Kind, f.Origin, f.Body, f.Kind.Label()}:
		case <-c.done:
			return
		}
	}
}

// recheck closes c once the kernel no longer names key live, or does not
// answer.
func (s *server) recheck(c *served, key ed25519.PublicKey) {
	t := time.NewTicker(s.every)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			if !s.stillLive(key) {
				c.close()
				return
			}
		}
	}
}

// stillLive asks the kernel whether key is live, and reads an answer not
// given within s.limit as no: a slow kernel never keeps a revoked edge
// served past the second (decision 5).
func (s *server) stillLive(key ed25519.PublicKey) bool {
	ans := make(chan bool, 1)
	go func() {
		e, err := s.kernel.EdgeKey(key)
		ans <- err == nil && e.Live
	}()
	select {
	case ok := <-ans:
		return ok
	case <-time.After(s.limit):
		return false
	}
}

// errNoEdge: an outbound frame with no live edge connected; it is dropped.
var errNoEdge = errors.New("agentos-link: no live edge is connected")

// send writes one outbound frame to the live edge.
func (s *server) send(f edgelink.Frame) error {
	b, err := edgelink.AppendFrame(nil, edgelink.ToEdge, f)
	if err != nil {
		return err
	}
	s.mu.Lock()
	c := s.live
	s.mu.Unlock()
	if c == nil {
		return errNoEdge
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.conn.SetWriteDeadline(time.Now().Add(handshakeFor))
	if _, err := c.conn.Write(b); err != nil {
		c.close()
		return errNoEdge
	}
	return nil
}
