package camera

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// The clerk reaches each decoder session over a connection to the decoder
// unit's socket (CAM-decoder-uid, #4134): every connection starts a fresh
// agentos-camdecode@.service under a user of its own, which runs the
// session's sandbox (package decodehost), so a sandbox escape holds
// neither the clerk's uid, its files nor its socket. The connection
// carries the session's Spec first, then the clerk's frames one way and
// the sandbox's output the other, unchanged: the clerk checks every byte
// that comes back (Decoder.read), as it does a local sandbox's.

// SpecLen is a Spec's length on the connection: the video and the
// thermal shapes' widths and heights, big-endian.
const SpecLen = 8

func (s Spec) marshal() []byte {
	b := make([]byte, SpecLen)
	binary.BigEndian.PutUint16(b[0:], s.Video.Width)
	binary.BigEndian.PutUint16(b[2:], s.Video.Height)
	binary.BigEndian.PutUint16(b[4:], s.Thermal.Width)
	binary.BigEndian.PutUint16(b[6:], s.Thermal.Height)
	return b
}

// ReadSpec reads a session's Spec from the start of its connection and
// holds it to CheckShapes.
func ReadSpec(r io.Reader) (Spec, error) {
	var b [SpecLen]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return Spec{}, err
	}
	s := Spec{
		Video:   camwire.Shape{Width: binary.BigEndian.Uint16(b[0:]), Height: binary.BigEndian.Uint16(b[2:])},
		Thermal: camwire.Shape{Width: binary.BigEndian.Uint16(b[4:]), Height: binary.BigEndian.Uint16(b[6:])},
	}
	return s, CheckShapes(s.Video, s.Thermal)
}

// decoderStop bounds how long a Stop waits for the decoder unit to end
// its sandbox and close the connection. Its own process ends with the
// connection; one that does not is the unit's to stop.
var decoderStop = 10 * time.Second

// DialDecoder is the StartFunc that starts each session in the decoder
// unit listening on sock.
func DialDecoder(sock string) StartFunc {
	return func(ctx context.Context, s Spec) (Proc, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "unix", sock)
		if err != nil {
			return nil, err
		}
		uc := c.(*net.UnixConn)
		if _, err := uc.Write(s.marshal()); err != nil {
			uc.Close()
			return nil, err
		}
		return &connProc{c: uc, done: make(chan struct{})}, nil
	}
}

// connProc is a session in the decoder unit.
type connProc struct {
	c    *net.UnixConn
	done chan struct{}
	once sync.Once
}

func (p *connProc) In() io.Writer         { return p.c }
func (p *connProc) Out() io.Reader        { return p.c }
func (p *connProc) Done() <-chan struct{} { return p.done }

// Stop ends the session: no more is written, and its output is read and
// dropped until the unit closes the connection, which it does once the
// sandbox is gone, or decoderStop passes. The session's reader has
// stopped passing output on by then (Decoder.read).
func (p *connProc) Stop() {
	p.once.Do(func() {
		p.c.SetWriteDeadline(time.Now())
		p.c.CloseWrite()
		p.c.SetReadDeadline(time.Now().Add(decoderStop))
		io.Copy(io.Discard, p.c)
		p.c.Close()
		close(p.done)
	})
	<-p.done
}
