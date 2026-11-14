package proc

import (
	"encoding/binary"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// chronyd's command protocol, version 6 (chrony's candm.h, pktlength.c): a
// REQ_TRACKING request, padded to its reply's length, and the RPY_TRACKING
// reply, both big-endian and 104 bytes.
const (
	chronyLen      = 104
	chronyTracking = 33         // REQ_TRACKING
	chronyRpy      = 5          // RPY_TRACKING
	chronyUnsynced = 3          // LEAP_Unsynchronised
	chronyLocal    = 0x7F7F0101 // "LOCL": chronyd's own clock, no source
	chronyWait     = 100 * time.Millisecond
	chronyRetry    = 10 * time.Second
)

// Chrony reads chronyd's tracking report over its command socket sock, from
// a datagram socket bound at reply and connected to sock, so the host
// delivers it only chronyd's datagrams.
type Chrony struct {
	sock, reply string
	mu          sync.Mutex
	c           *net.UnixConn
	seq         uint32
	next        time.Time // no try before this after a failure
}

// NewChrony is a source reading chronyd at sock, answered at reply.
func NewChrony(sock, reply string) *Chrony { return &Chrony{sock: sock, reply: reply} }

// Read is the kernel process's TIM-1 source (onLog). With chronyd synced,
// true time is the box clock plus chronyd's correction, within root delay /
// 2 + root dispersion, and the reading is the hull of that and the box
// clock: a disagreement widens it. Otherwise it vouches for no lower bound
// (Earliest 0) and Latest is the box clock.
func (s *Chrony) Read() kernel.Reading {
	s.mu.Lock()
	defer s.mu.Unlock()
	b0 := time.Now().UnixMilli()
	corr, err, ok := s.track()
	b1 := time.Now().UnixMilli()
	if !ok {
		return kernel.Reading{Latest: b1}
	}
	lo := b0 + int64(math.Floor((corr-err)*1000))
	hi := b1 + int64(math.Ceil((corr+err)*1000))
	return kernel.Reading{Earliest: min(b0, lo), Latest: max(b1, hi)}
}

// Close closes the reply socket and removes its file.
func (s *Chrony) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drop()
}

func (s *Chrony) drop() {
	if s.c != nil {
		s.c.Close()
		os.Remove(s.reply)
		s.c = nil
	}
}

// track asks chronyd once: its correction (true time minus the box clock)
// and its error bound, in seconds; !ok when chronyd is not synced to a
// source or does not answer well. A failure closes the socket and waits
// chronyRetry, so a hung chronyd delays a decision at most once in that.
func (s *Chrony) track() (corr, bound float64, ok bool) {
	if time.Now().Before(s.next) {
		return 0, 0, false
	}
	if corr, bound, ok = s.ask(); !ok {
		s.drop()
		s.next = time.Now().Add(chronyRetry)
	}
	return
}

func (s *Chrony) ask() (float64, float64, bool) {
	if s.c == nil {
		os.Remove(s.reply)
		c, err := net.DialUnix("unixgram", &net.UnixAddr{Name: s.reply, Net: "unixgram"}, &net.UnixAddr{Name: s.sock, Net: "unixgram"})
		if err != nil {
			return 0, 0, false
		}
		s.c = c
		// chronyd runs as its own user; the connect above, not the mode,
		// keeps every other sender out.
		if os.Chmod(s.reply, 0o666) != nil {
			return 0, 0, false
		}
	}
	s.seq++
	q := make([]byte, chronyLen)
	q[0], q[1] = 6, 1 // version, PKT_TYPE_CMD_REQUEST
	binary.BigEndian.PutUint16(q[4:], chronyTracking)
	binary.BigEndian.PutUint32(q[8:], s.seq)
	if s.c.SetDeadline(time.Now().Add(chronyWait)) != nil {
		return 0, 0, false
	}
	if _, err := s.c.Write(q); err != nil {
		return 0, 0, false
	}
	p := make([]byte, chronyLen+1)
	n, err := s.c.Read(p)
	if err != nil {
		return 0, 0, false
	}
	return parseTracking(p[:n], s.seq)
}

// parseTracking reads an RPY_TRACKING reply to request seq: chronyd's
// correction and error bound, in seconds; !ok for any other reply, or one
// not synced to a source.
func parseTracking(p []byte, seq uint32) (float64, float64, bool) {
	be := binary.BigEndian
	if len(p) != chronyLen || p[0] != 6 || p[1] != 2 || be.Uint16(p[4:]) != chronyTracking ||
		be.Uint16(p[6:]) != chronyRpy || be.Uint16(p[8:]) != 0 || be.Uint32(p[16:]) != seq {
		return 0, 0, false
	}
	if be.Uint32(p[28:]) == chronyLocal || be.Uint16(p[52:]) == 0 || be.Uint16(p[54:]) == chronyUnsynced {
		return 0, 0, false
	}
	corr := chronyFloat(be.Uint32(p[68:]))
	bound := chronyFloat(be.Uint32(p[92:]))/2 + chronyFloat(be.Uint32(p[96:]))
	// A bound past a day, or a correction past ten years, is no time anyone
	// should act on.
	if !(bound >= 0 && bound <= 86400) || math.Abs(corr) > 10*365*86400 {
		return 0, 0, false
	}
	return corr, bound, true
}

// chronyFloat decodes the protocol's float: a 7-bit exponent and a 25-bit
// coefficient, both signed (chrony's UTI_FloatNetworkToHost).
func chronyFloat(x uint32) float64 {
	exp, coef := int(x>>25), int(x&(1<<25-1))
	if exp >= 64 {
		exp -= 128
	}
	if coef >= 1<<24 {
		coef -= 1 << 25
	}
	return math.Ldexp(float64(coef), exp-25)
}
