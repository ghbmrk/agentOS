package withings

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"
)

// Link is the scale's one characteristic, as a connected, subscribed GATT
// client gives it: Write writes a request, Read returns the next
// notification. The enforcer's radio stack provides it (NET-2); it offers
// the reader nothing else.
type Link interface {
	Write(ctx context.Context, frame []byte) error
	Read(ctx context.Context) ([]byte, error)
}

// Prover holds the scale's secret kl and answers for it, so the session
// never holds kl (CLK-1). Answer is SHA1(challenge ‖ mac ‖ kl), the answer
// to the scale's challenge; Check is whether answer is the scale's correct
// answer to our own challenge.
type Prover interface {
	Answer(challenge []byte, mac string) ([]byte, error)
	Check(own []byte, mac string, answer []byte) bool
}

// Errors a read ends with. None carries a value from the scale or the
// prover.
var (
	// ErrRefused is a frame off the allowlist: it was not written.
	ErrRefused = errors.New("withings: frame refused, not sent")
	// ErrSetupMode is a scale that answered without a challenge (a button
	// press in setup mode): nothing is read from it.
	ErrSetupMode = errors.New("withings: scale in setup mode, nothing read")
	// ErrUnproven is a scale that did not prove it knows kl.
	ErrUnproven = errors.New("withings: scale did not prove its key")
	// ErrScale is a reply the reader cannot use.
	ErrScale = errors.New("withings: unexpected reply from the scale")
	// ErrFlood is a scale that sent more requests of its own than a sync
	// needs.
	ErrFlood = errors.New("withings: too many requests from the scale")
)

// ScaleError is an error the scale answered a request with.
type ScaleError struct {
	Cmd  uint16
	Code int32
}

func (e ScaleError) Error() string {
	return fmt.Sprintf("withings: scale refused command %d with %d", e.Cmd, e.Code)
}

// Limits on one session.
const (
	replyWait     = 5 * time.Second
	recordsWait   = 10 * time.Second
	maxDeviceReqs = 32
	maxReplies    = 256 // messages in one multi-message reply
)

// Result is one read. Readings are merged by time, user and measure;
// Battery and Reason are -1 when the scale did not say.
type Result struct {
	Readings []Reading
	Battery  int
	Reason   int
	Firmware uint32
	// Dropped counts values the reader did not return: unknown measure
	// codes and records that did not parse.
	Dropped int
}

// Session is one connection's read.
type Session struct {
	Link   Link
	Prover Prover
	// Log takes one line per event, each a fixed phrase and numbers only:
	// never a value from the scale or the prover. Nil discards.
	Log func(string)
	// Rand is the source of our challenge; nil is crypto/rand.
	Rand io.Reader

	reasm   reassembler
	inbox   []message
	devReqs int
}

func (s *Session) log(format string, args ...any) {
	if s.Log != nil {
		s.Log(fmt.Sprintf(format, args...))
	}
}

// send writes frame if the allowlist allows it. This is the only call of
// Link.Write.
func (s *Session) send(ctx context.Context, frame []byte) error {
	if !allowed(frame) {
		cmd := -1
		if len(frame) >= 3 {
			cmd = int(frame[1])<<8 | int(frame[2])
		}
		s.log("refused frame, command %d, %d bytes, not sent", cmd, len(frame))
		return ErrRefused
	}
	return s.Link.Write(ctx, frame)
}

// request sends frame and collects its reply: the messages whose command is
// in expect, up to a NULL TLV when multi. A request from the scale meanwhile
// is answered; an error reply ends the request.
func (s *Session) request(ctx context.Context, frame []byte, expect []uint16, multi bool, wait time.Duration) ([]message, error) {
	s.inbox = nil // a reply to an earlier request is stale
	if err := s.send(ctx, frame); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	var out []message
	for {
		m, err := s.next(ctx)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && len(out) > 0 {
				return out, nil
			}
			return nil, err
		}
		if m.base() == cmdError {
			r := reader{b: m.find(tCmdError)}
			c, code := r.u16(), r.i32()
			if !r.done() {
				return nil, ErrScale
			}
			return nil, ScaleError{c, code}
		}
		if !in(m.base(), expect) {
			s.log("ignored unsolicited command %d", m.base())
			continue
		}
		out = append(out, m)
		if !multi || m.has(tNull) {
			return out, nil
		}
		if len(out) >= maxReplies {
			return nil, ErrScale
		}
	}
}

// next is the next message for the request, answering the scale's own
// requests on the way.
func (s *Session) next(ctx context.Context) (message, error) {
	for len(s.inbox) == 0 {
		frag, err := s.Link.Read(ctx)
		if err != nil {
			return message{}, err
		}
		ms, err := s.reasm.feed(frag)
		if err != nil {
			s.log("stream out of sync, %d bytes", len(frag))
			return message{}, ErrScale
		}
		for _, m := range ms {
			if m.fromDevice() && m.base() != cmdError {
				if err := s.answerDevice(ctx, m); err != nil {
					return message{}, err
				}
				continue
			}
			s.inbox = append(s.inbox, m)
		}
	}
	m := s.inbox[0]
	s.inbox = s.inbox[1:]
	return m, nil
}

// answerDevice answers a request the scale started: SYNC_OK is echoed, as
// the scale expects; anything else is "unsupported", as the phone app does.
// Neither is a write to the scale.
func (s *Session) answerDevice(ctx context.Context, m message) error {
	s.devReqs++
	if s.devReqs > maxDeviceReqs {
		return ErrFlood
	}
	if m.base() == cmdSyncOK {
		return s.send(ctx, syncOKEcho)
	}
	s.log("scale request, command %d, answered unsupported", m.base())
	e := message{cmdError | deviceRequest, []tlv{{tCmdError, []byte{
		byte(m.base() >> 8), byte(m.base()), 0xff, 0xff, 0xff, byte(errUnsupported & 0xff)}}}}
	return s.send(ctx, e.encode())
}

// fatal is an error that ends the session: anything but the scale's own
// refusal or silence.
func fatal(err error) bool {
	var se ScaleError
	return !errors.As(err, &se) && !errors.Is(err, context.DeadlineExceeded)
}

// lead16 is the value's leading big-endian u16 (or its one byte), as the
// source reads battery and connect reason; -1 when empty.
func lead16(v []byte) int {
	switch {
	case len(v) >= 2:
		return int(v[0])<<8 | int(v[1])
	case len(v) == 1:
		return int(v[0])
	}
	return -1
}

func in(c uint16, set []uint16) bool {
	for _, x := range set {
		if x == c {
			return true
		}
	}
	return false
}

// Read runs one read-only session on a connected, subscribed link: prove
// both sides know kl, read the stored records, acknowledge the sync and say
// goodbye. A scale that does not prove kl gets DISCONNECT and nothing else
// (DEV-3). Nothing in a session writes the scale's state (allow.go).
func (s *Session) Read(ctx context.Context) (Result, error) {
	res := Result{Battery: -1, Reason: -1}
	firm, err := s.authenticate(ctx)
	if err != nil {
		s.goodbye(ctx)
		return res, err
	}
	res.Firmware = firm
	// Battery and connect reason are optional, as in the source: a scale
	// that refuses them is still read.
	if r, err := s.request(ctx, batteryFrame, []uint16{cmdBattery}, false, replyWait); err == nil {
		if b := lead16(r[0].find(tBattery)); b >= 0 && b <= 100 {
			res.Battery = b
		}
	} else if fatal(err) {
		s.goodbye(ctx)
		return res, err
	}
	if r, err := s.request(ctx, connectReasonFrame, []uint16{cmdConnectReason}, false, replyWait); err == nil {
		res.Reason = lead16(r[0].find(tConnectReason))
	} else if fatal(err) {
		s.goodbye(ctx)
		return res, err
	}
	r, err := s.request(ctx, statusFrame, []uint16{cmdStoredMeasure}, false, replyWait)
	if err != nil {
		s.goodbye(ctx)
		return res, err
	}
	st := reader{b: r[0].find(tMeasureStatus)}
	count := st.i16()
	if st.err {
		s.goodbye(ctx)
		return res, ErrScale
	}
	if count > 0 {
		recs, err := s.request(ctx, allFrame, []uint16{cmdStoredMeasure}, true, recordsWait)
		if err != nil {
			s.goodbye(ctx)
			return res, err
		}
		res.Readings, res.Dropped = parseRecords(recs)
	}
	// SYNC_OK neither deletes nor hides readings (protocol.md, observed
	// twice); without it the scale may ignore the next connection.
	if _, err := s.request(ctx, syncOKFrame, []uint16{cmdSyncOK}, false, 3*time.Second); err != nil {
		s.log("sync acknowledgement not answered")
	}
	s.goodbye(ctx)
	s.log("read %d readings, %d dropped", len(res.Readings), res.Dropped)
	return res, nil
}

// authenticate runs PROBE and the mutual challenge, returning the
// firmware version the scale reports.
func (s *Session) authenticate(ctx context.Context) (uint32, error) {
	both := []uint16{cmdProbe, cmdChallenge}
	r, err := s.request(ctx, probeFrame, both, false, replyWait)
	if err != nil {
		return 0, err
	}
	if r[0].base() == cmdProbe {
		return 0, ErrSetupMode
	}
	c := reader{b: r[0].find(tChallenge)}
	mac, challenge := c.str(), c.str()
	// The challenge may carry fields after these (protocol.md: "extra").
	if c.err || len(mac) == 0 || len(mac) > maxMAC || len(challenge) != challengeLen {
		return 0, ErrScale
	}
	answer, err := s.Prover.Answer(challenge, string(mac))
	if err != nil || len(answer) != answerLen {
		s.log("prover gave no answer")
		return 0, ErrUnproven
	}
	own := make([]byte, challengeLen)
	rnd := s.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	if _, err := io.ReadFull(rnd, own); err != nil {
		return 0, err
	}
	frame := message{cmdChallenge, []tlv{
		{tChallengeResponse, str(answer)},
		{tChallenge, append(str(mac), str(own)...)},
	}}.encode()
	r, err = s.request(ctx, frame, both, false, replyWait)
	if err != nil {
		return 0, err
	}
	a := reader{b: r[0].find(tChallengeResponse)}
	theirs := a.str()
	if a.err || !s.Prover.Check(own, string(mac), theirs) {
		s.log("scale failed the key check")
		return 0, ErrUnproven
	}
	return firmware(r[0].find(tProbeReply)), nil
}

// firmware is the firmware version in a PROBE_REPLY, or 0: vid, pid, name,
// mac, secret, hardware version, manufacturer ID, bootloader, firmware.
// Only the number is kept; the strings are the scale's and never returned.
func firmware(v []byte) uint32 {
	r := reader{b: v}
	r.u16()
	r.u16()
	r.str()
	r.str()
	r.str()
	r.u32()
	r.str()
	r.u32()
	f := r.u32()
	if r.err {
		return 0
	}
	return f
}

// goodbye sends DISCONNECT without waiting, as the phone app does.
func (s *Session) goodbye(ctx context.Context) {
	if err := s.send(ctx, disconnectFrame); err != nil {
		s.log("disconnect not delivered")
	}
}
