// Package withings reads a Withings Body Smart scale over Bluetooth, read
// only (DEV-12, DEV-4). It speaks the scale's WPP protocol over one GATT
// characteristic: requests are written to it, replies come back as
// notifications. The protocol facts come from github.com/pierosavi/withings-local
// (MIT), docs/protocol.md and src/withings_wpp, read at eab5a03.
//
// Every frame the reader writes passes the allowlist in allow.go, at the one
// write path (session.send), so a write or delete never reaches the scale,
// whatever a plan or a reply asks. The per-scale secret kl never enters this
// package's session: a Prover answers the scale's challenge (CLK-1).
package withings

import (
	"encoding/binary"
	"errors"
)

// The scale's one GATT service and characteristic (protocol.md, observed).
const (
	ServiceUUID        = "00000020-5749-5448-0010-000000000000"
	CharacteristicUUID = "00000024-5749-5448-0010-000000000000"
)

// Commands. A request the scale starts carries deviceRequest.
const (
	cmdError         = 256
	cmdProbe         = 257
	cmdBattery       = 261
	cmdStoredMeasure = 271
	cmdDisconnect    = 272
	cmdConnectReason = 273
	cmdSyncOK        = 277
	cmdChallenge     = 296

	deviceRequest = 0x4000
)

// TLV types. They share numbers with commands but are a separate table.
const (
	tNull              = 256
	tProbeReply        = 257
	tBattery           = 263
	tCmdError          = 272
	tMeasureAction     = 276
	tMeasureStatus     = 277
	tMeasureMeta       = 278
	tMeasureData       = 279
	tConnectReason     = 280
	tChallenge         = 290
	tChallengeResponse = 291
	tAppProbe          = 298
	tAppProbeOSVersion = 2344
)

const (
	version   = 0x01
	headerLen = 5
	tlvHeader = 4
	// errUnsupported is the only error the reader ever sends: its answer to
	// a request from the scale it does not handle.
	errUnsupported = -3
)

var errFrame = errors.New("withings: malformed frame")

type tlv struct {
	typ uint16
	val []byte
}

type message struct {
	cmd  uint16
	tlvs []tlv
}

func (m message) base() uint16     { return m.cmd &^ deviceRequest }
func (m message) fromDevice() bool { return m.cmd&deviceRequest != 0 }
func (m message) find(t uint16) []byte {
	for _, x := range m.tlvs {
		if x.typ == t {
			return x.val
		}
	}
	return nil
}
func (m message) has(t uint16) bool {
	for _, x := range m.tlvs {
		if x.typ == t {
			return true
		}
	}
	return false
}

// encode is m's frame. A payload past a u16 cannot be framed; the reader's
// own messages are all a few dozen bytes.
func (m message) encode() []byte {
	n := 0
	for _, t := range m.tlvs {
		n += tlvHeader + len(t.val)
	}
	b := make([]byte, headerLen, headerLen+n)
	b[0] = version
	binary.BigEndian.PutUint16(b[1:], m.cmd)
	binary.BigEndian.PutUint16(b[3:], uint16(n))
	for _, t := range m.tlvs {
		b = binary.BigEndian.AppendUint16(b, t.typ)
		b = binary.BigEndian.AppendUint16(b, uint16(len(t.val)))
		b = append(b, t.val...)
	}
	return b
}

// decode reads exactly one frame.
func decode(b []byte) (message, error) {
	if len(b) < headerLen || b[0] != version {
		return message{}, errFrame
	}
	n := int(binary.BigEndian.Uint16(b[3:]))
	if len(b) != headerLen+n {
		return message{}, errFrame
	}
	m := message{cmd: binary.BigEndian.Uint16(b[1:])}
	p := b[headerLen:]
	for len(p) > 0 {
		if len(p) < tlvHeader {
			return message{}, errFrame
		}
		l := int(binary.BigEndian.Uint16(p[2:]))
		if len(p) < tlvHeader+l {
			return message{}, errFrame
		}
		m.tlvs = append(m.tlvs, tlv{binary.BigEndian.Uint16(p), p[tlvHeader : tlvHeader+l]})
		p = p[tlvHeader+l:]
	}
	return m, nil
}

// reassembler joins notification fragments into frames by the header's
// length. Its buffer never holds more than one frame's worth plus one
// fragment, since a frame is cut off as soon as it is whole, and a frame is
// at most headerLen+65535 bytes.
type reassembler struct{ buf []byte }

// feed adds one fragment and returns the whole frames it completes. A stream
// whose next byte is not a frame start is out of sync and fails; the session
// ends rather than guessing where the next frame starts.
func (r *reassembler) feed(frag []byte) ([]message, error) {
	r.buf = append(r.buf, frag...)
	var out []message
	for len(r.buf) >= headerLen {
		if r.buf[0] != version {
			r.buf = nil
			return out, errFrame
		}
		total := headerLen + int(binary.BigEndian.Uint16(r.buf[3:]))
		if len(r.buf) < total {
			break
		}
		m, err := decode(r.buf[:total])
		// The frame's TLVs alias r.buf; copy so the next fragment cannot
		// change them.
		r.buf = append([]byte(nil), r.buf[total:]...)
		if err != nil {
			r.buf = nil
			return out, err
		}
		out = append(out, m)
	}
	return out, nil
}

// reader takes fields from a TLV value in order.
type reader struct {
	b   []byte
	err bool
}

func (r *reader) take(n int) []byte {
	if r.err || len(r.b) < n {
		r.err = true
		return make([]byte, n)
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
func (r *reader) u8() uint8   { return r.take(1)[0] }
func (r *reader) u16() uint16 { return binary.BigEndian.Uint16(r.take(2)) }
func (r *reader) u32() uint32 { return binary.BigEndian.Uint32(r.take(4)) }
func (r *reader) i16() int16  { return int16(r.u16()) }
func (r *reader) i32() int32  { return int32(r.u32()) }

// str is a 1-byte length-prefixed string or byte array.
func (r *reader) str() []byte { return r.take(int(r.u8())) }

// done is whether every field was there and nothing is left over.
func (r *reader) done() bool { return !r.err && len(r.b) == 0 }

// str packs a 1-byte length-prefixed value; callers keep it under 256 bytes.
func str(b []byte) []byte { return append([]byte{byte(len(b))}, b...) }
