package se

import (
	"encoding/binary"
	"errors"
)

// The OPTIGA Trust M I2C protocol's data-link and transport framing, as
// Infineon's host library (MIT) defines it in src/comms/ifx_i2c: a frame
// is FCTR (1 byte), LEN (2 bytes, big-endian), LEN bytes of packet and a
// 2-byte frame check sequence over everything before it. The packet opens
// with the transport layer's PCTR byte; the rest is one command APDU or
// its response. The driver runs without the shielded connection, without
// chaining and without retransmission: any frame that fails a check ends
// the exchange with ErrLink and the server fails closed (ASSUMPTIONS
// CAM-se-1).

// FCTR fields.
const (
	fctrControl   = 0x80 // frame type: control frame (no packet)
	fctrSeqMask   = 0x60 // sequence control
	fctrSeqAck    = 0x00
	fctrFrameMask = 0x0C // frame number
	fctrFrameOff  = 2
	fctrAckMask   = 0x03 // acknowledged frame number
	frameNumMask  = 0x03
)

// PCTR: the presence bit set, no chaining.
const (
	pctrPresence  = 0x08
	pctrChainMask = 0x07
)

// linkHeader and linkTrailer are a frame's FCTR and LEN, and its check
// sequence.
const (
	linkHeader  = 3
	linkTrailer = 2
	// maxPacket is the largest packet the driver sends or takes: the
	// element's default frame size (0x115 bytes) less the link overhead.
	maxPacket = 0x115 - linkHeader - linkTrailer
)

// ErrLink is any frame that fails a check: its CRC, its length, its
// sequence or acknowledgement number, its type or its packet control.
var ErrLink = errors.New("se: element frame malformed")

// crc16 is the link's frame check sequence: CRC-16/KERMIT (polynomial
// 0x1021 reflected, initial value 0), the value ifx_i2c_dl_calc_crc
// computes; it is sent high byte first. Check value: "123456789" gives
// 0x2189.
func crc16(p []byte) uint16 {
	var c uint16
	for _, b := range p {
		c ^= uint16(b)
		for range 8 {
			if c&1 != 0 {
				c = c>>1 ^ 0x8408
			} else {
				c >>= 1
			}
		}
	}
	return c
}

// dataFrame is a data frame carrying packet as frame number fr, which
// acknowledges the element's frame ack.
func dataFrame(fr, ack uint8, packet []byte) []byte {
	out := []byte{(fr&frameNumMask)<<fctrFrameOff | fctrSeqAck | ack&fctrAckMask}
	out = binary.BigEndian.AppendUint16(out, uint16(len(packet)))
	out = append(out, packet...)
	return binary.BigEndian.AppendUint16(out, crc16(out))
}

// ackFrame is the control frame that acknowledges the element's frame ack.
func ackFrame(ack uint8) []byte {
	out := []byte{fctrControl | fctrSeqAck | ack&fctrAckMask, 0, 0}
	return binary.BigEndian.AppendUint16(out, crc16(out))
}

// frame is one decoded link frame.
type frame struct {
	control bool
	fr, ack uint8
	packet  []byte
}

// parseFrame checks p is exactly one frame: its CRC, its length field
// against its size, ACK sequence control, a control frame with no packet
// and a data frame with one.
func parseFrame(p []byte) (frame, error) {
	if len(p) < linkHeader+linkTrailer {
		return frame{}, ErrLink
	}
	n := int(binary.BigEndian.Uint16(p[1:3]))
	if len(p) != linkHeader+n+linkTrailer || n > maxPacket {
		return frame{}, ErrLink
	}
	body := p[:len(p)-linkTrailer]
	if binary.BigEndian.Uint16(p[len(body):]) != crc16(body) {
		return frame{}, ErrLink
	}
	f := frame{
		control: p[0]&fctrControl != 0,
		fr:      (p[0] & fctrFrameMask) >> fctrFrameOff,
		ack:     p[0] & fctrAckMask,
		packet:  p[linkHeader : linkHeader+n],
	}
	if p[0]&fctrSeqMask != fctrSeqAck || f.control != (n == 0) {
		return frame{}, ErrLink
	}
	return f, nil
}

// packet wraps an APDU in the transport layer's PCTR byte.
func packet(apdu []byte) []byte { return append([]byte{pctrPresence}, apdu...) }

// unpacket checks a received packet's PCTR (presence set, no chaining)
// and returns its APDU.
func unpacket(p []byte) ([]byte, error) {
	if len(p) < 1 || p[0]&^pctrChainMask != pctrPresence || p[0]&pctrChainMask != 0 {
		return nil, ErrLink
	}
	return p[1:], nil
}
