package homekit

import (
	"encoding/binary"
	"fmt"
)

// TLV8 types used by pair-setup and pair-verify (HAP R2 table 5-6).
const (
	tlvMethod        = 0x00
	tlvIdentifier    = 0x01
	tlvSalt          = 0x02
	tlvPublicKey     = 0x03
	tlvProof         = 0x04
	tlvEncryptedData = 0x05
	tlvState         = 0x06
	tlvError         = 0x07
	tlvSignature     = 0x0a
	tlvSeparator     = 0xff
)

// Bounds on accessory TLV8 (hostile input): pairing messages are under a
// kilobyte; nothing here needs more than 4 KiB or 16 items.
const (
	maxTLVInput = 4096
	maxTLVItems = 16
)

type tlvItem struct {
	typ byte
	val []byte
}

func tb(typ byte, v byte) tlvItem   { return tlvItem{typ, []byte{v}} }
func tv(typ byte, v []byte) tlvItem { return tlvItem{typ, v} }
func ts(typ byte, v string) tlvItem { return tlvItem{typ, []byte(v)} }
func (t tlvItem) String() string    { return fmt.Sprintf("tlv(%#x,%d bytes)", t.typ, len(t.val)) }
func u16le(b []byte) int            { return int(binary.LittleEndian.Uint16(b)) }
func putU16le(b []byte, v int)      { binary.LittleEndian.PutUint16(b, uint16(v)) }
func catBytes(parts ...[]byte) (out []byte) {
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// encodeTLV writes items in order, splitting a value over 255 bytes into
// consecutive fragments of the same type.
func encodeTLV(items ...tlvItem) []byte {
	var out []byte
	for _, it := range items {
		v := it.val
		for {
			n := min(len(v), 255)
			out = append(out, it.typ, byte(n))
			out = append(out, v[:n]...)
			v = v[n:]
			if len(v) == 0 {
				break
			}
		}
	}
	return out
}

// tlvMap is a decoded TLV8 message: one value per type.
type tlvMap map[byte][]byte

// decodeTLV parses at most maxTLVInput bytes. Consecutive items of one type
// join only when the earlier fragment was full (255 bytes); a type that
// appears twice otherwise is refused, as is a truncated item.
func decodeTLV(b []byte) (tlvMap, error) {
	if len(b) > maxTLVInput {
		return nil, fmt.Errorf("%w: tlv8 of %d bytes", ErrProtocol, len(b))
	}
	m := tlvMap{}
	var last byte
	lastFull := false
	items := 0
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, fmt.Errorf("%w: truncated tlv8 header", ErrProtocol)
		}
		typ, n := b[0], int(b[1])
		if len(b) < 2+n {
			return nil, fmt.Errorf("%w: truncated tlv8 value", ErrProtocol)
		}
		v := b[2 : 2+n]
		b = b[2+n:]
		if items > 0 && typ == last && lastFull {
			m[typ] = append(m[typ], v...)
		} else {
			if _, dup := m[typ]; dup && typ != tlvSeparator {
				return nil, fmt.Errorf("%w: repeated tlv8 type %#x", ErrProtocol, typ)
			}
			items++
			if items > maxTLVItems {
				return nil, fmt.Errorf("%w: too many tlv8 items", ErrProtocol)
			}
			m[typ] = append([]byte{}, v...)
		}
		last, lastFull = typ, n == 255
	}
	return m, nil
}
