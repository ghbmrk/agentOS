package at

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// SMS PDU codec (3GPP TS 23.040, alphabet from TS 23.038). The driver runs
// both modems in PDU mode (AT+CMGF=0): text mode leaves the character set to
// each vendor's firmware, while a PDU is the same bytes on every modem.

// gsm7 is the GSM 03.38 default alphabet in code order; 0x1B is the escape to
// the extension table.
var gsm7 = []rune("@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?" +
	"¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà")

// gsm7Ext maps an extension-table code to its character.
var gsm7Ext = map[byte]rune{0x0A: '\f', 0x14: '^', 0x28: '{', 0x29: '}', 0x2F: '\\', 0x3C: '[', 0x3D: '~', 0x3E: ']', 0x40: '|', 0x65: '€'}

var gsm7Code, gsm7ExtCode = func() (map[rune]byte, map[rune]byte) {
	b, e := map[rune]byte{}, map[rune]byte{}
	for i, r := range gsm7 {
		if r != 0x1b {
			b[r] = byte(i)
		}
	}
	for c, r := range gsm7Ext {
		e[r] = c
	}
	return b, e
}()

// Segment sizes: a single GSM-7 text holds 160 septets and each part of a
// concatenated one 153; UCS-2 holds 70 and 67 UTF-16 units. They match
// modem.Segments, which the owner channel budgets with (CH-12).
const (
	single7, multi7   = 160, 153
	singleU2, multiU2 = 70, 67
	// MaxParts bounds one outbound text. The owner channel sends at most
	// three segments (CH-12); the bound only stops a runaway caller.
	MaxParts = 10
)

// Submit is one encoded SMS-SUBMIT part: Hex for the modem and Len, the
// octet count AT+CMGS takes (the PDU without its SMSC field).
type Submit struct {
	Hex string
	Len int
}

// Deliver is a decoded SMS-DELIVER (or a decoded SMS-SUBMIT, for the
// simulator).
type Deliver struct {
	Addr string // sender of a DELIVER, recipient of a SUBMIT
	// TON is the address's type of number (TS 23.040 9.1.2.5): 1 is
	// international, 5 alphanumeric. An alphanumeric address is a sender
	// ID that can spell any text, a phone number included.
	TON byte
	// PID is TP-PID. 0x40 (silent Type-0) and 0x41-0x47 (replace-message)
	// are not texts for anyone to read.
	PID  byte
	Text string
	// Concat is set on one part of a concatenated text.
	Concat *Concat
}

// Concat identifies one part of a concatenated text.
type Concat struct {
	Ref        int
	Total, Seq int
}

// ErrPDU reports a PDU the codec cannot read. The driver deletes such a
// message from the modem's store and drops it.
var ErrPDU = errors.New("at: unreadable PDU")

// EncodeSubmit encodes text to number as one or more SMS-SUBMIT PDUs. ref is
// the concatenation reference used when the text needs more than one part.
func EncodeSubmit(number, text string, ref byte) ([]Submit, error) {
	da, err := encodeAddr(number)
	if err != nil {
		return nil, err
	}
	parts, ucs2, err := split(text)
	if err != nil {
		return nil, err
	}
	out := make([]Submit, 0, len(parts))
	for i, p := range parts {
		var udh []byte
		if len(parts) > 1 {
			udh = []byte{0x00, 0x03, ref, byte(len(parts)), byte(i + 1)}
		}
		fo := byte(0x01) // SMS-SUBMIT, no validity period, no status report
		if udh != nil {
			fo |= 0x40
		}
		b := []byte{0x00, fo, 0x00} // SMSC from the SIM, TP-MR set by the modem
		b = append(b, da...)
		dcs := byte(0x00)
		if ucs2 {
			dcs = 0x08
		}
		b = append(b, 0x00, dcs)
		b = append(b, userData(p, udh, ucs2)...)
		out = append(out, Submit{Hex: strings.ToUpper(hex.EncodeToString(b)), Len: len(b) - 1})
	}
	return out, nil
}

// EncodeDeliver encodes an SMS-DELIVER from number, split as a network would.
// Only the simulator uses it.
func EncodeDeliver(from, text string, ref byte) ([]string, error) {
	oa, err := encodeAddr(from)
	if err != nil {
		return nil, err
	}
	return encodeDeliver(oa, 0x00, text, ref)
}

func encodeDeliver(oa []byte, pid byte, text string, ref byte) ([]string, error) {
	parts, ucs2, err := split(text)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(parts))
	for i, p := range parts {
		var udh []byte
		if len(parts) > 1 {
			udh = []byte{0x00, 0x03, ref, byte(len(parts)), byte(i + 1)}
		}
		fo := byte(0x04) // SMS-DELIVER, no more messages waiting
		if udh != nil {
			fo |= 0x40
		}
		// SMSC +15550000000, timestamp 2026-10-04 12:00:00 UTC.
		b := []byte{0x07, 0x91, 0x51, 0x55, 0x00, 0x00, 0x00, 0xF0, fo}
		b = append(b, oa...)
		dcs := byte(0x00)
		if ucs2 {
			dcs = 0x08
		}
		b = append(b, pid, dcs, 0x62, 0x01, 0x40, 0x21, 0x00, 0x00, 0x00)
		b = append(b, userData(p, udh, ucs2)...)
		out = append(out, strings.ToUpper(hex.EncodeToString(b)))
	}
	return out, nil
}

// split cuts text into parts that fit one segment each and reports whether
// the text needs UCS-2. GSM-7 parts never split an escape pair and UCS-2
// parts never split a surrogate pair.
func split(text string) (parts [][]rune, ucs2 bool, err error) {
	rs := []rune(text)
	for _, r := range rs {
		if _, ok := gsm7Code[r]; ok {
			continue
		}
		if _, ok := gsm7ExtCode[r]; ok {
			continue
		}
		ucs2 = true
		break
	}
	cost := func(r rune) int {
		if ucs2 {
			if r > 0xFFFF {
				return 2
			}
			return 1
		}
		if _, ok := gsm7ExtCode[r]; ok {
			return 2
		}
		return 1
	}
	total := 0
	for _, r := range rs {
		total += cost(r)
	}
	one, many := single7, multi7
	if ucs2 {
		one, many = singleU2, multiU2
	}
	if total <= one {
		return [][]rune{rs}, ucs2, nil
	}
	var cur []rune
	n := 0
	for _, r := range rs {
		if n+cost(r) > many {
			parts = append(parts, cur)
			cur, n = nil, 0
		}
		cur = append(cur, r)
		n += cost(r)
	}
	parts = append(parts, cur)
	if len(parts) > MaxParts {
		return nil, false, fmt.Errorf("at: text needs %d parts, limit %d", len(parts), MaxParts)
	}
	return parts, ucs2, nil
}

// userData returns TP-UDL followed by TP-UD.
func userData(p []rune, udh []byte, ucs2 bool) []byte {
	var hdr []byte
	if udh != nil {
		hdr = append([]byte{byte(len(udh))}, udh...)
	}
	if ucs2 {
		body := hdr
		for _, u := range utf16.Encode(p) {
			body = append(body, byte(u>>8), byte(u))
		}
		return append([]byte{byte(len(body))}, body...)
	}
	var septets []byte
	for _, r := range p {
		if c, ok := gsm7Code[r]; ok {
			septets = append(septets, c)
		} else {
			septets = append(septets, 0x1B, gsm7ExtCode[r])
		}
	}
	hdrSeptets := (len(hdr)*8 + 6) / 7
	packed := pack7(septets, len(hdr)*8, hdr)
	return append([]byte{byte(hdrSeptets + len(septets))}, packed...)
}

// pack7 packs septets after a header of bitOff bits, the header padded to
// a septet boundary.
func pack7(septets []byte, bitOff int, hdr []byte) []byte {
	start := ((bitOff + 6) / 7) * 7
	nbits := start + 7*len(septets)
	out := make([]byte, (nbits+7)/8)
	copy(out, hdr)
	for i, s := range septets {
		pos := start + 7*i
		for b := 0; b < 7; b++ {
			if s&(1<<b) != 0 {
				out[(pos+b)/8] |= 1 << ((pos + b) % 8)
			}
		}
	}
	return out
}

// unpack7 reads n septets from data starting at bit off.
func unpack7(data []byte, off, n int) ([]byte, error) {
	if (off+7*n+7)/8 > len(data) {
		return nil, ErrPDU
	}
	out := make([]byte, n)
	for i := range out {
		pos := off + 7*i
		var s byte
		for b := 0; b < 7; b++ {
			if data[(pos+b)/8]&(1<<((pos+b)%8)) != 0 {
				s |= 1 << b
			}
		}
		out[i] = s
	}
	return out, nil
}

func decode7(septets []byte) string {
	var sb strings.Builder
	for i := 0; i < len(septets); i++ {
		c := septets[i]
		if c == 0x1B && i+1 < len(septets) {
			i++
			if r, ok := gsm7Ext[septets[i]]; ok {
				sb.WriteRune(r)
			} else {
				sb.WriteRune(gsm7[septets[i]&0x7F]) // unknown escape: base character (TS 23.038)
			}
			continue
		}
		if c == 0x1B {
			sb.WriteRune(' ')
			continue
		}
		sb.WriteRune(gsm7[c&0x7F])
	}
	return sb.String()
}

// encodeAddr encodes a TP-DA/TP-OA: digit count, type, swapped BCD. A
// leading + makes the number international (0x91), anything else is
// unknown-type (0x81).
func encodeAddr(number string) ([]byte, error) {
	toa := byte(0x81)
	d := number
	if strings.HasPrefix(d, "+") {
		toa, d = 0x91, d[1:]
	}
	if d == "" || len(d) > 20 {
		return nil, fmt.Errorf("at: bad number %q", number)
	}
	for _, c := range d {
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("at: bad number %q", number)
		}
	}
	out := []byte{byte(len(d)), toa}
	for i := 0; i < len(d); i += 2 {
		lo := d[i] - '0'
		hi := byte(0xF)
		if i+1 < len(d) {
			hi = d[i+1] - '0'
		}
		out = append(out, hi<<4|lo)
	}
	return out, nil
}

// reader walks a PDU's octets.
type reader struct {
	b   []byte
	pos int
	err error
}

func (r *reader) byte() byte {
	if r.err != nil || r.pos >= len(r.b) {
		r.err = ErrPDU
		return 0
	}
	r.pos++
	return r.b[r.pos-1]
}

func (r *reader) bytes(n int) []byte {
	if r.err != nil || n < 0 || r.pos+n > len(r.b) {
		r.err = ErrPDU
		return nil
	}
	r.pos += n
	return r.b[r.pos-n : r.pos]
}

// addr reads a TP-OA/TP-DA and its type of number. Alphanumeric senders
// (type 101) are returned as text; the caller must never treat one as a
// phone number, since the text can spell one.
func (r *reader) addr() (string, byte) {
	n := int(r.byte())
	toa := r.byte()
	return r.addrBody(n, toa), (toa >> 4) & 7
}

func (r *reader) addrBody(n int, toa byte) string {
	if n > 20 {
		r.err = ErrPDU
		return ""
	}
	raw := r.bytes((n + 1) / 2)
	if r.err != nil {
		return ""
	}
	if (toa>>4)&7 == 5 {
		s, err := unpack7(raw, 0, n*4/7)
		if err != nil {
			r.err = err
			return ""
		}
		return decode7(s)
	}
	var sb strings.Builder
	if (toa>>4)&7 == 1 {
		sb.WriteByte('+')
	}
	for i := 0; i < n; i++ {
		v := raw[i/2] >> (4 * (i % 2)) & 0xF
		switch {
		case v <= 9:
			sb.WriteByte('0' + v)
		case v == 0xA:
			sb.WriteByte('*')
		case v == 0xB:
			sb.WriteByte('#')
		default:
			r.err = ErrPDU
			return ""
		}
	}
	return sb.String()
}

// DecodeDeliver decodes an SMS-DELIVER PDU as the modem hands it over
// (with its leading SMSC field).
func DecodeDeliver(h string) (Deliver, error) {
	return decode(h, false)
}

// DecodeSubmit decodes an SMS-SUBMIT PDU with its SMSC field. Only the
// simulator uses it.
func DecodeSubmit(h string) (Deliver, error) {
	return decode(h, true)
}

func decode(h string, submit bool) (Deliver, error) {
	b, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil {
		return Deliver{}, ErrPDU
	}
	r := &reader{b: b}
	r.bytes(int(r.byte())) // SMSC
	fo := r.byte()
	if submit {
		if fo&0x03 != 0x01 {
			return Deliver{}, ErrPDU
		}
		r.byte() // TP-MR
	} else if fo&0x03 != 0x00 {
		return Deliver{}, ErrPDU
	}
	var d Deliver
	d.Addr, d.TON = r.addr()
	d.PID = r.byte()
	dcs := r.byte()
	if submit {
		switch fo >> 3 & 0x3 { // TP-VPF
		case 2:
			r.byte()
		case 1, 3:
			r.bytes(7)
		}
	} else {
		r.bytes(7) // TP-SCTS: the driver stamps receipt time instead
	}
	udl := int(r.byte())
	ud := r.b[min(r.pos, len(r.b)):]
	if r.err != nil {
		return Deliver{}, r.err
	}
	alpha, ok := alphabet(dcs)
	if !ok {
		return Deliver{}, ErrPDU
	}
	hdrLen := 0
	if fo&0x40 != 0 {
		if len(ud) < 1 || int(ud[0])+1 > len(ud) {
			return Deliver{}, ErrPDU
		}
		hdrLen = int(ud[0]) + 1
		d.Concat = concat(ud[1:hdrLen])
	}
	switch alpha {
	case 0:
		hdrSeptets := (hdrLen*8 + 6) / 7
		if udl < hdrSeptets || udl > 160 {
			return Deliver{}, ErrPDU
		}
		s, err := unpack7(ud, hdrSeptets*7, udl-hdrSeptets)
		if err != nil {
			return Deliver{}, err
		}
		d.Text = decode7(s)
	case 2:
		if udl > len(ud) || udl < hdrLen || (udl-hdrLen)%2 != 0 {
			return Deliver{}, ErrPDU
		}
		body := ud[hdrLen:udl]
		u := make([]uint16, len(body)/2)
		for i := range u {
			u[i] = uint16(body[2*i])<<8 | uint16(body[2*i+1])
		}
		d.Text = string(utf16.Decode(u))
	}
	return d, nil
}

// alphabet reads TP-DCS: 0 for GSM-7, 2 for UCS-2. 8-bit data and
// compressed text are not texts the broker reads.
func alphabet(dcs byte) (int, bool) {
	switch {
	case dcs&0xC0 == 0x00: // general data coding
		if dcs&0x20 != 0 {
			return 0, false
		}
		a := int(dcs >> 2 & 0x3)
		return a, a == 0 || a == 2
	case dcs&0xF0 == 0xC0, dcs&0xF0 == 0xD0: // message waiting, GSM-7
		return 0, true
	case dcs&0xF0 == 0xE0: // message waiting, UCS-2
		return 2, true
	case dcs&0xF0 == 0xF0:
		return 0, dcs&0x04 == 0
	}
	return 0, false
}

// concat finds a concatenation element (8- or 16-bit reference) in a UDH.
func concat(h []byte) *Concat {
	for i := 0; i+1 < len(h); {
		iei, l := h[i], int(h[i+1])
		v := h[i+2 : min(i+2+l, len(h))]
		switch {
		case iei == 0x00 && len(v) == 3:
			return validConcat(int(v[0]), int(v[1]), int(v[2]))
		case iei == 0x08 && len(v) == 4:
			return validConcat(int(v[0])<<8|int(v[1]), int(v[2]), int(v[3]))
		}
		i += 2 + l
	}
	return nil
}

func validConcat(ref, total, seq int) *Concat {
	if total < 1 || seq < 1 || seq > total {
		return nil
	}
	return &Concat{Ref: ref, Total: total, Seq: seq}
}

// Silent reports a PDU that is not a text for anyone to read: a silent
// Type-0 message or a replace-message type.
func (d Deliver) Silent() bool { return d.PID >= 0x40 && d.PID <= 0x47 }

// TPDULen returns the length AT+CMGR and AT+CMGL report for a PDU: its
// octets without the SMSC field. A line whose length disagrees is not the
// PDU the header announced.
func TPDULen(h string) (int, bool) {
	b, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil || len(b) == 0 || int(b[0])+1 > len(b) {
		return 0, false
	}
	return len(b) - int(b[0]) - 1, true
}
