package at

import (
	"encoding/hex"
	"strings"
	"time"
)

func init() { simRetry = time.Millisecond }

// DeliverAlpha encodes an SMS-DELIVER from an alphanumeric sender ID
// (type 101), which can spell any text, a phone number included.
func DeliverAlpha(name, text string) string {
	var septets []byte
	for _, r := range name {
		septets = append(septets, gsm7Code[r])
	}
	oa := append([]byte{byte((len(septets)*7 + 3) / 4), 0xD0}, pack7(septets, 0, nil)...)
	p, _ := encodeDeliver(oa, 0x00, text, 1, sctsFixed)
	return p[0]
}

// DeliverNational encodes an SMS-DELIVER from a national-format number.
func DeliverNational(digits, text string) string {
	oa, _ := encodeAddr(digits)
	p, _ := encodeDeliver(oa, 0x00, text, 1, sctsFixed)
	return p[0]
}

// DeliverPID encodes an SMS-DELIVER with the given TP-PID.
func DeliverPID(from string, pid byte, text string) string {
	oa, _ := encodeAddr(from)
	p, _ := encodeDeliver(oa, pid, text, 1, sctsFixed)
	return p[0]
}

// DeliverAlphaPart encodes part 1 of a long SMS-DELIVER from an
// alphanumeric sender ID.
func DeliverAlphaPart(name, text string, ref byte) string {
	var septets []byte
	for _, r := range name {
		septets = append(septets, gsm7Code[r])
	}
	oa := append([]byte{byte((len(septets)*7 + 3) / 4), 0xD0}, pack7(septets, 0, nil)...)
	p, _ := encodeDeliver(oa, 0x00, text, ref, sctsFixed)
	return p[0]
}

// PendingFrom counts the texts from addr being reassembled.
func (m *Modem) PendingFrom(addr string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, a := range m.parts {
		if a.from == addr {
			n++
		}
	}
	return n
}

// DeliverPush encodes an 8-bit SMS-DELIVER from a number carrying udh (the
// IEIs, without the length octet) and body, as a WAP push arrives. A dcs
// of 0 means 0x04 (8-bit data).
func DeliverPush(from string, dcs byte, udh, body []byte) string {
	oa, _ := encodeAddr(from)
	if dcs == 0 {
		dcs = 0x04
	}
	b := []byte{0x07, 0x91, 0x51, 0x55, 0x00, 0x00, 0x00, 0xF0, 0x44}
	b = append(b, oa...)
	b = append(b, 0x00, dcs)
	b = append(b, scts(sctsFixed)...)
	ud := append(append([]byte{byte(len(udh))}, udh...), body...)
	b = append(b, byte(len(ud)))
	b = append(b, ud...)
	return strings.ToUpper(hex.EncodeToString(b))
}
