package se

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"
)

// Bus is the board's I2C bus with the element's address set: one write
// transaction and one read transaction (i2c_linux.go; a recorded
// transcript in the tests).
type Bus interface {
	Write(p []byte) error
	Read(p []byte) error
}

// The element's I2C registers (src/comms/ifx_i2c/ifx_i2c_physical_layer.c).
const (
	regData      = 0x80
	regState     = 0x82
	regSoftReset = 0x88
	stateLen     = 4
	stateBusy    = 0x80
	stateReady   = 0x40
)

// Commands (src/cmd/optiga_cmd.c). The high bit clears the element's last
// error code.
const (
	cmdGetData    = 0x81
	cmdSetData    = 0x82
	cmdCalcSign   = 0xB1
	cmdGenKeyPair = 0xB8
	cmdOpenApp    = 0xF0

	paramRead   = 0x00
	paramWrite  = 0x00
	paramCount  = 0x02
	paramECDSA  = 0x11 // ECDSA FIPS 186-3 over a supplied digest
	paramP256   = 0x03 // NIST P-256
	usageSign   = 0x10
	tagDigest   = 0x01
	tagOID      = 0x03
	tagKeyOID   = 0x01
	tagUsage    = 0x02
	tagPubKey   = 0x02
	staSuccess  = 0x00
	apduHeader  = 4
	countMaxOne = 0xFF // the most one count command adds
)

// Object IDs this driver uses. The device key's slot is never read: no
// command here names it except CalcSign and GenKeyPair.
const (
	oidDeviceKey = 0xE0F1 // the device key's private key slot
	oidSettings  = 0xE120 // monotonic counter 1
	oidImage     = 0xE121 // monotonic counter 2
	oidOwnerPin  = 0xF1D0 // arbitrary data object: the owner pin
	oidPublic    = 0xF1D1 // arbitrary data object: the device key's public point
)

// appID is the Trust M application identifier OpenApplication selects.
var appID = []byte{0xD2, 0x76, 0x00, 0x00, 0x04, 0x47, 0x65, 0x6E, 0x41, 0x75, 0x74, 0x68, 0x41, 0x70, 0x70, 0x6C}

// ErrRefused is a response whose status is not success: the element
// refused the command.
var ErrRefused = errors.New("se: element refused the command")

// ErrTimeout is an element that never signalled a response.
var ErrTimeout = errors.New("se: element did not respond")

// maxCounter is the most an element counter holds: 32 bits.
const maxCounter = 1<<32 - 1

var _ Element = (*Optiga)(nil)

// Optiga is an OPTIGA Trust M class element on bus. It is not safe for
// concurrent use; the server serialises its calls.
type Optiga struct {
	bus Bus
	// tx is the last frame number sent, rx the last received. Both start
	// at 3, so each side's first frame is 0, as the host library does.
	tx, rx uint8
	// Sleep waits between polls of the state register; Polls bounds them.
	Sleep func(time.Duration)
	Polls int
}

// Open resets the element's link and opens its application.
func Open(bus Bus) (*Optiga, error) {
	o := &Optiga{bus: bus, tx: frameNumMask, rx: frameNumMask, Sleep: time.Sleep, Polls: 400}
	if err := bus.Write([]byte{regSoftReset, 0, 0}); err != nil {
		return nil, err
	}
	if _, err := o.command(cmdOpenApp, 0, appID); err != nil {
		return nil, err
	}
	return o, nil
}

// command sends one APDU and returns its response's data.
func (o *Optiga) command(cmd, param byte, payload []byte) ([]byte, error) {
	apdu := []byte{cmd, param}
	apdu = binary.BigEndian.AppendUint16(apdu, uint16(len(payload)))
	apdu = append(apdu, payload...)
	resp, err := o.exchange(packet(apdu))
	if err != nil {
		return nil, err
	}
	a, err := unpacket(resp)
	if err != nil {
		return nil, err
	}
	if len(a) < apduHeader || int(binary.BigEndian.Uint16(a[2:4])) != len(a)-apduHeader {
		return nil, ErrLink
	}
	if a[0] != staSuccess {
		return nil, ErrRefused
	}
	return a[apduHeader:], nil
}

// exchange sends p in one data frame and returns the element's one data
// frame in reply, which it acknowledges. One control frame acknowledging
// p may come first.
func (o *Optiga) exchange(p []byte) ([]byte, error) {
	if len(p) > maxPacket {
		return nil, ErrLink
	}
	o.tx = (o.tx + 1) & frameNumMask
	if err := o.bus.Write(append([]byte{regData}, dataFrame(o.tx, o.rx, p)...)); err != nil {
		return nil, err
	}
	for range 2 {
		raw, err := o.read()
		if err != nil {
			return nil, err
		}
		f, err := parseFrame(raw)
		if err != nil || f.ack != o.tx {
			return nil, ErrLink
		}
		if f.control {
			continue
		}
		if f.fr != (o.rx+1)&frameNumMask {
			return nil, ErrLink
		}
		o.rx = f.fr
		if err := o.bus.Write(append([]byte{regData}, ackFrame(o.rx)...)); err != nil {
			return nil, err
		}
		return f.packet, nil
	}
	return nil, ErrLink
}

// read polls the state register until a response is ready and reads it.
func (o *Optiga) read() ([]byte, error) {
	st := make([]byte, stateLen)
	for range o.Polls {
		if err := o.bus.Write([]byte{regState}); err != nil {
			return nil, err
		}
		if err := o.bus.Read(st); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(st[2:4]))
		if st[0]&stateBusy != 0 || st[0]&stateReady == 0 || n == 0 {
			o.Sleep(5 * time.Millisecond)
			continue
		}
		if n > linkHeader+maxPacket+linkTrailer {
			return nil, ErrLink
		}
		if err := o.bus.Write([]byte{regData}); err != nil {
			return nil, err
		}
		buf := make([]byte, n)
		if err := o.bus.Read(buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
	return nil, ErrTimeout
}

// getData reads n bytes of object oid from offset 0.
func (o *Optiga) getData(oid uint16, n int) ([]byte, error) {
	p := binary.BigEndian.AppendUint16(nil, oid)
	p = binary.BigEndian.AppendUint16(p, 0)
	p = binary.BigEndian.AppendUint16(p, uint16(n))
	d, err := o.command(cmdGetData, paramRead, p)
	if err != nil {
		return nil, err
	}
	if len(d) > n {
		return nil, ErrLink
	}
	return d, nil
}

// setData writes or counts object oid at offset 0.
func (o *Optiga) setData(param byte, oid uint16, data []byte) error {
	p := binary.BigEndian.AppendUint16(nil, oid)
	p = binary.BigEndian.AppendUint16(p, 0)
	_, err := o.command(cmdSetData, param, append(p, data...))
	return err
}

// Public reads the device key's public point, which provisioning stored
// beside the key (Generate).
func (o *Optiga) Public() ([PointLen]byte, error) {
	var out [PointLen]byte
	d, err := o.getData(oidPublic, PointLen)
	if err != nil {
		return out, err
	}
	if len(d) != PointLen || d[0] != 4 {
		return out, ErrLink
	}
	copy(out[:], d)
	return out, nil
}

// Sign signs digest with the device key. The element returns r and s as
// two DER INTEGERs; Sign checks each is minimal and wraps them in the
// SEQUENCE ASN.1 DER calls for.
func (o *Optiga) Sign(digest [32]byte) ([]byte, error) {
	p := append([]byte{tagDigest, 0, 32}, digest[:]...)
	p = append(p, tagOID, 0, 2)
	p = binary.BigEndian.AppendUint16(p, oidDeviceKey)
	d, err := o.command(cmdCalcSign, paramECDSA, p)
	if err != nil {
		return nil, err
	}
	n, ok := derInteger(d)
	if !ok {
		return nil, ErrLink
	}
	m, ok := derInteger(d[n:])
	if !ok || n+m != len(d) {
		return nil, ErrLink
	}
	return append([]byte{0x30, byte(len(d))}, d...), nil
}

// derInteger reports the length of the minimal, positive DER INTEGER of
// at most 33 bytes that opens p.
func derInteger(p []byte) (int, bool) {
	if len(p) < 3 || p[0] != 0x02 {
		return 0, false
	}
	n := int(p[1])
	if n < 1 || n > 33 || len(p) < 2+n {
		return 0, false
	}
	v := p[2 : 2+n]
	if v[0]&0x80 != 0 || (n > 1 && v[0] == 0 && v[1]&0x80 == 0) {
		return 0, false
	}
	return 2 + n, true
}

// counterOID is k's object.
func counterOID(k Kind) (uint16, error) {
	switch k {
	case Settings:
		return oidSettings, nil
	case Image:
		return oidImage, nil
	}
	return 0, ErrCounter
}

// Counter reads counter k: a counter object is its value and its
// threshold, 4 bytes each.
func (o *Optiga) Counter(k Kind) (uint64, error) {
	oid, err := counterOID(k)
	if err != nil {
		return 0, err
	}
	d, err := o.getData(oid, 8)
	if err != nil {
		return 0, err
	}
	if len(d) != 8 {
		return 0, ErrLink
	}
	return uint64(binary.BigEndian.Uint32(d)), nil
}

// Raise counts k up to to, at most countMaxOne per command, and reads it
// back. A counter can only count, so a failure part way leaves it between
// its old value and to, never below.
func (o *Optiga) Raise(k Kind, to uint64) error {
	oid, err := counterOID(k)
	if err != nil {
		return err
	}
	cur, err := o.Counter(k)
	if err != nil {
		return err
	}
	if to <= cur || to > maxCounter {
		return ErrCounter
	}
	for cur < to {
		step := min(to-cur, countMaxOne)
		if err := o.setData(paramCount, oid, []byte{byte(step)}); err != nil {
			return err
		}
		cur += step
	}
	got, err := o.Counter(k)
	if err != nil {
		return err
	}
	if got != to {
		return ErrCounter
	}
	return nil
}

// OwnerPin reads the owner pin. An object never written, or written with
// zeros by ClearOwnerPin, holds no pin.
func (o *Optiga) OwnerPin() ([32]byte, bool, error) {
	var pin [32]byte
	d, err := o.getData(oidOwnerPin, 32)
	if err != nil {
		return pin, false, err
	}
	switch len(d) {
	case 0:
		return pin, false, nil
	case 32:
		copy(pin[:], d)
		return pin, pin != [32]byte{}, nil
	}
	return pin, false, ErrLink
}

// SetOwnerPin writes the owner pin. The zero pin would read back as none,
// so it is refused.
func (o *Optiga) SetOwnerPin(pin [32]byte) error {
	if pin == [32]byte{} {
		return ErrLink
	}
	return o.setData(paramWrite, oidOwnerPin, pin[:])
}

// ClearOwnerPin overwrites the owner pin with zeros.
func (o *Optiga) ClearOwnerPin() error {
	return o.setData(paramWrite, oidOwnerPin, make([]byte, 32))
}

// Generate makes the device key inside the element and stores its public
// point beside it. It runs once, at provisioning, before the key slot is
// locked (part d); the server never calls it.
func (o *Optiga) Generate() ([PointLen]byte, error) {
	var out [PointLen]byte
	p := []byte{tagKeyOID, 0, 2}
	p = binary.BigEndian.AppendUint16(p, oidDeviceKey)
	p = append(p, tagUsage, 0, 1, usageSign)
	d, err := o.command(cmdGenKeyPair, paramP256, p)
	if err != nil {
		return out, err
	}
	// Tag 0x02, a 2-byte length of 0x45, then the public key as a DER
	// BIT STRING: 03 42 00 04 X Y.
	prefix := []byte{tagPubKey, 0, 0x45, 0x03, 0x42, 0x00}
	if len(d) != len(prefix)+PointLen || !bytes.Equal(d[:len(prefix)], prefix) || d[len(prefix)] != 4 {
		return out, ErrLink
	}
	copy(out[:], d[len(prefix):])
	return out, o.setData(paramWrite, oidPublic, out[:])
}
