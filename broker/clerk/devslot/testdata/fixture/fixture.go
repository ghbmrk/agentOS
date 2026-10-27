// Package fixture is a test driver for the slot: a made-up Bluetooth
// thermometer, standing in for a private vendor driver. It proves itself to
// the device with its lent key, asks for the stored temperatures and parses
// them with bounds checks. Its fake device for the conformance suite
// is in fake. Nothing here is a real device's protocol.
package fixture

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The fixture's frames: the device's challenge (0x10, 8 bytes), our answer
// (0x02, an 8-byte tag), our request (0x01), and its reply (0x81, a count,
// then 6 bytes per reading: a signed hundredth of a degree and a Unix time).
const (
	OpChallenge = 0x10
	OpAnswer    = 0x02
	OpGet       = 0x01
	OpReadings  = 0x81
	tagLen      = 8
	maxReadings = 32
)

// Driver is the fixture driver.
type Driver struct{}

// Declaration is its declaration.
func Declaration() devslot.Declaration {
	return devslot.Declaration{
		Device: "fixture-thermometer",
		Link:   devslot.GATT,
		Channels: []devslot.Channel{
			{Name: "control", Service: "0000fff0-0000-1000-8000-00805f9b34fb", Char: "0000fff1-0000-1000-8000-00805f9b34fb"},
			{Name: "data", Service: "0000fff0-0000-1000-8000-00805f9b34fb", Char: "0000fff2-0000-1000-8000-00805f9b34fb"},
		},
		Shapes: []devslot.Shape{
			{Name: "answer", Channel: "control", Kind: devslot.GATTWrite, Prefix: []byte{OpAnswer}, Min: 1 + tagLen, Max: 1 + tagLen},
			{Name: "get", Channel: "control", Kind: devslot.GATTWrite, Prefix: []byte{OpGet}, Min: 1, Max: 1},
		},
		Operations:  []devslot.Operation{{Name: "read-temperature", Verb: key.Read, Shapes: []string{"answer", "get"}}},
		Readings:    []string{"temperature"},
		MaxRead:     2 + 6*maxReadings,
		MaxReadings: maxReadings,
	}
}

func (Driver) Declare() devslot.Declaration { return Declaration() }

// ErrDevice is a reply the fixture cannot use.
var ErrDevice = errors.New("fixture: unexpected reply")

// Tag is the answer to challenge under key.
func Tag(key, challenge []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(challenge)
	return m.Sum(nil)[:tagLen]
}

func (Driver) Run(ctx context.Context, op string, l devslot.Link, sec devslot.Secrets) ([]devslot.Reading, error) {
	ch, f, err := l.Read(ctx)
	if err != nil {
		return nil, err
	}
	if ch != "data" || len(f) != 9 || f[0] != OpChallenge {
		return nil, ErrDevice
	}
	answer := []byte{OpAnswer}
	if err := sec.Open(func(k []byte) error { answer = append(answer, Tag(k, f[1:])...); return nil }); err != nil {
		return nil, err
	}
	if err := l.Write(ctx, "control", answer); err != nil {
		return nil, err
	}
	if err := l.Write(ctx, "control", []byte{OpGet}); err != nil {
		return nil, err
	}
	ch, f, err = l.Read(ctx)
	if err != nil {
		return nil, err
	}
	return Parse(ch, f)
}

// Parse reads the device's readings frame, checking every length first.
func Parse(ch string, f []byte) ([]devslot.Reading, error) {
	if ch != "data" || len(f) < 2 || f[0] != OpReadings {
		return nil, ErrDevice
	}
	n := int(f[1])
	if n > maxReadings || len(f) != 2+6*n {
		return nil, ErrDevice
	}
	rs := make([]devslot.Reading, 0, n)
	for i := range n {
		b := f[2+6*i:]
		rs = append(rs, devslot.Reading{
			Kind:  "temperature",
			Value: int64(int16(binary.BigEndian.Uint16(b))),
			Exp:   -2,
			Time:  time.Unix(int64(binary.BigEndian.Uint32(b[2:])), 0).UTC(),
		})
	}
	return rs, nil
}
