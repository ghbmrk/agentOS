// Package fake is the fixture driver's fake device, for the conformance
// suite.
package fake

import (
	"crypto/hmac"
	"encoding/binary"

	"github.com/ghbmrk/agentos/broker/clerk/devslot/conformance"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"
)

// Device is the fixture's fake thermometer: it challenges, checks the
// answer, and sends Temps (hundredths of a degree) at Unix time 1.7e9 on.
type Device struct {
	Key       []byte
	Temps     []int16
	challenge []byte
	proven    bool
}

func (d *Device) Connect(string) []conformance.Frame {
	d.challenge = []byte("chal-001")
	return []conformance.Frame{{Channel: "data", Bytes: append([]byte{fixture.OpChallenge}, d.challenge...)}}
}

func (d *Device) Respond(ch string, f []byte) []conformance.Frame {
	switch {
	case ch == "control" && len(f) > 0 && f[0] == fixture.OpAnswer:
		d.proven = hmac.Equal(f[1:], fixture.Tag(d.Key, d.challenge))
		return nil
	case ch == "control" && len(f) == 1 && f[0] == fixture.OpGet && d.proven:
		out := []byte{fixture.OpReadings, byte(len(d.Temps))}
		for i, t := range d.Temps {
			out = binary.BigEndian.AppendUint16(out, uint16(t))
			out = binary.BigEndian.AppendUint32(out, uint32(1_700_000_000+60*i))
		}
		return []conformance.Frame{{Channel: "data", Bytes: out}}
	}
	return nil
}
