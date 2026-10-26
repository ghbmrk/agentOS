package withings

// REQ: DEV-3, DEV-4, DEV-8, DEV-12, CLK-1

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"sync"
)

// klCanary is the synthetic per-scale secret; no scale has it.
const klCanary = "CANARY-kl-0f3a9e-not-a-real-key"

// fakeScale is a synthetic Body Smart behind a Link: it answers the reader's
// frames as protocol.md describes, fragments its replies to a small MTU, and
// records every frame written to it.
type fakeScale struct {
	kl       []byte
	mac      string
	setup    bool // answers PROBE without a challenge
	badProof bool // answers our challenge wrongly
	// records are the STORED_MEASURE action-1 reply's messages' TLVs.
	records [][]tlv
	// after are frames the scale sends once authenticated, before its
	// reply to the next request (its own requests, or garbage).
	after [][]byte
	mtu   int

	mu      sync.Mutex
	written [][]byte
	out     [][]byte
	wake    chan struct{}
}

func newScale() *fakeScale {
	return &fakeScale{kl: []byte(klCanary), mac: "aa:bb:cc:dd:ee:ff", mtu: 20, wake: make(chan struct{}, 1)}
}

var scaleChallenge = bytes.Repeat([]byte{0x5c}, 16)

func sha(parts ...[]byte) []byte {
	h := sha1.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func u16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

// probeReply is a PROBE_REPLY as the source observed: vid, pid, name, mac,
// secret, hardware, manufacturer ID, bootloader, firmware 1311, rescue.
func (f *fakeScale) probeReply() []byte {
	var b []byte
	b = append(b, u16(1)...)
	b = append(b, u16(2)...)
	b = append(b, str([]byte("Body Smart"))...)
	b = append(b, str([]byte(f.mac))...)
	b = append(b, str(nil)...)
	b = append(b, u32(0xffffff)...)
	b = append(b, str([]byte("MFG00001"))...)
	b = append(b, u32(2)...)
	b = append(b, u32(1311)...)
	b = append(b, u32(0xffffff)...)
	return b
}

func (f *fakeScale) emit(m message) {
	b := m.encode()
	for len(b) > 0 {
		n := min(f.mtu, len(b))
		f.out = append(f.out, b[:n])
		b = b[n:]
	}
}

func (f *fakeScale) Write(_ context.Context, frame []byte) error {
	f.mu.Lock()
	defer func() {
		f.mu.Unlock()
		select {
		case f.wake <- struct{}{}:
		default:
		}
	}()
	f.written = append(f.written, append([]byte(nil), frame...))
	m, err := decode(frame)
	if err != nil {
		return nil
	}
	switch m.cmd {
	case cmdProbe:
		if f.setup {
			f.emit(message{cmdProbe, []tlv{{tProbeReply, f.probeReply()}}})
			return nil
		}
		f.emit(message{cmdChallenge, []tlv{{tChallenge, append(str([]byte(f.mac)), str(scaleChallenge)...)}}})
	case cmdChallenge:
		a := reader{b: m.find(tChallengeResponse)}
		ans := a.str()
		if !bytes.Equal(ans, sha(scaleChallenge, []byte(f.mac), f.kl)) {
			f.emit(message{cmdError, []tlv{{tCmdError, append(u16(cmdChallenge), u32(0xfffffffb)...)}}})
			return nil
		}
		c := reader{b: m.find(tChallenge)}
		c.str()
		own := c.str()
		mine := sha(own, []byte(f.mac), f.kl)
		if f.badProof {
			mine[0] ^= 1
		}
		for _, a := range f.after {
			for len(a) > 0 {
				n := min(f.mtu, len(a))
				f.out = append(f.out, a[:n])
				a = a[n:]
			}
		}
		f.emit(message{cmdProbe, []tlv{{tChallengeResponse, str(mine)}, {tProbeReply, f.probeReply()}}})
	case cmdBattery:
		f.emit(message{cmdBattery, []tlv{{tBattery, u16(87)}}})
	case cmdConnectReason:
		f.emit(message{cmdConnectReason, []tlv{{tConnectReason, u16(2)}}})
	case cmdStoredMeasure:
		switch m.find(tMeasureAction)[0] {
		case 0:
			st := append(u16(uint16(len(f.records))), u32(1700000000)...)
			f.emit(message{cmdStoredMeasure, []tlv{{tMeasureStatus, append(st, 1)}}})
		case 1:
			for i, r := range f.records {
				if i == len(f.records)-1 {
					r = append(r, tlv{tNull, nil})
				}
				f.emit(message{cmdStoredMeasure, r})
			}
		}
	case cmdSyncOK:
		f.emit(message{cmd: cmdSyncOK})
	}
	return nil
}

func (f *fakeScale) Read(ctx context.Context) ([]byte, error) {
	for {
		f.mu.Lock()
		if len(f.out) > 0 {
			b := f.out[0]
			f.out = f.out[1:]
			f.mu.Unlock()
			return b, nil
		}
		f.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.wake:
		}
	}
}

func (f *fakeScale) frames() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.written...)
}

// meta is a STORED_MEASURE_META record: uid, valid, ids, attrib, time.
func meta(t uint32, valid uint8, ids ...uint32) tlv {
	b := append(u32(9), valid, uint8(len(ids)))
	for _, id := range ids {
		b = append(b, u32(id)...)
	}
	b = append(b, 0)
	return tlv{tMeasureMeta, append(b, u32(t)...)}
}

// data is a STORED_MEASURE_DATA value: value × 10^exp of measure typ.
func data(v int32, typ uint16, exp int16) tlv {
	b := append(u32(uint32(v)), u16(typ)...)
	return tlv{tMeasureData, append(b, u16(uint16(exp))...)}
}
