package se

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camnode"
)

// REQ: DEV-3, KRN-2

// chip is the element's side of the bus as the driver's tests script it:
// it decodes each data frame the driver writes, answers its APDU with
// handle, and lets a test bend the reply frame before the driver reads
// it. Its frames follow the host library's framing (link.go), so a
// transcript here is what the driver must produce and accept; the board
// run in part d records the real element's (ASSUMPTIONS CAM-se-1).
type chip struct {
	t      *testing.T
	handle func(cmd, param byte, payload []byte) (sta byte, data []byte)
	// bend changes the next reply frame; nil leaves it.
	bend func([]byte) []byte
	// ack sends a control frame before each data frame.
	ack bool

	reg     byte
	out     [][]byte // reply frames queued for the driver
	fr, got uint8    // the chip's last frame number sent and received
	writes  [][]byte // every write, for the transcript test
}

func newChip(t *testing.T) *chip {
	return &chip{t: t, fr: frameNumMask, got: frameNumMask}
}

func (c *chip) Write(p []byte) error {
	c.writes = append(c.writes, bytes.Clone(p))
	c.reg = p[0]
	if c.reg != regData || len(p) == 1 {
		return nil
	}
	f, err := parseFrame(p[1:])
	if err != nil {
		c.t.Fatalf("driver sent a malformed frame %x: %v", p[1:], err)
	}
	if f.control {
		return nil // the driver's acknowledgement
	}
	c.got = f.fr
	apdu, err := unpacket(f.packet)
	if err != nil || len(apdu) < apduHeader || int(binary.BigEndian.Uint16(apdu[2:])) != len(apdu)-apduHeader {
		c.t.Fatalf("driver sent a malformed APDU %x", f.packet)
	}
	sta, data := c.handle(apdu[0], apdu[1], apdu[apduHeader:])
	resp := []byte{sta, 0}
	resp = binary.BigEndian.AppendUint16(resp, uint16(len(data)))
	resp = append(resp, data...)
	if c.ack {
		c.out = append(c.out, ackFrame(c.got))
	}
	c.fr = (c.fr + 1) & frameNumMask
	reply := dataFrame(c.fr, c.got, packet(resp))
	if c.bend != nil {
		reply = c.bend(reply)
		c.bend = nil
	}
	c.out = append(c.out, reply)
	return nil
}

func (c *chip) Read(p []byte) error {
	switch c.reg {
	case regState:
		clear(p)
		if len(c.out) > 0 {
			p[0] = stateReady
			binary.BigEndian.PutUint16(p[2:], uint16(len(c.out[0])))
		}
	case regData:
		if len(c.out) == 0 || len(p) != len(c.out[0]) {
			return errors.New("chip: nothing to read")
		}
		copy(p, c.out[0])
		c.out = c.out[1:]
	}
	return nil
}

// fakeObjects answers the commands the driver sends with a P-256 key, two
// counters and the two data objects (the public point and the bundle
// record).
type fakeObjects struct {
	key      *ecdsa.PrivateKey
	objects  map[uint16][]byte
	counters map[uint16]uint32
	counts   int
}

func newObjects(t *testing.T) *fakeObjects {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := k.PublicKey.Bytes()
	return &fakeObjects{k, map[uint16][]byte{oidPublic: pub}, map[uint16]uint32{oidSettings: 0, oidImage: 0}, 0}
}

func (o *fakeObjects) handle(cmd, param byte, p []byte) (byte, []byte) {
	switch cmd {
	case cmdOpenApp:
		if !bytes.Equal(p, appID) {
			return 0xFF, nil
		}
		return 0, nil
	case cmdGetData:
		oid := binary.BigEndian.Uint16(p)
		if c, ok := o.counters[oid]; ok {
			return 0, binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, c), 0xFFFFFFFF)
		}
		return 0, o.objects[oid]
	case cmdSetData:
		oid := binary.BigEndian.Uint16(p)
		data := p[4:]
		if param == paramCount {
			o.counts++
			o.counters[oid] += uint32(data[0])
			return 0, nil
		}
		o.objects[oid] = bytes.Clone(data)
		return 0, nil
	case cmdCalcSign:
		if param != paramECDSA || p[0] != tagDigest || binary.BigEndian.Uint16(p[1:]) != 32 ||
			!bytes.Equal(p[35:], []byte{tagOID, 0, 2, 0xE0, 0xF1}) {
			return 0xFF, nil
		}
		sig, _ := ecdsa.SignASN1(rand.Reader, o.key, p[3:35])
		return 0, sig[2:] // the element sends r and s without the SEQUENCE
	}
	return 0xFF, nil
}

func open(t *testing.T) (*Optiga, *chip, *fakeObjects) {
	t.Helper()
	c := newChip(t)
	objs := newObjects(t)
	c.handle = objs.handle
	o, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	o.Sleep = func(time.Duration) {}
	return o, c, objs
}

// TestCRCKnownAnswer: the frame check sequence is CRC-16/KERMIT, whose
// catalogue check value for "123456789" is 0x2189; the host library's
// bytewise routine gives the same.
func TestCRCKnownAnswer(t *testing.T) {
	if got := crc16([]byte("123456789")); got != 0x2189 {
		t.Fatalf("crc16 = %#04x, want 0x2189", got)
	}
}

// TestElementCommandFraming: the driver's OpenApplication frame is the
// recorded transcript's bytes; a reply with a flipped CRC, a length field
// that disagrees with its size, a wrong acknowledgement or frame number,
// a chaining bit, a refused status, or a signature that is not two
// minimal DER INTEGERs is refused, and nothing malformed reaches a caller.
// Revert mutant: parseFrame without its CRC check.
func TestElementCommandFraming(t *testing.T) {
	c := newChip(t)
	c.handle = newObjects(t).handle
	if _, err := Open(c); err != nil {
		t.Fatal(err)
	}
	// Soft reset, then OpenApplication as frame 0 acknowledging 3: FCTR
	// 0x03, LEN 0x0015, PCTR 0x08, APDU F0 00 0010 ‖ AID, FCS.
	want := "880000"
	if hex.EncodeToString(c.writes[0]) != want {
		t.Fatalf("reset = %x, want %s", c.writes[0], want)
	}
	openApp := "80" + "030015" + "08" + "f0000010" + hex.EncodeToString(appID)
	body, _ := hex.DecodeString(openApp[2:])
	openApp += hex.EncodeToString(binary.BigEndian.AppendUint16(nil, crc16(body)))
	if got := hex.EncodeToString(c.writes[1]); got != openApp {
		t.Fatalf("open application = %s\nwant %s", got, openApp)
	}

	bends := map[string]func([]byte) []byte{
		"crc": func(f []byte) []byte { f[len(f)-1] ^= 1; return f },
		"length": func(f []byte) []byte {
			f[2]++
			return reCRC(f)
		},
		"short":     func(f []byte) []byte { return f[:4] },
		"ack":       func(f []byte) []byte { f[0] ^= 0x01; return reCRC(f) },
		"frame":     func(f []byte) []byte { f[0] ^= 0x04; return reCRC(f) },
		"nack":      func(f []byte) []byte { f[0] |= 0x20; return reCRC(f) },
		"chaining":  func(f []byte) []byte { f[3] |= 0x01; return reCRC(f) },
		"apdu len":  func(f []byte) []byte { f[linkHeader+1+3]++; return reCRC(f) },
		"no packet": func(f []byte) []byte { return reCRC(append([]byte{f[0], 0, 0}, 0, 0)) },
	}
	for name, bend := range bends {
		t.Run(name, func(t *testing.T) {
			o, c, _ := open(t)
			c.bend = bend
			if _, err := o.Image(); !errors.Is(err, ErrLink) {
				t.Fatalf("Counter after a %s reply: %v, want ErrLink", name, err)
			}
		})
	}

	t.Run("refused", func(t *testing.T) {
		o, c, _ := open(t)
		c.handle = func(byte, byte, []byte) (byte, []byte) { return 0xFF, nil }
		if _, err := o.Image(); !errors.Is(err, ErrRefused) {
			t.Fatalf("Counter on a refused status: %v", err)
		}
	})
	t.Run("ack control frame first", func(t *testing.T) {
		o, c, _ := open(t)
		c.ack = true
		if _, err := o.Image(); err != nil {
			t.Fatal(err)
		}
	})
	for name, sig := range map[string][]byte{
		"one integer":   {0x02, 0x01, 0x01},
		"padded":        {0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01},
		"negative":      {0x02, 0x01, 0x81, 0x02, 0x01, 0x01},
		"trailing byte": {0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00},
		"sequence":      {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
	} {
		t.Run("signature "+name, func(t *testing.T) {
			o, c, _ := open(t)
			c.handle = func(byte, byte, []byte) (byte, []byte) { return 0, sig }
			if _, err := o.Sign(make([]byte, 32)); !errors.Is(err, ErrLink) {
				t.Fatalf("Sign with a %s reply: %v", name, err)
			}
		})
	}
}

func reCRC(f []byte) []byte {
	binary.BigEndian.PutUint16(f[len(f)-2:], crc16(f[:len(f)-2]))
	return f
}

// The driver is the node's element.
var _ camnode.Element = (*Optiga)(nil)

// TestOptigaCommands: through the framing, Sign gives a signature the
// device key verifies and refuses a digest that is not 32 bytes; a commit
// writes the record and counts the settings counter up in steps of at most
// 255; a commit or image raise that would not rise, or would pass 32 bits,
// is refused before anything is written; ClearBundle zeroes the record and
// keeps the counter. Revert mutant: CommitBundle writing the record before
// its range check.
func TestOptigaCommands(t *testing.T) {
	o, _, objs := open(t)
	pt, err := o.Public()
	if pub, _ := objs.key.PublicKey.Bytes(); err != nil || !bytes.Equal(pt[:], pub) {
		t.Fatalf("Public: %v", err)
	}
	d := []byte{31: 1}
	sig, err := o.Sign(d)
	if err != nil || !ecdsa.VerifyASN1(&objs.key.PublicKey, d, sig) {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := o.Sign(d[:20]); !errors.Is(err, ErrDigest) {
		t.Fatalf("short digest: %v", err)
	}

	if c, rec, err := o.Settings(); c != 0 || rec != ([32]byte{}) || err != nil {
		t.Fatalf("fresh element: %d %x %v", c, rec, err)
	}
	rec := [32]byte{9}
	if err := o.CommitBundle(600, rec); err != nil {
		t.Fatal(err)
	}
	if c, got, _ := o.Settings(); c != 600 || got != rec || objs.counts != 3 {
		t.Fatalf("after commit: counter %d record %x after %d counts, want 600, %x, 3", c, got, objs.counts, rec)
	}
	for _, to := range []uint64{600, 599, 1 << 32} {
		if err := o.CommitBundle(to, [32]byte{7}); !errors.Is(err, ErrCounter) {
			t.Fatalf("commit at %d: %v", to, err)
		}
		if _, got, _ := o.Settings(); got != rec {
			t.Fatalf("commit at %d refused but wrote the record", to)
		}
	}
	if err := o.ClearBundle(); err != nil {
		t.Fatal(err)
	}
	if c, got, _ := o.Settings(); c != 600 || got != ([32]byte{}) {
		t.Fatalf("after clear: %d %x", c, got)
	}

	if c, _ := o.Image(); c != 0 {
		t.Fatalf("image counter moved to %d", c)
	}
	if err := o.RaiseImage(3); err != nil {
		t.Fatal(err)
	}
	for _, to := range []uint64{3, 2, 1 << 32} {
		if err := o.RaiseImage(to); !errors.Is(err, ErrCounter) {
			t.Fatalf("image raise to %d: %v", to, err)
		}
	}
	if c, _ := o.Image(); c != 3 {
		t.Fatalf("image counter %d, want 3", c)
	}
}

// TestOptigaConcurrent: handshakes sign while a bundle commits, and the
// link carries one exchange at a time, so concurrent calls must not
// interleave frames (the chip fails the test on a malformed frame).
func TestOptigaConcurrent(t *testing.T) {
	o, c, _ := open(t)
	var mu sync.Mutex
	h := c.handle
	c.handle = func(cmd, param byte, p []byte) (byte, []byte) {
		mu.Lock()
		defer mu.Unlock()
		return h(cmd, param, p)
	}
	done := make(chan error)
	for i := range 8 {
		go func() {
			var err error
			if i%2 == 0 {
				_, err = o.Sign(make([]byte, 32))
			} else {
				_, _, err = o.Settings()
			}
			done <- err
		}()
	}
	for range 8 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
