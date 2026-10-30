package capture

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// REQ: NET-2, DEV-3

// Generated H.264 NAL units (start code, header, a few payload bytes):
// first_mb_in_slice is 0 when the byte after the header has its top bit
// set.
var (
	sps    = []byte{0, 0, 0, 1, 0x67, 0x42, 0xc0, 0x1f}
	pps    = []byte{0, 0, 1, 0x68, 0xce, 0x3c, 0x80}
	idr    = []byte{0, 0, 1, 0x65, 0x88, 0x84, 0x21}
	idr2   = []byte{0, 0, 1, 0x65, 0x40, 0x12, 0x34} // a second slice of the same picture
	pslice = []byte{0, 0, 0, 1, 0x41, 0x9a, 0x02, 0x05}
)

// threeByte is n with a 3-byte start code.
func threeByte(n []byte) []byte {
	if n[2] == 0 {
		return n[1:]
	}
	return n
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// TestAccessUnits: a generated stream splits into its pictures (parameter
// sets ride with the IDR; a second slice stays with its picture), each in
// Annex B form with no trailing zeros; a stream that does not open with a
// start code, and an access unit over camwire.MaxVideo, are refused. Every
// unit passes camwire's frame check. Revert mutant: the first_mb_in_slice
// test dropped (each slice its own unit).
func TestAccessUnits(t *testing.T) {
	stream := cat(sps, pps, idr, idr2, []byte{0, 0}, pslice, pslice)
	a := NewAccessUnits(bytes.NewReader(stream))
	want := [][]byte{
		cat(threeByte(sps), pps, idr, idr2),
		threeByte(pslice),
		threeByte(pslice),
	}
	for i, w := range want {
		got, err := a.Next()
		if err != nil || !bytes.Equal(got, w) {
			t.Fatalf("unit %d = %x, %v\nwant %x", i, got, err, w)
		}
		if _, err := camwire.AppendFrame(nil, camwire.ToCore, camwire.Shape{}, camwire.Frame{Type: camwire.TypeVideo, Payload: got}); err != nil {
			t.Fatalf("unit %d refused by camwire: %v", i, err)
		}
	}
	if _, err := a.Next(); err != io.EOF {
		t.Fatalf("after the stream: %v, want EOF", err)
	}

	if _, err := NewAccessUnits(bytes.NewReader([]byte{0, 1, 0x65})).Next(); !errors.Is(err, ErrAccessUnit) {
		t.Fatalf("no start code: %v", err)
	}
	big := cat(idr, bytes.Repeat([]byte{0xAA}, camwire.MaxVideo), pslice)
	if _, err := NewAccessUnits(bytes.NewReader(big)).Next(); !errors.Is(err, ErrAccessUnit) {
		t.Fatalf("over-cap unit: %v", err)
	}
}

// TestCRCKnownAnswer: VoSPI's CRC is CRC-16/XMODEM, whose catalogue check
// value for "123456789" is 0x31C3.
func TestCRCKnownAnswer(t *testing.T) {
	if got := crcXMODEM([]byte("123456789")); got != 0x31C3 {
		t.Fatalf("crc = %#04x, want 0x31c3", got)
	}
}

// vospi is a generated Lepton: it emits frames of a known pattern as VoSPI
// packets, with discard packets between them.
type vospi struct {
	shape  camwire.Shape
	frame  int
	bend   func(seg, num int, p []byte) // changes one packet; nil leaves it
	buf    bytes.Buffer
	frames int // frames to emit before EOF
}

func pixel(frame, i int) uint16 { return uint16(frame*7+i) & 0x3FFF }

func (v *vospi) packet(id uint16, payload []byte) []byte {
	p := make([]byte, packetLen)
	binary.BigEndian.PutUint16(p, id)
	copy(p[4:], payload)
	binary.BigEndian.PutUint16(p[2:], vospiCRC(p))
	return p
}

func (v *vospi) Read(p []byte) (int, error) {
	for v.buf.Len() < len(p) {
		if v.frame == v.frames {
			if v.buf.Len() == 0 {
				return 0, io.EOF
			}
			break
		}
		v.buf.Write(v.packet(0x0F00, nil)) // discard
		segs := 1
		if v.shape == Lepton3 {
			segs = 4
		}
		for seg := range segs {
			for num := range packetsPerSeg {
				payload := make([]byte, packetPayload)
				for k := range 80 {
					binary.BigEndian.PutUint16(payload[2*k:], pixel(v.frame, (seg*packetsPerSeg+num)*80+k))
				}
				id := uint16(num)
				if num == segmentPacket && segs > 1 {
					id |= uint16(seg+1) << segmentShift
				}
				pk := v.packet(id, payload)
				if v.bend != nil {
					v.bend(seg, num, pk)
				}
				v.buf.Write(pk)
			}
		}
		v.frame++
	}
	return v.buf.Read(p)
}

func wantFrame(shape camwire.Shape, frame int, counter uint32) []byte {
	s := make([]byte, 2*int(shape.Width)*int(shape.Height))
	for i := range len(s) / 2 {
		binary.BigEndian.PutUint16(s[2*i:], pixel(frame, i))
	}
	return camwire.AppendThermal(nil, camwire.Thermal{Width: shape.Width, Height: shape.Height, Counter: counter, Samples: s})
}

// TestLeptonFrames: both shapes assemble whole frames in order, skipping
// discard packets; a packet with a bad CRC, a lost packet, or a Lepton 3
// segment out of order drops that frame, and the next whole frame follows.
// Every frame passes camwire's thermal check. Revert mutant: the CRC check
// dropped.
func TestLeptonFrames(t *testing.T) {
	for _, shape := range []camwire.Shape{Lepton2, Lepton3} {
		v := &vospi{shape: shape, frames: 2}
		l, err := NewLepton(v, shape)
		if err != nil {
			t.Fatal(err)
		}
		for i := range 2 {
			got, err := l.Next()
			if err != nil || !bytes.Equal(got, wantFrame(shape, i, uint32(i+1))) {
				t.Fatalf("%v frame %d: %v", shape, i, err)
			}
			if _, err := camwire.ParseThermal(got, shape); err != nil {
				t.Fatalf("camwire refuses the frame: %v", err)
			}
		}
	}
	for name, bend := range map[string]func(seg, num int, p []byte){
		"crc":     func(seg, num int, p []byte) { p[40] ^= 1 },
		"lost":    func(seg, num int, p []byte) { p[1] = 59 /* renumber over packet 7 */ },
		"segment": func(seg, num int, p []byte) { p[0] = 0x30 | p[0]&0x0F /* segment 3 claimed */ },
	} {
		v := &vospi{shape: Lepton3, frames: 2}
		v.bend = func(seg, num int, p []byte) {
			if v.frame == 0 && seg == 1 && ((name == "segment" && num == segmentPacket) || (name != "segment" && num == 7)) {
				bend(seg, num, p)
				if name != "crc" {
					binary.BigEndian.PutUint16(p[2:], vospiCRC(p))
				}
			}
		}
		l, _ := NewLepton(v, Lepton3)
		got, err := l.Next()
		if err != nil || !bytes.Equal(got, wantFrame(Lepton3, 1, 1)) {
			t.Fatalf("%s: the torn frame was not dropped for the next one (%v)", name, err)
		}
	}
	if _, err := NewLepton(nil, camwire.Shape{Width: 4, Height: 4}); !errors.Is(err, ErrShape) {
		t.Fatal("a shape no Lepton has was taken")
	}
}

// The helper encoder: when the test binary runs as -capture-helper FILE N
// it writes its remaining arguments to FILE, then a generated stream of frames
// access units, and exits.
func TestMain(m *testing.M) {
	// The encoder runs with an empty environment, so the helper takes its
	// file and frame count as its first two arguments.
	if len(os.Args) > 3 && os.Args[1] == "-capture-helper" {
		out := os.Args[2]
		n, _ := strconv.Atoi(os.Args[3])
		args := os.Args[4:]
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		os.WriteFile(out, []byte(strings.Join(args, " ")), 0o600)
		os.Stdout.Write(cat(sps, pps, idr))
		for range n {
			os.Stdout.Write(pslice)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// TestCameraRunsEncoder: Apply starts the encoder with the bundle's
// settings, its access units reach Read, an encoder that exits is started
// again, Read is safe for two readers at once (#3588 item 1), and a stream
// turned off starts nothing. Revert mutant: run without its restart loop.
func TestCameraRunsEncoder(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args")
	var irs []uint8
	c := New(Config{
		Encoder: []string{os.Args[0], "-capture-helper", argsFile, "3", "--"},
		IR:      func(m uint8) error { irs = append(irs, m); return nil },
		Restart: 10 * time.Millisecond,
	})
	defer c.Close()
	s := camwire.Settings{Width: 1280, Height: 720, FPS: 25, BitrateKbps: 3000, IR: camwire.IRAuto, Stream: true}
	if err := c.Apply(s); err != nil {
		t.Fatal(err)
	}
	// Two runs of the encoder are 2×4 units; read them from two readers.
	var wg sync.WaitGroup
	var mu sync.Mutex
	idrs := 0
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 4 {
				f, err := c.Read()
				if err != nil || f.Type != camwire.TypeVideo {
					t.Errorf("Read: %v %v", f.Type, err)
					return
				}
				mu.Lock()
				if f.Payload[3]&0x1F == 7 {
					idrs++
				}
				mu.Unlock()
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the encoder was not restarted after it exited")
	}
	if idrs < 2 {
		t.Fatalf("%d IDR units, want one per encoder run (2)", idrs)
	}
	args, _ := os.ReadFile(argsFile)
	if got, want := string(args), strings.Join(Args(s), " "); got != want {
		t.Fatalf("encoder args %q\nwant %q", got, want)
	}
	if len(irs) != 1 || irs[0] != camwire.IRAuto {
		t.Fatalf("IR set %v", irs)
	}

	// Apply returns only once every producer has ended, so an encoder that
	// was mid-restart cannot write the file after the Remove below.
	s.Stream = false
	if err := c.Apply(s); err != nil {
		t.Fatal(err)
	}
	os.Remove(argsFile)
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(argsFile); err == nil {
		t.Fatal("encoder started with the stream off")
	}
	if err := c.Apply(camwire.Settings{Thermal: true, Stream: true}); err == nil {
		t.Fatal("thermal applied with no core fitted")
	}
}

// TestHaltedCameraStartsNothing: a producer whose stop is already closed
// opens nothing, with its restart due at once. It reaches the check before
// open on the first pass, which is the check that also stops a restart
// chosen as stop closes. Revert mutant: run without that check.
func TestHaltedCameraStartsNothing(t *testing.T) {
	c := New(Config{Restart: time.Nanosecond})
	stop := make(chan struct{})
	close(stop)
	opened := 0
	c.run(stop, func() (func() (camwire.Frame, error), func(), error) {
		opened++
		return nil, nil, errors.New("capture: not fitted")
	})
	c.wg.Wait()
	if opened != 0 {
		t.Fatalf("a halted camera opened %d producers", opened)
	}
}

// TestCaptureOpensNoSocket (the capture half of camnode's
// TestNoOutboundDial): no source file here imports a network package. The
// one child it starts is the encoder, whose path the binary fixes.
func TestCaptureOpensNoSocket(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	fs := token.NewFileSet()
	seen := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fs, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		seen++
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if p == "net" || strings.HasPrefix(p, "net/") {
				t.Errorf("%s imports %s", name, p)
			}
		}
	}
	if seen == 0 {
		t.Fatal(fmt.Sprint("no source files read"))
	}
}

// TestCameraFailsClosedAndKeepsNewest: settings the camera refuses (an IR
// write that fails) leave capture stopped, never running at the old
// settings (Security on #3617, finding 2); a full buffer drops its oldest
// frame, so a reader that starts late gets the newest (L3 on #3617,
// finding 4).
func TestCameraFailsClosedAndKeepsNewest(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args")
	fail := false
	c := New(Config{
		Encoder: []string{os.Args[0], "-capture-helper", argsFile, "1000", "--"},
		IR: func(uint8) error {
			if fail {
				return errors.New("ir: write failed")
			}
			return nil
		},
		Restart: 10 * time.Millisecond,
	})
	defer c.Close()
	s := camwire.Settings{Width: 1280, Height: 720, FPS: 25, BitrateKbps: 3000, Stream: true}
	if err := c.Apply(s); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(); err != nil {
		t.Fatal(err)
	}
	fail, s.Stream = true, false
	if err := c.Apply(s); err == nil {
		t.Fatal("a failed IR write was taken")
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(c.frames); n != 0 {
		t.Fatalf("%d frames captured after a refused stream-off", n)
	}

	d := New(Config{})
	for i := range 20 {
		d.offer(camwire.Frame{Type: camwire.TypeVideo, Payload: []byte{byte(i)}})
	}
	if f, _ := d.Read(); f.Payload[0] != 20-byte(cap(d.frames)) {
		t.Fatalf("oldest kept frame %d, want %d", f.Payload[0], 20-cap(d.frames))
	}
}
