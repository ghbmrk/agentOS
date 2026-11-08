package camera

// REQ: CLK-1, NET-2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// TestSpecRoundTrips: a session's Spec reads back as written, and one out
// of CheckShapes' bounds is refused on the decoder unit's side too.
func TestSpecRoundTrips(t *testing.T) {
	for _, s := range []Spec{{picture, lepton}, {picture, camwire.Shape{}}, {camwire.Shape{Width: 4096, Height: 4096}, lepton}} {
		got, err := ReadSpec(bytes.NewReader(s.marshal()))
		if err != nil || got != s {
			t.Errorf("ReadSpec(%+v) = %+v, %v", s, got, err)
		}
	}
	for _, s := range []Spec{{camwire.Shape{Width: 4097, Height: 1}, lepton}, {camwire.Shape{}, lepton},
		{picture, camwire.Shape{Width: 1024, Height: 1024}}, {picture, camwire.Shape{Width: 4}}} {
		if _, err := ReadSpec(bytes.NewReader(s.marshal())); !errors.Is(err, ErrShapes) {
			t.Errorf("ReadSpec(%+v) = %v, want ErrShapes", s, err)
		}
	}
	if _, err := ReadSpec(bytes.NewReader(make([]byte, SpecLen-1))); err == nil {
		t.Error("a short spec was read")
	}
}

// TestDialDecoderSendsTheSpecAndStopsOnTheUnitsClose: a session is a
// connection to the decoder unit that starts with its Spec and carries the
// frames both ways; Stop ends the clerk's side and waits until the unit
// closes its own, and a unit that never does is cut off after decoderStop.
func TestDialDecoderSendsTheSpecAndStopsOnTheUnitsClose(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "conn.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	closeAfterEOF := make(chan time.Duration, 2)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				s, err := ReadSpec(c)
				if err != nil || s != (Spec{picture, lepton}) {
					return
				}
				io.Copy(c, c) // echo until the clerk ends its side
				time.Sleep(<-closeAfterEOF)
			}(c)
		}
	}()
	start := DialDecoder(sock)
	closeAfterEOF <- 50 * time.Millisecond
	p, err := start(context.Background(), Spec{picture, lepton})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.In().Write([]byte("frame")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	if _, err := io.ReadFull(p.Out(), b); err != nil || string(b) != "frame" {
		t.Fatalf("echo %q, %v", b, err)
	}
	t0 := time.Now()
	p.Stop()
	if d := time.Since(t0); d < 50*time.Millisecond {
		t.Errorf("Stop returned after %v, before the unit closed its side", d)
	}
	select {
	case <-p.Done():
	default:
		t.Error("Done is open after Stop")
	}
	if _, err := p.In().Write([]byte("x")); err == nil {
		t.Error("a write went through after Stop")
	}
	p.Stop() // again: no wait, no panic

	old := decoderStop
	decoderStop = 100 * time.Millisecond
	defer func() { decoderStop = old }()
	closeAfterEOF <- time.Hour
	p, err = start(context.Background(), Spec{picture, lepton})
	if err != nil {
		t.Fatal(err)
	}
	t0 = time.Now()
	p.Stop()
	if d := time.Since(t0); d > 5*time.Second {
		t.Errorf("Stop waited %v on a unit that never closes", d)
	}

	// No socket, no session.
	if _, err := DialDecoder(filepath.Join(t.TempDir(), "none"))(context.Background(), Spec{picture, lepton}); err == nil {
		t.Error("a session started with no decoder unit")
	}
}

// TestCloseStopsHungUnitsAtOnce (#4392): Close stops every camera's
// session at once, so units that never close their side hold it for one
// decoderStop, not one each. It fails if Close removes the cameras one
// after another, which takes cams times decoderStop.
func TestCloseStopsHungUnitsAtOnce(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "conn.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const cams = 6
	opened := make(chan net.Conn, cams)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if _, err := ReadSpec(c); err != nil {
					c.Close()
					return
				}
				opened <- c
				io.Copy(io.Discard, c) // a hung unit: never closes its side
			}(c)
		}
	}()
	old := decoderStop
	decoderStop = 400 * time.Millisecond
	defer func() { decoderStop = old }()
	d, err := NewDecoder(DecodeConfig{Start: DialDecoder(sock), Stall: time.Minute, Idle: time.Minute,
		Out: func(Decoded) {}, Report: func(string, Kind) {}})
	if err != nil {
		t.Fatal(err)
	}
	for i := range cams {
		id := fmt.Sprintf("cam%d", i)
		if err := d.Add(id, picture, lepton); err != nil {
			t.Fatal(err)
		}
		if err := d.Frame(id, thermalN(1)); err != nil {
			t.Fatal(err)
		}
	}
	var conns []net.Conn
	for range cams {
		select {
		case c := <-opened:
			conns = append(conns, c)
		case <-time.After(10 * time.Second):
			t.Fatalf("%d of %d sessions opened", len(conns), cams)
		}
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	t0 := time.Now()
	d.Close()
	if got := time.Since(t0); got >= 3*decoderStop {
		t.Fatalf("Close took %v for %d hung units, each stopped after %v: one after another", got, cams, decoderStop)
	}
}
