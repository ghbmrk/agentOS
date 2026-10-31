package decodehost

// REQ: CLK-1, NET-2, RES-2

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/clerk/camera"
	"github.com/ghbmrk/agentos/broker/cmd/agentos-camdecode/camdecode"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

var (
	picture = camwire.Shape{Width: 8, Height: 6}
	lepton  = camwire.Shape{Width: 4, Height: 3}
)

// sandbox is a decoder sandbox in this process, running the sandbox's own
// decoder on the argv it was started with.
type sandbox struct {
	inR, outR *io.PipeReader
	inW, outW *io.PipeWriter
	done      chan struct{}
	once      sync.Once
}

func (p *sandbox) In() io.Writer         { return p.inW }
func (p *sandbox) Out() io.Reader        { return p.outR }
func (p *sandbox) Done() <-chan struct{} { return p.done }
func (p *sandbox) Stop() {
	p.once.Do(func() { p.inW.Close(); p.inR.Close(); p.outW.Close(); p.outR.Close() })
	<-p.done
}

// starts records each sandbox's stream and how many are still running.
type starts struct {
	mu      sync.Mutex
	streams []gvisor.Stream
	running int
}

func (s *starts) start(_ context.Context, st gvisor.Stream) (camera.Proc, error) {
	c, err := camdecode.ParseArgs(st.Argv[1:])
	if err != nil {
		return nil, err
	}
	p := &sandbox{done: make(chan struct{})}
	p.inR, p.inW = io.Pipe()
	p.outR, p.outW = io.Pipe()
	s.mu.Lock()
	s.streams = append(s.streams, st)
	s.running++
	s.mu.Unlock()
	go func() {
		defer close(p.done)
		camdecode.Run(p.inR, p.outW, c)
		p.outW.Close()
		s.mu.Lock()
		s.running--
		s.mu.Unlock()
	}()
	return p, nil
}

func (s *starts) state() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams), s.running
}

// unit is the decoder unit: each connection on its socket is one session,
// served as agentos-camdecode-host serves it and closed when Serve returns.
func unit(t *testing.T, st *starts) (sock string, served chan error) {
	t.Helper()
	sock = filepath.Join(t.TempDir(), "conn.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	served = make(chan error, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				err := Serve(context.Background(), c, Config{Start: st.start, Root: "/img/camdecode",
					Cgroup: "/sys/fs/cgroup/unit", MemBytes: camera.DefaultDecodeMem})
				c.Close()
				served <- err
			}()
		}
	}()
	return sock, served
}

func thermal(n uint32) camwire.Frame {
	s := make([]byte, 2*int(lepton.Width)*int(lepton.Height))
	s[0] = byte(n)
	return camwire.Frame{Type: camwire.TypeThermal, Payload: camwire.AppendThermal(nil,
		camwire.Thermal{Width: lepton.Width, Height: lepton.Height, Counter: n, Samples: s})}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestClerkDecodesThroughTheUnit: the clerk's decoder, dialling the unit's
// socket, gets each frame back decoded and checked, from a sandbox the unit
// started with the camera's declared shapes, its root, its memory cap and
// its own group; and once the clerk removes the camera, the session's
// sandbox is stopped and the unit's process has ended.
func TestClerkDecodesThroughTheUnit(t *testing.T) {
	st := &starts{}
	sock, served := unit(t, st)
	var mu sync.Mutex
	var out []camera.Decoded
	d, err := camera.NewDecoder(camera.DecodeConfig{Start: camera.DialDecoder(sock),
		Out:    func(f camera.Decoded) { mu.Lock(); out = append(out, f); mu.Unlock() },
		Report: func(string, camera.Kind) {}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Add("porch", picture, lepton); err != nil {
		t.Fatal(err)
	}
	for n := uint32(1); n <= 3; n++ {
		if err := d.Frame("porch", thermal(n)); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "three decoded frames", func() bool { mu.Lock(); defer mu.Unlock(); return len(out) == 3 })
	for i, f := range out {
		if !f.Thermal || f.Counter != uint32(i+1) || f.Width != lepton.Width || f.Pixels[0] != byte(i+1) {
			t.Errorf("frame %d: %+v", i, f)
		}
	}
	n, _ := st.state()
	if n != 1 {
		t.Fatalf("%d sandboxes started", n)
	}
	s := st.streams[0]
	want := camera.Spec{Video: picture, Thermal: lepton}.Argv()
	if s.Name != "camdecode" || s.Root != "/img/camdecode" || s.Cgroup != "/sys/fs/cgroup/unit" ||
		s.MemBytes != camera.DefaultDecodeMem || len(s.Argv) != len(want) {
		t.Errorf("stream %+v", s)
	}
	for i := range want {
		if s.Argv[i] != want[i] {
			t.Errorf("argv %q, want %q", s.Argv, want)
			break
		}
	}
	d.Remove("porch")
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("the session ended with %v", err)
		}
	default:
		t.Fatal("Remove returned before the unit's session ended")
	}
	if _, running := st.state(); running != 0 {
		t.Error("the sandbox still runs after the session ended")
	}
}

// TestServeRefusesABadSpec: a spec out of bounds starts no sandbox, and a
// config missing a part serves nothing.
func TestServeRefusesABadSpec(t *testing.T) {
	st := &starts{}
	sock, served := unit(t, st)
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{0x10, 0x01, 0, 1, 0, 0, 0, 0}) // a picture 4097 wide
	if err := <-served; !errors.Is(err, camera.ErrShapes) {
		t.Errorf("Serve = %v, want ErrShapes", err)
	}
	if n, _ := st.state(); n != 0 {
		t.Error("a sandbox started for a bad spec")
	}
	if err := Serve(context.Background(), c, Config{Start: st.start, Root: "/r", MemBytes: 1}); !errors.Is(err, ErrConfig) {
		t.Errorf("no cgroup: %v", err)
	}
}

// TestServeEndsWithTheSandbox: a sandbox that exits ends the session,
// which tells the clerk by closing the connection.
func TestServeEndsWithTheSandbox(t *testing.T) {
	st := &starts{}
	sock, served := unit(t, st)
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	spec := []byte{0, 8, 0, 6, 0, 4, 0, 3} // picture and lepton
	c.Write(append(spec, "not a frame at all"...))
	if err := <-served; err != nil {
		t.Errorf("Serve = %v", err)
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Errorf("the connection did not end with the sandbox: %v", err)
	}
	if n, running := st.state(); n != 1 || running != 0 {
		t.Errorf("%d started, %d running", n, running)
	}
}

// TestLeaveJoinsTheLeaf: the process moves into its leaf of its unit's
// group, and a group it cannot join refuses the session.
func TestLeaveJoinsTheLeaf(t *testing.T) {
	cg := t.TempDir()
	if err := Leave(cg); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(cg, leaf, "cgroup.procs")); err != nil || string(b) != "0" {
		t.Fatalf("leaf's cgroup.procs = %q, %v; want the process itself (0)", b, err)
	}
	if err := Leave(filepath.Join(cg, "missing")); err == nil {
		t.Fatal("a missing group was joined")
	}
}

// TestOwnCgroup reads the v2 line of /proc/self/cgroup and nothing else.
func TestOwnCgroup(t *testing.T) {
	f := filepath.Join(t.TempDir(), "cgroup")
	for in, want := range map[string]string{
		"0::/agentos.slice/agentos-camdecode@1-2-3.service\n": "/sys/fs/cgroup/agentos.slice/agentos-camdecode@1-2-3.service",
		"12:pids:/x\n0::/a.slice/b.service\n":                 "/sys/fs/cgroup/a.slice/b.service",
		"12:pids:/x\n":                                        "",
		"0::relative\n":                                       "",
		"0::/a/../../etc\n":                                   "",
	} {
		os.WriteFile(f, []byte(in), 0o600)
		got, err := OwnCgroup(f)
		if got != want || (want == "") != (err != nil) {
			t.Errorf("OwnCgroup(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
