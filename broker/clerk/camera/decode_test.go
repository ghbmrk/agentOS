package camera

// REQ: NET-2, DEV-7, DEV-8

import (
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/cmd/agentos-camdecode/camdecode"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

var picture = camwire.Shape{Width: 8, Height: 6}

// fakeProc is a decoder sandbox in this process: run reads what the
// decoder feeds and writes what it reads back; a nil run reads nothing
// and sends nothing. Stop closes every pipe, which ends run, and waits
// for it.
type fakeProc struct {
	inR, outR *io.PipeReader
	inW, outW *io.PipeWriter
	stop      chan struct{}
	done      chan struct{}
	once      sync.Once
}

func newFakeProc(run func(in io.Reader, out io.Writer)) *fakeProc {
	p := &fakeProc{stop: make(chan struct{}), done: make(chan struct{})}
	p.inR, p.inW = io.Pipe()
	p.outR, p.outW = io.Pipe()
	go func() {
		defer close(p.done)
		if run == nil {
			<-p.stop
		} else {
			run(p.inR, p.outW)
		}
		p.outW.Close()
		p.inR.Close()
	}()
	return p
}

func (p *fakeProc) In() io.Writer         { return p.inW }
func (p *fakeProc) Out() io.Reader        { return p.outR }
func (p *fakeProc) Done() <-chan struct{} { return p.done }
func (p *fakeProc) Stop() {
	p.once.Do(func() {
		close(p.stop)
		p.inW.Close()
		p.inR.Close()
		p.outW.Close()
		p.outR.Close()
	})
	<-p.done
}

// decodes runs the sandbox's own decoder on the declared shapes.
func decodes(in io.Reader, out io.Writer) {
	camdecode.Run(in, out, camdecode.Config{Video: picture, Thermal: lepton})
}

// starts records each sandbox start and gives the n-th start the n-th
// behaviour (the last one repeats).
type starts struct {
	mu    sync.Mutex
	runs  []func(io.Reader, io.Writer)
	at    []time.Time
	specs []gvisor.Stream
	procs []*fakeProc
}

func (s *starts) start(_ context.Context, st gvisor.Stream) (Proc, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.runs[min(len(s.at), len(s.runs)-1)]
	s.at = append(s.at, time.Now())
	s.specs = append(s.specs, st)
	p := newFakeProc(run)
	s.procs = append(s.procs, p)
	return p, nil
}

func (s *starts) n() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.at)
}

type outs struct {
	mu sync.Mutex
	d  []Decoded
}

func (o *outs) add(d Decoded) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.d = append(o.d, d)
}

func (o *outs) all() []Decoded {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.d)
}

type reports struct {
	mu sync.Mutex
	k  []Kind
}

func (r *reports) add(_ string, k Kind) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.k = append(r.k, k)
}

func (r *reports) count(k Kind) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, x := range r.k {
		if x == k {
			n++
		}
	}
	return n
}

type decRig struct {
	d   *Decoder
	st  *starts
	out *outs
	rep *reports
	log *lines
}

func newDecRig(t *testing.T, mut func(*DecodeConfig), runs ...func(io.Reader, io.Writer)) *decRig {
	t.Helper()
	r := &decRig{st: &starts{runs: runs}, out: &outs{}, rep: &reports{}, log: &lines{}}
	cfg := DecodeConfig{
		Start: r.st.start, Root: "/img/camdecode", Cgroup: "/sys/fs/cgroup/agentos/camdecode",
		Stall: 200 * time.Millisecond, Idle: 5 * time.Second,
		Backoff: Backoff{Min: 100 * time.Millisecond, Max: 400 * time.Millisecond},
		Out:     r.out.add, Report: r.rep.add, Log: r.log.add,
	}
	if mut != nil {
		mut(&cfg)
	}
	var err error
	if r.d, err = NewDecoder(cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.d.Close)
	if err := r.d.Add(testID, picture, lepton); err != nil {
		t.Fatal(err)
	}
	return r
}

// thermalN is a thermal frame with counter n and the marker in its
// samples.
func thermalN(n uint32) camwire.Frame {
	s := make([]byte, 2*int(lepton.Width)*int(lepton.Height))
	copy(s, marker)
	return camwire.Frame{Type: camwire.TypeThermal, Payload: camwire.AppendThermal(nil, camwire.Thermal{Width: lepton.Width, Height: lepton.Height, Counter: n, Samples: s})}
}

// TestDecodeFormatMatchesDecoder: the clerk's copy of the output format,
// the argv it passes and its bounds are the sandbox decoder's own, which
// the clerk must not link (design point 4).
func TestDecodeFormatMatchesDecoder(t *testing.T) {
	if outHeaderLen != camdecode.HeaderLen || outVideo != camdecode.KindVideo || outThermal != camdecode.KindThermal ||
		maxVideoSide != camdecode.MaxVideoSide {
		t.Fatal("format constants differ from camdecode's")
	}
	for _, s := range []camwire.Shape{{Width: 1, Height: 1}, {Width: 7, Height: 5}, picture, lepton, {Width: 4096, Height: 4096}} {
		for _, k := range []byte{outVideo, outThermal} {
			if outLen(k, s) != camdecode.Len(k, s) {
				t.Errorf("outLen(%d, %v) = %d, camdecode %d", k, s, outLen(k, s), camdecode.Len(k, s))
			}
		}
	}
	r := newDecRig(t, nil, decodes)
	r.d.Frame(testID, thermalN(1))
	waitFor(t, "a start", func() bool { return r.st.n() == 1 })
	spec := r.st.specs[0]
	c, err := camdecode.ParseArgs(spec.Argv[1:])
	if spec.Argv[0] != decoderBinary || err != nil || c.Video != picture || c.Thermal != lepton {
		t.Errorf("argv %q parses to %+v, %v", spec.Argv, c, err)
	}
	if spec.Name != "camdecode-"+testID || spec.Root != "/img/camdecode" || spec.MemBytes != DefaultDecodeMem ||
		spec.Cgroup != "/sys/fs/cgroup/agentos/camdecode" {
		t.Errorf("stream %+v", spec)
	}
}

// TestClerkDoesNotLinkDecoder: no file of the clerk links the sandbox's
// decoder, so no stream payload is decoded in the trusted base (design
// point 3); and the decoder links nothing that reaches a network,
// another process or memory outside Go (NET-2: no network in the
// sandbox, by its imports as well as its namespace). The one exception is
// cgo in camdecode/h264.go, the libavcodec-tagged file that links the
// pinned H.264-only libavcodec (image/libavcodec.sh): configured with
// --disable-network, it reaches no network by its build, and the
// sandbox's namespace stops any that would. Every other file of both
// sandbox directories is refused "C", so no further C enters unseen.
func TestClerkDoesNotLinkDecoder(t *testing.T) {
	check := func(dir string, ok func(file, path string) bool) {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, im := range f.Imports {
				p, _ := strconv.Unquote(im.Path.Value)
				if !ok(name, p) {
					t.Errorf("%s imports %s", name, p)
				}
			}
		}
	}
	check(".", func(_, p string) bool { return !strings.Contains(p, "camdecode") })
	forbidden := []string{"net", "os/exec", "plugin", "unsafe", "syscall"}
	cgo := filepath.Join("..", "..", "cmd", "agentos-camdecode", "camdecode", "h264.go")
	inSandbox := func(file, p string) bool {
		if p == "C" {
			return file == cgo
		}
		if strings.HasPrefix(p, "net/") || slices.Contains(forbidden, p) {
			return false
		}
		return !strings.Contains(p, ".") || p == "github.com/ghbmrk/agentos/broker/camwire" ||
			p == "github.com/ghbmrk/agentos/broker/cmd/agentos-camdecode/camdecode"
	}
	check("../../cmd/agentos-camdecode", inSandbox)
	check("../../cmd/agentos-camdecode/camdecode", inSandbox)
}

// TestDecoderThermalThroughSandbox: thermal frames go through the
// sandbox's own decoder and come back checked, one per frame fed, with
// their counters; no fault is raised and no line carries a sample.
func TestDecoderThermalThroughSandbox(t *testing.T) {
	r := newDecRig(t, nil, decodes)
	for i := uint32(1); i <= 3; i++ {
		if err := r.d.Frame(testID, thermalN(i)); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "three frames", func() bool { return len(r.out.all()) == 3 })
	for i, d := range r.out.all() {
		if !d.Thermal || d.Camera != testID || d.Width != lepton.Width || d.Height != lepton.Height ||
			d.Counter != uint32(i+1) || !bytes.HasPrefix(d.Pixels, marker) || len(d.Pixels) != outLen(outThermal, lepton) {
			t.Errorf("frame %d = %+v", i, d)
		}
	}
	if r.rep.count(DecoderFault) != 0 || r.st.n() != 1 {
		t.Errorf("faults %d, starts %d", r.rep.count(DecoderFault), r.st.n())
	}
	if strings.Contains(r.log.all(), string(marker)) {
		t.Error("a sample reached the log")
	}
}

// liar reads each frame and answers it with write, the decoder's lie.
func liar(write func(out io.Writer, f camwire.Frame)) func(io.Reader, io.Writer) {
	return func(in io.Reader, out io.Writer) {
		for {
			f, err := camwire.ReadFrame(in, camwire.ToCore, lepton)
			if err != nil {
				return
			}
			write(out, f)
		}
	}
}

func header(kind byte, s camwire.Shape) []byte {
	return camdecode.AppendHeader(nil, kind, s, 7)
}

// TestDecoderOutputMustMatchDeclaredSize: an output frame whose kind,
// dimensions, padding or length is not what the bundle declares, or one
// more than the frames fed, ends the sandbox as a fault before any of it
// reaches a consumer (design point 4).
func TestDecoderOutputMustMatchDeclaredSize(t *testing.T) {
	good := func(out io.Writer) {
		out.Write(header(outThermal, lepton))
		out.Write(make([]byte, outLen(outThermal, lepton)))
	}
	cases := map[string]func(io.Writer, camwire.Frame){
		"wider": func(out io.Writer, _ camwire.Frame) {
			s := camwire.Shape{Width: lepton.Width + 1, Height: lepton.Height}
			out.Write(header(outThermal, s))
			out.Write(make([]byte, outLen(outThermal, s)))
		},
		"video shape for thermal": func(out io.Writer, _ camwire.Frame) {
			out.Write(header(outThermal, picture))
			out.Write(make([]byte, outLen(outThermal, picture)))
		},
		"short": func(out io.Writer, _ camwire.Frame) {
			out.Write(header(outThermal, lepton))
			out.Write(make([]byte, outLen(outThermal, lepton)-1))
		},
		"unknown kind": func(out io.Writer, _ camwire.Frame) {
			out.Write(header(9, lepton))
			out.Write(make([]byte, outLen(outThermal, lepton)))
		},
		"padding": func(out io.Writer, _ camwire.Frame) {
			h := header(outThermal, lepton)
			h[2] = 1
			out.Write(h)
			out.Write(make([]byte, outLen(outThermal, lepton)))
		},
		"video never fed": func(out io.Writer, _ camwire.Frame) {
			out.Write(header(outVideo, picture))
			out.Write(make([]byte, outLen(outVideo, picture)))
		},
		"two for one": func(out io.Writer, _ camwire.Frame) { good(out); good(out) },
	}
	for name, lie := range cases {
		t.Run(name, func(t *testing.T) {
			r := newDecRig(t, func(c *DecodeConfig) { c.Backoff = Backoff{Min: time.Hour, Max: time.Hour} }, liar(lie))
			r.d.Frame(testID, thermalN(1))
			waitFor(t, "a fault", func() bool { return r.rep.count(DecoderFault) == 1 })
			want := 0
			if name == "two for one" {
				want = 1
			}
			if n := len(r.out.all()); n != want {
				t.Errorf("%d frames reached the consumer, want %d", n, want)
			}
			waitFor(t, "the sandbox stopped", func() bool {
				select {
				case <-r.st.procs[0].done:
					return true
				default:
					return false
				}
			})
		})
	}
	// The same lies with no thermal core declared: a thermal frame out is
	// never accepted.
	r := newDecRig(t, nil, liar(func(out io.Writer, _ camwire.Frame) { good(out) }))
	if err := r.d.Add(testID, picture, camwire.Shape{}); err != nil {
		t.Fatal(err)
	}
	r.st.runs = []func(io.Reader, io.Writer){func(in io.Reader, out io.Writer) {
		io.ReadFull(in, make([]byte, camwire.HeaderLen))
		good(out)
		io.Copy(io.Discard, in)
	}}
	r.d.Frame(testID, video())
	waitFor(t, "a fault", func() bool { return r.rep.count(DecoderFault) == 1 })
	if len(r.out.all()) != 0 {
		t.Error("a thermal frame from a camera with no thermal core reached the consumer")
	}
}

// TestDecoderStallKilled: a sandbox that takes frames and sends nothing
// back is stopped once a frame has waited past the stall deadline, as a
// fault.
func TestDecoderStallKilled(t *testing.T) {
	r := newDecRig(t, nil, func(in io.Reader, _ io.Writer) { io.Copy(io.Discard, in) })
	start := time.Now()
	r.d.Frame(testID, thermalN(1))
	waitFor(t, "a fault", func() bool { return r.rep.count(DecoderFault) == 1 })
	if el := time.Since(start); el < 200*time.Millisecond {
		t.Errorf("stopped after %v, before the 200ms deadline", el)
	}
	<-r.st.procs[0].done
	// A sandbox that stops reading its input is caught the same way.
	r = newDecRig(t, nil, nil)
	r.d.Frame(testID, thermalN(1))
	waitFor(t, "a fault", func() bool { return r.rep.count(DecoderFault) == 1 })
}

// TestDecoderCrashRestartsWithBackoff: a sandbox that exits is a fault
// and is restarted on a later frame only after the backoff, which
// doubles with each fault in a row; frames that arrive meanwhile are
// dropped and counted; the first good frame after raises
// DecoderRecovered, and the backoff starts over.
func TestDecoderCrashRestartsWithBackoff(t *testing.T) {
	crash := func(in io.Reader, _ io.Writer) { io.ReadFull(in, make([]byte, camwire.HeaderLen)) }
	r := newDecRig(t, nil, crash, crash, decodes)
	stop := make(chan struct{})
	fed := make(chan struct{})
	go func() {
		defer close(fed)
		for i := uint32(1); ; i++ {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
				r.d.Frame(testID, thermalN(i))
			}
		}
	}()
	waitFor(t, "a recovery", func() bool { return r.rep.count(DecoderRecovered) == 1 })
	waitFor(t, "a frame after it", func() bool { return len(r.out.all()) > 0 })
	close(stop)
	<-fed
	if n := r.rep.count(DecoderFault); n != 2 {
		t.Errorf("%d faults, want 2", n)
	}
	r.st.mu.Lock()
	at := slices.Clone(r.st.at)
	r.st.mu.Unlock()
	if len(at) != 3 {
		t.Fatalf("%d starts, want 3", len(at))
	}
	if gap := at[1].Sub(at[0]); gap < 100*time.Millisecond {
		t.Errorf("first restart after %v, before the 100ms backoff", gap)
	}
	if gap := at[2].Sub(at[1]); gap < 200*time.Millisecond {
		t.Errorf("second restart after %v, before the doubled 200ms backoff", gap)
	}
	if dropped, faults := r.d.Dropped(testID); dropped == 0 || faults != 2 {
		t.Errorf("dropped %d, faults %d", dropped, faults)
	}
	if !strings.Contains(r.log.all(), "decoder recovered") || strings.Contains(r.log.all(), string(marker)) {
		t.Errorf("log %q", r.log.all())
	}
}

// TestDecoderIdleStopsWithoutFault: a sandbox fed nothing for the idle
// time is stopped without a fault, and the camera's next frame starts a
// new one at once.
func TestDecoderIdleStopsWithoutFault(t *testing.T) {
	r := newDecRig(t, func(c *DecodeConfig) {
		c.Idle = 50 * time.Millisecond
		c.Backoff = Backoff{Min: time.Hour, Max: time.Hour}
	}, decodes)
	r.d.Frame(testID, thermalN(1))
	waitFor(t, "the first frame", func() bool { return len(r.out.all()) == 1 })
	<-r.st.procs[0].done
	r.d.Frame(testID, thermalN(2))
	waitFor(t, "the second frame", func() bool { return len(r.out.all()) == 2 })
	if r.st.n() != 2 || r.rep.count(DecoderFault) != 0 {
		t.Errorf("starts %d, faults %d", r.st.n(), r.rep.count(DecoderFault))
	}
}

// TestDecoderRemoveStops: frames for a camera never added are refused;
// removing a camera stops its sandbox and no frame of it reaches the
// consumer after.
func TestDecoderRemoveStops(t *testing.T) {
	r := newDecRig(t, nil, decodes)
	if err := r.d.Frame("other", thermalN(1)); !errors.Is(err, ErrNotDecoding) {
		t.Errorf("unknown camera: %v", err)
	}
	r.d.Frame(testID, thermalN(1))
	waitFor(t, "a frame", func() bool { return len(r.out.all()) == 1 })
	r.d.Remove(testID)
	select {
	case <-r.st.procs[0].done:
	default:
		t.Error("sandbox still running after Remove")
	}
	if err := r.d.Frame(testID, thermalN(2)); !errors.Is(err, ErrNotDecoding) {
		t.Errorf("removed camera: %v", err)
	}
}

// TestDecoderAddRefusesShapes: a video side over the bound, a zero side,
// a thermal shape the camera wire could not carry, or a bad ID is
// refused.
func TestDecoderAddRefusesShapes(t *testing.T) {
	r := newDecRig(t, nil, decodes)
	for _, c := range []struct {
		id      string
		v, th   camwire.Shape
		wantErr error
	}{
		{testID, camwire.Shape{Width: 4097, Height: 8}, lepton, ErrShapes},
		{testID, camwire.Shape{Width: 0, Height: 8}, lepton, ErrShapes},
		{testID, picture, camwire.Shape{Width: 1024, Height: 1024}, ErrShapes},
		{testID, picture, camwire.Shape{Width: 4, Height: 0}, ErrShapes},
		{"Bad ID", picture, lepton, ErrNode},
	} {
		if err := r.d.Add(c.id, c.v, c.th); !errors.Is(err, c.wantErr) {
			t.Errorf("Add(%q, %v, %v) = %v", c.id, c.v, c.th, err)
		}
	}
	if _, err := NewDecoder(DecodeConfig{}); !errors.Is(err, ErrDecodeConfig) {
		t.Errorf("empty config: %v", err)
	}
}

// TestDecoderBehindClerk: the clerk hands a pinned node's thermal frames
// to the decoder, its faults go out as the clerk's rate-limited, verified
// events, and no sample reaches the clerk's log or events (DEV-7, DEV-8).
func TestDecoderBehindClerk(t *testing.T) {
	out := &outs{}
	var d *Decoder
	rig := newRig(t, func(c *Config, _ *Node) {
		var err error
		st := &starts{runs: []func(io.Reader, io.Writer){decodes}}
		d, err = NewDecoder(DecodeConfig{Start: st.start, Root: "/r", Cgroup: "/c", Out: out.add,
			Report: func(id string, k Kind) {}})
		if err != nil {
			t.Fatal(err)
		}
		c.Frames = d
	})
	defer d.Close()
	if err := d.Add(testID, picture, lepton); err != nil {
		t.Fatal(err)
	}
	rig.node.serve = func(_ int, c *tlsConn) { write(c, thermal(), thermal()); hold(c) }
	stop := rig.start(func(ctx context.Context) error { return rig.c.Run(ctx, testID) })
	waitFor(t, "decoded frames", func() bool { return len(out.all()) == 2 })
	stop()
	rig.c.Report(testID, DecoderFault)
	rig.c.Report(testID, Silent)
	if len(rig.ev.of(DecoderFault)) != 1 || len(rig.ev.of(Silent)) != 0 {
		t.Errorf("events %+v", rig.ev.ev)
	}
	if e := rig.ev.of(DecoderFault)[0]; !e.Verified || e.Label != Label || e.Camera != testID {
		t.Errorf("event %+v", e)
	}
	if strings.Contains(rig.log.all(), string(marker)) {
		t.Error("a sample reached the clerk's log")
	}
}
