package main

// REQ: KRN-3, DEV-7, RES-3

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/childproc"
	"github.com/ghbmrk/agentos/broker/vision"
)

// helperArg makes the test binary run main, for the fd-3 test.
const helperArg = "agentos-vision-main"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == helperArg {
		os.Args = append(os.Args[:1], os.Args[2:]...)
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		main()
		return
	}
	os.Exit(m.Run())
}

const sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// fake is the CI runtime: it sees a person in every frame, and the
// glass-break label in every clip, with switches to fail loads, crash,
// panic, hang or answer outside the protocol on the next calls.
type fake struct {
	mu      sync.Mutex
	loadErr error
	model   Model
	mode    string // "", "crash", "panic", "hang", "slow", "off-list", "outside", "enrolled", "plate"
	times   int
	loads   int
	frames  int
	last    []byte // the last frame's buffer, as the service lent it
	release chan struct{} // closed by Load: a hung call returns
	inside  int
	maxIn   int
	gate    chan struct{} // when set, calls wait on it
}

func newFake() *fake {
	return &fake{model: Model{Name: "vis-fake", SHA256: sha}, release: make(chan struct{})}
}

func (f *fake) Load() (Model, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loads++
	close(f.release)
	f.release = make(chan struct{})
	return f.model, f.loadErr
}

func (f *fake) failNext(mode string, n int) {
	f.mu.Lock()
	f.mode, f.times = mode, n
	f.mu.Unlock()
}

// enter counts a call in and returns its mode.
func (f *fake) enter() (string, chan struct{}, chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inside++
	f.maxIn = max(f.maxIn, f.inside)
	mode := ""
	if f.times > 0 {
		mode = f.mode
		f.times--
	}
	return mode, f.release, f.gate
}

func (f *fake) leave() {
	f.mu.Lock()
	f.inside--
	f.mu.Unlock()
}

func (f *fake) Detect(fr vision.Frame) ([]vision.Detection, error) {
	mode, release, gate := f.enter()
	defer f.leave()
	if gate != nil {
		<-gate
	}
	f.mu.Lock()
	f.frames++
	f.last = fr.Data
	f.mu.Unlock()
	d := vision.Detection{Class: vision.Person, Box: vision.Box{X0: 0, Y0: 0, X1: fr.Width, Y1: fr.Height}, Conf: 80, Face: vision.FaceUnknown}
	switch mode {
	case "crash":
		return nil, errors.New("segfault in the runtime: frame bytes 0xCAFE")
	case "panic":
		panic("runtime panic")
	case "hang":
		<-release
		return nil, errors.New("released")
	case "slow":
		time.Sleep(300 * time.Millisecond)
	case "off-list":
		d.Class = "burglar"
	case "outside":
		d.Box.X1 = fr.Width + 1
	case "enrolled":
		d.Face = vision.FaceEnrolledAs + "alice"
	case "plate":
		d = vision.Detection{Class: vision.Vehicle, Box: d.Box, Conf: 60, Plate: "CANARY 9"}
	}
	return []vision.Detection{d}, nil
}

func (f *fake) Sound(pcm []byte) ([]vision.Sound, error) {
	mode, _, _ := f.enter()
	defer f.leave()
	if mode == "off-list" {
		return []vision.Sound{{Label: "speech", Conf: 50}}, nil
	}
	return []vision.Sound{{Label: "glass-break", Conf: 90}}, nil
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// start serves s on a fresh socket and returns a client of it.
func start(t *testing.T, s *service) vision.Client {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vision.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go s.Serve(ln)
	return vision.Client{Path: path, Timeout: 5 * time.Second}
}

func gray(w, h int, fill byte) vision.Frame {
	return vision.Frame{Format: vision.FormatGray8, Width: w, Height: h, Data: bytes.Repeat([]byte{fill}, w*h)}
}

func TestDetectAndSoundThroughTheService(t *testing.T) {
	c := start(t, newService(Config{}, newFake(), nil))
	in, err := c.Hello(context.Background())
	if err != nil || in != (vision.Info{Model: "vis-fake", SHA256: sha, Device: vision.DeviceCPU}) {
		t.Fatalf("hello: %+v, %v", in, err)
	}
	for _, f := range []vision.Frame{
		gray(32, 24, 1),
		{Format: vision.FormatRGB24, Width: 64, Height: 48, Data: make([]byte, 64*48*3)},
		{Format: vision.FormatY16, Width: 160, Height: 120, Data: make([]byte, 160*120*2)},
		gray(vision.MaxWidth, vision.MaxHeight, 0),
	} {
		ds, err := c.Detect(context.Background(), f)
		if err != nil || len(ds) != 1 || ds[0].Box != (vision.Box{X1: f.Width, Y1: f.Height}) || ds[0].Face != vision.FaceUnknown {
			t.Fatalf("%s %dx%d: %+v, %v", f.Format, f.Width, f.Height, ds, err)
		}
	}
	ss, err := c.Sound(context.Background(), make([]byte, 16000))
	if err != nil || len(ss) != 1 || ss[0].Label != "glass-break" {
		t.Fatalf("sound: %+v, %v", ss, err)
	}
}

// raw sends b on a fresh connection and returns the reply line, and
// whether the service then closed the connection.
func raw(t *testing.T, path string, b []byte) (string, bool) {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write(b)
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("no reply to %.60q: %v", b, err)
	}
	_, err = r.ReadByte()
	return strings.TrimSpace(line), err == io.EOF
}

// A header over its bound, malformed, or declaring a payload outside the
// bounds is answered bad_request and the connection is closed, without
// the service reading or holding the payload.
func TestServiceRejectsOversizeRequest(t *testing.T) {
	f := newFake()
	c := start(t, newService(Config{}, f, nil))
	hdr := func(r vision.Request) []byte { b, _ := json.Marshal(r); return append(b, '\n') }
	for name, b := range map[string][]byte{
		"header over its bound": append(bytes.Repeat([]byte(" "), vision.MaxHeaderLine+1), '\n'),
		"malformed header":      []byte("{\"op\":\n"),
		"unknown field":         []byte(`{"op":"detect","format":"gray8","width":2,"height":2,"bytes":4,"camera":"gate"}` + "\n"),
		"frame too wide":        hdr(vision.Request{Op: vision.OpDetect, Format: vision.FormatGray8, Width: vision.MaxWidth + 1, Height: 1, Bytes: vision.MaxWidth + 1}),
		"bytes over the frame":  hdr(vision.Request{Op: vision.OpDetect, Format: vision.FormatGray8, Width: 2, Height: 2, Bytes: 1 << 30}),
		"audio over its bound":  hdr(vision.Request{Op: vision.OpSound, Format: vision.AudioPCM16k, Bytes: vision.MaxAudioBytes + 2}),
		"unknown op":            hdr(vision.Request{Op: "describe"}),
		"unknown format":        hdr(vision.Request{Op: vision.OpDetect, Format: "jpeg", Width: 2, Height: 2, Bytes: 4}),
	} {
		got, closed := raw(t, c.Path, b)
		if got != `{"error":"bad_request"}` || !closed {
			t.Errorf("%s: %q, closed %v", name, got, closed)
		}
	}
	if f.frames != 0 {
		t.Fatalf("the runtime saw %d frames", f.frames)
	}
	// A payload that ends short is bad_request too.
	b := append(hdr(vision.Request{Op: vision.OpDetect, Format: vision.FormatGray8, Width: 4, Height: 4, Bytes: 16}), make([]byte, 8)...)
	conn, err := net.Dial("unix", c.Path)
	if err != nil {
		t.Fatal(err)
	}
	conn.Write(b)
	conn.(*net.UnixConn).CloseWrite()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	line, _ := bufio.NewReader(conn).ReadString('\n')
	conn.Close()
	if strings.TrimSpace(line) != `{"error":"bad_request"}` {
		t.Fatalf("short payload: %q", line)
	}
	// And the service still answers.
	if _, err := c.Detect(context.Background(), gray(4, 4, 0)); err != nil {
		t.Fatal(err)
	}
}

// The service checks its runtime's answer as the client does, so a
// runtime that answers off the list, outside the frame or with an id it
// was not lent is unavailable, and the next call reloads.
func TestServiceChecksItsRuntime(t *testing.T) {
	f := newFake()
	c := start(t, newService(Config{CallTimeout: 200 * time.Millisecond}, f, nil))
	for _, mode := range []string{"crash", "panic", "hang", "off-list", "outside", "enrolled"} {
		f.failNext(mode, 1)
		before := f.loads
		_, err := c.Detect(context.Background(), gray(8, 8, 0))
		if !isCause(err, vision.Unavailable) {
			t.Errorf("%s: %v", mode, err)
		}
		if _, err := c.Detect(context.Background(), gray(8, 8, 0)); err != nil {
			t.Errorf("%s: no recovery: %v", mode, err)
		}
		if f.loads <= before {
			t.Errorf("%s: not reloaded", mode)
		}
	}
	f.failNext("off-list", 1)
	if _, err := c.Sound(context.Background(), make([]byte, 320)); !isCause(err, vision.Unavailable) {
		t.Errorf("sound off the list: %v", err)
	}
}

func TestServiceReportsMissingAndCorrupt(t *testing.T) {
	for _, c := range []struct {
		err   error
		model Model
		want  vision.Cause
	}{
		{ErrMissing, Model{}, vision.Missing},
		{ErrRefused, Model{}, vision.Corrupt},
		{errors.New("runtime binary absent"), Model{}, vision.Unavailable},
		{nil, Model{Name: "Free text model", SHA256: sha}, vision.Corrupt},
		{nil, Model{Name: "vis", SHA256: "abc"}, vision.Corrupt},
	} {
		f := newFake()
		f.loadErr, f.model = c.err, c.model
		cl := start(t, newService(Config{Retry: time.Hour}, f, nil))
		if _, err := cl.Hello(context.Background()); !isCause(err, c.want) {
			t.Errorf("%v %+v: %v, want %s", c.err, c.model, err, c.want)
		}
		if _, err := cl.Detect(context.Background(), gray(2, 2, 0)); !isCause(err, c.want) {
			t.Errorf("%v %+v: detect %v, want %s", c.err, c.model, err, c.want)
		}
	}
}

// REQ: RES-3
//
// The service needs no accelerator: it reports the CPU and answers every
// op with nothing but the CPU, and it links no accelerator discovery.
func TestRunsWithNoAccelerator(t *testing.T) {
	c := start(t, newService(Config{}, newFake(), nil))
	in, err := c.Hello(context.Background())
	if err != nil || in.Device != vision.DeviceCPU {
		t.Fatalf("hello: %+v, %v", in, err)
	}
	if _, err := c.Detect(context.Background(), gray(16, 16, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sound(context.Background(), make([]byte, 320)); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range strings.Fields(string(out)) {
		if p == "github.com/ghbmrk/agentos/broker/accel" {
			t.Fatal("agentos-vision links accelerator discovery")
		}
	}
}

// At most Concurrent payloads are held: a burst queues before its frames
// are read.
func TestServiceCapsHeldPayloads(t *testing.T) {
	f := newFake()
	f.gate = make(chan struct{})
	s := newService(Config{Concurrent: 2}, f, nil)
	c := start(t, s)
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Detect(context.Background(), gray(8, 8, 0))
		}()
	}
	time.Sleep(200 * time.Millisecond)
	f.mu.Lock()
	in := f.inside
	f.mu.Unlock()
	close(f.gate)
	wg.Wait()
	if f.maxIn > 2 || in != 2 {
		t.Fatalf("%d calls in flight at most, %d while blocked", f.maxIn, in)
	}
	if p := peak(s); p > 2 {
		t.Fatalf("%d payloads held at once", p)
	}
}

// A runtime call that outlives its deadline keeps its frame, so it keeps
// its slot until it returns: timed-out calls cannot pile up frames.
func TestTimedOutCallKeepsItsSlot(t *testing.T) {
	f := newFake()
	s := newService(Config{Concurrent: 1, CallTimeout: 50 * time.Millisecond}, f, nil)
	c := start(t, s)
	f.failNext("slow", 4)
	for range 4 {
		if _, err := c.Detect(context.Background(), gray(8, 8, 0)); !isCause(err, vision.Unavailable) {
			t.Fatalf("slow call: %v", err)
		}
	}
	f.mu.Lock()
	maxIn := f.maxIn
	f.mu.Unlock()
	if p := peak(s); maxIn > 1 || p > 1 {
		t.Fatalf("%d runtime calls and %d payloads at once, over Concurrent 1", maxIn, p)
	}
	if _, err := c.Detect(context.Background(), gray(8, 8, 0)); err != nil {
		t.Fatalf("after the slow calls: %v", err)
	}
}

// REQ: DEV-7
//
// A frame's buffer is zeroed once the runtime is done with it.
func TestPayloadZeroedAfterUse(t *testing.T) {
	f := newFake()
	c := start(t, newService(Config{}, f, nil))
	if _, err := c.Detect(context.Background(), gray(8, 8, 'Q')); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	last := f.last
	f.mu.Unlock()
	if len(last) != 64 || bytes.ContainsRune(last, 'Q') {
		t.Fatalf("frame buffer after use: %q", last)
	}
}

// REQ: DEV-7
//
// The service's log carries counts and causes only: no frame byte, no
// plate, no runtime text.
func TestLogsCarryNoCapture(t *testing.T) {
	var log lockedBuffer
	f := newFake()
	c := start(t, newService(Config{}, f, &log))
	c.Detect(context.Background(), gray(8, 8, 'Q'))
	f.failNext("plate", 1)
	if ds, err := c.Detect(context.Background(), gray(8, 8, 'Q')); err != nil || ds[0].Plate != "CANARY 9" {
		t.Fatalf("plate: %+v, %v", ds, err)
	}
	f.failNext("crash", 1)
	c.Detect(context.Background(), gray(8, 8, 'Q'))
	c.Sound(context.Background(), bytes.Repeat([]byte{'Q'}, 320))
	got := log.String()
	for _, bad := range []string{"QQQQ", "CANARY", "0xCAFE", "segfault", "person"} {
		if strings.Contains(got, bad) {
			t.Errorf("log holds %q:\n%s", bad, got)
		}
	}
	if !strings.Contains(got, "1 detections") {
		t.Errorf("log has no counts:\n%s", got)
	}
}

// REQ: KRN-3
//
// main serves the listener it is handed as fd 3 and names no socket of its
// own; with no runtime in this build it answers, Unavailable.
func TestMainServesTheListenerOnFD3(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "vision.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	lf, err := ul.File()
	if err != nil {
		t.Fatal(err)
	}
	ul.Close() // the child holds the only copy now
	var stderr lockedBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := childproc.Command(ctx, childproc.NewEnv("PATH=/usr/bin:/bin"),
		childproc.Options{Dir: dir, Stderr: &stderr, ExtraFiles: []*os.File{lf}, WaitDelay: time.Second},
		os.Args[0], helperArg)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lf.Close()
	defer func() { cancel(); cmd.Wait() }()
	c := vision.Client{Path: sock, Timeout: 5 * time.Second}
	if _, err := c.Hello(context.Background()); !isCause(err, vision.Unavailable) {
		t.Fatalf("hello: %v (log: %s)", err, stderr.String())
	}
	if _, err := c.Detect(context.Background(), gray(4, 4, 0)); !isCause(err, vision.Unavailable) {
		t.Fatalf("detect: %v", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("the service made files beside its socket: %v", ents)
	}
}

// isCause reports a failed call with cause c.
func isCause(err error, c vision.Cause) bool { return err != nil && vision.CauseOf(err) == c }

// peak is the most payloads s held at once.
func peak(s *service) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peak
}
