package main

// REQ: KRN-3, DEV-7
//
// Kills for the service.go statement deletions that mutgate run
// 44872395344 found alive (MUT-kill-6409-vision, #6457): each test names
// the lines whose deletion it catches.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/vision"
)

// stubRT is a Runtime whose every answer a test sets; a nil func answers
// as a ready runtime with nothing seen.
type stubRT struct {
	mu     sync.Mutex
	loads  int
	load   func() (Model, error)
	detect func(vision.Frame, bool) ([]Seen, error)
	encode func(vision.Frame) ([]float32, error)
	sound  func([]byte) ([]vision.Sound, error)
}

func (r *stubRT) Load() (Model, error) {
	r.mu.Lock()
	r.loads++
	r.mu.Unlock()
	if r.load != nil {
		return r.load()
	}
	return Model{Name: "vis-stub", SHA256: sha}, nil
}

func (r *stubRT) Detect(f vision.Frame, enc bool) ([]Seen, error) {
	if r.detect != nil {
		return r.detect(f, enc)
	}
	return nil, nil
}

func (r *stubRT) Encode(f vision.Frame) ([]float32, error) {
	if r.encode != nil {
		return r.encode(f)
	}
	return []float32{1, 0, 0}, nil
}

func (r *stubRT) Sound(p []byte) ([]vision.Sound, error) {
	if r.sound != nil {
		return r.sound(p)
	}
	return nil, nil
}

func (r *stubRT) loaded() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loads
}

// scriptConn is a net.Conn that reads a fixed input and records a copy
// of each Write, and the slice as given in sent, failing every write when
// failWrite is set.
type scriptConn struct {
	in        io.Reader
	failWrite bool
	writes    [][]byte
	sent      [][]byte
}

func (c *scriptConn) Read(p []byte) (int, error) { return c.in.Read(p) }
func (c *scriptConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.sent = append(c.sent, p)
	if c.failWrite {
		return 0, errors.New("peer gone")
	}
	return len(p), nil
}
func (c *scriptConn) Close() error                     { return nil }
func (c *scriptConn) LocalAddr() net.Addr              { return nil }
func (c *scriptConn) RemoteAddr() net.Addr             { return nil }
func (c *scriptConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptConn) SetWriteDeadline(time.Time) error { return nil }

// drive runs one connection over input and returns the reply lines it
// wrote, copied, without their newlines.
func drive(s *service, control bool, input []byte) []string {
	c := &scriptConn{in: bytes.NewReader(input)}
	s.conn(c, control)
	var out []string
	for _, w := range c.writes {
		out = append(out, strings.TrimSuffix(string(w), "\n"))
	}
	return out
}

func header(t *testing.T, r vision.Request) []byte {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func f32s(v ...float32) []byte {
	b := make([]byte, 0, 4*len(v))
	for _, x := range v {
		b = binary.LittleEndian.AppendUint32(b, math.Float32bits(x))
	}
	return b
}

func lendPayload(t *testing.T, ts ...vision.Template) []byte {
	t.Helper()
	p, err := vision.EncodeLend(ts)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("never: %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// Unset or out-of-range settings take their defaults (lines 146-147,
// 152-153).
func TestServiceDefaults(t *testing.T) {
	s := newService(Config{}, &stubRT{}, nil)
	want := Config{Concurrent: 2, CallTimeout: 10 * time.Second, Retry: 10 * time.Second, Idle: time.Minute, Match: DefaultMatch}
	if s.cfg != want {
		t.Fatalf("defaults: %+v, want %+v", s.cfg, want)
	}
	for _, m := range []float64{-0.5, 1.5} {
		if got := newService(Config{Match: m}, &stubRT{}, nil).cfg.Match; got != DefaultMatch {
			t.Errorf("Match %v became %v, want %v", m, got, DefaultMatch)
		}
	}
	if got := newService(Config{Match: 0.9, Retry: time.Hour}, &stubRT{}, nil).cfg; got.Match != 0.9 || got.Retry != time.Hour {
		t.Errorf("set values not kept: %+v", got)
	}
}

// timeoutErr is a net.Error that timed out.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "accept timed out" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// errListener fails each Accept with the next error.
type errListener struct{ errs []error }

func (l *errListener) Accept() (net.Conn, error) {
	err := l.errs[0]
	l.errs = l.errs[1:]
	return nil, err
}
func (l *errListener) Close() error   { return nil }
func (l *errListener) Addr() net.Addr { return nil }

// An Accept that times out is retried; any other failure ends Serve
// (line 175).
func TestServeRetriesAcceptTimeouts(t *testing.T) {
	end := errors.New("listener closed")
	s := newService(Config{}, &stubRT{}, nil)
	if err := s.Serve(&errListener{errs: []error{timeoutErr{}, timeoutErr{}, end}}); err != end {
		t.Fatalf("Serve returned %v, want the listener's own failure", err)
	}
}

// A connection that sends nothing is closed once Idle passes (line 193).
func TestIdleConnectionIsClosed(t *testing.T) {
	c := start(t, newService(Config{Idle: 50 * time.Millisecond}, &stubRT{}, nil))
	conn, err := net.Dial("unix", c.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("an idle connection read %d bytes, %v; want the service to close it", n, err)
	}
}

// A header over its bound is answered once, logged, and ends the
// connection even with a good request behind it (line 196).
func TestOverlongHeaderEndsTheConnection(t *testing.T) {
	log := &lockedBuffer{}
	s := newService(Config{}, &stubRT{}, log)
	in := append(bytes.Repeat([]byte(" "), vision.MaxHeaderLine+1), '\n')
	in = append(in, header(t, vision.Request{Op: vision.OpHello})...)
	if got := drive(s, false, in); len(got) != 1 || got[0] != `{"error":"bad_request"}` {
		t.Fatalf("replies: %q", got)
	}
	if !strings.Contains(log.String(), "header line over") {
		t.Fatalf("log: %q", log.String())
	}
}

// A peer that closes before a header gets no reply (lines 200-201).
func TestClosedPeerGetsNoReply(t *testing.T) {
	s := newService(Config{}, &stubRT{}, nil)
	for _, in := range []string{"", `{"op":"hello"}`} { // nothing; a line with no newline
		if got := drive(s, false, []byte(in)); len(got) != 0 {
			t.Errorf("%q: replies %q", in, got)
		}
	}
}

// A request outside the bounds or on the wrong socket is logged by op
// (line 211).
func TestBadRequestIsLogged(t *testing.T) {
	log := &lockedBuffer{}
	s := newService(Config{}, &stubRT{}, log)
	if got := drive(s, false, header(t, vision.Request{Op: vision.OpLend})); len(got) != 1 || got[0] != `{"error":"bad_request"}` {
		t.Fatalf("lend on the feed socket: %q", got)
	}
	if !strings.Contains(log.String(), "vision: bad lend request (0 bytes)") {
		t.Fatalf("log: %q", log.String())
	}
}

// A reply the peer did not take ends the connection: no later request is
// answered (line 218).
func TestFailedWriteEndsTheConnection(t *testing.T) {
	s := newService(Config{}, &stubRT{}, nil)
	h := header(t, vision.Request{Op: vision.OpHello})
	c := &scriptConn{in: bytes.NewReader(append(append([]byte{}, h...), h...)), failWrite: true}
	s.conn(c, false)
	if len(c.writes) != 1 {
		t.Fatalf("%d writes after the first failed", len(c.writes))
	}
}

// opName names each op and nothing else (lines 226-228).
func TestOpName(t *testing.T) {
	for _, op := range []string{vision.OpHello, vision.OpDetect, vision.OpSound, vision.OpEnrol, vision.OpLend} {
		if got := opName(op); got != op {
			t.Errorf("opName(%q) = %q", op, got)
		}
	}
	if got := opName("frame bytes 0xCAFE"); got != "unknown" {
		t.Errorf("an unknown op logged as %q", got)
	}
}

// A reply over the line bound goes as unavailable (line 238).
func TestOversizeReplyGoesUnavailable(t *testing.T) {
	log := &lockedBuffer{}
	s := newService(Config{}, &stubRT{}, log)
	c := &scriptConn{in: bytes.NewReader(nil)}
	if !s.write(c, vision.Reply{Template: make([]byte, vision.MaxReplyLine)}) {
		t.Fatal("write failed")
	}
	if len(c.writes) != 1 || string(c.writes[0]) != "{\"error\":\"unavailable\"}\n" {
		t.Fatalf("wrote %.80q", c.writes)
	}
	if !strings.Contains(log.String(), "reply over") {
		t.Fatalf("log: %q", log.String())
	}
}

// A reply the peer never reads gives up at CallTimeout (line 242).
func TestWriteHasADeadline(t *testing.T) {
	s := newService(Config{CallTimeout: 50 * time.Millisecond}, &stubRT{}, nil)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	done := make(chan bool, 1)
	go func() { done <- s.write(a, vision.Reply{State: vision.StateReady}) }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("an unread reply was reported sent")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a reply nobody reads held the connection past CallTimeout")
	}
}

// The reply line's buffer is zeroed once sent, since an enrol reply's
// line holds a template as text (line 245). The conn keeps the slice it
// was handed, which shares the line's buffer when that has room for the
// newline.
func TestReplyLineZeroedAfterWrite(t *testing.T) {
	s := newService(Config{}, &stubRT{}, nil)
	rep := vision.Reply{Template: f32s(0.25, -0.5, 1, 2)}
	b, _ := json.Marshal(rep)
	if cap(b) == len(b) {
		t.Fatal("this reply's line has no room for its newline, so the conn's slice is a copy and the line 245 wipe goes unchecked")
	}
	c := &scriptConn{in: bytes.NewReader(nil)}
	if !s.write(c, rep) {
		t.Fatal("write failed")
	}
	if len(c.writes) != 1 {
		t.Fatalf("wrote %q", c.writes)
	}
	if string(c.writes[0]) != string(b)+"\n" {
		t.Fatalf("wrote %q, want %q", c.writes[0], b)
	}
	if !zero(c.sent[0][:len(b)]) {
		t.Fatalf("the sent line was left in memory: %q", c.sent[0])
	}
}

// stuckEnv makes the test binary, re-run by TestDefaultStuckExits, call
// the default stuck and report back through its exit status.
const stuckEnv = "AGENTOS_VISION_DEFAULT_STUCK"

// A runtime call wedged past CallTimeout still holds its payload, so the
// default stuck ends the process with status 1 rather than serve on
// (line 159). The child runs it; the parent checks the exit.
func TestDefaultStuckExits(t *testing.T) {
	if os.Getenv(stuckEnv) == "1" {
		newService(Config{}, &stubRT{}, nil).stuck()
		os.Exit(0) // reached only when stuck returns
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDefaultStuckExits$", "-test.count=1")
	cmd.Env = append(os.Environ(), stuckEnv+"=1")
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 {
		t.Fatalf("default stuck: %v, want exit status 1", err)
	}
}

// One request holds one payload, and gives it back (lines 272, 420-421).
func TestHeldPayloadsCounted(t *testing.T) {
	s := newService(Config{}, &stubRT{}, nil)
	fr := gray(4, 4, 7)
	in := append(header(t, vision.Request{Op: vision.OpDetect, Format: fr.Format, Width: 4, Height: 4, Bytes: 16}), fr.Data...)
	if got := drive(s, false, in); len(got) != 1 || strings.Contains(got[0], "error") {
		t.Fatalf("detect: %q", got)
	}
	s.mu.Lock()
	held, pk := s.held, s.peak
	s.mu.Unlock()
	if held != 0 || pk != 1 {
		t.Fatalf("held %d, peak %d; want 0 and 1", held, pk)
	}
}

// A short payload is logged (line 274).
func TestShortPayloadLogged(t *testing.T) {
	log := &lockedBuffer{}
	s := newService(Config{}, &stubRT{}, log)
	in := append(header(t, vision.Request{Op: vision.OpDetect, Format: vision.FormatGray8, Width: 4, Height: 4, Bytes: 16}), 1, 2, 3)
	if got := drive(s, false, in); len(got) != 1 || got[0] != `{"error":"bad_request"}` {
		t.Fatalf("short payload: %q", got)
	}
	if !strings.Contains(log.String(), "vision: detect payload short of 16 bytes") {
		t.Fatalf("log: %q", log.String())
	}
}

// A lend that does not decode is bad_request and keeps the templates
// held; one that does is logged with its count (lines 281, 284, 590).
func TestLendRefusesABadPayload(t *testing.T) {
	log := &lockedBuffer{}
	s := newService(Config{}, &stubRT{}, log)
	good := lendPayload(t, vision.Template{ID: "alice", Vec: f32s(1, 0, 0)})
	in := append(header(t, vision.Request{Op: vision.OpLend, Bytes: len(good)}), good...)
	if got := drive(s, true, in); len(got) != 1 || got[0] != `{"state":"ready"}` {
		t.Fatalf("good lend: %q", got)
	}
	if !strings.Contains(log.String(), "vision: 1 templates lent") {
		t.Fatalf("log: %q", log.String())
	}
	bad := good[:len(good)-1] // cut short
	in = append(header(t, vision.Request{Op: vision.OpLend, Bytes: len(bad)}), bad...)
	if got := drive(s, true, in); len(got) != 1 || got[0] != `{"error":"bad_request"}` {
		t.Fatalf("bad lend: %q", got)
	}
	if n, err := s.lend(bad); err == nil || n != 0 {
		t.Fatalf("lend of a cut payload: %d, %v", n, err)
	}
	if !s.enrolled("alice") {
		t.Fatal("a refused lend dropped the templates held")
	}
}

// Enrolment's answers are each logged, and a failed encode is
// unavailable on the wire (lines 313, 315, 318).
func TestEnrolAnswers(t *testing.T) {
	fr := gray(4, 4, 9)
	req := append(header(t, vision.Request{Op: vision.OpEnrol, Format: fr.Format, Width: 4, Height: 4, Bytes: 16}), fr.Data...)
	for _, c := range []struct {
		name  string
		enc   func(vision.Frame) ([]float32, error)
		reply string
		log   string
	}{
		{"one face", nil, `{"template":"` + b64(f32s(1, 0, 0)) + `"}`, "vision: enrolment template made in"},
		{"no face", func(vision.Frame) ([]float32, error) { return nil, ErrNoFace }, `{"error":"no_face"}`, "enrolment frame without one clear face"},
		{"crash", func(vision.Frame) ([]float32, error) { return nil, errors.New("boom") }, `{"error":"unavailable"}`, "runtime failed; reloading"},
	} {
		log := &lockedBuffer{}
		s := newService(Config{}, &stubRT{encode: c.enc}, log)
		if got := drive(s, true, req); len(got) != 1 || got[0] != c.reply {
			t.Errorf("%s: %q, want %s", c.name, got, c.reply)
		}
		if !strings.Contains(log.String(), c.log) {
			t.Errorf("%s: log %q", c.name, log.String())
		}
	}
}

func b64(b []byte) string {
	j, _ := json.Marshal(b)
	return strings.Trim(string(j), `"`)
}

// A sound answer is logged with its count (line 326).
func TestSoundLogged(t *testing.T) {
	log := &lockedBuffer{}
	s := newService(Config{}, &stubRT{sound: func([]byte) ([]vision.Sound, error) {
		return []vision.Sound{{Label: "glass-break", Conf: 90}}, nil
	}}, log)
	in := append(header(t, vision.Request{Op: vision.OpSound, Format: vision.AudioPCM16k, Bytes: 320}), make([]byte, 320)...)
	if got := drive(s, false, in); len(got) != 1 || !strings.Contains(got[0], "glass-break") {
		t.Fatalf("sound: %q", got)
	}
	if !strings.Contains(log.String(), "vision: 320 audio bytes, 1 sounds in") {
		t.Fatalf("log: %q", log.String())
	}
}

// An op with no model in this build is logged as such and is no reload
// (line 378).
func TestNoModelLogged(t *testing.T) {
	log := &lockedBuffer{}
	rt := &stubRT{detect: func(vision.Frame, bool) ([]Seen, error) { return nil, ErrNoModel }}
	s := newService(Config{}, rt, log)
	fr := gray(4, 4, 0)
	in := append(header(t, vision.Request{Op: vision.OpDetect, Format: fr.Format, Width: 4, Height: 4, Bytes: 16}), fr.Data...)
	if got := drive(s, false, in); len(got) != 1 || got[0] != `{"error":"unavailable"}` {
		t.Fatalf("detect: %q", got)
	}
	if got := log.String(); !strings.Contains(got, "vision: no model for this op") || strings.Contains(got, "reloading") {
		t.Fatalf("log: %q", got)
	}
}

// A timed-out call is logged, reloads at once without waiting for the
// next request, and that reload ends it, so the service is not taken
// for stuck (lines 391, 394).
func TestTimedOutCallReloadsAtOnce(t *testing.T) {
	log := &lockedBuffer{}
	f := newFake()
	s := newService(Config{CallTimeout: 50 * time.Millisecond}, f, log)
	stuck := make(chan struct{}, 1)
	s.stuck = func() { stuck <- struct{}{} }
	c := start(t, s)
	if _, err := c.Hello(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.failNext("hang", 1)
	if _, err := c.Detect(t.Context(), gray(4, 4, 0)); !isCause(err, vision.Unavailable) {
		t.Fatalf("hung call: %v", err)
	}
	waitFor(t, "the late answer discarded", func() bool { return strings.Contains(log.String(), "late runtime answer was discarded") })
	if !strings.Contains(log.String(), "vision: runtime timed out; reloading") {
		t.Fatalf("log: %q", log.String())
	}
	f.mu.Lock()
	loads := f.loads
	f.mu.Unlock()
	if loads != 2 {
		t.Fatalf("%d loads, want the first and the reload", loads)
	}
	select {
	case <-stuck:
		t.Fatal("the reload did not end the hung call")
	default:
	}
}

// A call the reload does not end is logged before the service exits
// (line 401).
func TestStuckCallLogged(t *testing.T) {
	log := &lockedBuffer{}
	f := newFake()
	f.wedge = make(chan struct{})
	t.Cleanup(func() { close(f.wedge) })
	s := newService(Config{CallTimeout: 20 * time.Millisecond}, f, log)
	exited := make(chan struct{})
	s.stuck = func() { close(exited) }
	c := start(t, s)
	f.failNext("wedge", 1)
	c.Detect(t.Context(), gray(4, 4, 0))
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("never taken for stuck")
	}
	if !strings.Contains(log.String(), "runtime call stuck after the reload; exiting") {
		t.Fatalf("log: %q", log.String())
	}
}

// Two calls that find no load load once: the second, waiting on the
// first's load, takes it (lines 448, 450-451).
func TestConcurrentReadyLoadsOnce(t *testing.T) {
	gate := make(chan struct{})
	entered := make(chan struct{}, 2)
	rt := &stubRT{}
	rt.load = func() (Model, error) {
		entered <- struct{}{}
		<-gate
		return Model{Name: "vis-stub", SHA256: sha}, nil
	}
	s := newService(Config{}, rt, nil)
	got := make(chan loaded, 2)
	go func() { got <- s.ready() }()
	<-entered // the first holds the load lock
	go func() { got <- s.ready() }()
	time.Sleep(200 * time.Millisecond) // the second waits on it
	close(gate)
	for range 2 {
		if l := <-got; l.cause != "" || l.model.Name != "vis-stub" {
			t.Fatalf("ready: %+v", l)
		}
	}
	if n := rt.loaded(); n != 1 {
		t.Fatalf("%d loads, want 1", n)
	}
}

// A load is logged either way, and a failed one keeps no model name
// (lines 474-475, 477-478).
func TestLoadLoggedAndFailedLoadNamesNoModel(t *testing.T) {
	log := &lockedBuffer{}
	s := newService(Config{}, &stubRT{}, log)
	if l := s.ready(); l.cause != "" {
		t.Fatalf("load: %+v", l)
	}
	if !strings.Contains(log.String(), "vision: models loaded in") {
		t.Fatalf("log: %q", log.String())
	}
	log = &lockedBuffer{}
	s = newService(Config{}, &stubRT{load: func() (Model, error) { return Model{Name: "vis", SHA256: sha}, ErrMissing }}, log)
	if l := s.ready(); l.cause != vision.Missing || l.model != (Model{}) {
		t.Fatalf("failed load: %+v", l)
	}
	s.mu.Lock()
	m := s.cur.model
	s.mu.Unlock()
	if m != (Model{}) {
		t.Fatalf("a failed load kept model %+v", m)
	}
	if !strings.Contains(log.String(), "vision: models not loaded: missing") {
		t.Fatalf("log: %q", log.String())
	}
}

// detect refuses more detections than a reply holds itself, before
// naming any face (line 499).
func TestDetectRefusesTooMany(t *testing.T) {
	seen := make([]Seen, vision.MaxDetections+1)
	for i := range seen {
		seen[i] = Seen{Detection: vision.Detection{Class: vision.Person, Box: vision.Box{X1: 1, Y1: 1}, Conf: 50}}
	}
	s := newService(Config{}, &stubRT{detect: func(vision.Frame, bool) ([]Seen, error) { return seen, nil }}, nil)
	if ds, err := s.detect(gray(4, 4, 0)); err != errMalformed || ds != nil {
		t.Fatalf("%d detections: %d back, %v", len(seen), len(ds), err)
	}
}

// A template of another length than the face is skipped, not compared
// (line 526).
func TestNameSkipsOtherLengths(t *testing.T) {
	s := newService(Config{}, &stubRT{}, nil)
	s.tpl = map[string][]float32{"long": {1, 0, 0, 0}, "alice": {0, 1, 0}}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("name compared a template of another length: %v", r)
		}
	}()
	if got := s.name([]float32{1, 0, 0}); got != vision.FaceUnknown {
		t.Fatalf("named %q", got)
	}
	if got := s.name([]float32{0, 2, 0}); got != vision.FaceEnrolledAs+"alice" {
		t.Fatalf("named %q", got)
	}
}

// enrolled gives its read lock back, so a lend can follow (line 562).
func TestEnrolledReleasesItsLock(t *testing.T) {
	s := newService(Config{}, &stubRT{}, nil)
	s.enrolled("alice")
	done := make(chan error, 1)
	go func() {
		_, err := s.lend(lendPayload(t, vision.Template{ID: "alice", Vec: f32s(1)}))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a lend after enrolled never got the lock")
	}
}

// encode refuses an empty or oversize encoding itself (line 575).
func TestEncodeRefusesOutOfBounds(t *testing.T) {
	for _, n := range []int{0, vision.MaxTemplate/4 + 1} {
		v := make([]float32, n)
		for i := range v {
			v[i] = 1
		}
		s := newService(Config{}, &stubRT{encode: func(vision.Frame) ([]float32, error) { return v, nil }}, nil)
		if b, err := s.encode(gray(4, 4, 0)); err != errMalformed || b != nil {
			t.Errorf("%d floats: %d bytes, %v", n, len(b), err)
		}
	}
}

// A lent template is held at unit length, and the set it replaces is
// zeroed (lines 607-608, 616-617).
func TestLendScalesAndZeroesTheOldSet(t *testing.T) {
	s := newService(Config{}, &stubRT{}, nil)
	if _, err := s.lend(lendPayload(t, vision.Template{ID: "alice", Vec: f32s(0.06, -0.08, 0)})); err != nil {
		t.Fatal(err)
	}
	old := s.tpl["alice"]
	if math.Abs(norm(old)-1) > 1e-6 {
		t.Fatalf("lent template held at length %v: %v", norm(old), old)
	}
	if got := s.name([]float32{0.6, -0.8, 0}); got != vision.FaceEnrolledAs+"alice" {
		t.Fatalf("the face the short template points at named %q", got)
	}
	if _, err := s.lend(lendPayload(t, vision.Template{ID: "bob", Vec: f32s(0, 1, 0)})); err != nil {
		t.Fatal(err)
	}
	for _, x := range old {
		if x != 0 {
			t.Fatalf("the replaced template was not zeroed: %v", old)
		}
	}
}
