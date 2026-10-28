package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/vision"
)

// Runtime is the model runtime behind the service: one adapter file
// (runtime_<name>.go) implements it, so the runtime choice changes one file
// (VIS-core part e). Load loads the models, replacing whatever was loaded,
// and names them. Detect and Sound answer one frame or clip; the service
// checks what they return as the client will. Encode is the enrolment
// frame's one face's encoding, ErrNoFace when there is not exactly one
// clear face. All may be called from several goroutines; a Load must make
// a call still running on the old load return, since that call holds a
// frame and its slot until it does.
//
// A face's encoding comes back in Seen.Face, never in the detection: the
// service compares it with the lent templates, names the face, and zeroes
// the encoding before anything is sent (DEV-7, D-207). The runtime keeps
// no copy.
type Runtime interface {
	Load() (Model, error)
	Detect(f vision.Frame) ([]Seen, error)
	Encode(f vision.Frame) ([]float32, error)
	Sound(pcm []byte) ([]vision.Sound, error)
}

// Seen is one detection as the runtime gives it: the detection, with Face
// unset, and, for a person whose face it saw, that face's encoding.
type Seen struct {
	vision.Detection
	Face []float32
}

// Model names what a Runtime loaded: a name from [a-z0-9._-] and the
// SHA-256 of its model files.
type Model struct {
	Name, SHA256 string
}

// ErrMissing and ErrRefused are a Runtime's answers to absent and
// unusable model files: the service reports them as Missing and Corrupt.
// Any other Load error is Unavailable.
var (
	ErrMissing = errors.New("model files absent")
	ErrRefused = errors.New("runtime refused the model files")
)

// ErrNoFace is Encode's answer to an enrolment frame without exactly one
// clear face: the service reports it as NoFace, and it is no failure of
// the runtime.
var ErrNoFace = errors.New("not exactly one clear face")

// Config is the service's settings, from its flags.
type Config struct {
	// Concurrent bounds the requests whose payload is held or whose
	// runtime call is in flight, so a burst queues rather than
	// multiplying memory (2 by default).
	Concurrent int
	// CallTimeout bounds one runtime call; past it the call is
	// Unavailable and the runtime is reloaded.
	CallTimeout time.Duration
	// Retry is the least time between two loads that failed.
	Retry time.Duration
	// Idle bounds the wait for a request on an open connection, and for
	// its payload.
	Idle time.Duration
	// Match is the least cosine similarity between a face's encoding and
	// an enrolled template that names the face; below it on every
	// template the face is unknown. It depends on the encoder (part e);
	// 0 is DefaultMatch.
	Match float64
}

// DefaultMatch is Match when none is set.
const DefaultMatch = 0.6

// loaded is the outcome of the last load.
type loaded struct {
	cause vision.Cause // "" when ready
	model Model
	at    time.Time
}

// service answers the vision protocol on a listener. Its log carries
// causes, counts, sizes and durations only, never a frame, a clip, a
// detection's content or anything the runtime says (DEV-7); the
// supervisor drops it anyway (vision/supervise), so it is for tests and
// a developer's terminal.
type service struct {
	cfg  Config
	rt   Runtime
	log  io.Writer
	sem  chan struct{}
	load sync.Mutex // one load at a time

	// stuck ends the process when a timed-out runtime call has not
	// returned even after the reload: the supervisor restarts the
	// service, which frees its slot and frame (os.Exit; tests replace
	// it).
	stuck func()

	mu   sync.Mutex
	cur  loaded
	held int // payloads allocated and not yet released
	peak int // the most held at once

	// tpl is the lent templates by id, each scaled to unit length. A
	// lend replaces the whole set and zeroes the old one; a compare
	// holds tmu's read lock while it reads them.
	tmu sync.RWMutex
	tpl map[string][]float32
}

func newService(cfg Config, rt Runtime, log io.Writer) *service {
	if cfg.Concurrent <= 0 {
		cfg.Concurrent = 2
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = 10 * time.Second
	}
	if cfg.Retry <= 0 {
		cfg.Retry = 10 * time.Second
	}
	if cfg.Idle <= 0 {
		cfg.Idle = time.Minute
	}
	if cfg.Match <= 0 || cfg.Match > 1 {
		cfg.Match = DefaultMatch
	}
	if log == nil {
		log = io.Discard
	}
	return &service{cfg: cfg, rt: rt, log: log, sem: make(chan struct{}, cfg.Concurrent),
		stuck: func() { os.Exit(1) }, cur: loaded{cause: vision.Unavailable}}
}

// Serve answers each connection on the feed socket on its own goroutine
// until ln fails: hello, detect and sound.
func (s *service) Serve(ln net.Listener) error { return s.serve(ln, false) }

// ServeControl answers the control socket the same way: enrol and lend,
// and nothing else.
func (s *service) ServeControl(ln net.Listener) error { return s.serve(ln, true) }

func (s *service) serve(ln net.Listener, control bool) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go s.conn(c, control)
	}
}

// conn answers requests until the peer closes or idles. A header that is
// over its bound, malformed or outside the bounds, or whose op is not this
// socket's, is answered BadRequest and ends the connection, since its
// payload's length is not known: the payload is never read, so a bad
// header cannot make the service hold it.
func (s *service) conn(c net.Conn, control bool) {
	defer c.Close()
	r := bufio.NewReaderSize(c, 4<<10)
	for {
		c.SetReadDeadline(time.Now().Add(s.cfg.Idle))
		line, err := vision.ReadLine(r, vision.MaxHeaderLine)
		if err == vision.ErrLineTooLong {
			fmt.Fprintf(s.log, "vision: header line over %d bytes\n", vision.MaxHeaderLine)
			s.write(c, errReply(vision.BadRequest))
			return
		}
		if err != nil {
			return
		}
		var req vision.Request
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			s.write(c, errReply(vision.BadRequest))
			return
		}
		if err := req.Check(); err != nil || vision.Control(req.Op) != control {
			fmt.Fprintf(s.log, "vision: bad %s request (%d bytes)\n", opName(req.Op), req.Bytes)
			s.write(c, errReply(vision.BadRequest))
			return
		}
		rep := s.answer(req, r)
		ok := s.write(c, rep)
		clear(rep.Template)
		if !ok {
			return
		}
	}
}

// opName is a request's op for the log: one of the three, or "unknown".
func opName(op string) string {
	switch op {
	case vision.OpHello, vision.OpDetect, vision.OpSound, vision.OpEnrol, vision.OpLend:
		return op
	}
	return "unknown"
}

func errReply(c vision.Cause) vision.Reply { return vision.Reply{Error: c} }

// write sends one reply line; a reply over the bound goes as Unavailable.
func (s *service) write(c net.Conn, r vision.Reply) bool {
	b, err := json.Marshal(r)
	if err != nil || len(b) > vision.MaxReplyLine {
		fmt.Fprintf(s.log, "vision: reply over %d bytes\n", vision.MaxReplyLine)
		b, _ = json.Marshal(errReply(vision.Unavailable))
	}
	c.SetWriteDeadline(time.Now().Add(s.cfg.CallTimeout))
	_, err = c.Write(append(b, '\n'))
	// An enrol reply's line holds a template as text.
	clear(b[:cap(b)])
	return err == nil
}

// answer reads a checked request's payload from r and answers it. The
// payload is read only once a slot is free, and the slot is given back,
// with the payload zeroed, only when nothing holds the payload any more:
// a runtime call that outlives its deadline keeps both until it returns.
// So at most Concurrent payloads are ever held.
func (s *service) answer(req vision.Request, r io.Reader) vision.Reply {
	s.sem <- struct{}{}
	var payload []byte
	release := func() {
		if payload != nil {
			clear(payload)
			s.hold(-1)
		}
		<-s.sem
	}
	handed := false // to a runtime call, which releases when it returns
	defer func() {
		if !handed {
			release()
		}
	}()
	if req.Bytes > 0 {
		payload = make([]byte, req.Bytes)
		s.hold(1)
		if _, err := io.ReadFull(r, payload); err != nil {
			fmt.Fprintf(s.log, "vision: %s payload short of %d bytes\n", req.Op, req.Bytes)
			return errReply(vision.BadRequest)
		}
	}
	if req.Op == vision.OpLend {
		// Templates need no model: a lend lands while the runtime loads.
		n, err := s.lend(payload)
		if err != nil {
			return errReply(vision.BadRequest)
		}
		fmt.Fprintf(s.log, "vision: %d templates lent\n", n)
		return vision.Reply{State: vision.StateReady}
	}
	cur := s.ready()
	if cur.cause != "" {
		return errReply(cur.cause)
	}
	start := time.Now()
	switch req.Op {
	case vision.OpHello:
		return vision.Reply{State: vision.StateReady, Device: vision.DeviceCPU, Model: cur.model.Name, SHA256: cur.model.SHA256}
	case vision.OpDetect:
		f := vision.Frame{Format: req.Format, Width: req.Width, Height: req.Height, Data: payload}
		handed = true
		ds, err := call(s, cur, release, func() ([]vision.Detection, error) { return s.detect(f) },
			func(ds []vision.Detection) error {
				return vision.CheckDetections(ds, req.Width, req.Height, s.enrolled)
			})
		if err != nil {
			return errReply(vision.Unavailable)
		}
		fmt.Fprintf(s.log, "vision: %dx%d %s frame, %d detections in %s\n", req.Width, req.Height, req.Format, len(ds), since(start))
		return vision.Reply{Detections: ds}
	case vision.OpEnrol:
		f := vision.Frame{Format: req.Format, Width: req.Width, Height: req.Height, Data: payload}
		handed = true
		t, err := call(s, cur, release, func() ([]byte, error) { return s.encode(f) }, vision.CheckTemplate)
		switch {
		case errors.Is(err, ErrNoFace):
			fmt.Fprintln(s.log, "vision: enrolment frame without one clear face")
			return errReply(vision.NoFace)
		case err != nil:
			return errReply(vision.Unavailable)
		}
		fmt.Fprintf(s.log, "vision: enrolment template made in %s\n", since(start))
		return vision.Reply{Template: t}
	default: // vision.OpSound; Check admits no other op with a payload
		handed = true
		ss, err := call(s, cur, release, func() ([]vision.Sound, error) { return s.rt.Sound(payload) }, vision.CheckSounds)
		if err != nil {
			return errReply(vision.Unavailable)
		}
		fmt.Fprintf(s.log, "vision: %d audio bytes, %d sounds in %s\n", req.Bytes, len(ss), since(start))
		return vision.Reply{Sounds: ss}
	}
}

func since(t time.Time) time.Duration { return time.Since(t).Round(time.Millisecond) }

// The causes of a failed call, for the log: fixed text, never the
// runtime's own.
var (
	errCrashed   = errors.New("runtime failed")
	errTimedOut  = errors.New("runtime timed out")
	errMalformed = errors.New("runtime answered outside the protocol")
)

// call runs one runtime call within CallTimeout and checks its answer as
// the client will: a runtime is not trusted to keep its own shape. A
// failed call marks the load it ran on failed, so the next call reloads;
// a timed-out one also reloads at once, which makes it return (Runtime),
// and if it still has not returned three CallTimeouts later the service
// exits rather than hold its slot for ever. release runs when run returns,
// however late, and before the answer is sent, so the frame is zeroed by
// the time any reply leaves.
func call[T any](s *service, on loaded, release func(), run func() (T, error), check func(T) error) (T, error) {
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		var r result
		defer func() {
			if recover() != nil {
				r = result{err: errCrashed}
			}
			release()
			done <- r
		}()
		r.v, r.err = run()
	}()
	t := time.NewTimer(s.cfg.CallTimeout)
	defer t.Stop()
	var zero T
	var err error
	select {
	case r := <-done:
		switch {
		case errors.Is(r.err, ErrNoFace):
			// An answer about the frame, not a failure of the runtime.
			return zero, ErrNoFace
		case r.err != nil:
			err = errCrashed
		case check(r.v) != nil:
			wipe(r.v)
			err = errMalformed
		default:
			return r.v, nil
		}
	case <-t.C:
		err = errTimedOut
	}
	fmt.Fprintf(s.log, "vision: %s; reloading\n", err)
	s.fail(on)
	if err == errTimedOut {
		go s.ready()
		go func() {
			select {
			case r := <-done:
				wipe(r.v) // a late template is zeroed too
			case <-time.After(3 * s.cfg.CallTimeout):
				fmt.Fprintln(s.log, "vision: runtime call stuck after the reload; exiting")
				s.stuck()
			}
		}()
	}
	return zero, err
}

// wipe zeroes a call's answer that will not be sent: an enrolment
// template, the only answer that holds an encoding's bytes.
func wipe[T any](v T) {
	if b, ok := any(v).([]byte); ok {
		clear(b)
	}
}

// hold counts payloads held in and out of their slots.
func (s *service) hold(n int) {
	s.mu.Lock()
	s.held += n
	s.peak = max(s.peak, s.held)
	s.mu.Unlock()
}

// fail marks the load a failed call ran on as unavailable, so the next
// call reloads at once; a load made since is left alone.
func (s *service) fail(on loaded) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur.at.Equal(on.at) {
		s.cur = loaded{cause: vision.Unavailable}
	}
}

// ready returns the current load, loading first when the last one failed
// and is older than Retry (or was marked failed by a call).
func (s *service) ready() loaded {
	fresh := func(l loaded) bool { return l.cause == "" || (!l.at.IsZero() && time.Since(l.at) < s.cfg.Retry) }
	s.mu.Lock()
	cur := s.cur
	s.mu.Unlock()
	if fresh(cur) {
		return cur
	}
	s.load.Lock()
	defer s.load.Unlock()
	s.mu.Lock()
	cur = s.cur
	s.mu.Unlock()
	if fresh(cur) {
		return cur // another call loaded while this one waited
	}
	cur = s.loadModels()
	s.mu.Lock()
	s.cur = cur
	s.mu.Unlock()
	return cur
}

func (s *service) loadModels() loaded {
	start := time.Now()
	m, err := s.rt.Load()
	l := loaded{model: m, at: time.Now()}
	switch {
	case errors.Is(err, ErrMissing):
		l.cause = vision.Missing
	case errors.Is(err, ErrRefused):
		l.cause = vision.Corrupt
	case err != nil:
		l.cause = vision.Unavailable
	case !vision.ValidModelName(m.Name) || !vision.ValidHash(m.SHA256):
		l.cause = vision.Corrupt
	}
	if l.cause == "" {
		fmt.Fprintf(s.log, "vision: models loaded in %s\n", since(start))
	} else {
		l.model = Model{}
		fmt.Fprintf(s.log, "vision: models not loaded: %s\n", l.cause)
	}
	return l
}

// detect runs the runtime on f and names each face it saw: enrolled:<id>
// for the best lent template at or above Match, else unknown. Every
// encoding is zeroed before detect returns, whatever happens, so none
// outlives the call that made it (DEV-7, D-207). A runtime that names a
// face itself, or gives an encoding for anything but a person, is
// answering outside the protocol.
func (s *service) detect(f vision.Frame) ([]vision.Detection, error) {
	seen, err := s.rt.Detect(f)
	defer func() {
		for _, d := range seen {
			clear(d.Face)
		}
	}()
	if err != nil {
		return nil, err
	}
	if len(seen) > vision.MaxDetections {
		return nil, errMalformed
	}
	ds := make([]vision.Detection, len(seen))
	s.tmu.RLock()
	defer s.tmu.RUnlock()
	for i, d := range seen {
		if d.Detection.Face != "" || (d.Face != nil && d.Class != vision.Person) {
			return nil, errMalformed
		}
		ds[i] = d.Detection
		if d.Face != nil {
			ds[i].Face = s.name(d.Face)
		}
	}
	return ds, nil
}

// name is the face's name: the best lent template's id at or above Match,
// else unknown. The caller holds tmu's read lock.
func (s *service) name(face []float32) string {
	best, id := s.cfg.Match, ""
	n := norm(face)
	if n == 0 {
		return vision.FaceUnknown
	}
	for tid, t := range s.tpl {
		if len(t) != len(face) {
			continue
		}
		var dot float64
		for i := range t {
			dot += float64(t[i]) * float64(face[i])
		}
		if c := dot / n; c >= best {
			best, id = c, tid
		}
	}
	if id == "" {
		return vision.FaceUnknown
	}
	return vision.FaceEnrolledAs + id
}

func norm(v []float32) float64 {
	var sum float64
	for _, x := range v {
		sum += float64(x) * float64(x)
	}
	return math.Sqrt(sum)
}

// enrolled reports an id the service holds a template for.
func (s *service) enrolled(id string) bool {
	s.tmu.RLock()
	defer s.tmu.RUnlock()
	_, ok := s.tpl[id]
	return ok
}

// encode is the enrolment frame's template, as little-endian float32s;
// the runtime's encoding is zeroed once copied.
func (s *service) encode(f vision.Frame) ([]byte, error) {
	v, err := s.rt.Encode(f)
	defer clear(v)
	if err != nil {
		return nil, err
	}
	if len(v) == 0 || len(v)*4 > vision.MaxTemplate {
		return nil, errMalformed
	}
	b := make([]byte, 0, 4*len(v))
	for _, x := range v {
		b = binary.LittleEndian.AppendUint32(b, math.Float32bits(x))
	}
	return b, nil
}

// lend replaces the lent templates with the payload's (vision.DecodeLend),
// each scaled to unit length, and zeroes the set it replaces. The payload
// itself is zeroed by its release.
func (s *service) lend(payload []byte) (int, error) {
	ts, err := vision.DecodeLend(payload)
	if err != nil {
		return 0, err
	}
	next := make(map[string][]float32, len(ts))
	for _, t := range ts {
		v := make([]float32, len(t.Vec)/4)
		for i := range v {
			v[i] = math.Float32frombits(binary.LittleEndian.Uint32(t.Vec[4*i:]))
		}
		n := norm(v)
		if n == 0 || math.IsInf(n, 0) {
			for _, old := range next {
				clear(old)
			}
			clear(v)
			return 0, errMalformed
		}
		for i := range v {
			v[i] = float32(float64(v[i]) / n)
		}
		next[t.ID] = v
	}
	s.tmu.Lock()
	old := s.tpl
	s.tpl = next
	s.tmu.Unlock()
	for _, v := range old {
		clear(v)
	}
	return len(next), nil
}
