package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/vision"
)

// Runtime is the model runtime behind the service: one adapter file
// (runtime_<name>.go) implements it, so the runtime choice changes one file
// (VIS-core part e). Load loads the models, replacing whatever was loaded,
// and names them. Detect and Sound answer one frame or clip; the service
// checks what they return as the client will. All may be called from
// several goroutines; a Load must make a call still running on the old
// load return, since that call holds a frame and its slot until it does.
type Runtime interface {
	Load() (Model, error)
	Detect(f vision.Frame) ([]vision.Detection, error)
	Sound(pcm []byte) ([]vision.Sound, error)
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
}

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

	mu   sync.Mutex
	cur  loaded
	held int // payloads allocated and not yet released
	peak int // the most held at once
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
	if log == nil {
		log = io.Discard
	}
	return &service{cfg: cfg, rt: rt, log: log, sem: make(chan struct{}, cfg.Concurrent),
		cur: loaded{cause: vision.Unavailable}}
}

// Serve answers each connection on its own goroutine until ln fails.
func (s *service) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go s.conn(c)
	}
}

// conn answers requests until the peer closes or idles. A header that is
// over its bound, malformed or outside the bounds is answered BadRequest
// and ends the connection, since its payload's length is not known: the
// payload is never read, so a bad header cannot make the service hold it.
func (s *service) conn(c net.Conn) {
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
		if err := req.Check(); err != nil {
			fmt.Fprintf(s.log, "vision: bad %s request (%d bytes)\n", opName(req.Op), req.Bytes)
			s.write(c, errReply(vision.BadRequest))
			return
		}
		if !s.write(c, s.answer(req, r)) {
			return
		}
	}
}

// opName is a request's op for the log: one of the three, or "unknown".
func opName(op string) string {
	switch op {
	case vision.OpHello, vision.OpDetect, vision.OpSound:
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
		ds, err := call(s, cur, release, func() ([]vision.Detection, error) { return s.rt.Detect(f) },
			func(ds []vision.Detection) error {
				// No template is loaded in this build, so no id is enrolled
				// (part c lends them).
				return vision.CheckDetections(ds, req.Width, req.Height, nil)
			})
		if err != nil {
			return errReply(vision.Unavailable)
		}
		fmt.Fprintf(s.log, "vision: %dx%d %s frame, %d detections in %s\n", req.Width, req.Height, req.Format, len(ds), since(start))
		return vision.Reply{Detections: ds}
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
// a timed-out one also reloads at once, which makes it return (Runtime).
// release runs when run returns, however late.
func call[T any](s *service, on loaded, release func(), run func() (T, error), check func(T) error) (T, error) {
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer release()
		defer func() {
			if recover() != nil {
				done <- result{err: errCrashed}
			}
		}()
		v, err := run()
		done <- result{v, err}
	}()
	t := time.NewTimer(s.cfg.CallTimeout)
	defer t.Stop()
	var zero T
	var err error
	select {
	case r := <-done:
		switch {
		case r.err != nil:
			err = errCrashed
		case check(r.v) != nil:
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
	}
	return zero, err
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
