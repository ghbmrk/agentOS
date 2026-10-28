package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/infer"
)

// Runtime is the model runtime behind the service: one adapter file
// (runtime_<name>.go) implements it, so the runtime choice changes one file
// (INFER-SVC Q1). Load loads the model file at path, replacing (and
// stopping) whatever was loaded before, and reports the ops the model
// serves. Embed returns one vector per text; Generate returns the text
// for a prompt, at most maxOut tokens. All three may be called from
// several goroutines; a Load must make a call stuck in the old model
// return.
type Runtime interface {
	Load(path string) (Serves, error)
	Embed(texts []string) ([][]float32, error)
	Generate(prompt string, maxOut int) (string, error)
}

// Serves is what a loaded model serves: embed when Dim (its vector length)
// is above zero, and generate when Generate is set.
type Serves struct {
	Dim      int
	Generate bool
}

// ErrRefused is a Runtime's answer to a model file it cannot use: the
// service reports it as Corrupt. Any other Load error is Unavailable.
var ErrRefused = errors.New("runtime refused the model file")

// Config is the service's settings, from its flags.
type Config struct {
	Name  string // the model's name in hello replies
	Model string // the model file
	Pin   string // the model file's SHA-256, lower-case hex
	// Concurrent bounds the runtime calls in flight, so a burst queues
	// rather than multiplying memory. Zero is 2, of which at most one is a
	// generate call (ASSUMPTIONS INFER-A6); set, generate calls take any
	// of the slots.
	Concurrent int
	// CallTimeout bounds one embed call; past it the call is Unavailable
	// and the runtime is reloaded.
	CallTimeout time.Duration
	// GenerateTimeout bounds one generate call likewise (120 s by default,
	// the client's own deadline).
	GenerateTimeout time.Duration
	// Retry is the least time between two loads of a model that failed to
	// load; a call that finds the runtime crashed reloads at once.
	Retry time.Duration
	// Idle bounds the wait for a request line on an open connection.
	Idle time.Duration
}

// loaded is the outcome of the last load.
type loaded struct {
	cause  infer.Cause // "" when ready
	detail string
	sha    string
	serves Serves
	at     time.Time
}

// service answers the inference protocol on a listener. Its log carries
// causes, counts, sizes and durations only, never request text or vectors
// (INF-8).
type service struct {
	cfg  Config
	rt   Runtime
	log  io.Writer
	sem  chan struct{}
	gen  chan struct{} // nil, or the one generate slot when Concurrent is defaulted
	load sync.Mutex    // one load at a time

	mu  sync.Mutex
	cur loaded
}

func newService(cfg Config, rt Runtime, log io.Writer) *service {
	var gen chan struct{}
	if cfg.Concurrent <= 0 {
		cfg.Concurrent = 2
		gen = make(chan struct{}, 1)
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = 30 * time.Second
	}
	if cfg.GenerateTimeout <= 0 {
		cfg.GenerateTimeout = infer.DefaultGenerateTimeout
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
	return &service{cfg: cfg, rt: rt, log: log, sem: make(chan struct{}, cfg.Concurrent), gen: gen,
		cur: loaded{cause: infer.Unavailable, detail: "not loaded"}}
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

// conn answers request lines until the peer closes, idles or sends a line
// over the bound (after which the stream cannot be resynchronised).
func (s *service) conn(c net.Conn) {
	defer c.Close()
	r := bufio.NewReaderSize(c, 64<<10)
	for {
		c.SetReadDeadline(time.Now().Add(s.cfg.Idle))
		line, err := infer.ReadLine(r, infer.MaxRequestLine)
		if err == infer.ErrLineTooLong {
			fmt.Fprintf(s.log, "infer: request line over %d bytes\n", infer.MaxRequestLine)
			s.write(c, errReply(infer.BadRequest, "request line over its bound"))
			return
		}
		if err != nil {
			return
		}
		var req infer.Request
		if err := json.Unmarshal(line, &req); err != nil {
			s.write(c, errReply(infer.BadRequest, "malformed request"))
			continue
		}
		if err := req.Check(); err != nil {
			fmt.Fprintf(s.log, "infer: bad %s request (%d texts, %d-byte prompt)\n", opName(req.Op), len(req.Texts), len(req.Prompt))
			s.write(c, errReply(infer.BadRequest, err.(*infer.Error).Detail))
			continue
		}
		if !s.write(c, s.answer(req)) {
			return
		}
	}
}

// opName is op for the log: a known op, else "unknown", since the op is
// the peer's text.
func opName(op string) string {
	switch op {
	case infer.OpHello, infer.OpEmbed, infer.OpGenerate:
		return op
	}
	return "unknown"
}

func errReply(c infer.Cause, detail string) infer.Reply {
	return infer.Reply{Error: c, Detail: detail}
}

// write sends one reply line; a reply over the bound goes as Unavailable.
func (s *service) write(c net.Conn, r infer.Reply) bool {
	b, err := json.Marshal(r)
	if err != nil || len(b) > infer.MaxReplyLine {
		fmt.Fprintf(s.log, "infer: reply over %d bytes\n", infer.MaxReplyLine)
		b, _ = json.Marshal(errReply(infer.Unavailable, "reply over its bound"))
	}
	c.SetWriteDeadline(time.Now().Add(s.cfg.CallTimeout))
	_, err = c.Write(append(b, '\n'))
	return err == nil
}

// answer is the reply to one checked request.
func (s *service) answer(req infer.Request) infer.Reply {
	if req.Op == infer.OpGenerate && s.gen != nil {
		s.gen <- struct{}{}
		defer func() { <-s.gen }()
	}
	s.sem <- struct{}{}
	defer func() { <-s.sem }()
	cur := s.ready()
	if cur.cause != "" {
		return errReply(cur.cause, cur.detail)
	}
	in := infer.Info{Dim: cur.serves.Dim, Generate: cur.serves.Generate}
	switch req.Op {
	case infer.OpHello:
		return infer.Reply{Model: s.cfg.Name, SHA256: cur.sha, Dim: in.Dim, State: infer.StateReady, Ops: in.Ops()}
	case infer.OpGenerate:
		if !in.Generate {
			return errReply(infer.Missing, "the model does not serve generate")
		}
		return s.generate(req, cur)
	}
	if in.Dim == 0 {
		return errReply(infer.Missing, "the model does not serve embed")
	}
	start := time.Now()
	vs, err := s.embed(req.Texts, in.Dim)
	if err != nil {
		fmt.Fprintf(s.log, "infer: embed of %d texts failed after %s: %s; reloading\n",
			len(req.Texts), time.Since(start).Round(time.Millisecond), err)
		s.fail(cur)
		return errReply(infer.Unavailable, err.Error())
	}
	fmt.Fprintf(s.log, "infer: embedded %d texts in %s\n", len(req.Texts), time.Since(start).Round(time.Millisecond))
	return infer.Reply{SHA256: cur.sha, Dim: in.Dim, Vectors: vs}
}

// generate runs one generate call within GenerateTimeout and checks its
// text as the client will. Its log names sizes and durations, never the
// prompt or the text.
func (s *service) generate(req infer.Request, cur loaded) infer.Reply {
	start := time.Now()
	text, err := within(s.cfg.GenerateTimeout, func() (string, error) { return s.rt.Generate(req.Prompt, req.MaxOut) })
	if err == nil && !infer.ValidText(text) {
		err = errMalformedText
	}
	if err != nil {
		fmt.Fprintf(s.log, "infer: generate from a %d-byte prompt failed after %s: %s; reloading\n",
			len(req.Prompt), time.Since(start).Round(time.Millisecond), err)
		s.fail(cur)
		return errReply(infer.Unavailable, err.Error())
	}
	fmt.Fprintf(s.log, "infer: generated %d bytes from a %d-byte prompt in %s\n",
		len(text), len(req.Prompt), time.Since(start).Round(time.Millisecond))
	return infer.Reply{SHA256: cur.sha, Text: &text}
}

// The causes of a failed embed: fixed text, never the runtime's own, which
// may echo a request.
var (
	errCrashed   = errors.New("runtime failed")
	errTimedOut  = errors.New("runtime timed out")
	errMalformed = errors.New("runtime answered malformed vectors")
	// errMalformedText is text over MaxGenerate or not UTF-8.
	errMalformedText = errors.New("runtime answered malformed text")
)

// within runs one runtime call, giving up after d: errTimedOut past it,
// errCrashed for the call's error or panic.
func within[T any](d time.Duration, call func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer func() {
			if recover() != nil {
				done <- result{err: errCrashed}
			}
		}()
		v, err := call()
		done <- result{v, err}
	}()
	t := time.NewTimer(d)
	defer t.Stop()
	var zero T
	select {
	case r := <-done:
		if r.err != nil {
			return zero, errCrashed
		}
		return r.v, nil
	case <-t.C:
		return zero, errTimedOut
	}
}

// embed runs one runtime call within CallTimeout and checks its answer as
// the client will: a runtime is not trusted to keep its own shape.
func (s *service) embed(texts []string, dim int) ([][]float32, error) {
	vs, err := within(s.cfg.CallTimeout, func() ([][]float32, error) { return s.rt.Embed(texts) })
	if err != nil {
		return nil, err
	}
	if len(vs) != len(texts) {
		return nil, errMalformed
	}
	for _, v := range vs {
		if len(v) != dim || !infer.Finite(v) {
			return nil, errMalformed
		}
	}
	return vs, nil
}

// fail marks the load the failed call ran on as unavailable, so the next
// call reloads at once; a load made since is left alone.
func (s *service) fail(on loaded) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur.at.Equal(on.at) {
		s.cur = loaded{cause: infer.Unavailable, detail: "runtime reloading"}
	}
}

// ready returns the current load, loading first when the last one failed
// and is older than Retry (or was marked failed by a call).
func (s *service) ready() loaded {
	s.mu.Lock()
	cur := s.cur
	s.mu.Unlock()
	if cur.cause == "" || (!cur.at.IsZero() && time.Since(cur.at) < s.cfg.Retry) {
		return cur
	}
	s.load.Lock()
	defer s.load.Unlock()
	s.mu.Lock()
	cur = s.cur
	s.mu.Unlock()
	if cur.cause == "" || (!cur.at.IsZero() && time.Since(cur.at) < s.cfg.Retry) {
		return cur // another call loaded while this one waited
	}
	cur = s.loadModel()
	s.mu.Lock()
	s.cur = cur
	s.mu.Unlock()
	return cur
}

// loadModel hashes the model file, checks it against the pin and hands it
// to the runtime. A file that changes between the hash and the runtime's
// read is outside this check: the file is read-only to the service and
// owned by the image (ASSUMPTIONS INFER-A2).
func (s *service) loadModel() loaded {
	start := time.Now()
	l := s.hashAndLoad()
	l.at = time.Now()
	if l.cause == "" {
		fmt.Fprintf(s.log, "infer: model loaded (dim %d, generate %t) in %s\n", l.serves.Dim, l.serves.Generate, time.Since(start).Round(time.Millisecond))
	} else {
		fmt.Fprintf(s.log, "infer: model not loaded: %s: %s\n", l.cause, l.detail)
	}
	return l
}

func (s *service) hashAndLoad() loaded {
	f, err := os.Open(s.cfg.Model)
	if errors.Is(err, fs.ErrNotExist) {
		return loaded{cause: infer.Missing, detail: "model file absent"}
	}
	if err != nil {
		return loaded{cause: infer.Missing, detail: "model file unreadable"}
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	f.Close()
	if err != nil {
		return loaded{cause: infer.Missing, detail: "model file unreadable"}
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if !infer.ValidHash(s.cfg.Pin) || sum != s.cfg.Pin {
		return loaded{cause: infer.Corrupt, detail: "model file hash differs from the pin"}
	}
	sv, err := s.rt.Load(s.cfg.Model)
	switch {
	case errors.Is(err, ErrRefused):
		return loaded{cause: infer.Corrupt, detail: "runtime refused the model file"}
	case err != nil:
		return loaded{cause: infer.Unavailable, detail: "runtime did not load"}
	case sv.Dim < 0 || sv.Dim > infer.MaxDim:
		return loaded{cause: infer.Corrupt, detail: "runtime reported a bad dim"}
	case sv.Dim == 0 && !sv.Generate:
		return loaded{cause: infer.Corrupt, detail: "runtime serves no op with the model"}
	}
	return loaded{sha: sum, serves: sv}
}
