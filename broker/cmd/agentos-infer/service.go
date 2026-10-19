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
// stopping) whatever was loaded before, and returns the vector length.
// Embed returns one vector per text. Both may be called from several
// goroutines; a Load must make an Embed stuck in the old model return.
type Runtime interface {
	Load(path string) (int, error)
	Embed(texts []string) ([][]float32, error)
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
	// rather than multiplying memory (2 by default).
	Concurrent int
	// CallTimeout bounds one runtime call; past it the call is Unavailable
	// and the runtime is reloaded.
	CallTimeout time.Duration
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
	dim    int
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
	load sync.Mutex // one load at a time

	mu  sync.Mutex
	cur loaded
}

func newService(cfg Config, rt Runtime, log io.Writer) *service {
	if cfg.Concurrent <= 0 {
		cfg.Concurrent = 2
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = 30 * time.Second
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
			fmt.Fprintf(s.log, "infer: bad request (%d texts)\n", len(req.Texts))
			s.write(c, errReply(infer.BadRequest, err.(*infer.Error).Detail))
			continue
		}
		if !s.write(c, s.answer(req)) {
			return
		}
	}
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
	s.sem <- struct{}{}
	defer func() { <-s.sem }()
	cur := s.ready()
	if cur.cause != "" {
		return errReply(cur.cause, cur.detail)
	}
	if req.Op == infer.OpHello {
		return infer.Reply{Model: s.cfg.Name, SHA256: cur.sha, Dim: cur.dim, State: infer.StateReady}
	}
	start := time.Now()
	vs, err := s.embed(req.Texts, cur.dim)
	if err != nil {
		fmt.Fprintf(s.log, "infer: embed of %d texts failed after %s: %s; reloading\n",
			len(req.Texts), time.Since(start).Round(time.Millisecond), err)
		s.fail(cur)
		return errReply(infer.Unavailable, err.Error())
	}
	fmt.Fprintf(s.log, "infer: embedded %d texts in %s\n", len(req.Texts), time.Since(start).Round(time.Millisecond))
	return infer.Reply{SHA256: cur.sha, Dim: cur.dim, Vectors: vs}
}

// The causes of a failed embed: fixed text, never the runtime's own, which
// may echo a request.
var (
	errCrashed   = errors.New("runtime failed")
	errTimedOut  = errors.New("runtime timed out")
	errMalformed = errors.New("runtime answered malformed vectors")
)

// embed runs one runtime call within CallTimeout and checks its answer as
// the client will: a runtime is not trusted to keep its own shape.
func (s *service) embed(texts []string, dim int) ([][]float32, error) {
	type result struct {
		vs  [][]float32
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer func() {
			if recover() != nil {
				done <- result{err: errCrashed}
			}
		}()
		vs, err := s.rt.Embed(texts)
		done <- result{vs, err}
	}()
	t := time.NewTimer(s.cfg.CallTimeout)
	defer t.Stop()
	var r result
	select {
	case r = <-done:
	case <-t.C:
		return nil, errTimedOut
	}
	if r.err != nil {
		return nil, errCrashed
	}
	if len(r.vs) != len(texts) {
		return nil, errMalformed
	}
	for _, v := range r.vs {
		if len(v) != dim || !infer.Finite(v) {
			return nil, errMalformed
		}
	}
	return r.vs, nil
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
		fmt.Fprintf(s.log, "infer: model loaded (dim %d) in %s\n", l.dim, time.Since(start).Round(time.Millisecond))
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
	dim, err := s.rt.Load(s.cfg.Model)
	switch {
	case errors.Is(err, ErrRefused):
		return loaded{cause: infer.Corrupt, detail: "runtime refused the model file"}
	case err != nil:
		return loaded{cause: infer.Unavailable, detail: "runtime did not load"}
	case dim <= 0 || dim > infer.MaxDim:
		return loaded{cause: infer.Corrupt, detail: "runtime reported a bad dim"}
	}
	return loaded{sha: sum, dim: dim}
}
