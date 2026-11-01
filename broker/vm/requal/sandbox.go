package requal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/ghbmrk/agentos/broker/update"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
	"github.com/ghbmrk/agentos/broker/vm/requal/wire"
)

// The production sandbox (UPD-5r-b2). Start mounts the release's /usr
// read-only at the usr of a fresh root (Images, which checks it against
// its root hash first) and boots the release's case driver from it under
// gVisor: no network, a read-only root, no devices, an unprivileged user
// and a cgroup memory cap (gvisor.Stream). The driver's stdin and stdout
// are the one case channel (package wire); it has no other way out. A
// model call it sends comes to the host, which meters it against the
// installed release's evaluation budget (HLD-2) before the model channel
// sees it.

// DriverPath is the case driver's path in a release's root.
const DriverPath = "/usr/lib/agentos/agentos-requal-driver"

// Images mounts a release's /usr, checked against its root hash, read-only
// at a directory. A nil release is the installed one.
type Images interface {
	Mount(ctx context.Context, rel *update.Verified, at string) (unmount func() error, err error)
}

// Streams starts a gVisor stream (gvisor.Runtime through GVisor).
type Streams interface {
	StartStream(ctx context.Context, s gvisor.Stream) (Stream, error)
}

// Stream is a started gVisor stream (gvisor.StreamRun).
type Stream interface {
	In() io.Writer
	Out() io.Reader
	Stop()
}

// GVisor is Streams over a gvisor.Runtime.
type GVisor struct{ R *gvisor.Runtime }

func (g GVisor) StartStream(ctx context.Context, s gvisor.Stream) (Stream, error) {
	return g.R.StartStream(ctx, s)
}

// ModelFunc is the host's model channel (the model clerk, wired by b6).
type ModelFunc func(ctx context.Context, req []byte) ([]byte, error)

// SandboxConfig configures NewSandbox. Every limit is the installed
// release's: the candidate can change none of them.
type SandboxConfig struct {
	Images  Images
	Streams Streams
	// Staging holds a private root directory per session.
	Staging string
	// Cgroup is the cgroup v2 group each session's sandbox is made under;
	// MemBytes caps the sandbox's memory there.
	Cgroup   string
	MemBytes int64
	// MaxOutput bounds every frame the driver sends: an answer and a
	// model request alike. A longer frame ends the session.
	MaxOutput int
	// Models is the model channel; nil refuses every model call.
	Models ModelFunc
	// ModelCalls is how many model calls one session may make (HLD-2's
	// evaluation budget). Calls past it are refused; 0 refuses all.
	ModelCalls int
}

type sandbox struct{ c SandboxConfig }

// NewSandbox checks c and returns the production Sandbox.
func NewSandbox(c SandboxConfig) (Sandbox, error) {
	if c.Images == nil || c.Streams == nil || c.Staging == "" || c.Cgroup == "" || c.MemBytes <= 0 ||
		c.MaxOutput <= 0 || c.MaxOutput > wire.MaxBody || c.ModelCalls < 0 {
		return nil, errors.New("requal: sandbox needs images, streams, staging, a cgroup, a memory cap, an output bound and a model budget")
	}
	return &sandbox{c: c}, nil
}

// rootDirs are a session root's directories: usr, where the release's
// /usr is mounted, and the empty mount points runsc needs.
var rootDirs = []string{"usr", "proc", "dev", "sys", "tmp"}

func (b *sandbox) Start(ctx context.Context, rel *update.Verified) (Session, error) {
	if rel != nil && !rel.OK() {
		return nil, errors.New("requal: release is not checked")
	}
	name, err := randomName()
	if err != nil {
		return nil, err
	}
	root := filepath.Join(b.c.Staging, name)
	if err := os.Mkdir(root, 0o755); err != nil {
		return nil, err
	}
	s := &session{c: b.c, ctx: ctx, name: name, root: root, unmount: func() error { return nil }}
	for _, d := range rootDirs {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			s.Close()
			return nil, err
		}
	}
	// Mkdir honours the umask; runsc reads the root as the sandbox user.
	if err := os.Chmod(root, 0o755); err != nil {
		s.Close()
		return nil, err
	}
	unmount, err := b.c.Images.Mount(ctx, rel, filepath.Join(root, "usr"))
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("requal: mount /usr: %w", err)
	}
	s.unmount = unmount
	if err := s.start(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func randomName() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "requal-" + hex.EncodeToString(b[:]), nil
}

// session is one booted release. Its driver runs until a case ends it
// (a deadline, a broken channel or a frame out of turn), and the next case
// boots a fresh one from the same root, so one case's end never decides
// another's. The model budget is the session's, across those boots.
type session struct {
	c SandboxConfig
	// ctx is Start's: the run's, which bounds every boot of the session.
	ctx     context.Context
	name    string
	root    string
	unmount func() error

	mu     sync.Mutex
	st     Stream
	calls  int
	closed bool
}

func (s *session) start() error {
	st, err := s.c.Streams.StartStream(s.ctx, gvisor.Stream{
		Name: s.name, Root: s.root, Argv: []string{DriverPath}, MemBytes: s.c.MemBytes, Cgroup: s.c.Cgroup,
	})
	if err != nil {
		return fmt.Errorf("requal: start driver: %w", err)
	}
	s.st = st
	return nil
}

func (s *session) stop() {
	if s.st != nil {
		s.st.Stop()
		s.st = nil
	}
}

// maxReason bounds the case-error text kept from the driver.
const maxReason = 1 << 10

// errCase is the driver reporting that a case could not run; the driver
// is still in turn, so its session goes on.
var errCase = errors.New("requal: case error")

// Run sends input to the driver and returns its answer. When ctx ends
// first the driver is killed and the error is ctx's: no output comes back
// after the deadline, even one that arrived as it passed.
func (s *session) Run(ctx context.Context, input []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("requal: session closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.st == nil {
		if err := s.start(); err != nil {
			return nil, err
		}
	}
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	st := s.st
	go func() {
		out, err := s.exchange(ctx, st, input)
		done <- result{out, err}
	}()
	var r result
	select {
	case r = <-done:
	case <-ctx.Done():
		s.stop()
		<-done
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		s.stop()
		return nil, err
	}
	if r.err != nil {
		if !errors.Is(r.err, errCase) {
			s.stop()
		}
		return nil, r.err
	}
	return r.out, nil
}

// exchange runs one case on st. Only Run's goroutine calls it, under mu.
func (s *session) exchange(ctx context.Context, st Stream, input []byte) ([]byte, error) {
	if err := wire.Write(st.In(), wire.Case, input); err != nil {
		return nil, err
	}
	for {
		kind, body, err := wire.Read(st.Out(), s.c.MaxOutput)
		if err != nil {
			return nil, fmt.Errorf("requal: driver: %w", err)
		}
		switch kind {
		case wire.Answer:
			return body, nil
		case wire.CaseError:
			if len(body) > maxReason {
				body = body[:maxReason]
			}
			return nil, fmt.Errorf("%w: %q", errCase, body)
		case wire.ModelCall:
			k, b := s.model(ctx, body)
			if err := wire.Write(st.In(), k, b); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("requal: driver sent frame %q out of turn", kind)
		}
	}
}

// model meters one model call against the session's budget, counted
// before the call so a failed call spends it too, and answers the frame
// the driver gets back.
func (s *session) model(ctx context.Context, req []byte) (byte, []byte) {
	if s.c.Models == nil {
		return wire.ModelRefuse, []byte("no model channel")
	}
	if s.calls >= s.c.ModelCalls {
		return wire.ModelRefuse, []byte("evaluation budget spent")
	}
	s.calls++
	resp, err := s.c.Models(ctx, req)
	if err != nil {
		return wire.ModelRefuse, []byte("model call failed")
	}
	if len(resp) > wire.MaxBody {
		return wire.ModelRefuse, []byte("model answer too large")
	}
	return wire.ModelResult, resp
}

// Close kills the driver, unmounts the release's /usr and removes the
// root. The root is removed one known directory at a time, never
// recursively, so a /usr that would not unmount is never walked; a Close
// after one that failed tries the unmount again.
func (s *session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.stop()
	if s.unmount != nil {
		if err := s.unmount(); err != nil {
			return fmt.Errorf("requal: unmount /usr: %w", err)
		}
		s.unmount = nil
	}
	var errs []error
	for _, d := range rootDirs {
		if err := os.Remove(filepath.Join(s.root, d)); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	if err := os.Remove(s.root); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
