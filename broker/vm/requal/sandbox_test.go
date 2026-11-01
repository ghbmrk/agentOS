package requal

// REQ: UPD-5, HLD-2

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/update"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
	drv "github.com/ghbmrk/agentos/broker/vm/requal/driver"
	"github.com/ghbmrk/agentos/broker/vm/requal/wire"
)

// pipeStream runs the real case driver over in-process pipes, as the
// sandbox's stdin and stdout.
type pipeStream struct {
	inW  *io.PipeWriter
	outR *io.PipeReader
	quit chan struct{}
	once sync.Once
}

func (p *pipeStream) In() io.Writer  { return p.inW }
func (p *pipeStream) Out() io.Reader { return p.outR }
func (p *pipeStream) Stop() {
	p.once.Do(func() {
		close(p.quit)
		p.inW.CloseWithError(errors.New("stopped"))
		p.outR.CloseWithError(errors.New("stopped"))
	})
}

// fakeStreams starts a driver with eval for each stream and records what
// each start was given.
type fakeStreams struct {
	mu     sync.Mutex
	eval   func(quit <-chan struct{}) drv.Evaluator
	starts []gvisor.Stream
	live   []*pipeStream
	err    error
	// raw, when set, is the driver's side instead of drv.Serve.
	raw func(r io.Reader, w io.Writer)
}

func (f *fakeStreams) StartStream(_ context.Context, s gvisor.Stream) (Stream, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	p := &pipeStream{inW: inW, outR: outR, quit: make(chan struct{})}
	f.starts = append(f.starts, s)
	f.live = append(f.live, p)
	go func() {
		if f.raw != nil {
			f.raw(inR, outW)
		} else {
			drv.Serve(inR, outW, f.eval(p.quit))
		}
		outW.Close()
	}()
	return p, nil
}

func (f *fakeStreams) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.starts)
}

// fakeImages records mounts; the release's /usr is a marker file.
type fakeImages struct {
	mounted   []string
	rels      []*update.Verified
	unmounted int
	err       error
}

func (f *fakeImages) Mount(_ context.Context, rel *update.Verified, at string) (func() error, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.mounted = append(f.mounted, at)
	f.rels = append(f.rels, rel)
	return func() error { f.unmounted++; return nil }, nil
}

func echoEval(quit <-chan struct{}) drv.Evaluator {
	return func(in []byte, _ drv.Models) ([]byte, error) { return append([]byte("out:"), in...), nil }
}

func newSandbox(t *testing.T, st *fakeStreams, im *fakeImages, edit func(*SandboxConfig)) Sandbox {
	t.Helper()
	var streams Streams
	if st != nil {
		streams = st
	}
	c := SandboxConfig{Images: im, Streams: streams, Staging: t.TempDir(), Cgroup: "/sys/fs/cgroup/test", MemBytes: 64 << 20, MaxOutput: 1 << 10, ModelCalls: 2}
	if edit != nil {
		edit(&c)
	}
	sb, err := NewSandbox(c)
	if err != nil {
		t.Fatal(err)
	}
	return sb
}

func TestSandboxRunsTheDriverFromTheReleasesUsr(t *testing.T) {
	for _, rel := range []*update.Verified{nil, release(t)} {
		st, im := &fakeStreams{eval: echoEval}, &fakeImages{}
		var staging string
		sb := newSandbox(t, st, im, func(c *SandboxConfig) { staging = c.Staging })
		sess, err := sb.Start(context.Background(), rel)
		if err != nil {
			t.Fatal(err)
		}
		out, err := sess.Run(context.Background(), []byte("in"))
		if err != nil || string(out) != "out:in" {
			t.Fatalf("Run = %q, %v", out, err)
		}
		if len(im.rels) != 1 || im.rels[0] != rel {
			t.Fatalf("mounted %v, want the release given to Start", im.rels)
		}
		s := st.starts[0]
		if im.mounted[0] != filepath.Join(s.Root, "usr") || filepath.Dir(s.Root) != staging {
			t.Fatalf("/usr mounted at %s, root %s", im.mounted[0], s.Root)
		}
		if len(s.Argv) != 1 || s.Argv[0] != DriverPath || s.MemBytes != 64<<20 || s.Cgroup != "/sys/fs/cgroup/test" {
			t.Fatalf("stream %+v", s)
		}
		for _, d := range rootDirs {
			if fi, err := os.Stat(filepath.Join(s.Root, d)); err != nil || !fi.IsDir() {
				t.Fatalf("root has no %s: %v", d, err)
			}
		}
		if err := sess.Close(); err != nil {
			t.Fatal(err)
		}
		if im.unmounted != 1 {
			t.Fatalf("%d unmounts after Close, want 1", im.unmounted)
		}
		if _, err := os.Stat(s.Root); !os.IsNotExist(err) {
			t.Fatalf("root left after Close: %v", err)
		}
		if err := sess.Close(); err != nil || im.unmounted != 1 {
			t.Fatalf("second Close: %v, %d unmounts", err, im.unmounted)
		}
	}
}

// TestSandboxKillsAGuestThatIgnoresTheDeadline: a driver that never
// answers is killed when the case's context ends, Run returns the
// context's error at once, and the next case boots a fresh driver
// (#4044 scope addition).
func TestSandboxKillsAGuestThatIgnoresTheDeadline(t *testing.T) {
	hang := true
	st := &fakeStreams{eval: func(quit <-chan struct{}) drv.Evaluator {
		h := hang
		return func(in []byte, _ drv.Models) ([]byte, error) {
			if h {
				<-quit // deaf to everything but the kill
				return nil, errors.New("killed")
			}
			return in, nil
		}
	}}
	sb := newSandbox(t, st, &fakeImages{}, nil)
	sess, err := sb.Start(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	out, err := sess.Run(ctx, []byte("x"))
	if !errors.Is(err, context.DeadlineExceeded) || out != nil {
		t.Fatalf("Run = %q, %v; want the deadline", out, err)
	}
	if d := time.Since(t0); d > 2*time.Second {
		t.Fatalf("Run returned %v after a 50ms deadline", d)
	}
	select {
	case <-st.live[0].quit:
	default:
		t.Fatal("the deaf driver was not killed")
	}
	hang = false
	out, err = sess.Run(context.Background(), []byte("y"))
	if err != nil || string(out) != "y" || st.count() != 2 {
		t.Fatalf("after a kill: Run = %q, %v, %d boots; want a fresh driver", out, err, st.count())
	}
}

// TestNoOutputAfterTheDeadline: an answer that arrives once the case's
// context has ended is never returned. Each case's context ends during
// its model call, so the answer and the deadline race at Run's select.
func TestNoOutputAfterTheDeadline(t *testing.T) {
	var cancel context.CancelFunc
	st := &fakeStreams{eval: func(quit <-chan struct{}) drv.Evaluator {
		return func(in []byte, m drv.Models) ([]byte, error) {
			m.Call([]byte("q")) // the host ends the case during this call
			return []byte("late"), nil
		}
	}}
	sb := newSandbox(t, st, &fakeImages{}, func(c *SandboxConfig) {
		c.ModelCalls = 100
		c.Models = func(context.Context, []byte) ([]byte, error) { cancel(); return []byte("a"), nil }
	})
	sess, err := sb.Start(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	for i := 0; i < 40; i++ {
		var ctx context.Context
		ctx, cancel = context.WithCancel(context.Background())
		out, err := sess.Run(ctx, []byte("x"))
		cancel()
		if err == nil || out != nil {
			t.Fatalf("case %d: Run = %q, %v after the deadline", i, out, err)
		}
	}
}

// TestDeadlineReachesTheModelChannel: a model call in flight gets the
// case's context, so a deadline ends it and Run returns.
// lateCtx is a context whose deadline passes as the answer is read, with
// no Done signal, so only Run's check after the answer can catch it.
type lateCtx struct {
	context.Context
	mu  sync.Mutex
	err error
}

func (c *lateCtx) Done() <-chan struct{} { return nil }
func (c *lateCtx) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

type passOnRead struct {
	Stream
	ctx *lateCtx
}

func (p passOnRead) Out() io.Reader { return p }
func (p passOnRead) Read(b []byte) (int, error) {
	n, err := p.Stream.Out().Read(b)
	if n > 0 && b[0] == wire.Answer {
		p.ctx.mu.Lock()
		p.ctx.err = context.DeadlineExceeded
		p.ctx.mu.Unlock()
	}
	return n, err
}

type lateStreams struct {
	*fakeStreams
	ctx *lateCtx
}

func (l lateStreams) StartStream(ctx context.Context, s gvisor.Stream) (Stream, error) {
	st, err := l.fakeStreams.StartStream(ctx, s)
	if err != nil {
		return nil, err
	}
	return passOnRead{st, l.ctx}, nil
}

// TestAnswerAtTheDeadlineIsNotReturned: an answer read as the deadline
// passes, before any Done signal, is still refused.
func TestAnswerAtTheDeadlineIsNotReturned(t *testing.T) {
	ctx := &lateCtx{Context: context.Background()}
	st := lateStreams{&fakeStreams{eval: echoEval}, ctx}
	sb := newSandbox(t, nil, &fakeImages{}, func(c *SandboxConfig) { c.Streams = st })
	sess, err := sb.Start(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if out, err := sess.Run(ctx, []byte("x")); !errors.Is(err, context.DeadlineExceeded) || out != nil {
		t.Fatalf("Run = %q, %v; want the deadline", out, err)
	}
}

func TestDeadlineReachesTheModelChannel(t *testing.T) {
	st := &fakeStreams{eval: func(<-chan struct{}) drv.Evaluator {
		return func(in []byte, m drv.Models) ([]byte, error) { return m.Call(in) }
	}}
	sb := newSandbox(t, st, &fakeImages{}, func(c *SandboxConfig) {
		c.Models = func(ctx context.Context, _ []byte) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() }
	})
	sess, _ := sb.Start(context.Background(), nil)
	defer sess.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := sess.Run(ctx, []byte("x")); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Run = %v, want the deadline", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run hung past the deadline while a model call was in flight")
	}
}

func TestOutputIsBounded(t *testing.T) {
	size := 1 << 10
	st := &fakeStreams{eval: func(<-chan struct{}) drv.Evaluator {
		return func([]byte, drv.Models) ([]byte, error) { return bytes.Repeat([]byte("a"), size), nil }
	}}
	sb := newSandbox(t, st, &fakeImages{}, nil)
	sess, err := sb.Start(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if out, err := sess.Run(context.Background(), nil); err != nil || len(out) != size {
		t.Fatalf("answer at the bound: %d bytes, %v", len(out), err)
	}
	size++
	st.mu.Lock()
	st.live[0].Stop() // the next boot answers one byte more
	st.mu.Unlock()
	sess.(*session).st = nil
	out, err := sess.Run(context.Background(), nil)
	if !errors.Is(err, wire.ErrTooLarge) || out != nil {
		t.Fatalf("answer past the bound: %d bytes, %v", len(out), err)
	}
	if sess.(*session).st != nil {
		t.Fatal("a driver past the bound was not killed")
	}
}

// TestModelCallsAreMeteredPerSession: the session's model calls stop at
// the installed release's budget, across its cases; a refused call never
// reaches the model channel; a new session has its own budget.
func TestModelCallsAreMeteredPerSession(t *testing.T) {
	var calls int
	st := &fakeStreams{eval: func(<-chan struct{}) drv.Evaluator {
		return func(in []byte, m drv.Models) ([]byte, error) {
			var got []string
			for i := 0; i < 2; i++ {
				a, err := m.Call(in)
				if errors.Is(err, drv.ErrRefused) {
					got = append(got, "refused:"+strings.SplitN(err.Error(), ": ", 3)[2])
					continue
				}
				got = append(got, string(a))
			}
			return []byte(strings.Join(got, ",")), nil
		}
	}}
	sb := newSandbox(t, st, &fakeImages{}, func(c *SandboxConfig) {
		c.ModelCalls = 3
		c.Models = func(_ context.Context, req []byte) ([]byte, error) { calls++; return append([]byte("m-"), req...), nil }
	})
	for range 2 {
		calls = 0
		sess, err := sb.Start(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := sess.Run(context.Background(), []byte("1"))
		b, _ := sess.Run(context.Background(), []byte("2"))
		sess.Close()
		if string(a) != "m-1,m-1" || string(b) != "m-2,refused:evaluation budget spent" || calls != 3 {
			t.Fatalf("answers %q %q with %d model calls; want the third call the last", a, b, calls)
		}
	}
}

// TestModelBudgetSurvivesARestart: a driver that breaks its channel
// after each call gets a fresh boot, never a fresh budget.
func TestModelBudgetSurvivesARestart(t *testing.T) {
	var calls int
	st := &fakeStreams{raw: func(r io.Reader, w io.Writer) {
		for {
			if _, _, err := wire.Read(r, wire.MaxBody); err != nil {
				return
			}
			wire.Write(w, wire.ModelCall, []byte("q"))
			k, _, err := wire.Read(r, wire.MaxBody)
			if err != nil {
				return
			}
			if k == wire.ModelResult {
				wire.Write(w, 'Z', nil) // out of turn: the host kills this boot
				io.Copy(io.Discard, r)
				return
			}
			wire.Write(w, wire.Answer, []byte("refused"))
		}
	}}
	sb := newSandbox(t, st, &fakeImages{}, func(c *SandboxConfig) {
		c.ModelCalls = 2
		c.Models = func(context.Context, []byte) ([]byte, error) { calls++; return []byte("a"), nil }
	})
	sess, _ := sb.Start(context.Background(), nil)
	defer sess.Close()
	sess.Run(context.Background(), nil)
	sess.Run(context.Background(), nil)
	out, err := sess.Run(context.Background(), nil)
	if err != nil || string(out) != "refused" || calls != 2 || st.count() != 3 {
		t.Fatalf("third case: %q, %v; %d model calls over %d boots, want the budget spent at 2", out, err, calls, st.count())
	}
}

// TestCloseRetriesAFailedUnmount: a Close whose unmount failed leaves the
// root in place, and the next Close unmounts and removes it.
func TestCloseRetriesAFailedUnmount(t *testing.T) {
	fails := 1
	im := &failingUnmount{fails: &fails}
	st := &fakeStreams{eval: echoEval}
	sb := newSandbox(t, st, &fakeImages{}, func(c *SandboxConfig) { c.Images = im })
	sess, err := sb.Start(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	root := st.starts[0].Root
	if err := sess.Close(); err == nil {
		t.Fatal("Close passed a failed unmount")
	}
	if _, err := os.Stat(filepath.Join(root, "usr")); err != nil {
		t.Fatalf("root removed under a mounted /usr: %v", err)
	}
	if _, err := sess.Run(context.Background(), []byte("x")); err == nil {
		t.Fatal("Run after Close")
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) || im.unmounts != 2 {
		t.Fatalf("after the retry: %v, %d unmounts", err, im.unmounts)
	}
}

type failingUnmount struct {
	fails    *int
	unmounts int
}

func (f *failingUnmount) Mount(context.Context, *update.Verified, string) (func() error, error) {
	return func() error {
		f.unmounts++
		if *f.fails > 0 {
			*f.fails--
			return errors.New("busy")
		}
		return nil
	}, nil
}

func TestCaseErrorTextIsClipped(t *testing.T) {
	st := &fakeStreams{raw: func(r io.Reader, w io.Writer) {
		wire.Read(r, wire.MaxBody)
		wire.Write(w, wire.CaseError, bytes.Repeat([]byte("e"), 5000))
		io.Copy(io.Discard, r)
	}}
	sb := newSandbox(t, st, &fakeImages{}, func(c *SandboxConfig) { c.MaxOutput = 8 << 10 })
	sess, _ := sb.Start(context.Background(), nil)
	defer sess.Close()
	_, err := sess.Run(context.Background(), nil)
	if !errors.Is(err, errCase) || len(err.Error()) > maxReason+64 {
		t.Fatalf("case error of %d bytes", len(err.Error()))
	}
}

func TestModelCallsWithoutAChannelAreRefused(t *testing.T) {
	st := &fakeStreams{eval: func(<-chan struct{}) drv.Evaluator {
		return func(in []byte, m drv.Models) ([]byte, error) {
			_, err := m.Call(in)
			return nil, err
		}
	}}
	sb := newSandbox(t, st, &fakeImages{}, nil)
	sess, _ := sb.Start(context.Background(), nil)
	defer sess.Close()
	if _, err := sess.Run(context.Background(), []byte("x")); err == nil || !strings.Contains(err.Error(), "no model channel") {
		t.Fatalf("Run = %v, want the refusal as a case error", err)
	}
}

func TestModelCallThatFailsIsRefusedAndSpent(t *testing.T) {
	var calls int
	st := &fakeStreams{eval: func(<-chan struct{}) drv.Evaluator {
		return func(in []byte, m drv.Models) ([]byte, error) {
			_, err := m.Call(in)
			return nil, err
		}
	}}
	sb := newSandbox(t, st, &fakeImages{}, func(c *SandboxConfig) {
		c.ModelCalls = 1
		c.Models = func(context.Context, []byte) ([]byte, error) { calls++; return nil, errors.New("secret host detail") }
	})
	sess, _ := sb.Start(context.Background(), nil)
	defer sess.Close()
	_, err := sess.Run(context.Background(), []byte("x"))
	if err == nil || strings.Contains(err.Error(), "secret host detail") || !strings.Contains(err.Error(), "model call failed") {
		t.Fatalf("first call: %v", err)
	}
	_, err = sess.Run(context.Background(), []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "evaluation budget spent") || calls != 1 {
		t.Fatalf("second call: %v, %d calls", err, calls)
	}
}

func TestCaseErrorKeepsTheDriver(t *testing.T) {
	st := &fakeStreams{eval: func(<-chan struct{}) drv.Evaluator {
		return func(in []byte, _ drv.Models) ([]byte, error) {
			if string(in) == "bad" {
				return nil, drv.ErrNoEvaluator
			}
			return in, nil
		}
	}}
	sb := newSandbox(t, st, &fakeImages{}, nil)
	sess, _ := sb.Start(context.Background(), nil)
	defer sess.Close()
	if _, err := sess.Run(context.Background(), []byte("bad")); !errors.Is(err, errCase) {
		t.Fatalf("Run = %v, want a case error", err)
	}
	if out, err := sess.Run(context.Background(), []byte("ok")); err != nil || string(out) != "ok" || st.count() != 1 {
		t.Fatalf("after a case error: %q, %v, %d boots", out, err, st.count())
	}
}

func TestFrameOutOfTurnEndsTheDriver(t *testing.T) {
	for _, kind := range []byte{wire.Case, wire.ModelResult, wire.ModelRefuse, 'Z'} {
		st := &fakeStreams{raw: func(r io.Reader, w io.Writer) {
			if _, _, err := wire.Read(r, wire.MaxBody); err == nil {
				wire.Write(w, kind, []byte("x"))
			}
			io.Copy(io.Discard, r)
		}}
		sb := newSandbox(t, st, &fakeImages{}, nil)
		sess, _ := sb.Start(context.Background(), nil)
		out, err := sess.Run(context.Background(), []byte("x"))
		if err == nil || out != nil || sess.(*session).st != nil {
			t.Fatalf("frame %q: Run = %q, %v; want an error and the driver killed", kind, out, err)
		}
		sess.Close()
	}
}

func TestSandboxRefusesAnUncheckedRelease(t *testing.T) {
	st, im := &fakeStreams{eval: echoEval}, &fakeImages{}
	sb := newSandbox(t, st, im, nil)
	if _, err := sb.Start(context.Background(), &update.Verified{}); err == nil || len(im.mounted)+st.count() != 0 {
		t.Fatalf("Start = %v with %d mounts and %d boots", err, len(im.mounted), st.count())
	}
}

func TestSandboxStartUnwinds(t *testing.T) {
	staging := ""
	empty := func() {
		t.Helper()
		if es, _ := os.ReadDir(staging); len(es) != 0 {
			t.Fatalf("staging holds %d entries after a failed start", len(es))
		}
	}
	im := &fakeImages{err: errors.New("bad hash")}
	sb := newSandbox(t, &fakeStreams{eval: echoEval}, im, func(c *SandboxConfig) { staging = c.Staging })
	if _, err := sb.Start(context.Background(), nil); err == nil {
		t.Fatal("Start passed a failed mount")
	}
	empty()
	im = &fakeImages{}
	sb = newSandbox(t, &fakeStreams{err: errors.New("runsc")}, im, func(c *SandboxConfig) { staging = c.Staging })
	if _, err := sb.Start(context.Background(), nil); err == nil || im.unmounted != 1 {
		t.Fatalf("Start = %v with %d unmounts; want an error and /usr unmounted", err, im.unmounted)
	}
	empty()
}

func TestNewSandboxNeedsEveryLimit(t *testing.T) {
	ok := SandboxConfig{Images: &fakeImages{}, Streams: &fakeStreams{}, Staging: "/s", Cgroup: "/c", MemBytes: 1, MaxOutput: 1}
	if _, err := NewSandbox(ok); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*SandboxConfig){
		"images":    func(c *SandboxConfig) { c.Images = nil },
		"streams":   func(c *SandboxConfig) { c.Streams = nil },
		"staging":   func(c *SandboxConfig) { c.Staging = "" },
		"cgroup":    func(c *SandboxConfig) { c.Cgroup = "" },
		"memory":    func(c *SandboxConfig) { c.MemBytes = 0 },
		"output":    func(c *SandboxConfig) { c.MaxOutput = 0 },
		"output>":   func(c *SandboxConfig) { c.MaxOutput = wire.MaxBody + 1 },
		"modelcall": func(c *SandboxConfig) { c.ModelCalls = -1 },
	} {
		c := ok
		edit(&c)
		if _, err := NewSandbox(c); err == nil {
			t.Errorf("%s: NewSandbox passed", name)
		}
	}
}
