package gvisor

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ghbmrk/agentos/broker/childproc"
)

// Stream is a long-running program in a fresh sandbox, fed on its stdin
// and read on its stdout while it runs (CAM-clerk part b: one camera
// decoder per streaming camera). Its confinement is a OneShot's: no
// network, a read-only root, no mounts of broker state, no devices, an
// unprivileged user and a cgroup memory cap. It has no deadline: the
// caller watches its output and stops it.
type Stream struct {
	// Name keys the runsc container ID, the bundle directory and the
	// cgroup. Streams of one name take turns: a second start waits until
	// the first is stopped. A sandbox a crashed broker left under it is
	// killed before the next start.
	Name string
	Root string   // as OneShot.Root
	Argv []string // in the sandbox; Argv[0] is a path under Root
	// MemBytes caps the memory of the whole sandbox, as OneShot.MemBytes.
	MemBytes int64
	// Cgroup is the cgroup v2 group the stream's own group is made under;
	// it is required.
	Cgroup string
}

// StreamRun is a started Stream.
type StreamRun struct {
	in, out *os.File
	cancel  context.CancelFunc
	done    chan struct{}
	err     error
	once    sync.Once
}

// streamStderr caps the program's stderr kept; nothing reads it but the
// exec log on a runsc failure.
const streamStderr = 1 << 10

// StartStream starts s and returns once the program runs. Every path
// that does not return a run kills and deletes what it made; a run's
// sandbox is killed and deleted when it ends or is stopped.
func (r *Runtime) StartStream(ctx context.Context, s Stream) (*StreamRun, error) {
	if s.Name == "" || strings.ContainsAny(s.Name, "/_.") || len(s.Argv) == 0 || s.MemBytes <= 0 || s.Cgroup == "" {
		return nil, fmt.Errorf("gvisor: bad stream %q", s.Name)
	}
	// "/" is in no one-shot name, so a stream never takes a run's turn.
	unlock := r.oneShotLock("stream/" + s.Name)
	id := cid("stream-" + s.Name)
	dir := filepath.Join(r.StateDir, "stream-"+s.Name)
	var undo []func()
	fail := func(err error) (*StreamRun, error) {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		return nil, err
	}
	undo = append(undo, unlock)
	r.removeOneShot(id)
	undo = append(undo, func() { r.removeOneShot(id); os.RemoveAll(dir) })
	if err := os.MkdirAll(r.StateDir, 0o700); err != nil {
		return fail(err)
	}
	bundle := filepath.Join(dir, "bundle")
	if err := writeOneShotBundle(bundle, OneShot{Root: s.Root, Argv: s.Argv}); err != nil {
		return fail(err)
	}
	errLog := filepath.Join(dir, "runsc.err")
	g, err := sandboxGroup(s.Cgroup, "stream-"+s.Name, s.MemBytes)
	if err != nil {
		return fail(err)
	}
	undo = append(undo, func() {
		ctx, cancel := context.WithTimeout(context.Background(), oneShotCleanup)
		defer cancel()
		g.Kill(ctx)
		g.Remove()
	})
	ooms, err := g.OOMKills()
	if err != nil {
		return fail(err)
	}
	var opts childproc.Options
	release, err := startIn(g.Path, &opts)
	if err != nil {
		return fail(err)
	}
	undo = append(undo, release)
	// What the run's end undoes: all of the above.
	sandbox := append([]func(){}, undo...)
	inR, inW, err := os.Pipe()
	if err != nil {
		return fail(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		return fail(err)
	}
	undo = append(undo, func() { inW.Close(); outR.Close() })
	ctx, cancel := context.WithCancel(ctx)
	undo = append(undo, cancel)
	stderr := &capped{max: streamStderr}
	opts.Stdin, opts.Stdout, opts.Stderr = inR, outW, stderr
	opts.WaitDelay = ExecWaitDelay
	cmd := r.cmd(ctx, opts, "--log="+errLog, "run", "--bundle", bundle, id)
	err = cmd.Start()
	// The child holds its own copies; the parent keeps only its ends, so
	// the program's exit is an end of output here.
	inR.Close()
	outW.Close()
	if err != nil {
		return fail(err)
	}
	run := &StreamRun{in: inW, out: outR, cancel: cancel, done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		// The kill takes the whole group (memory.oom.group), runsc too.
		if n, cerr := g.OOMKills(); cerr != nil || n > ooms {
			err = ErrOneShotMemory
		} else if size(errLog) > 0 {
			r.logStart(id, "run", err, clipped(errLog))
			err = ErrOneShotFailed
		}
		run.err = err
		cancel()
		// The sandbox's steps, last first; the caller's ends are Stop's.
		for i := len(sandbox) - 1; i >= 0; i-- {
			sandbox[i]()
		}
		close(run.done)
	}()
	return run, nil
}

// In is the program's stdin.
func (s *StreamRun) In() io.Writer { return s.in }

// Out is the program's stdout. It ends when the program does.
func (s *StreamRun) Out() io.Reader { return s.out }

// Done is closed once the program has ended and its sandbox is deleted.
func (s *StreamRun) Done() <-chan struct{} { return s.done }

// Err is why the run ended, once Done is closed: ErrOneShotMemory at the
// memory cap, ErrOneShotFailed when runsc failed, or the program's exit.
func (s *StreamRun) Err() error {
	<-s.done
	return s.err
}

// Stop kills the run, waits until its sandbox is deleted, and closes its
// stdin and stdout. It is safe to call more than once and from any
// goroutine.
func (s *StreamRun) Stop() {
	s.cancel()
	<-s.done
	s.once.Do(func() {
		s.in.Close()
		s.out.Close()
	})
}
