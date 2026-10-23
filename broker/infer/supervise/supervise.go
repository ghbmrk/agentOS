// Package supervise starts and keeps up the local inference service
// (agentos-infer) for agentosd (INF-1, INF-4, INF-6): in the inference
// cgroup leaf, as its own user, in new user, network and IPC namespaces,
// with no_new_privs, handed only its listener. agentosd calls Start after
// the budget groups exist and never waits on it.
package supervise

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/childproc"
)

// Backoff is the restart delay: Min after the first exit, doubling to
// Max, back to Min once a run lasted Reset (INF-4: 1 s, 60 s, 5 min).
type Backoff struct{ Min, Max, Reset time.Duration }

// DefaultBackoff is INF-4's.
var DefaultBackoff = Backoff{Min: time.Second, Max: time.Minute, Reset: 5 * time.Minute}

// Options say what to start and where.
type Options struct {
	// Path is the service binary, Args its arguments.
	Path string
	Args []string
	// Socket is the listener's path. Its directory is created 0700 and
	// owned by the caller, so only the caller can reach the socket; the
	// child gets the listener as fd 3 and never names it.
	Socket string
	// Cgroup is the inference leaf, whose memory.max is the budget's
	// InferenceMB. The child starts in it (CLONE_INTO_CGROUP); nil starts
	// it in the caller's group, which only tests do.
	Cgroup *cgroup.Group
	// UID and GID are the service's user, with no supplementary groups.
	// UID 0 is refused.
	UID, GID uint32
	// Log receives the child's stdout and stderr and the supervisor's
	// own lines, which carry causes and counts only (INF-8). Nil drops
	// them.
	Log     io.Writer
	Backoff Backoff

	// started, if set, is told each start's time (tests).
	started func(time.Time)
	// timer, if set, makes each restart's timer in place of
	// time.NewTimer (tests).
	timer func(time.Duration) *time.Timer
}

// States the supervisor reports.
const (
	Starting    = "starting"
	Up          = "up"
	Unavailable = "unavailable"
	Stopped     = "stopped"
)

// Status is what State reports for STATUS (INF-4).
type Status struct {
	State string
	// Cause is why the service last stopped, empty before it has.
	Cause    string
	Restarts int
}

// Supervisor keeps one service up until its context ends.
type Supervisor struct {
	o    Options
	log  io.Writer
	mu   sync.Mutex
	st   Status
	done chan struct{}
}

// Start checks o and starts the restart loop; it returns before the
// service is up. The loop ends, killing the service, when ctx ends.
func Start(ctx context.Context, o Options) (*Supervisor, error) {
	if o.UID == 0 || o.GID == 0 {
		return nil, errors.New("supervise: refusing to run the service as root")
	}
	if !filepath.IsAbs(o.Path) || !filepath.IsAbs(o.Socket) {
		return nil, errors.New("supervise: the service and socket paths must be absolute")
	}
	if o.Backoff == (Backoff{}) {
		o.Backoff = DefaultBackoff
	}
	if o.Backoff.Min <= 0 || o.Backoff.Max < o.Backoff.Min {
		return nil, errors.New("supervise: bad backoff")
	}
	s := newSupervisor(o)
	go s.loop(ctx, s.run)
	return s, nil
}

func newSupervisor(o Options) *Supervisor {
	s := &Supervisor{o: o, log: o.Log, st: Status{State: Starting}, done: make(chan struct{})}
	if s.log == nil {
		s.log = io.Discard
	}
	if s.o.timer == nil {
		s.o.timer = time.NewTimer
	}
	return s
}

// State reports the service's state, the cause of its last stop and how
// many times it was restarted.
func (s *Supervisor) State() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

// Done is closed once the loop has ended and the service is gone.
func (s *Supervisor) Done() <-chan struct{} { return s.done }

func (s *Supervisor) set(f func(*Status)) {
	s.mu.Lock()
	f(&s.st)
	s.mu.Unlock()
}

// loop runs the service with run until ctx ends, restarting it with
// backoff; run returns why the service stopped.
func (s *Supervisor) loop(ctx context.Context, run func(context.Context) string) {
	defer close(s.done)
	delay := s.o.Backoff.Min
	for {
		begin := time.Now()
		cause := run(ctx)
		if ctx.Err() != nil {
			s.set(func(st *Status) { st.State = Stopped })
			return
		}
		if time.Since(begin) >= s.o.Backoff.Reset {
			delay = s.o.Backoff.Min
		}
		var n int
		s.set(func(st *Status) {
			st.State, st.Cause = Unavailable, cause
			st.Restarts++
			n = st.Restarts
		})
		fmt.Fprintf(s.log, "infer: service stopped (%s); restart %d in %s\n", cause, n, delay)
		t := s.o.timer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			s.set(func(st *Status) { st.State = Stopped })
			return
		case <-t.C:
		}
		delay = min(delay*2, s.o.Backoff.Max)
		s.set(func(st *Status) { st.State = Starting })
	}
}

// run starts the service once and waits for it, returning why it stopped.
func (s *Supervisor) run(ctx context.Context) string {
	g := s.o.Cgroup
	if g != nil {
		// A previous broker's service, or this one's children, still in
		// the leaf would hold memory against the budget.
		if pop, err := g.Populated(); err != nil {
			return "cgroup: " + err.Error()
		} else if pop {
			if err := g.Kill(ctx); err != nil {
				return "cgroup kill: " + err.Error()
			}
		}
	}
	var ooms int64
	if g != nil {
		ooms, _ = g.OOMKills()
	}
	lf, err := s.listen()
	if err != nil {
		return "listen: " + err.Error()
	}
	// The socket path goes with the service, so no client reaches a
	// listener nobody serves.
	defer os.Remove(s.o.Socket)

	attr := &syscall.SysProcAttr{Setpgid: true}
	jail(attr, s.o.UID, s.o.GID)
	if g != nil {
		fd, err := syscall.Open(g.Path, syscall.O_DIRECTORY|syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			lf.Close()
			return "cgroup open: " + err.Error()
		}
		defer syscall.Close(fd)
		attr.UseCgroupFD, attr.CgroupFD = true, fd
	}
	cmd := childproc.Command(ctx, childproc.NewEnv("PATH=/usr/bin:/bin"), childproc.Options{
		Dir:         "/",
		Stdout:      s.log,
		Stderr:      s.log,
		SysProcAttr: attr,
		ExtraFiles:  []*os.File{lf},
		WaitDelay:   2 * time.Second,
		KillGroup:   true,
	}, s.o.Path, s.o.Args...)
	err = startNoNewPrivs(cmd.Start)
	// The child holds its own copy; the caller keeps none.
	lf.Close()
	if err != nil {
		return "start: " + err.Error()
	}
	if s.o.started != nil {
		s.o.started(time.Now())
	}
	s.set(func(st *Status) { st.State = Up })
	err = cmd.Wait()
	cause := "exited"
	if err != nil {
		cause = "exited: " + err.Error()
	}
	if g != nil {
		if n, oerr := g.OOMKills(); oerr == nil && n > ooms {
			cause = "oom: " + cause
		}
		// Anything the service left behind goes with it.
		kctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		g.Kill(kctx)
		cancel()
	}
	return cause
}

// listen makes the socket directory 0700, replaces any old socket and
// returns the new listener as a file for the child's fd 3.
func (s *Supervisor) listen() (*os.File, error) {
	dir := filepath.Dir(s.o.Socket)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Remove(s.o.Socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", s.o.Socket)
	if err != nil {
		return nil, err
	}
	ul := ln.(*net.UnixListener)
	// The path outlives the parent's copy: the child serves it.
	ul.SetUnlinkOnClose(false)
	f, err := ul.File()
	ul.Close()
	if err != nil {
		os.Remove(s.o.Socket)
		return nil, err
	}
	return f, nil
}

// jail sets the service's user and namespaces (INF-1, INF-6): an empty
// network namespace whose only device is a loopback that is down, an IPC
// namespace of its own, and a user namespace mapping only the service's
// user and group to themselves, so it keeps its ids, gains no
// capability across exec, and has no supplementary group.
func jail(a *syscall.SysProcAttr, uid, gid uint32) {
	a.Credential = &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}
	a.Cloneflags = syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUSER
	a.UidMappings = []syscall.SysProcIDMap{{ContainerID: int(uid), HostID: int(uid), Size: 1}}
	a.GidMappings = []syscall.SysProcIDMap{{ContainerID: int(gid), HostID: int(gid), Size: 1}}
	a.GidMappingsEnableSetgroups = true
}

// startNoNewPrivs runs start on a goroutine locked to its thread with
// no_new_privs set first, so neither the service nor anything it execs
// gains privileges through a setuid or file-capability binary. The flag
// is per thread and Go's fork clones the child from the calling thread;
// the goroutine exits still locked, so the runtime ends that thread and
// the flag reaches no other child.
func startNoNewPrivs(start func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// No UnlockOSThread: the thread must die with this goroutine.
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			done <- fmt.Errorf("setting no_new_privs: %w", err)
			return
		}
		done <- start()
	}()
	return <-done
}
