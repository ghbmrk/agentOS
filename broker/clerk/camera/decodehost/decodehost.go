// Package decodehost runs one camera decoder session in the decoder unit
// (CAM-decoder-uid, #4134; CLK-1, NET-2, RES-2). Each connection the
// camera clerk opens on agentos-camdecode.socket starts a fresh
// agentos-camdecode@.service under a dynamic user of its own, never the
// clerk's; its process reads the session's Spec, starts the decoder's
// gVisor sandbox (rootless, no network, a read-only root, its own cgroup
// with the decoder's memory cap) and copies the connection to the
// sandbox's stdin and its stdout back, until either side ends. It checks
// nothing the sandbox writes: the clerk does (camera.Decoder).
package decodehost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/clerk/camera"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
	"golang.org/x/sys/unix"
)

// StartFunc starts the session's sandbox; GVisor is the unit's.
type StartFunc func(context.Context, gvisor.Stream) (camera.Proc, error)

// GVisor is the StartFunc that runs the sandbox under rt.
func GVisor(rt *gvisor.Runtime) StartFunc {
	return func(ctx context.Context, s gvisor.Stream) (camera.Proc, error) {
		run, err := rt.StartStream(ctx, s)
		if err != nil {
			return nil, err
		}
		return run, nil
	}
}

// Config is one session's wiring.
type Config struct {
	Start StartFunc
	// Root is the sandbox's read-only root, holding /agentos-camdecode.
	Root string
	// Cgroup is the unit's own group, delegated to its user: the
	// sandbox's group is made in it, beside the process's leaf (Leave).
	Cgroup string
	// MemBytes caps the sandbox, gVisor's own share included.
	MemBytes int64
}

// ErrConfig is a Config with no start, root, cgroup or memory cap, or a
// connection that is not a socket.
var ErrConfig = errors.New("decodehost: config needs a start, a root, a cgroup and a memory cap")

// Serve runs the session on conn: its Spec, then the sandbox until the
// clerk ends its side, the sandbox's output ends, the sandbox stops or
// ctx is done. The clerk's end is seen as a hang-up on the socket itself,
// not only as the end of the copy into the sandbox, so a sandbox that
// stops reading its input still ends with the session. The sandbox is
// stopped and gone when Serve returns; the caller then closes conn, which
// tells the clerk.
func Serve(ctx context.Context, conn net.Conn, cfg Config) error {
	if cfg.Start == nil || cfg.Root == "" || cfg.Cgroup == "" || cfg.MemBytes <= 0 {
		return ErrConfig
	}
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return ErrConfig
	}
	rw := conn
	hctx, hcancel := context.WithCancel(ctx)
	defer hcancel()
	hup, err := hangup(hctx, sc)
	if err != nil {
		return fmt.Errorf("decodehost: the session's connection: %w", err)
	}
	spec, err := camera.ReadSpec(rw)
	if err != nil {
		return fmt.Errorf("decodehost: the session's spec: %w", err)
	}
	p, err := cfg.Start(ctx, gvisor.Stream{Name: "camdecode", Root: cfg.Root, Argv: spec.Argv(),
		MemBytes: cfg.MemBytes, Cgroup: cfg.Cgroup})
	if err != nil {
		return fmt.Errorf("decodehost: the decoder's sandbox: %w", err)
	}
	defer p.Stop()
	in, out := make(chan struct{}), make(chan struct{})
	go func() { io.Copy(p.In(), rw); close(in) }()
	go func() { io.Copy(rw, p.Out()); close(out) }()
	select {
	case <-in:
	case <-out:
	case <-hup:
	case <-p.Done():
	case <-ctx.Done():
	}
	return nil
}

// hangup is closed once the peer of conn, a stream socket, has shut down
// its side or closed it (POLLRDHUP, POLLHUP or POLLERR), whatever data is
// still unread, or once ctx is done. It reads nothing from conn.
func hangup(ctx context.Context, conn syscall.Conn) (<-chan struct{}, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		rc.Control(func(fd uintptr) {
			for ctx.Err() == nil {
				pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLRDHUP}}
				n, err := unix.Poll(pfd, 1000)
				if err == unix.EINTR {
					continue
				}
				if err != nil || n > 0 && pfd[0].Revents&(unix.POLLRDHUP|unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
					return
				}
			}
		})
	}()
	return ch, nil
}

// leaf is the process's own group in the unit's.
const leaf = "host"

// Leave moves the calling process into its leaf of its unit's group cg
// (CAM-host-11): cgroup v2 lets a group that holds a process give its
// children no controller, so the process leaves the unit's group before
// the sandbox's group, with its memory cap, is made there.
func Leave(cg string) error {
	g := &cgroup.Group{Path: filepath.Join(cg, leaf)}
	if err := os.Mkdir(g.Path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := g.Join(0); err != nil {
		return fmt.Errorf("joining %s: %w", g.Path, err)
	}
	return nil
}

// OwnCgroup is the calling process's cgroup v2 group, as a path under
// /sys/fs/cgroup, read from procSelf ("/proc/self/cgroup").
func OwnCgroup(procSelf string) (string, error) {
	b, err := os.ReadFile(procSelf)
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(l, "0::"); ok && strings.HasPrefix(p, "/") && !strings.Contains(p, "..") {
			return filepath.Join("/sys/fs/cgroup", p), nil
		}
	}
	return "", errors.New("decodehost: no cgroup v2 group in " + procSelf)
}
