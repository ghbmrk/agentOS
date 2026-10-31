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
	"os"
	"path/filepath"
	"strings"

	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/clerk/camera"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
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

// ErrConfig is a Config with no start, root or cgroup.
var ErrConfig = errors.New("decodehost: config needs a start, a root, a cgroup and a memory cap")

// Serve runs the session on conn: its Spec, then the sandbox until the
// clerk ends its side, the sandbox's output ends, the sandbox stops or
// ctx is done. The sandbox is stopped and gone when Serve returns; the
// caller then closes conn, which tells the clerk.
func Serve(ctx context.Context, conn io.ReadWriter, cfg Config) error {
	if cfg.Start == nil || cfg.Root == "" || cfg.Cgroup == "" || cfg.MemBytes <= 0 {
		return ErrConfig
	}
	spec, err := camera.ReadSpec(conn)
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
	go func() { io.Copy(p.In(), conn); close(in) }()
	go func() { io.Copy(conn, p.Out()); close(out) }()
	select {
	case <-in:
	case <-out:
	case <-p.Done():
	case <-ctx.Done():
	}
	return nil
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
