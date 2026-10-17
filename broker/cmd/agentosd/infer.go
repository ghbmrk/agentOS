package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/infer/supervise"
)

// inferFlags is the local inference service's configuration (INFER-SVC
// INF-1, INF-2). Off, nothing starts and the socket is absent: clients get
// unavailable and the broker is unaffected (DEP-1).
type inferFlags struct {
	On     bool
	Socket string
	UID    int
	Bin    string
	Model  string
	Pin    string
}

func (f *inferFlags) register(fs interface {
	BoolVar(*bool, string, bool, string)
	StringVar(*string, string, string, string)
	IntVar(*int, string, int, string)
}) {
	fs.BoolVar(&f.On, "infer", false, "run the local inference service (INFER-SVC); off, its socket is absent and its clients get unavailable")
	fs.StringVar(&f.Socket, "infer-socket", "/run/agentos/infer/infer.sock", "the inference service's socket, in a 0700 directory of agentosd's")
	fs.IntVar(&f.UID, "infer-uid", -1, "uid of the inference service (agentos-infer), distinct from the broker's")
	fs.StringVar(&f.Bin, "infer-bin", "/usr/lib/agentos/agentos-infer", "the inference service's binary")
	fs.StringVar(&f.Model, "infer-model", "", "the inference service's model file, read-only to it")
	fs.StringVar(&f.Pin, "infer-model-sha256", "", "the model file's SHA-256; a file that differs is answered corrupt")
}

// startInference starts the inference service's supervisor in the
// inference leaf beside the machine pool and returns at once: the service
// being off, unconfigured, unable to start or crash-looping never stops
// the broker or delays owner control (INF-4, DEP-1). leaf opens the leaf;
// with no leaf the service does not run, since nothing may run outside its
// budget (RES-2). Each reason it does not start goes to logw.
func startInference(ctx context.Context, f inferFlags, leaf func() (*cgroup.Group, error), logw io.Writer) *supervise.Supervisor {
	if !f.On {
		return nil
	}
	sv, err := superviseInference(ctx, f, leaf, logw)
	if err != nil {
		fmt.Fprintf(logw, "local inference not started: %v\n", err)
		return nil
	}
	return sv
}

func superviseInference(ctx context.Context, f inferFlags, leaf func() (*cgroup.Group, error), logw io.Writer) (*supervise.Supervisor, error) {
	if f.UID <= 0 || f.UID == os.Getuid() {
		return nil, errors.New("-infer-uid must name the service's own uid, distinct from root and the broker's")
	}
	u, err := user.LookupId(strconv.Itoa(f.UID))
	if err != nil {
		return nil, fmt.Errorf("-infer-uid %d: %v", f.UID, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil || gid <= 0 {
		return nil, fmt.Errorf("-infer-uid %d: group %q is not a service group", f.UID, u.Gid)
	}
	g, err := leaf()
	if err != nil {
		return nil, fmt.Errorf("no inference cgroup: %v", err)
	}
	return supervise.Start(ctx, supervise.Options{
		Path:   f.Bin,
		Args:   []string{"-model", f.Model, "-model-sha256", f.Pin},
		Socket: f.Socket,
		Cgroup: g,
		UID:    uint32(f.UID),
		GID:    uint32(gid),
		Log:    logw,
	})
}

// inferenceLeaf opens the inference component the budget creates beside
// the machine pool (budget.Memory.Apply), which exists only with a
// non-zero InferenceMB.
func inferenceLeaf(machines func() (*cgroup.Group, error), inferenceMB int64) func() (*cgroup.Group, error) {
	return func() (*cgroup.Group, error) {
		if inferenceMB <= 0 {
			return nil, errors.New("the inference budget is 0 MB")
		}
		m, err := machines()
		if err != nil {
			return nil, err
		}
		// The leaf takes the service itself, so it is not opened for
		// children (cgroup.Open would enable its subtree controllers, and
		// a group with those holds no process). It must carry the budget.
		g := &cgroup.Group{Path: filepath.Join(filepath.Dir(m.Path), "inference")}
		b, err := os.ReadFile(filepath.Join(g.Path, "memory.max"))
		if err != nil {
			return nil, err
		}
		if want := strconv.FormatInt(inferenceMB<<20, 10); strings.TrimSpace(string(b)) != want {
			return nil, fmt.Errorf("%s: memory.max is %q, not the budget's %s", g.Path, strings.TrimSpace(string(b)), want)
		}
		return g, nil
	}
}
