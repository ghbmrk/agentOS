package gvisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/childproc"
)

// OneShot is one run of a single program in a fresh sandbox that is
// deleted when it ends (CH-23, ARC-5): no network, a read-only root, no
// mounts of broker state, no devices, a memory limit and a deadline.
type OneShot struct {
	// Name keys the runsc container ID and the bundle directory. Runs of
	// one name take turns; a sandbox a crashed broker left under it is
	// killed before the next run starts.
	Name string
	// Root is the sandbox's root directory, mounted read-only. It holds
	// the program and empty /proc, /dev and /sys directories, nothing else.
	Root string
	Argv []string // in the sandbox; Argv[0] is a path under Root
	// Stdin is all of the program's input; the caller caps it.
	Stdin []byte
	// MaxOutput caps the stdout and stderr kept, each; 0 means no cap.
	MaxOutput int
	// MemBytes is the program's RLIMIT_DATA. gVisor's kernel enforces it
	// against the program's heap and anonymous mappings (ASSUMPTIONS V-photo-1).
	MemBytes int64
	Timeout  time.Duration
	// Cgroup, if set, is a cgroup v2 directory runsc is started in, so the
	// sandbox and its gofer are held to the group's limits from the start.
	Cgroup string
}

// OneShotResult is a finished run's output. Truncated reports that
// stdout or stderr passed MaxOutput.
type OneShotResult struct {
	Stdout, Stderr []byte
	ExitCode       int
	Truncated      bool
}

// ErrOneShotFailed is runsc failing to run the program, as against the
// program exiting non-zero. The run's runsc messages go to the exec log.
var ErrOneShotFailed = errors.New("gvisor: one-shot run failed")

// oneShotNOFILE is the program's open-file limit: stdio and a few more.
const oneShotNOFILE = 16

// oneShotCleanup bounds the kill and delete after a run, which use a
// context of their own: the run's may already have ended.
const oneShotCleanup = 5 * time.Second

func (r *Runtime) oneShotLock(name string) func() {
	r.oneShotMu.Lock()
	if r.oneShot == nil {
		r.oneShot = map[string]*sync.Mutex{}
	}
	m := r.oneShot[name]
	if m == nil {
		m = &sync.Mutex{}
		r.oneShot[name] = m
	}
	r.oneShotMu.Unlock()
	m.Lock()
	return m.Unlock
}

// RunOnce runs o.Argv in a new sandbox and returns its output and exit
// code. The sandbox is killed and deleted on every return path; one
// left by an earlier crash under the same name is removed first.
// The error is the context's when the deadline ended the run.
func (r *Runtime) RunOnce(ctx context.Context, o OneShot) (OneShotResult, error) {
	if o.Name == "" || strings.ContainsAny(o.Name, "/_") || len(o.Argv) == 0 || o.MemBytes <= 0 || o.Timeout <= 0 {
		return OneShotResult{}, fmt.Errorf("gvisor: bad one-shot %q", o.Name)
	}
	defer r.oneShotLock(o.Name)()
	id := cid("oneshot-" + o.Name)
	dir := filepath.Join(r.StateDir, "oneshot-"+o.Name)
	r.removeOneShot(id)
	defer func() {
		r.removeOneShot(id)
		os.RemoveAll(dir)
	}()
	if err := os.MkdirAll(r.StateDir, 0o700); err != nil {
		return OneShotResult{}, err
	}
	bundle := filepath.Join(dir, "bundle")
	if err := writeOneShotBundle(bundle, o); err != nil {
		return OneShotResult{}, err
	}
	errLog := filepath.Join(dir, "runsc.err")
	var opts childproc.Options
	if o.Cgroup != "" {
		fd, err := syscall.Open(o.Cgroup, syscall.O_DIRECTORY|syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			return OneShotResult{}, err
		}
		defer syscall.Close(fd)
		opts.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	stdout, stderr := &capped{max: o.MaxOutput}, &capped{max: o.MaxOutput}
	opts.Stdin = bytes.NewReader(o.Stdin)
	opts.Stdout, opts.Stderr = stdout, stderr
	opts.WaitDelay = ExecWaitDelay
	err := r.cmd(ctx, opts, "--log="+errLog, "run", "--bundle", bundle, id).Run()
	if ctx.Err() != nil {
		return OneShotResult{}, ctx.Err()
	}
	// runsc writes its own errors to --log as well as to stderr; the
	// program's stderr carries no line there. With any, the exit code is
	// not known to be the program's, and the messages go only to the exec
	// log, which no machine reads (SR2-3h).
	if size(errLog) > 0 {
		r.logStart(id, "run", err, clipped(errLog))
		return OneShotResult{}, ErrOneShotFailed
	}
	res := OneShotResult{Stdout: stdout.bytes(), Stderr: stderr.bytes(), Truncated: stdout.truncated() || stderr.truncated()}
	var exit *childproc.ExitError
	if errors.As(err, &exit) {
		res.ExitCode = exit.ExitCode()
		return res, nil
	}
	return res, err
}

// removeOneShot kills and deletes the one-shot sandbox id, if any.
func (r *Runtime) removeOneShot(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), oneShotCleanup)
	defer cancel()
	_ = r.run(ctx, "kill", id, "KILL")
	_ = r.run(ctx, "delete", "-force", id)
}

// writeOneShotBundle writes the OCI bundle of a one-shot run: the root
// read-only, an unprivileged user with no capabilities, no new
// privileges, only /proc mounted, private namespaces (the network one
// empty, as runsc --network=none makes it), and the memory and file
// limits.
func writeOneShotBundle(dir string, o OneShot) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	none := []string{}
	spec := map[string]any{
		"ociVersion": "1.0.0",
		"process": map[string]any{
			"user":            map[string]int{"uid": 65534, "gid": 65534},
			"capabilities":    map[string][]string{"bounding": none, "effective": none, "permitted": none},
			"noNewPrivileges": true,
			"rlimits": []map[string]any{
				{"type": "RLIMIT_DATA", "hard": o.MemBytes, "soft": o.MemBytes},
				{"type": "RLIMIT_NOFILE", "hard": oneShotNOFILE, "soft": oneShotNOFILE},
			},
			"args": o.Argv,
			"cwd":  "/",
			"env":  []string{"PATH=/"},
		},
		"root":     map[string]any{"path": o.Root, "readonly": true},
		"hostname": "oneshot",
		"mounts": []map[string]any{
			{"destination": "/proc", "type": "proc", "source": "proc"},
		},
		"linux": map[string]any{
			"namespaces": []map[string]string{{"type": "pid"}, {"type": "network"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"}},
		},
	}
	b, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "config.json"), b, 0o600)
}
