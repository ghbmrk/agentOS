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

	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/childproc"
)

// OneShot is one run of a single program in a fresh sandbox that is
// deleted when it ends (CH-23, ARC-5): no network, a read-only root, no
// mounts of broker state, no devices, a memory limit and a deadline.
// The memory limit is a cgroup's: gVisor's kernel does not enforce
// RLIMIT_DATA or RLIMIT_AS, so a run is refused without one.
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
	// MemBytes caps the memory of the whole run: the program, gVisor's
	// sentry and gofer, and runsc (memory.max of the run's cgroup, with no
	// swap). A run that reaches it is killed (ASSUMPTIONS V-photo-1).
	MemBytes int64
	Timeout  time.Duration
	// Cgroup is the cgroup v2 group the run's own group is made under; it
	// is required. runsc starts in the run's group, so the sandbox and its
	// gofer are held to MemBytes and oneShotPids from their start.
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

// ErrOneShotMemory is the run killed at its memory cap.
var ErrOneShotMemory = errors.New("gvisor: one-shot run reached its memory cap")

// oneShotNOFILE is the program's open-file limit: stdio and a few more.
const oneShotNOFILE = 16

// oneShotPids caps the run's tasks, the sentry's and gofer's threads
// included, as the fuzz runs' cap does.
const oneShotPids = 256

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
	if o.Name == "" || strings.ContainsAny(o.Name, "/_.") || len(o.Argv) == 0 || o.MemBytes <= 0 || o.Timeout <= 0 || o.Cgroup == "" {
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
	g, err := sandboxGroup(o.Cgroup, "oneshot-"+o.Name, o.MemBytes)
	if err != nil {
		return OneShotResult{}, err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), oneShotCleanup)
		defer cancel()
		g.Kill(ctx)
		g.Remove()
	}()
	// The count before the run, so a group a crashed broker left behind
	// does not report a kill this run did not have.
	ooms, err := g.OOMKills()
	if err != nil {
		return OneShotResult{}, err
	}
	var opts childproc.Options
	release, err := startIn(g.Path, &opts)
	if err != nil {
		return OneShotResult{}, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	stdout, stderr := &capped{max: o.MaxOutput}, &capped{max: o.MaxOutput}
	opts.Stdin = bytes.NewReader(o.Stdin)
	opts.Stdout, opts.Stderr = stdout, stderr
	opts.WaitDelay = ExecWaitDelay
	err = r.cmd(ctx, opts, "--log="+errLog, "run", "--bundle", bundle, id).Run()
	// The kill takes the whole group (memory.oom.group), runsc too, so its
	// exit says nothing of the program's.
	if n, cerr := g.OOMKills(); cerr != nil || n > ooms {
		return OneShotResult{}, ErrOneShotMemory
	}
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

// SandboxCPU is a one-shot or stream sandbox's CPU ceiling, in
// thousandths of a CPU: one core, sentry and gofer included, even when
// the host is idle, so a sandbox that still answers in time cannot spin
// more (design point 4).
const SandboxCPU = 1000

// sandboxGroup makes a one-shot or stream sandbox's cgroup, name, under
// parent, first emptying and removing one an earlier run left. Its
// memory.high is its memory.max, so a run over the cap is killed rather
// than slowed until the deadline, and cpu.max holds it to SandboxCPU.
func sandboxGroup(parentPath, name string, mem int64) (*cgroup.Group, error) {
	parent, err := cgroup.Open(parentPath)
	if err != nil {
		return nil, err
	}
	stale := &cgroup.Group{Path: filepath.Join(parent.Path, name)}
	if _, err := os.Stat(stale.Path); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), oneShotCleanup)
		stale.Kill(ctx)
		cancel()
		stale.Remove()
	}
	return parent.Child(name, cgroup.Limits{MaxBytes: mem, HighBytes: mem, CPUWeight: 100, IOWeight: 100, CPUMilli: SandboxCPU, Pids: oneShotPids})
}

// startIn sets opts so runsc starts in the cgroup at path: clone3 places
// it, and so the sandbox and gofer it starts, there from its first
// instruction. release closes the group's descriptor after the run.
var startIn = func(path string, opts *childproc.Options) (release func(), err error) {
	fd, err := syscall.Open(path, syscall.O_DIRECTORY|syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	opts.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	return func() { syscall.Close(fd) }, nil
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
// privileges, only /proc and an empty read-only /tmp mounted (gVisor
// otherwise gives /tmp a writable tmpfs of its own), private namespaces
// (the network one empty, as runsc --network=none makes it), and the
// open-file limit.
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
			{"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": []string{"ro", "nosuid", "nodev", "noexec", "size=4k"}},
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
