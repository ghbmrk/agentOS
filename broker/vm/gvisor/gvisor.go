// Package gvisor runs agent machines under gVisor's runsc (SPEC ARC-5, S3).
//
// Each machine's root is a host overlayfs mount (image + the machine's upper
// layer), served to the sandbox with gVisor's own overlay off, so the
// broker can snapshot the upper layer directly. runsc starts inside the
// machine's cgroup and is told to leave cgroups alone, so the sandbox and
// gofer are charged to the machine's budget (RES-2). The sandbox has no
// network; ARC-6 services reach it through broker sockets (P1-7).
//
// This package launches one program, the configured runsc binary, with a
// fixed set of verbs (TestOnlyRunscIsExecuted).
package gvisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/quota"
	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/vm/overlay"
)

// maxConsoleLog is the size at which a machine's console log is rotated:
// it and the one old log kept stay within vm.ConsoleMaxBytes (RES-4).
const maxConsoleLog = vm.ConsoleMaxBytes / 2

// guestCaps is the capability set of root inside the sandbox: the usual
// container default, enough to install packages and run services (REV-1).
// gVisor implements them against its own kernel, not the host's (ARC-5).
var guestCaps = []string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
	"CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE",
	"CAP_NET_RAW", "CAP_SYS_CHROOT", "CAP_MKNOD", "CAP_AUDIT_WRITE", "CAP_SETFCAP",
}

// Runtime implements vm.Runtime with runsc.
type Runtime struct {
	Bin      string // runsc binary
	StateDir string // runsc --root; broker-held
	Platform string // "systrap" (no KVM needed) or "kvm"

	logMu sync.Mutex // the exec log's appends and rotation
}

var _ vm.Runtime = (*Runtime)(nil)

// cid is the runsc container ID. runsc resolves IDs by prefix, so "m1"
// would match "m10"; the trailing "_" (not allowed in machine IDs) makes
// every ID a non-prefix of every other (S3 surprise 2).
func cid(id string) string { return id + "_" }

func (r *Runtime) platform() string {
	if r.Platform == "" {
		return "systrap"
	}
	return r.Platform
}

func (r *Runtime) cmd(ctx context.Context, args ...string) *exec.Cmd {
	base := []string{"--root", r.StateDir, "--platform=" + r.platform(), "--network=none", "--ignore-cgroups", "--overlay2=none", "--host-uds=open"}
	c := exec.CommandContext(ctx, r.Bin, append(base, args...)...)
	c.Env = runscEnv
	return c
}

// runscEnv is all of runsc's environment: a fixed PATH. runsc runs as
// root with every path on its command line or in the bundle, and the
// guest's environment is the OCI spec's (writeBundle), so nothing in
// agentosd's environment, which carries the owner's number, reaches it
// (P3-4b-3r-env).
var runscEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}

func (r *Runtime) run(ctx context.Context, args ...string) error {
	var stderr bytes.Buffer
	c := r.cmd(ctx, args...)
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("runsc %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Start mounts the machine's root and starts its guest.
func (r *Runtime) Start(ctx context.Context, l vm.Launch) error {
	return r.launch(ctx, l, "run", "--bundle", r.bundle(l), "-detach", cid(l.ID))
}

// Restore mounts the machine's root and restores memory from image.
func (r *Runtime) Restore(ctx context.Context, l vm.Launch, image string) error {
	return r.launch(ctx, l, "restore", "--bundle", r.bundle(l), "--image-path="+image, "-detach", cid(l.ID))
}

func (r *Runtime) bundle(l vm.Launch) string { return filepath.Join(l.Dir, "bundle") }

func (r *Runtime) launch(ctx context.Context, l vm.Launch, args ...string) error {
	if err := os.MkdirAll(r.StateDir, 0o700); err != nil {
		return err
	}
	if err := writeBundle(r.bundle(l), l); err != nil {
		return err
	}
	// nosuid and nodev: setuid files and device nodes a guest creates mean
	// nothing on the host side of its root. Private propagation keeps later
	// mounts under it out of other mount namespaces; the mount itself still
	// reaches peers of a shared parent, so agentosd runs in its own mount
	// namespace (ASSUMPTIONS V18).
	//
	// The mount is made without CAP_SYS_RESOURCE: overlayfs writes to the
	// upper layer with its mounter's credentials, and ext4 lets that
	// capability past the machine's disk quota (RES-4).
	opts := overlay.MountOptions(l.Lower, l.Upper, l.Work)
	if err := quota.Enforced(func() error {
		return syscall.Mount("overlay", l.Root, "overlay", syscall.MS_NOSUID|syscall.MS_NODEV, opts)
	}); err != nil {
		return fmt.Errorf("mount %s: %w", l.Root, err)
	}
	if err := syscall.Mount("", l.Root, "", syscall.MS_PRIVATE, ""); err != nil {
		syscall.Unmount(l.Root, syscall.MNT_DETACH)
		return fmt.Errorf("mount %s private: %w", l.Root, err)
	}
	c := r.cmd(ctx, args...)
	// The guest's console reaches the log through the broker, which caps
	// it: given the file itself, a guest printing without end would fill
	// the disk (RES-4).
	pr, pw, err := os.Pipe()
	if err != nil {
		syscall.Unmount(l.Root, syscall.MNT_DETACH)
		return err
	}
	go keepConsole(pr, filepath.Join(l.Dir, "console.log"), maxConsoleLog)
	defer pw.Close() // the sandbox holds its own copy
	c.Stdout, c.Stderr = pw, pw
	if l.Cgroup != "" {
		fd, err := syscall.Open(l.Cgroup, syscall.O_DIRECTORY|syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			syscall.Unmount(l.Root, syscall.MNT_DETACH)
			return err
		}
		defer syscall.Close(fd)
		// clone3 places runsc, and so the sandbox and gofer it starts, in
		// the machine's group from its first instruction.
		c.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	}
	if err := c.Run(); err != nil {
		r.Kill(context.WithoutCancel(ctx), l)
		return fmt.Errorf("runsc %s %s: %w (see %s)", args[0], l.ID, err, filepath.Join(l.Dir, "console.log"))
	}
	return nil
}

// keepConsole copies a machine's console from r to the log at path until
// r ends, keeping each log within limit bytes: when the log is full it
// becomes path.1, replacing the older one, and a new log starts.
func keepConsole(r io.ReadCloser, path string, limit int64) {
	defer r.Close()
	var f *os.File
	var size int64
	open := func() bool {
		var err error
		if f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600); err != nil {
			return false
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return false
		}
		size = fi.Size()
		return true
	}
	if !open() {
		io.Copy(io.Discard, r) // never block the guest on its console
		return
	}
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		for b := buf[:n]; len(b) > 0; {
			if size >= limit {
				f.Close()
				os.Rename(path, path+".1")
				if !open() {
					io.Copy(io.Discard, r)
					return
				}
				if size >= limit { // could not be rotated away
					f.Close()
					io.Copy(io.Discard, r)
					return
				}
			}
			k := min(int64(len(b)), limit-size)
			f.Write(b[:k])
			size += k
			b = b[k:]
		}
		if err != nil {
			f.Close()
			return
		}
	}
}

// Pause stops every task in the sandbox.
func (r *Runtime) Pause(ctx context.Context, id string) error { return r.run(ctx, "pause", cid(id)) }

// Resume undoes Pause.
func (r *Runtime) Resume(ctx context.Context, id string) error { return r.run(ctx, "resume", cid(id)) }

// Checkpoint saves a paused sandbox's memory and kernel state to image. The
// sandbox stays paused.
func (r *Runtime) Checkpoint(ctx context.Context, id, image string) error {
	return r.run(ctx, "checkpoint", "--leave-running", "--image-path="+image, cid(id))
}

// ExecWaitDelay bounds how long Exec waits, once its context ends, for the
// command's output to close: a command inside the sandbox can outlive the
// host's runsc exec and hold its stdio open (L3 MUST-1 on #146).
const ExecWaitDelay = 3 * time.Second

// Exec runs a command in a running sandbox, as root in the guest from its
// root directory, with c.Stdin as input (CAP-8). The command's arguments
// follow the container ID, past runsc's own flags, so none is read as a
// flag. A non-zero exit is a result; each output stream is capped.
//
// When ctx ends, the host runsc exec is killed and so is the command inside
// the sandbox (runsc kill by the pid runsc wrote); a failed kill is only
// logged. Exec returns within ExecWaitDelay of ctx ending whatever the
// command does: what it started may run on inside the worker until the
// worker is rolled back, parked or destroyed.
func (r *Runtime) Exec(ctx context.Context, id string, c vm.Command) (vm.ExecResult, error) {
	if err := os.MkdirAll(r.StateDir, 0o700); err != nil {
		return vm.ExecResult{}, err
	}
	pf, err := os.CreateTemp(r.StateDir, "exec-*.pid")
	if err != nil {
		return vm.ExecResult{}, err
	}
	pidFile := pf.Name()
	pf.Close()
	defer os.Remove(pidFile)
	// runsc's own messages: its errors, as JSON lines, and its info lines,
	// each to a file of this exec's (0600, from CreateTemp).
	var logs [2]string
	for i, pattern := range []string{"exec-*.err", "exec-*.debug"} {
		f, err := os.CreateTemp(r.StateDir, pattern)
		if err != nil {
			return vm.ExecResult{}, err
		}
		logs[i] = f.Name()
		f.Close()
		defer os.Remove(logs[i])
	}
	// The guest's stderr is a pipe of its own: runsc's fd 3, which
	// --pass-fd 3:2 makes the guest's fd 2. runsc's own fd 2 then carries
	// only runsc's text, so no guest write can split, mimic or crowd out a
	// trace on it, and none of it reaches the guest (SR2-3n).
	gr, gw, err := os.Pipe()
	if err != nil {
		return vm.ExecResult{}, err
	}
	defer gr.Close()
	cmd := r.cmd(ctx, append([]string{"--log=" + logs[0], "--debug-log=" + logs[1], "exec", "--cwd", "/", "--user", "0:0", "--internal-pid-file", pidFile, "--pass-fd", "3:2", cid(id)}, c.Argv...)...)
	cmd.Stdin = bytes.NewReader(c.Stdin)
	stdout, stderr := &capped{max: c.MaxOutput}, &capped{max: c.MaxOutput}
	runscErr := &capped{max: runscMsgMax}
	cmd.Stdout, cmd.Stderr, cmd.ExtraFiles = stdout, runscErr, []*os.File{gw}
	cmd.WaitDelay = ExecWaitDelay
	cmd.Cancel = func() error {
		// Read the pid now: the deferred Remove may run before the kill.
		b, _ := os.ReadFile(pidFile)
		go r.killExec(id, strings.TrimSpace(string(b)))
		return cmd.Process.Kill()
	}
	// The guest's stderr is read to its end, but no longer than
	// ExecWaitDelay past the context's end or runsc's exit, as os/exec
	// bounds stdout: something left in the sandbox may hold it open.
	copied := make(chan struct{})
	go func() { io.Copy(stderr, gr); close(copied) }()
	stop := context.AfterFunc(ctx, func() { gr.SetReadDeadline(time.Now().Add(ExecWaitDelay)) })
	err = cmd.Start()
	gw.Close()
	if err == nil {
		err = cmd.Wait()
	}
	if stop() {
		gr.SetReadDeadline(time.Now().Add(ExecWaitDelay))
	}
	<-copied
	// runsc writes each of its errors to stderr as well as to its log.
	// When runsc reports an error, or the command never started (runsc
	// writes the pid once it has), the guest's exit code and output are
	// not known to be its own: Exec answers no output, and runsc's
	// messages go only to the broker's exec log (SR2-3h). A Go runtime
	// panic, fatal error or fatal signal in runsc after the command
	// started writes no --log line, only its trace to runsc's stderr
	// (SR2-3m). runsc's stderr is only runsc's; the guest's is a pipe
	// apart (SR2-3n). So any failed exec with text on it is runsc's
	// failure, whatever the exit (2, a kill at the deadline or from
	// outside, any other) or ErrWaitDelay (P1-4-flake-crashed). An exit 0
	// with text is left a result: the same exit and text read as a
	// failure only when something held the pipes past ExecWaitDelay;
	// change neither case without the other. The error is a bare vm
	// sentinel, naming no path (SR2-3j): with no pid, it is the one
	// runsc's --log line shows (notRun, SR2-3q, SR2-3p); otherwise, a
	// crash after the start included, ErrExecFailed, since the command
	// may have run.
	var exit *exec.ExitError
	crashed := err != nil && len(runscErr.bytes()) > 0
	pid, _ := os.ReadFile(pidFile)
	if started := len(bytes.TrimSpace(pid)) > 0; !started || size(logs[0]) > 0 || crashed {
		r.logExec(id, err, logs, runscErr.bytes())
		if ctx.Err() != nil {
			return vm.ExecResult{}, err
		}
		if !started {
			return vm.ExecResult{}, notRun(logs[0], c.Argv)
		}
		return vm.ExecResult{}, vm.ErrExecFailed
	}
	res := vm.ExecResult{Stdout: stdout.bytes(), Stderr: stderr.bytes(), Truncated: stdout.truncated() || stderr.truncated()}
	if errors.As(err, &exit) && ctx.Err() == nil {
		res.ExitCode = exit.ExitCode()
		return res, nil
	}
	return res, err
}

// runscExecPrestart are the messages runsc's exec writes to --log for a
// failure before the command starts (runsc/cmd/exec.go at the pinned
// tag, V32); runscExecCall is the one of them for the sandbox's call,
// which sandbox.go follows with " in sandbox: " and the call's error.
var runscExecPrestart = []string{"loading container failed: ", "parsing process spec: ", runscExecCall}

const runscExecCall = "executing processes for container: "

// runscMsgLineMax bounds what notRun reads of runsc's --log: past the
// argv cap with every byte escaped by %q and then by JSON.
const runscMsgLineMax = 1 << 20

// notRun is the error for an exec whose pid runsc never wrote (SR2-3q):
// ErrExecNotStarted only when runsc's first --log line is one it writes
// before the command starts, ErrExecNoProgram when that line says the
// program was not found or cannot be loaded (SR2-3p), and otherwise
// ErrExecFailed, since the command may have run: a failed pid write, a
// lost answer from the sandbox (urpc's "urpc method" error, the call was
// sent), runsc killed or panicking with no line, or a line too long to
// read. The line's prefix is runsc's own text, and a guest's argv appears
// only after it; a guest argv that reads as a lost answer only makes the
// error the safer ErrExecFailed.
func notRun(errLog string, argv []string) error {
	f, err := os.Open(errLog)
	if err != nil {
		return vm.ErrExecFailed
	}
	defer f.Close()
	var line struct{ Msg string }
	if json.NewDecoder(io.LimitReader(f, runscMsgLineMax)).Decode(&line) != nil {
		return vm.ErrExecFailed
	}
	msg := line.Msg
	if !slices.ContainsFunc(runscExecPrestart, func(p string) bool { return strings.HasPrefix(msg, p) }) {
		return vm.ErrExecFailed
	}
	if !strings.HasPrefix(msg, runscExecCall) {
		return vm.ErrExecNotStarted
	}
	if strings.Contains(msg, ` in sandbox: urpc method "`) {
		return vm.ErrExecFailed
	}
	if len(argv) > 0 && noProgram(msg, argv[0]) {
		return vm.ErrExecNoProgram
	}
	return vm.ErrExecNotStarted
}

// cannotLoad are the errno texts with which the sentry fails a program it
// cannot find or load; a retry fails the same way.
var cannotLoad = []string{"no such file or directory", "permission denied", "exec format error", "not a directory"}

// noProgram reports whether msg, runsc's failed sandbox call for argv[0]
// name, ends with the sentry's error for that program: the loader's
// "failed to load <path>: <errno>" (pkg/sentry/loader), for name, the
// path runsc resolves it to, or, for a bare name, a PATH directory's
// entry; or the PATH lookup's "error finding executable <%q name> in PATH
// [<dirs>]: <errno>" (pkg/sentry/fsimpl/user/path.go). The match is
// anchored at the end, where the sentry's error is, and %q has escaped
// every quote of the argv before it; the PATH directories come from the
// worker image, not the guest, so they hold no space, quote or colon.
func noProgram(msg, name string) bool {
	const at = " in sandbox: "
	for _, e := range cannotLoad {
		m, ok := strings.CutSuffix(msg, ": "+e)
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(name, "/"):
			return strings.HasSuffix(m, at+"failed to load "+name)
		case strings.Contains(name, "/"):
			return strings.HasSuffix(m, at+"failed to load "+path.Join("/", name))
		}
		lookup := at + "error finding executable " + strconv.Quote(name) + " in PATH ["
		if i := strings.LastIndex(m, lookup); i >= 0 {
			dirs, ok := strings.CutSuffix(m[i+len(lookup):], "]")
			return ok && !strings.ContainsAny(dirs, `]":`)
		}
		if i := strings.LastIndex(m, at+"failed to load /"); i >= 0 {
			dir, ok := strings.CutSuffix(m[i+len(at+"failed to load "):], "/"+name)
			return ok && !strings.ContainsAny(dir, ` ":`)
		}
		return false
	}
	return false
}

// execLogMax is the size at which the broker's exec log is rotated: it and
// the one old log kept stay within twice this (RES-4). A var so tests can
// shorten it.
var execLogMax int64 = 1 << 20

// runscMsgMax bounds each of runsc's messages a failed exec adds to the log.
const runscMsgMax = 16 << 10

func (r *Runtime) execLog() string { return filepath.Join(r.StateDir, "exec.log") }

// logExec appends a failed exec's runsc messages, its error log, debug
// log and stderr, each clipped to runscMsgMax, to the exec log: 0600 in
// the broker-held state directory, which no machine can read.
func (r *Runtime) logExec(id string, err error, logs [2]string, stderr []byte) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s: runsc exec failed (%v)\n", time.Now().UTC().Format(time.RFC3339), id, err)
	for i, part := range [][]byte{clipped(logs[0]), clipped(logs[1]), stderr[:min(len(stderr), runscMsgMax)]} {
		fmt.Fprintf(&b, "-- %s\n%s\n", [...]string{"error log", "debug log", "stderr"}[i], bytes.TrimSpace(part))
	}
	r.logMu.Lock()
	defer r.logMu.Unlock()
	keepConsole(io.NopCloser(&b), r.execLog(), execLogMax)
}

// clipped is the first runscMsgMax bytes of the file at path.
func clipped(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, runscMsgMax))
	return b
}

func size(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// killExec kills the command an Exec started inside the sandbox, by the
// in-sandbox pid runsc wrote. Best effort and bounded: it runs off the
// caller's path, and a failure is logged.
func (r *Runtime) killExec(id, pid string) {
	if pid == "" {
		log.Printf("gvisor: %s: no pid to kill for a cancelled command", id)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.run(ctx, "kill", "--pid", pid, cid(id), "KILL"); err != nil {
		log.Printf("gvisor: %s: killing cancelled command %s: %v", id, pid, err)
	}
}

// capped keeps the first max bytes written (all of them when max is 0).
// It is safe for concurrent use: after ExecWaitDelay, Exec reads it while
// the copy may still be finishing.
type capped struct {
	mu   sync.Mutex
	b    bytes.Buffer
	max  int
	over bool
}

func (c *capped) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.b.Bytes())
}

func (c *capped) truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.over
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.max > 0 {
		if room := c.max - c.b.Len(); len(p) > room {
			c.b.Write(p[:max(room, 0)])
			c.over = true
			return len(p), nil
		}
	}
	return c.b.Write(p)
}

var _ vm.Execer = (*Runtime)(nil)

// Kill stops the sandbox, deletes runsc's record of it, and unmounts the
// machine's root. It is idempotent.
func (r *Runtime) Kill(ctx context.Context, l vm.Launch) error {
	_ = r.run(ctx, "kill", cid(l.ID), "KILL")
	err := r.run(ctx, "delete", "-force", cid(l.ID))
	if err != nil && (strings.Contains(err.Error(), "does not exist") || strings.Contains(err.Error(), "not found")) {
		err = nil
	}
	if uerr := syscall.Unmount(l.Root, syscall.MNT_DETACH); uerr != nil && !errors.Is(uerr, syscall.EINVAL) && !errors.Is(uerr, syscall.ENOENT) {
		return uerr
	}
	return err
}

// writeBundle writes the OCI bundle: root is the overlay mount; no host
// mounts beyond /proc, a private /tmp, and the machine's own services
// directory (read-only); private namespaces; no network.
func writeBundle(dir string, l vm.Launch) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	env := append([]string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}, l.Env...)
	spec := map[string]any{
		"ociVersion": "1.0.0",
		"process": map[string]any{
			"user": map[string]int{"uid": 0, "gid": 0}, // root inside (REV-1)
			"capabilities": map[string][]string{
				"bounding": guestCaps, "effective": guestCaps, "permitted": guestCaps,
			},
			"args": l.Argv,
			"cwd":  "/",
			"env":  env,
		},
		"root":     map[string]any{"path": l.Root, "readonly": false},
		"hostname": l.ID,
		"mounts": []map[string]any{
			{"destination": "/proc", "type": "proc", "source": "proc"},
			{"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"},
		},
		"linux": map[string]any{
			"namespaces": []map[string]string{{"type": "pid"}, {"type": "network"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"}},
		},
	}
	if l.Services != "" {
		spec["mounts"] = append(spec["mounts"].([]map[string]any), map[string]any{
			"destination": vm.ServicesMount, "type": "bind", "source": l.Services,
			"options": []string{"rbind", "ro", "nosuid", "nodev", "noexec"},
		})
	}
	b, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "config.json"), b, 0o600)
}
