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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/vm/overlay"
)

// maxConsoleLog is the size at which a machine's console log is rotated.
const maxConsoleLog = 4 << 20

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
	return exec.CommandContext(ctx, r.Bin, append(base, args...)...)
}

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
	opts := overlay.MountOptions(l.Lower, l.Upper, l.Work)
	if err := syscall.Mount("overlay", l.Root, "overlay", syscall.MS_NOSUID|syscall.MS_NODEV, opts); err != nil {
		return fmt.Errorf("mount %s: %w", l.Root, err)
	}
	if err := syscall.Mount("", l.Root, "", syscall.MS_PRIVATE, ""); err != nil {
		syscall.Unmount(l.Root, syscall.MNT_DETACH)
		return fmt.Errorf("mount %s private: %w", l.Root, err)
	}
	c := r.cmd(ctx, args...)
	logPath := filepath.Join(l.Dir, "console.log")
	if fi, err := os.Stat(logPath); err == nil && fi.Size() > maxConsoleLog {
		os.Rename(logPath, logPath+".1") // keep one old log; bounded disk use
	}
	log, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		syscall.Unmount(l.Root, syscall.MNT_DETACH)
		return err
	}
	defer log.Close()
	c.Stdout, c.Stderr = log, log
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

// Pause stops every task in the sandbox.
func (r *Runtime) Pause(ctx context.Context, id string) error { return r.run(ctx, "pause", cid(id)) }

// Resume undoes Pause.
func (r *Runtime) Resume(ctx context.Context, id string) error { return r.run(ctx, "resume", cid(id)) }

// Checkpoint saves a paused sandbox's memory and kernel state to image. The
// sandbox stays paused.
func (r *Runtime) Checkpoint(ctx context.Context, id, image string) error {
	return r.run(ctx, "checkpoint", "--leave-running", "--image-path="+image, cid(id))
}

// Exec runs a command in a running sandbox, as root in the guest from its
// root directory, with c.Stdin as input (CAP-8). The command's arguments
// follow the container ID, past runsc's own flags, so none is read as a
// flag. A non-zero exit is a result; each output stream is capped.
func (r *Runtime) Exec(ctx context.Context, id string, c vm.Command) (vm.ExecResult, error) {
	cmd := r.cmd(ctx, append([]string{"exec", "--cwd", "/", "--user", "0:0", cid(id)}, c.Argv...)...)
	cmd.Stdin = bytes.NewReader(c.Stdin)
	stdout, stderr := &capped{max: c.MaxOutput}, &capped{max: c.MaxOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	res := vm.ExecResult{Stdout: stdout.b.Bytes(), Stderr: stderr.b.Bytes(), Truncated: stdout.over || stderr.over}
	var exit *exec.ExitError
	if errors.As(err, &exit) && ctx.Err() == nil {
		res.ExitCode = exit.ExitCode()
		return res, nil
	}
	return res, err
}

// capped keeps the first max bytes written (all of them when max is 0).
type capped struct {
	b    bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
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
