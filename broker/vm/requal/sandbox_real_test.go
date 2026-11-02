package requal

// REQ: UPD-5, HLD-2

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/update"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

// copiedUsr is Images for the real-runsc tests: the release's /usr holds
// only a driver binary, copied rather than mounted (VerityImages has its
// own tests).
type copiedUsr struct{ bin string }

func (c copiedUsr) Mount(_ context.Context, _ *update.Verified, at string) (func() error, error) {
	dir := filepath.Join(at, "lib", "agentos")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(c.bin)
	if err != nil {
		return nil, err
	}
	dst := filepath.Join(dir, filepath.Base(DriverPath))
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		return nil, err
	}
	return func() error {
		for _, p := range []string{dst, dir, filepath.Join(at, "lib")} {
			if err := os.Remove(p); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

// realSandbox builds pkg as the driver and returns a sandbox that boots it
// under the real runsc, as the CI integration job runs it (root, runsc,
// a cgroup v2 parent).
func realSandbox(t *testing.T, pkg string) Sandbox {
	t.Helper()
	bin, cg := os.Getenv("AGENTOS_RUNSC"), os.Getenv("AGENTOS_CGROUP_PARENT")
	if bin == "" || cg == "" || os.Geteuid() != 0 {
		t.Skip("set AGENTOS_RUNSC to a runsc binary and AGENTOS_CGROUP_PARENT to a cgroup v2 group, and run as root (CI integration job)")
	}
	out := filepath.Join(t.TempDir(), "driver")
	build := exec.Command("go", "build", "-o", out, pkg)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v\n%s", pkg, err, b)
	}
	r := &gvisor.Runtime{Bin: bin, StateDir: filepath.Join(t.TempDir(), "runsc")}
	t.Cleanup(func() { syscall.Unmount(filepath.Join(r.StateDir, "null-netns"), syscall.MNT_DETACH) })
	staging := t.TempDir()
	os.Chmod(staging, 0o755)
	sb, err := NewSandbox(SandboxConfig{Images: copiedUsr{out}, Streams: GVisor{r}, Staging: staging, Cgroup: cg,
		MemBytes: 64 << 20, MaxOutput: 1 << 16, ModelCalls: 1})
	if err != nil {
		t.Fatal(err)
	}
	return sb
}

// TestRealShippedDriverAnswersUnderGVisor: the driver this release ships
// boots from the release's /usr under runsc and answers each case on the
// case channel, a case error while it has no evaluator.
func TestRealShippedDriverAnswersUnderGVisor(t *testing.T) {
	sb := realSandbox(t, "./driver/cmd/agentos-requal-driver")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	sess, err := sb.Start(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		cctx, ccancel := context.WithTimeout(ctx, 20*time.Second)
		_, err := sess.Run(cctx, []byte(`{"content":"x","canary":"c"}`))
		ccancel()
		if !errors.Is(err, errCase) || !strings.Contains(err.Error(), "no evaluator") {
			t.Fatalf("Run = %v, want the driver's case error", err)
		}
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestRealDeafDriverIsKilledAtTheDeadline: under runsc, a driver that
// ignores its input and every signal is killed when the case's deadline
// passes, Run returns at once with the deadline, and the sandbox's cgroup
// is gone after Close (#4044 scope addition).
func TestRealDeafDriverIsKilledAtTheDeadline(t *testing.T) {
	sb := realSandbox(t, "./testdata/deafdriver")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	sess, err := sb.Start(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	cctx, ccancel := context.WithTimeout(ctx, 2*time.Second)
	defer ccancel()
	t0 := time.Now()
	out, err := sess.Run(cctx, []byte("x"))
	if !errors.Is(err, context.DeadlineExceeded) || out != nil {
		t.Fatalf("Run = %q, %v; want the deadline", out, err)
	}
	if d := time.Since(t0); d > 15*time.Second {
		t.Fatalf("Run returned %v after a 2s deadline", d)
	}
	name := sess.(*session).name
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("AGENTOS_CGROUP_PARENT"), "stream-"+name)); !os.IsNotExist(err) {
		t.Fatalf("sandbox cgroup left: %v", err)
	}
}
