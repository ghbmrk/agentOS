package push

// REQ: NET-3

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/ap"
)

// apShell runs push's commands as the access point's shell would, under
// sh with flock, timeout, sha256sum and cut, with every access point path
// moved into a temporary directory and reload_config a stub. The fake
// access point matches commands by their text; this runs them, so the
// claim's glob, the exit statuses, the descriptor the reload is denied
// and the bound on it are checked by a shell. A shell is not busybox
// ash, and util-linux flock is not busybox flock: the live run checks
// those (ENF-g-11).
type apShell struct {
	t   *testing.T
	dir string
	sub *strings.Replacer
}

// stub is reload_config: it records whether it can write to descriptor
// 9 (the lock's), then, while the hang file exists, leaves a process in
// a session of its own behind (as a ubus call that busybox timeout,
// which ends reload_config alone, does not end) and hangs.
const stub = `#!/bin/sh
if (true >&9) 2>/dev/null; then echo fd9 >>"$D/reloads"; else echo ok >>"$D/reloads"; fi
if [ -e "$D/hang" ]; then setsid sleep 6 & sleep 6; fi
`

func newShell(t *testing.T) *apShell {
	t.Helper()
	for _, tool := range []string{"sh", "flock", "timeout", "sha256sum", "cut", "setsid"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("CI") != "" {
				t.Fatalf("CI runner lacks %s: %v", tool, err)
			}
			t.Skipf("no %s: %v", tool, err)
		}
	}
	dir := t.TempDir()
	for _, d := range []string{"etc/config", "etc/dropbear", "tmp", "bin"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "reload_config"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	return &apShell{t: t, dir: dir, sub: strings.NewReplacer(
		"/etc/", dir+"/etc/",
		"/tmp/agentos-ap", dir+"/tmp/agentos-ap",
		"timeout 20 ", "timeout 1 ", // the bound, shortened
	)}
}

// at is path p on the access point, in the temporary directory.
func (s *apShell) at(p string) string { return filepath.Join(s.dir, p) }

// run runs cmd with stdin and returns its exit status; it fails the test
// if any access point path was left unmoved or the run took over 5s.
func (s *apShell) run(cmd string, stdin []byte) int {
	s.t.Helper()
	sub := s.sub.Replace(cmd)
	if n := strings.Count(sub, "/etc/"); n != strings.Count(sub, s.dir+"/etc/") {
		s.t.Fatalf("an /etc path was not moved: %q", sub)
	}
	if n := strings.Count(sub, "/tmp/agentos-ap"); n != strings.Count(sub, s.dir+"/tmp/agentos-ap") {
		s.t.Fatalf("a /tmp path was not moved: %q", sub)
	}
	if strings.Contains(sub, "reload_config") != strings.Contains(sub, "timeout 1 reload_config") {
		s.t.Fatalf("the reload's bound was not found: %q", sub)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "sh", "-c", sub)
	c.Env = append(os.Environ(), "PATH="+filepath.Join(s.dir, "bin")+":"+os.Getenv("PATH"), "D="+s.dir)
	c.Stdin = bytes.NewReader(stdin)
	// Pipes, as an SSH session's are: the run ends only when every
	// process holding them has closed them.
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	err := c.Run()
	if ctx.Err() != nil {
		s.t.Fatalf("%q ran over 5s", sub)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	if err != nil {
		s.t.Fatalf("run %q: %v", sub, err)
	}
	return 0
}

func (s *apShell) read(p string) string {
	b, err := os.ReadFile(s.at(p))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		s.t.Fatal(err)
	}
	return string(b)
}

// temps is the temporary files left on /etc: every agentos-ap file
// there, whatever tmpGlob says.
func (s *apShell) temps() []string {
	m, err := filepath.Glob(s.at("/etc/agentos-ap*"))
	if err != nil {
		s.t.Fatal(err)
	}
	return m
}

// TestCommandsUnderShell runs a claim, writes and reloads under a real
// shell: the claim records its token and removes temporary files an
// earlier Sync left; a write moves only a file whose hash checks, leaves
// it readable by its owner only, and removes its temporary file on every
// failure; a write or reload of a superseded Sync exits refusedExit
// (and only those do); the reload does not get the lock's descriptor; a
// hung reload is ended at its bound, and what it left running holds
// neither the lock nor the command open. Catches a glob, status,
// redirection or bound that is right in shape and wrong in a shell.
func TestCommandsUnderShell(t *testing.T) {
	s := newShell(t)
	w := ap.PathWireless
	stale := s.at(tmpPath(w, "00000000000000000000000000000000"))
	if err := os.WriteFile(stale, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	t1, t2 := token(), token()

	if st := s.run(claimCmd(t1), nil); st != 0 || s.read(tokenPath) != t1+"\n" || len(s.temps()) != 0 {
		// The stale file has tmpPath's form, so it is gone only if the
		// claim's glob matches what tmpPath makes.
		t.Fatalf("claim: status %d token %q temps %q", st, s.read(tokenPath), s.temps())
	}
	data := []byte("config wifi-iface 'owner'\n\toption key 'CANARYOWNERKEYAAAAAAAAAA'\n")
	if st := s.run(writeCmd(w, t1, data), data); st != 0 || s.read(w) != string(data) || len(s.temps()) != 0 {
		t.Fatalf("write: status %d holds %q temps %q", st, s.read(w), s.temps())
	}
	if fi, err := os.Stat(s.at(w)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("written file mode %v %v", fi.Mode(), err)
	}
	next := []byte("config wifi-iface 'owner'\n\toption key 'CANARYNEXTKEYBBBBBBBBBBB'\n")
	if st := s.run(writeCmd(w, t1, next), next[:len(next)/2]); st != 1 || s.read(w) != string(data) || len(s.temps()) != 0 {
		t.Fatalf("cut write: status %d holds %q temps %q", st, s.read(w), s.temps())
	}

	if st := s.run(claimCmd(t2), nil); st != 0 {
		t.Fatalf("second claim: status %d", st)
	}
	if st := s.run(writeCmd(w, t1, next), next); st != refusedExit || s.read(w) != string(data) || len(s.temps()) != 0 {
		t.Fatalf("superseded write: status %d holds %q temps %q", st, s.read(w), s.temps())
	}
	if st := s.run(applyCmd(t1), nil); st != refusedExit || s.read("reloads") != "" {
		t.Fatalf("superseded reload: status %d reloads %q", st, s.read("reloads"))
	}
	if st := s.run(applyCmd(t2), nil); st != 0 || s.read("reloads") != "ok\n" {
		t.Fatalf("reload: status %d reloads %q (fd9 means it got the lock's descriptor)", st, s.read("reloads"))
	}

	if err := os.WriteFile(s.at("hang"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	st := s.run(applyCmd(t2), nil)
	if st == 0 || st == refusedExit || time.Since(start) > 3*time.Second {
		t.Fatalf("hung reload: status %d after %v", st, time.Since(start))
	}
	// What the hung reload left running must not hold the lock: the next
	// claim takes it at once.
	start = time.Now()
	if st := s.run(claimCmd(token()), nil); st != 0 || time.Since(start) > time.Second {
		t.Fatalf("claim after a hung reload: status %d after %v", st, time.Since(start))
	}
}

// TestClaimWaitsForTheLock: a claim waits while another process holds
// the access point's lock file. Catches a lock taken on the wrong file.
func TestClaimWaitsForTheLock(t *testing.T) {
	s := newShell(t)
	lock := s.at(lockPath)
	holder := exec.Command("flock", "-x", lock, "sleep", "1")
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer holder.Wait()
	for exec.Command("flock", "-n", lock, "true").Run() == nil {
		time.Sleep(10 * time.Millisecond) // until the holder has it
	}
	start := time.Now()
	if st := s.run(claimCmd(token()), nil); st != 0 || time.Since(start) < 500*time.Millisecond {
		t.Fatalf("claim behind a held lock: status %d after %v", st, time.Since(start))
	}
}
