// Package sitl starts ArduPilot Copter SITL for the drone package's tests
// (DRONE-sim, #3516). The binary is built at the pin by build.sh and named by
// AGENTOS_SITL_BIN, its defaults by AGENTOS_SITL_DEFAULTS; a test under the
// sitl build tag fails, never skips, when either is unset.
package sitl

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Home is the SITL start position: ArduPilot's own CMAC test site, the same
// synthetic place as the drone tests' policy fixture.
const Home = "-35.363261,149.165230,584,0"

// Instance is one running SITL.
type Instance struct {
	Dir      string
	Instance int

	t      testing.TB
	extra  []string
	cmd    *exec.Cmd
	exited chan struct{}

	mu    sync.Mutex
	ports map[int]int // SERIALn -> TCP port, as SITL reports binding them
	out   strings.Builder
}

// Options start an instance.
type Options struct {
	Instance int      // SITL -I; ports are 5760+10*Instance onwards
	Params   []string // extra "NAME VALUE" defaults lines
}

// Start boots SITL with a wiped EEPROM in a fresh directory and waits until it
// has bound its serial ports.
func Start(t testing.TB, o Options) *Instance {
	t.Helper()
	dir := t.TempDir()
	in := &Instance{Dir: dir, Instance: o.Instance, t: t}
	if len(o.Params) > 0 {
		p := filepath.Join(dir, "extra.parm")
		if err := os.WriteFile(p, []byte(strings.Join(o.Params, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		in.extra = []string{p}
	}
	in.boot(true)
	t.Cleanup(in.Stop)
	return in
}

func binaries(t testing.TB) (bin, defaults string) {
	bin, defaults = os.Getenv("AGENTOS_SITL_BIN"), os.Getenv("AGENTOS_SITL_DEFAULTS")
	if bin == "" || defaults == "" {
		t.Fatal("the sitl tag is set but AGENTOS_SITL_BIN or AGENTOS_SITL_DEFAULTS is not: build SITL with broker/drone/sitl/build.sh")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("AGENTOS_SITL_BIN: %v", err)
	}
	return bin, defaults
}

var bindLine = regexp.MustCompile(`SERIAL(\d+) on TCP port (\d+)`)

func (in *Instance) boot(wipe bool) {
	t := in.t
	t.Helper()
	bin, defaults := binaries(t)
	args := []string{"--model", "+", "--speedup", "1", "-I", strconv.Itoa(in.Instance), "--home", Home,
		"--defaults", strings.Join(append([]string{defaults}, in.extra...), ","),
		"--serial0", "tcp:0", "--serial1", "tcp:2", "--serial2", "tcp:3"}
	if wipe {
		args = append(args, "--wipe")
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = in.Dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + in.Dir}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	in.mu.Lock()
	in.ports = map[int]int{}
	in.mu.Unlock()
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting SITL: %v", err)
	}
	in.cmd, in.exited = cmd, make(chan struct{})
	go func() {
		cmd.Wait()
		pw.Close()
		close(in.exited)
	}()
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			line := sc.Text()
			in.mu.Lock()
			in.out.WriteString(line + "\n")
			if m := bindLine.FindStringSubmatch(line); m != nil {
				n, _ := strconv.Atoi(m[1])
				p, _ := strconv.Atoi(m[2])
				in.ports[n] = p
			}
			in.mu.Unlock()
		}
	}()
	deadline := time.Now().Add(60 * time.Second)
	for {
		in.mu.Lock()
		n := len(in.ports)
		in.mu.Unlock()
		if n >= 3 {
			break
		}
		select {
		case <-in.exited:
			t.Fatalf("SITL exited during boot:\n%s", in.Output())
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("SITL bound %d serial ports in 60 s:\n%s", n, in.Output())
		}
	}
	time.Sleep(2 * time.Second) // let the remaining ports bind before they are listed
}

// Ports lists the TCP ports SITL bound for its serial ports, by SERIAL number.
func (in *Instance) Ports() []int {
	in.mu.Lock()
	defer in.mu.Unlock()
	var ns []int
	for n := range in.ports {
		ns = append(ns, n)
	}
	sort.Ints(ns)
	out := make([]int, len(ns))
	for i, n := range ns {
		out[i] = in.ports[n]
	}
	return out
}

// RCPort is SITL's UDP RC input port.
func (in *Instance) RCPort() int { return 5501 + 10*in.Instance }

// Output is SITL's console so far.
func (in *Instance) Output() string {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.out.String()
}

// Dial connects to one of the instance's TCP ports, retrying while SITL
// starts listening.
func (in *Instance) Dial(port int) net.Conn {
	in.t.Helper()
	var err error
	for i := 0; i < 100; i++ {
		var c net.Conn
		c, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			return c
		}
		time.Sleep(100 * time.Millisecond)
	}
	in.t.Fatalf("dialling SITL port %d: %v", port, err)
	return nil
}

// Restart kills SITL and boots it again on the same EEPROM: the aircraft's
// stored key, parameters, fence and rally points survive, as on a power cycle.
func (in *Instance) Restart() {
	in.t.Helper()
	in.Stop()
	in.boot(false)
}

// Stop kills SITL's process group.
func (in *Instance) Stop() {
	if in.cmd == nil || in.cmd.Process == nil {
		return
	}
	syscall.Kill(-in.cmd.Process.Pid, syscall.SIGKILL)
	<-in.exited
	in.cmd = nil
}
