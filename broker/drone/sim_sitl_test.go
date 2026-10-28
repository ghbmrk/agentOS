//go:build sitl

// This file starts ArduPilot Copter SITL for the sitl-tagged tests (DRONE-sim,
// #3516). It is a test file so that no built package starts a process (the
// childproc gate). The binary is built at the pin by sitl/build.sh and named
// by AGENTOS_SITL_BIN, its defaults by AGENTOS_SITL_DEFAULTS; a test under the
// sitl build tag fails, never skips, when either is unset.
package drone

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// sitlHome is the SITL start position: ArduPilot's own CMAC test site, the same
// synthetic place as the drone tests' policy fixture.
const sitlHome = "-35.363261,149.165230,584,0"

// simulator is one running SITL.
type simulator struct {
	Dir string

	t      testing.TB
	cmd    *exec.Cmd
	exited chan struct{}

	mu    sync.Mutex
	ports map[int]int // SERIALn -> TCP port, as SITL reports binding them
	out   strings.Builder
}

// startSITL boots SITL instance 0 with a wiped EEPROM in a fresh directory and
// waits until it has bound its serial ports.
func startSITL(t testing.TB) *simulator {
	t.Helper()
	in := &simulator{Dir: t.TempDir(), t: t}
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

func (in *simulator) boot(wipe bool) {
	t := in.t
	t.Helper()
	bin, defaults := binaries(t)
	args := []string{"--model", "+", "--speedup", "1", "-I", "0", "--home", sitlHome,
		"--defaults", defaults,
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
func (in *simulator) Ports() []int {
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
func (in *simulator) RCPort() int { return 5501 }

// Output is SITL's console so far.
func (in *simulator) Output() string {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.out.String()
}

// Dial connects to one of the instance's TCP ports, retrying while SITL
// starts listening.
func (in *simulator) Dial(port int) net.Conn {
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
func (in *simulator) Restart() {
	in.t.Helper()
	in.Stop()
	in.boot(false)
}

// Stop kills SITL's process group.
func (in *simulator) Stop() {
	if in.cmd == nil || in.cmd.Process == nil {
		return
	}
	syscall.Kill(-in.cmd.Process.Pid, syscall.SIGKILL)
	<-in.exited
	in.cmd = nil
}
