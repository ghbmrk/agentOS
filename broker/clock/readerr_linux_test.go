package clock

// REQ: HW-8, TIM-1

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ttyChildEnv puts the test binary in TestHW8ReadErrorChild's role:
// "<mode>:<pty slave path>".
const ttyChildEnv = "AGENTOS_CLOCK_TTY_CHILD"

// bootIDPath and rtcPath are the files bootID and RTC read; the boot and
// rtc modes bind the pty (rtcparse: the file ttyChildEnv+"_SRC" names) over
// them.
const (
	bootIDPath = "/proc/sys/kernel/random/boot_id"
	rtcPath    = "/sys/class/rtc/rtc0/since_epoch"
)

// ttyReadErr makes a read return data and then fail, with no seam in
// readFile (L3 on #6050): line waits in a pty, whose slave a child session
// opens as its controlling tty and reads by path, ignoring SIGTTIN. Once the
// first read has taken the line, the child hands the tty to another process
// group, so its next read is a background read and fails with EIO. It
// returns what the child's mode reports (src: the file rtcparse binds). With userns, the child runs in a
// user and mount namespace of its own, where it may bind the slave over a
// procfs path.
func ttyReadErr(t *testing.T, mode string, line []byte, userns bool, src string) string {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skip("no pty:", err)
	}
	defer m.Close()
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave := fmt.Sprintf("/dev/pts/%d", n)
	s, err := os.OpenFile(slave, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// The line is queued before the child starts, so the child sees it taken
	// by its first read when the input queue empties.
	if _, err := m.Write(line); err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var out bytes.Buffer
	c := exec.Command(os.Args[0], "-test.run=^TestHW8ReadErrorChild$")
	c.Env = append(os.Environ(), ttyChildEnv+"="+mode+":"+slave, ttyChildEnv+"_SRC="+src)
	c.Stdin, c.Stdout, c.Stderr = s, &out, &out
	c.ExtraFiles = []*os.File{w}
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if userns {
		c.SysProcAttr.Cloneflags = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS
		c.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
		c.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
	}
	err = c.Start()
	w.Close()
	if userns && (errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EINVAL)) {
		t.Skip("no user namespace here:", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Wait()
	ctl := bufio.NewReader(r)
	next := func() string {
		l, err := ctl.ReadString('\n')
		if err != nil {
			c.Wait()
			t.Fatalf("child (%s): %v; output:\n%s", mode, err, out.String())
		}
		return strings.TrimSuffix(l, "\n")
	}
	if got := next(); got != "background" {
		t.Fatalf("child (%s): %s", mode, got)
	}
	// Wakes a read that blocked before the tty changed hands.
	if _, err := m.Write([]byte("x\n")); err != nil {
		t.Fatal(err)
	}
	return next()
}

// TestHW8ReadErrorChild is ttyReadErr's child; it does nothing unless
// ttyChildEnv names its mode.
func TestHW8ReadErrorChild(t *testing.T) {
	mode, slave, ok := strings.Cut(os.Getenv(ttyChildEnv), ":")
	if !ok {
		t.Skip("the child of ttyReadErr")
	}
	ctl := os.NewFile(3, "ctl")
	report := func(f string, a ...any) { fmt.Fprintf(ctl, f+"\n", a...) }
	signal.Ignore(syscall.SIGTTIN)
	src, target := slave, ""
	switch {
	case strings.HasPrefix(mode, "boot"):
		target = bootIDPath
	case strings.HasPrefix(mode, "rtc"):
		target = rtcPath
	}
	if mode == "rtcparse" {
		src = os.Getenv(ttyChildEnv + "_SRC")
	}
	if target != "" {
		// It binds only inside the one-uid user namespace ttyReadErr starts it
		// in, never in a caller's, as when run by hand as root (#6058).
		if m, err := os.ReadFile("/proc/self/uid_map"); err != nil || len(strings.Fields(string(m))) != 3 || strings.Fields(string(m))[2] != "1" {
			report("mount refused: not in a user namespace of its own")
			return
		}
		if err := unix.Mount(src, target, "", unix.MS_BIND, ""); err != nil {
			report("mount: %v", err)
			return
		}
	}
	if mode == "rtcparse" { // a clean read of what src holds: no pty involved
		_, err := RTC()
		report("background")
		report("%v", err != nil)
		return
	}
	res := make(chan string, 1)
	go func() {
		switch mode {
		case "bootfile", "rtcfile":
			b, err := readFile(target)
			res <- fmt.Sprintf("%d %v", len(b), errors.Is(err, syscall.EIO))
		case "bootid":
			res <- fmt.Sprintf("%q", bootID())
		case "rtc":
			rtc, err := RTC()
			res <- fmt.Sprintf("%v %v", rtc.Unix(), err != nil)
		}
	}()
	// The first read has taken the line once the input queue is empty.
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		n, err := unix.IoctlGetInt(0, unix.TIOCINQ)
		if err != nil {
			report("TIOCINQ: %v", err)
			return
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			report("line not read")
			return
		}
	}
	g := exec.Command("sleep", "60")
	g.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := g.Start(); err != nil {
		report("start: %v", err)
		return
	}
	defer g.Wait()
	defer g.Process.Kill()
	if err := unix.IoctlSetPointerInt(0, unix.TIOCSPGRP, g.Process.Pid); err != nil {
		report("TIOCSPGRP: %v", err)
		return
	}
	report("background")
	select {
	case r := <-res:
		report("%s", r)
	case <-time.After(10 * time.Second):
		report("read still blocked")
	}
}

// A boot_id read that fails after data names no boot, so no saved anchor
// or sync is taken as this boot's (L3 on #6050).
func TestTIM1BootIDRefusesAFailedRead(t *testing.T) {
	line := []byte("0f0e0d0c-0000-4000-8000-000000000001\n")
	// The rig works: boot_id's read returns the whole line and EIO.
	if got, want := ttyReadErr(t, "bootfile", line, true, ""), fmt.Sprintf("%d true", len(line)); got != want {
		t.Fatalf("readFile of boot_id on the pty: %s, want %s (bytes, EIO)", got, want)
	}
	if got := ttyReadErr(t, "bootid", line, true, ""); got != `""` {
		t.Fatalf("bootID after a failed read: %s, want \"\"", got)
	}
}

// The hardware clock's reading is refused when its read fails after data,
// or when it does not parse: RTC returns the error, never a time (L3 on
// #6050; the runners have /sys/class/rtc/rtc0, so these lines run there).
func TestHW8RTCRefusesAFailedOrGarbledRead(t *testing.T) {
	if _, err := os.Stat(rtcPath); err != nil {
		t.Skip("no hardware clock here")
	}
	line := []byte("1700000000\n")
	// The rig works: since_epoch's read returns the whole line and EIO.
	if got, want := ttyReadErr(t, "rtcfile", line, true, ""), fmt.Sprintf("%d true", len(line)); got != want {
		t.Fatalf("readFile of since_epoch on the pty: %s, want %s (bytes, EIO)", got, want)
	}
	if got := ttyReadErr(t, "rtc", line, true, ""); got != "-62135596800 true" {
		t.Fatalf("RTC after a failed read: %s, want the zero time and an error", got)
	}
	garbled := filepath.Join(t.TempDir(), "since_epoch")
	if err := os.WriteFile(garbled, []byte("not a number\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ttyReadErr(t, "rtcparse", line, true, garbled); got != "true" {
		t.Fatalf("RTC of a garbled reading: error %s, want one", got)
	}
}

// The child refuses to bind anything when started outside ttyReadErr's
// user namespace, as by hand, so it never covers the host's boot_id (#6058).
// Run as root, it gets a mount namespace of its own (no user namespace), so a
// child that did bind would bind there.
func TestTIM1ReadErrorChildRefusesTheCallersNamespace(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	before, err := os.ReadFile(bootIDPath)
	if err != nil {
		t.Skip("no boot_id:", err)
	}
	var out bytes.Buffer
	c := exec.Command(os.Args[0], "-test.run=^TestHW8ReadErrorChild$")
	c.Env = append(os.Environ(), ttyChildEnv+"=bootfile:/dev/null")
	c.Stdout, c.Stderr, c.ExtraFiles = &out, &out, []*os.File{w}
	if os.Geteuid() == 0 {
		c.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS}
	}
	err = c.Run()
	w.Close()
	if err != nil {
		t.Fatalf("child: %v; output:\n%s", err, out.String())
	}
	got, _ := bufio.NewReader(r).ReadString('\n')
	if got != "mount refused: not in a user namespace of its own\n" {
		t.Fatalf("child run by hand reports %q, want a refusal", got)
	}
	if after, err := os.ReadFile(bootIDPath); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("boot_id now %q, %v; want %q", after, err, before)
	}
}
