package proc_test

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/proc"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// REQ: CLK-1, DEV-1

// childEnv marks the test binary run as a driver's process: Main serves
// the probe driver on descriptor 3 and exits.
const childEnv = "DEVSLOT_TEST_CHILD"

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "1" {
		proc.Main(probe{})
	}
	os.Exit(m.Run())
}

// probe is a driver that reports its own process's dumpable flag. Its
// Declare says so on standard error, so the parent sees whether it ran.
type probe struct{}

func (probe) Declare() devslot.Declaration {
	if os.Getenv(childEnv) == "1" {
		os.Stderr.WriteString("declared\n")
	}
	return devslot.Declaration{
		Device:      "probe",
		Link:        devslot.GATT,
		Channels:    []devslot.Channel{{Name: "data", Service: "fff0", Char: "fff1"}},
		Operations:  []devslot.Operation{{Name: "dumpable", Verb: key.Read}},
		Readings:    []string{"dumpable"},
		MaxRead:     1,
		MaxReadings: 1,
	}
}

func (probe) Run(context.Context, string, devslot.Link, devslot.Secrets) ([]devslot.Reading, error) {
	r, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0, 0, 0, 0)
	if e != 0 {
		return nil, e
	}
	return []devslot.Reading{{Kind: "dumpable", Value: int64(r), Time: time.Unix(1e9, 0)}}, nil
}

// startDriver runs the test binary as a driver's process with one end of a
// socket pair on descriptor 3, as its socket unit would, and returns the
// host's end.
func startDriver(t *testing.T, hostUID int) (*os.File, *exec.Cmd, *bytes.Buffer) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.SetNonblock(fds[0], true); err != nil {
		t.Fatal(err)
	}
	host, end := os.NewFile(uintptr(fds[0]), "host"), os.NewFile(uintptr(fds[1]), "driver")
	t.Cleanup(func() { host.Close() })
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), childEnv+"=1", proc.HostUIDEnv+"="+strconv.Itoa(hostUID))
	cmd.ExtraFiles = []*os.File{end}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	end.Close()
	host.SetDeadline(time.Now().Add(20 * time.Second))
	return host, cmd, &out
}

func TestMainRefusesWrongPeer(t *testing.T) {
	host, cmd, out := startDriver(t, os.Getuid()+1)
	b, err := io.ReadAll(host)
	if err != nil || len(b) != 0 {
		t.Fatalf("the driver's process sent %d bytes (%v) to a peer that is not the host", len(b), err)
	}
	if err := cmd.Wait(); cmd.ProcessState.ExitCode() != 1 {
		t.Fatalf("exit: %v, want status 1", err)
	}
	if out.Len() != 0 {
		t.Fatalf("Declare ran, or Main wrote output, for a wrong peer: %q", out)
	}
}

func TestMainNonDumpable(t *testing.T) {
	if r, _, _ := syscall.RawSyscall6(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0, 0, 0, 0); r != 1 {
		t.Fatalf("the test process is not dumpable (%d); the check proves nothing", r)
	}
	host, cmd, out := startDriver(t, os.Getuid())
	m, err := devslot.ReadMsg(host)
	want, _ := devslot.Canonical(probe{}.Declare())
	if err != nil || m.T != devslot.MsgDeclare || !bytes.Equal(m.B, want) {
		t.Fatalf("first message %+v, %v; want the canonical declaration", m, err)
	}
	if err := devslot.WriteMsg(host, devslot.PinMsg("dumpable", devslot.Pin{Address: "02:00:00:00:00:01"}, netip.Prefix{})); err != nil {
		t.Fatal(err)
	}
	r, err := devslot.ReadMsg(host)
	if err != nil || r.T != devslot.MsgReading || r.Kind != "dumpable" {
		t.Fatalf("reading %+v, %v", r, err)
	}
	if r.Value != 0 {
		t.Fatalf("the driver's process is dumpable (%d) while it runs the driver", r.Value)
	}
	if d, err := devslot.ReadMsg(host); err != nil || d.T != devslot.MsgDone || d.Err != "" {
		t.Fatalf("done %+v, %v", d, err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("exit: %v (%s)", err, out)
	}
	if out.String() != "declared\n" {
		t.Fatalf("Main wrote output: %q", out)
	}
}

// proc reaches the host only through descriptor 3: it imports no socket
// package, and nothing from this repository but the slot.
func TestProcImports(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", `{{join .Imports " "}}`, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	allowed := map[string]bool{"context": true, "errors": true, "os": true, "strconv": true, "syscall": true,
		"github.com/ghbmrk/agentos/broker/clerk/devslot": true}
	imps := strings.Fields(string(out))
	if len(imps) == 0 {
		t.Fatal("go list gave no imports; the check proves nothing")
	}
	for _, imp := range imps {
		if !allowed[imp] {
			t.Errorf("proc imports %s", imp)
		}
	}
}
