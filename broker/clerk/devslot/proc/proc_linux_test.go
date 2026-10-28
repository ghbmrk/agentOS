package proc_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/proc"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// REQ: CLK-1, DEV-1, DEV-3

// childEnv marks the test binary run as a driver's process: Main serves
// the probe driver on descriptor 3 and exits.
const childEnv = "DEVSLOT_TEST_CHILD"

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "1" {
		// systemd sets LISTEN_PID to the process it execs; the parent
		// cannot know it before the start.
		if os.Getenv("LISTEN_FDS") != "" {
			os.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
		}
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
		Operations:  []devslot.Operation{{Name: "dumpable", Verb: key.Read}, {Name: "key", Verb: key.Read}},
		Readings:    []string{"dumpable", "key"},
		MaxRead:     1,
		MaxReadings: 1,
	}
}

// keyCanary is the device key the key test seals in the probe's slot, and
// otherCanary a slot beside it that no Lend may yield.
const keyCanary, otherCanary = "canary-devkey-0001", "canary-devkey-0002"

func (probe) Run(_ context.Context, op string, _ devslot.Link, s devslot.Secrets) ([]devslot.Reading, error) {
	if op == "key" {
		// 1: the canary; 2: the other slot; 3: no key; 0: anything else.
		v := int64(0)
		err := s.Open(func(k []byte) error {
			switch string(k) {
			case keyCanary:
				v = 1
			case otherCanary:
				v = 2
			}
			return nil
		})
		if errors.Is(err, devslot.ErrNoKey) {
			v = 3
		}
		return []devslot.Reading{{Kind: "key", Value: v, Time: time.Unix(1e9, 0)}}, nil
	}
	r, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0, 0, 0, 0)
	if e != 0 {
		return nil, e
	}
	return []devslot.Reading{{Kind: "dumpable", Value: int64(r), Time: time.Unix(1e9, 0)}}, nil
}

// startDriver runs the test binary as a driver's process with one end of a
// socket pair on descriptor 3, as its socket unit would, and returns the
// host's end.
func startDriver(t *testing.T, hostUID int, keyFiles ...*os.File) (*os.File, *exec.Cmd, *bytes.Buffer) {
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
	cmd.ExtraFiles = append([]*os.File{end}, keyFiles...)
	if len(keyFiles) > 0 {
		cmd.Env = append(cmd.Env, "LISTEN_FDS=3", "LISTEN_FDNAMES=connection:"+proc.KeyFDName+":"+proc.DeviceFDName, proc.DriverEnv+"=probe")
	}
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
		"crypto/aes": true, "crypto/cipher": true, "encoding/json": true, "io": true, "regexp": true, "strings": true,
		"github.com/ghbmrk/agentos/broker/clerk/devslot": true, "github.com/ghbmrk/agentos/broker/clerk/clerkkey": true}
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

// DEVSLOT-drivers b2b-2 (#3590): a driver's process given its unit's two
// key files (the kernel's hand-off as clerk driver-probe, and the sealed
// device-key file holding its slot and another) lends the driver its own
// slot's key and no other; given none, the device has no key. Fails if
// Main drops the key, or lends a slot other than device/<name>.
func TestMainLendsTheDeviceKey(t *testing.T) {
	for _, c := range []struct {
		name  string
		files func(t *testing.T) []*os.File
		want  int64
	}{
		{"the template's files", func(t *testing.T) []*os.File { return keyFiles(t, "driver-probe") }, 1},
		{"no files", func(*testing.T) []*os.File { return nil }, 3},
	} {
		host, cmd, out := startDriver(t, os.Getuid(), c.files(t)...)
		if m, err := devslot.ReadMsg(host); err != nil || m.T != devslot.MsgDeclare {
			t.Fatalf("%s: first message %+v, %v (%s)", c.name, m, err, out)
		}
		if err := devslot.WriteMsg(host, devslot.PinMsg("key", devslot.Pin{Address: "02:00:00:00:00:01"}, netip.Prefix{})); err != nil {
			t.Fatal(err)
		}
		if r, err := devslot.ReadMsg(host); err != nil || r.T != devslot.MsgReading || r.Kind != "key" || r.Value != c.want {
			t.Fatalf("%s: reading %+v, %v; want key=%d", c.name, r, err, c.want)
		}
		if d, err := devslot.ReadMsg(host); err != nil || d.T != devslot.MsgDone || d.Err != "" {
			t.Fatalf("%s: done %+v, %v", c.name, d, err)
		}
		if err := cmd.Wait(); err != nil {
			t.Fatalf("%s: exit: %v (%s)", c.name, err, out)
		}
	}
	// Another driver's key opens nothing: the process serves nothing.
	host, cmd, _ := startDriver(t, os.Getuid(), keyFiles(t, "driver-hue")...)
	if b, _ := io.ReadAll(host); len(b) != 0 {
		t.Fatalf("the driver's process served %d bytes under another driver's key", len(b))
	}
	if cmd.Wait(); cmd.ProcessState.ExitCode() != 1 {
		t.Fatal("the driver's process did not exit 1 under another driver's key")
	}
}

// keyFiles is the template's two files for driver probe: a pipe holding
// the kernel's hand-off as clerkName, and a device-key file sealed under the
// probe clerk's key, as the clerk's at-rest form, with the probe's slot
// and one beside it.
func keyFiles(t *testing.T, clerkName string) []*os.File {
	t.Helper()
	var root [clerkkey.Len]byte
	for i := range root {
		root[i] = byte(0x40 + i)
	}
	sealed := func(name string) []byte {
		k, err := clerkkey.Derive(&root, name)
		if err != nil {
			t.Fatal(err)
		}
		sk, _ := k.Sealer()
		sl, err := clerk.NewAESSealer(sk)
		if err != nil {
			t.Fatal(err)
		}
		s := clerk.NewSecrets(sl, nil)
		if s.Put("device/probe", clerk.KindStatic, []byte(keyCanary)) != nil || s.Put("device/other", clerk.KindStatic, []byte(otherCanary)) != nil {
			t.Fatal("put")
		}
		b, err := s.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	k, err := clerkkey.Derive(&root, clerkName)
	if err != nil {
		t.Fatal(err)
	}
	b, err := clerkkey.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Write(b)
	w.Close()
	p := filepath.Join(t.TempDir(), "device")
	if err := os.WriteFile(p, sealed("driver-probe"), 0o400); err != nil {
		t.Fatal(err)
	}
	d, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); d.Close() })
	return []*os.File{r, d}
}

// The CI boot probe's two programs (image/ci_boot.sh, b2b-2) build and vet
// here, so a change to proc or the kernel's key hand-off that breaks them
// fails before the image job.
func TestBootProbeBuilds(t *testing.T) {
	out, err := exec.Command("go", "vet", "./testdata/bootdriver", "./testdata/bootprobe").CombinedOutput()
	if err != nil {
		t.Fatalf("go vet: %v\n%s", err, out)
	}
}
