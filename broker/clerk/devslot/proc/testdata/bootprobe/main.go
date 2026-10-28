// Command bootprobe is the CI boot probe of a fixture driver instance
// (image/ci_boot.sh, DEVSLOT-drivers b2b-2, #3590), run as root in a CI-only
// unit of a booted image whose driver template is rendered for "fixture"
// with bootdriver as its binary:
//
//	bootprobe -cgroup /agentos.slice/agentos-drivers.slice/agentos-driver-fixture@.service
//
// It stands in for the kernel's unlock with a synthetic clerk root key, and
// for pairing: it writes the fixture's device-key file, two slots sealed
// under clerk driver-fixture's key, and serves that clerk's key socket with
// the kernel's own code (kernel/proc.ServeClerkKey) for the template's
// instances. Then, as the host's uid, it runs two operations through the
// driver's socket unit, each a fresh instance, and prints one
// "agentos-devslot:" line per check and a last DONE line:
//   - probe: no socket() of any family, /etc/passwd is not there (ENOENT)
//     in a root that is the empty tmpfs,
//     descriptor 0 is /dev/null, and Lend yields the fixture's own slot's
//     canary (so the instance started under the main side's mask, and the
//     kernel handed its key to a template instance);
//   - hang: a Run that never returns is ended by PID 1 at the template's
//     RuntimeMaxSec=, with no done message.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	kproc "github.com/ghbmrk/agentos/broker/kernel/proc"
)

// These match bootdriver's and the template's (mkosi.finalize's
// DRIVER_TEMPLATE, DRIVER_KEY_SOCKET and DEVHOST_UID).
const (
	name        = "fixture"
	keyCanary   = "canary-devkey-boot-0001"
	otherCanary = "canary-devkey-boot-0002"
	keySocket   = "/run/agentos-kernel/key-driver-fixture.sock"
	deviceFile  = "/var/lib/agentos-drivers/fixture/device"
	driverSock  = "/run/agentos-drivers/fixture.sock"
	hostUID     = 900
	runtimeMax  = 120 * time.Second
)

var failed bool

func say(ok bool, format string, a ...any) {
	v := "ok  "
	if !ok {
		v, failed = "FAIL", true
	}
	fmt.Printf("agentos-devslot: %s %s\n", v, fmt.Sprintf(format, a...))
}

func main() {
	cgroup := flag.String("cgroup", "", "the driver template's whole cgroup path")
	flag.Parse()
	if err := setUp(*cgroup); err != nil {
		say(false, "set-up: %v", err)
	} else {
		probe()
		hang()
	}
	fmt.Println("agentos-devslot: DONE")
}

// setUp writes the device-key file, serves the key socket, and drops to the
// host's uid.
func setUp(cgroup string) error {
	var root [clerkkey.Len]byte // synthetic: the unlock step's would be the store's
	for i := range root {
		root[i] = byte(0xb0 + i)
	}
	k, err := clerkkey.Derive(&root, "driver-"+name)
	if err != nil {
		return err
	}
	sk, err := k.Sealer()
	if err != nil {
		return err
	}
	sl, err := clerk.NewAESSealer(sk)
	if err != nil {
		return err
	}
	s := clerk.NewSecrets(sl, nil)
	if err := errors.Join(s.Put("device/"+name, clerk.KindStatic, []byte(keyCanary)),
		s.Put("device/other", clerk.KindStatic, []byte(otherCanary))); err != nil {
		return err
	}
	b, err := s.MarshalBinary()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(deviceFile), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(deviceFile, b, 0o400); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keySocket), 0o711); err != nil {
		return err
	}
	ln, err := kproc.ListenClerkKey(keySocket)
	if err != nil {
		return err
	}
	go func() {
		err := kproc.ServeClerkKey(ln, "driver-"+name, cgroup, &root)
		say(false, "key socket ended: %v", err)
	}()
	if err := syscall.Setgroups(nil); err != nil {
		return err
	}
	if err := syscall.Setresgid(hostUID, hostUID, hostUID); err != nil {
		return err
	}
	return syscall.Setresuid(hostUID, hostUID, hostUID)
}

// start connects as the host, so the socket unit starts an instance, and
// sends op once the instance has declared.
func start(op string) (net.Conn, error) {
	c, err := net.Dial("unix", driverSock)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(30 * time.Second))
	m, err := devslot.ReadMsg(c)
	if err != nil || m.T != devslot.MsgDeclare {
		c.Close()
		return nil, fmt.Errorf("no declaration (%v): the instance did not start", err)
	}
	if err := devslot.WriteMsg(c, devslot.PinMsg(op, devslot.Pin{Address: "02:00:00:00:00:01"}, netip.Prefix{})); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func probe() {
	c, err := start("probe")
	if err != nil {
		say(false, "probe: %v", err)
		return
	}
	defer c.Close()
	got := map[string]int64{}
	for {
		m, err := devslot.ReadMsg(c)
		if err != nil {
			say(false, "probe: %v", err)
			return
		}
		if m.T == devslot.MsgDone {
			say(m.Err == "", "probe operation done")
			break
		}
		if m.T == devslot.MsgReading {
			got[m.Kind] = m.Value
		}
	}
	say(true, "instance started under the main side's mask")
	say(got["inet"] == 1 && got["unix"] == 1, "socket() refused (inet=%d unix=%d)", got["inet"], got["unix"])
	say(got["passwd"] == 1, "opening /etc/passwd fails with ENOENT")
	say(got["root"] == 1, "the root is the empty tmpfs (no /etc, no /var)")
	say(got["stdin"] == 1, "descriptor 0 is /dev/null")
	say(got["key"] == 1, "Lend yields the canary key and no other slot (key=%d)", got["key"])
}

func hang() {
	t0 := time.Now()
	c, err := start("hang")
	if err != nil {
		say(false, "hang: %v", err)
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * runtimeMax))
	m, err := devslot.ReadMsg(c)
	d := time.Since(t0).Round(time.Second)
	say(err != nil && d >= runtimeMax-5*time.Second && d < runtimeMax+60*time.Second,
		"a hung operation is killed at RuntimeMaxSec (after %s, message %v, %v)", d, m.T, err)
}
