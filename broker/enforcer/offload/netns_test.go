package offload

// REQ: NET-2

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/internal/netnstest"
)

// These tests run against the kernel in a fresh user and network
// namespace (unshare -rn), as broker/enforcer/nft's netns tests do; CI
// fails rather than skips them when a tool or kernel feature is missing.

const childEnv = "AGENTOS_OFFLOAD_NETNS"

func required() bool { return netnstest.Required() }

// inNetns re-runs the calling test in that namespace; a skip inside that
// run fails the test in CI (#5112).
func inNetns(t *testing.T) bool {
	t.Helper()
	return netnstest.Run(t, childEnv, combined, "nsenter", "ip")
}

func combined(env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = env
	return cmd.CombinedOutput()
}

func ip(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func merging(t *testing.T, dev string) []string {
	t.Helper()
	a, err := features(dev)
	if err != nil {
		t.Fatal(err)
	}
	var on []string
	for _, f := range Merging {
		if a[f] {
			on = append(on, f)
		}
	}
	return on
}

// TestOffTurnsMergingOff (ENF-cap-gro, #4610; NET-2 Byte caps): Off turns
// GRO off on a port and on every device under it, a bridge's member, a
// VLAN's parent and a macvlan's lower device, reads them back, and a
// repeat changes nothing. A lower device is set before the device on it,
// so the first Off over a macvlan and its lower device succeeds. A
// missing port and a feature the device holds fixed are errors, so the
// daemon holds that port at its caps. A veth's peer in another namespace
// is not under the port and is left as it is, even where its index is a
// local device's; any other parent in another namespace is an error.
//
// The test sets features with CAP_NET_ADMIN in its own namespace. The
// daemon has it only once ENF-m-b's unit gives it, in the namespace that
// holds the enforcer's ports; until then the placeholder unit has no
// network and no capability (ASSUMPTIONS ENF-gro-4).
func TestOffTurnsMergingOff(t *testing.T) {
	if !inNetns(t) {
		return
	}
	on := func(devs ...string) {
		t.Helper()
		for _, d := range devs {
			if err := Set(d, map[string]bool{"rx-gro": true}); err != nil {
				t.Fatal(err)
			}
			if len(merging(t, d)) == 0 {
				t.Fatalf("%s: GRO did not turn on", d)
			}
		}
	}
	off := func(what string, devs ...string) {
		t.Helper()
		for _, d := range devs {
			if on := merging(t, d); len(on) > 0 {
				t.Errorf("%s still merging after %s: %v", d, what, on)
			}
		}
	}
	ip(t, "link", "add", "va", "type", "veth", "peer", "name", "vb")
	ip(t, "link", "add", "br0", "type", "bridge")
	ip(t, "link", "set", "va", "master", "br0")
	on("va", "vb", "br0")
	if err := Off("br0"); err != nil {
		t.Fatal(err)
	}
	off("Off(br0)", "br0", "va", "vb") // vb is va's peer, in this namespace
	if err := Off("br0"); err != nil {
		t.Fatalf("a repeat: %v", err)
	}

	vlan := exec.Command("ip", "link", "add", "link", "vb", "name", "vb.10", "type", "vlan", "id", "10").Run() == nil
	switch {
	case vlan:
		on("vb")
		if err := Off("vb.10"); err != nil {
			t.Fatal(err)
		}
		off("Off(vb.10)", "vb")
	case required():
		t.Fatal("the kernel has no 802.1Q VLAN support")
	default:
		t.Log("no 802.1Q support here: the VLAN case is skipped")
	}

	// A macvlan takes rx-gro from its lower device: set first, the macvlan
	// would read back still on. Its lower device is on the list too, after it.
	ip(t, "link", "add", "lw0", "type", "veth", "peer", "name", "lw1")
	ip(t, "link", "add", "mv0", "link", "lw0", "type", "macvlan")
	on("lw0", "mv0")
	if err := Off("mv0", "lw0"); err != nil {
		t.Fatalf("the first Off over a macvlan: %v", err)
	}
	off("Off(mv0, lw0)", "mv0", "lw0")

	if err := Off("nope"); err == nil || !strings.Contains(err.Error(), "port nope: no such device") {
		t.Fatalf("a missing port: %v", err)
	}
	if err := Set("va", map[string]bool{"rx-gro-hw": true}); !errors.Is(err, ErrStuck) {
		t.Fatalf("a feature the veth holds fixed off: %v", err)
	}

	// A peer in another namespace.
	other := exec.Command("unshare", "-n", "sleep", "60")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { other.Process.Kill(); other.Wait() }()
	self, _ := os.Readlink("/proc/self/ns/net")
	for i := 0; ; i++ {
		if ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", other.Process.Pid)); err == nil && ns != self {
			break
		}
		if i > 200 {
			t.Fatal("namespace never appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// vc's IFLA_LINK is vd's index in the other namespace, 77, which is
	// also lx's here: read as a local index, Off(vc) would reach lx.
	ip(t, "link", "add", "lx", "index", "77", "type", "veth", "peer", "name", "ly")
	// ip sets no index on a peer, so the pair is made there and vc moved here.
	pid := strconv.Itoa(other.Process.Pid)
	if out, err := exec.Command("nsenter", "-t", pid, "-n", "ip", "link", "add", "vd", "index", "77", "type", "veth",
		"peer", "name", "vc", "netns", strconv.Itoa(os.Getpid())).CombinedOutput(); err != nil {
		t.Fatalf("vd and vc: %v\n%s", err, out)
	}
	on("lx", "ly")
	inOther := func(f func()) {
		runtime.LockOSThread() // unlocked only once back: a thread left elsewhere exits with this goroutine
		back, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		defer back.Close()
		there, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", other.Process.Pid))
		if err != nil {
			t.Fatal(err)
		}
		defer there.Close()
		if err := unix.Setns(int(there.Fd()), unix.CLONE_NEWNET); err != nil {
			t.Fatal(err)
		}
		f()
		if err := unix.Setns(int(back.Fd()), unix.CLONE_NEWNET); err != nil {
			t.Fatal(err)
		}
		runtime.UnlockOSThread()
	}
	inOther(func() { on("vd") })
	if err := Off("vc"); err != nil {
		t.Fatal(err)
	}
	if len(merging(t, "lx")) == 0 || len(merging(t, "ly")) == 0 {
		t.Error("Off(vc) read its peer's index in another namespace as a local device's")
	}
	inOther(func() {
		if len(merging(t, "vd")) == 0 {
			t.Error("Off(vc) reached its peer in another namespace")
		}
	})

	// A macvlan whose lower device stays here once it is moved there: Off
	// cannot reach the lower device from there, so it is an error, not a
	// pass.
	ip(t, "link", "add", "mv1", "link", "vc", "type", "macvlan")
	ip(t, "link", "set", "mv1", "netns", pid)
	inOther(func() {
		if err := Off("mv1"); err == nil || !strings.Contains(err.Error(), "mv1: its parent is in another namespace") {
			t.Errorf("a macvlan whose lower device is in another namespace: %v", err)
		}
	})
}
