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
)

// These tests run against the kernel in a fresh user and network
// namespace (unshare -rn), as broker/enforcer/nft's netns tests do; CI
// fails rather than skips them when a tool or kernel feature is missing.

const childEnv = "AGENTOS_OFFLOAD_NETNS"

func required() bool { return os.Getenv("CI") != "" || os.Getenv("AGENTOS_REQUIRE_NETNS") == "1" }

func inNetns(t *testing.T) bool {
	t.Helper()
	if os.Getenv(childEnv) == "1" {
		return true
	}
	for _, tool := range []string{"unshare", "ip"} {
		if _, err := exec.LookPath(tool); err != nil {
			if required() {
				t.Fatalf("%s missing", tool)
			}
			t.Skipf("%s missing", tool)
		}
	}
	if err := exec.Command("unshare", "-rn", "true").Run(); err != nil {
		if required() {
			t.Fatalf("no unprivileged user namespaces: %v", err)
		}
		t.Skipf("no unprivileged user namespaces: %v", err)
	}
	cmd := exec.Command("unshare", "-rn", "--", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("in a fresh namespace:\n%s", out)
	if err != nil {
		t.Fatalf("netns run failed: %v", err)
	}
	return false
}

func ip(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func merging(t *testing.T, dev string) []string {
	t.Helper()
	a, err := Active(dev)
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
// GRO off on a port and on every device under it, a bridge's member and a
// VLAN's parent, reads them back, and a repeat changes nothing. A missing
// port and a feature the device holds fixed are errors, so the daemon
// refuses to start on them. A veth's peer in another namespace is not
// under the port and is left as it is.
func TestOffTurnsMergingOff(t *testing.T) {
	if !inNetns(t) {
		return
	}
	ip(t, "link", "add", "va", "type", "veth", "peer", "name", "vb")
	ip(t, "link", "add", "br0", "type", "bridge")
	ip(t, "link", "set", "va", "master", "br0")
	for _, d := range []string{"va", "vb", "br0"} {
		if err := Set(d, map[string]bool{"rx-gro": true}); err != nil {
			t.Fatal(err)
		}
		if on := merging(t, d); len(on) == 0 {
			t.Fatalf("%s: GRO did not turn on", d)
		}
	}
	if err := Off("br0"); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"br0", "va", "vb"} { // vb is va's peer, in this namespace
		if on := merging(t, d); len(on) > 0 {
			t.Errorf("%s still merging after Off(br0): %v", d, on)
		}
	}
	if err := Off("br0"); err != nil {
		t.Fatalf("a repeat: %v", err)
	}

	vlan := exec.Command("ip", "link", "add", "link", "vb", "name", "vb.10", "type", "vlan", "id", "10").Run() == nil
	switch {
	case vlan:
		if err := Set("vb", map[string]bool{"rx-gro": true}); err != nil {
			t.Fatal(err)
		}
		if err := Off("vb.10"); err != nil {
			t.Fatal(err)
		}
		if on := merging(t, "vb"); len(on) > 0 {
			t.Errorf("a VLAN's parent still merging: %v", on)
		}
	case required():
		t.Fatal("the kernel has no 802.1Q VLAN support")
	default:
		t.Log("no 802.1Q support here: the VLAN case is skipped")
	}

	if err := Off("nope"); err == nil || !strings.Contains(err.Error(), "port nope: no such device") {
		t.Fatalf("a missing port: %v", err)
	}
	if err := Set("va", map[string]bool{"rx-gro-hw": true}); err == nil {
		t.Fatal("a feature the veth holds fixed off turned on")
	} else if !errors.Is(err, ErrStuck) {
		t.Logf("the kernel refused the change itself: %v", err)
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
	ip(t, "link", "add", "vc", "type", "veth", "peer", "name", "vd", "netns", strconv.Itoa(other.Process.Pid))
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
	inOther(func() {
		if err := Set("vd", map[string]bool{"rx-gro": true}); err != nil {
			t.Fatal(err)
		}
	})
	if err := Off("vc"); err != nil {
		t.Fatal(err)
	}
	inOther(func() {
		if on := merging(t, "vd"); len(on) == 0 {
			t.Error("Off(vc) reached its peer in another namespace")
		}
	})
}
