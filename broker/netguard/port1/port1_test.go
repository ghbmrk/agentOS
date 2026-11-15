package port1

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REQ: CH-9, HW-12, HW-15

// sysNet builds a sysfs tree under a temporary root: one interface per
// entry, at its device path, with its type and, for a radio, a phy80211
// link; class/net links to each as the kernel's does.
func sysNet(t *testing.T, ifaces map[string]struct {
	dev, typ string
	radio    bool
}) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "class", "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, i := range ifaces {
		dir := filepath.Join(root, "devices", i.dev, "net", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "type"), []byte(i.typ+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if i.radio {
			if err := os.Mkdir(filepath.Join(dir, "phy80211"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(filepath.Join("..", "..", "devices", i.dev, "net", name), filepath.Join(root, "class", "net", name)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// WIFI-del-a3 (CH-9, HW-15, HW-12; review blockers on f778fcf and
// 713fd31): port 1 comes from what the hardware fixes, never from DHCP or
// routes, and never from a guess. The one fixed PCI Ethernet port is port
// 1; a USB adapter (the edge's cable), Thunderbolt networking, a PCIe NIC
// tunnelled through a dock (under a removable device), a radio, a virtual
// or non-Ethernet link never is; and two or three fixed ports, with port 1
// at any position among them, are refused, since nothing says which jack
// goes to the enforcer. It catches a page bound to the edge's cable or
// port 2.
func TestPort1IsFixedByHardwareNotRoutes(t *testing.T) {
	type nic = struct {
		dev, typ string
		radio    bool
	}
	i219 := nic{"pci0000:00/0000:00:1f.6", "1", false}
	edgeUSB := nic{"pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0", "1", false}
	onboard1c0 := nic{"pci0000:00/0000:00:1c.0/0000:01:00.0", "1", false}
	onboard1c1 := nic{"pci0000:00/0000:00:1c.1/0000:02:00.0", "1", false}
	dock := nic{"pci0000:00/0000:00:07.0/0000:20:00.0/0000:21:01.0/0000:2c:00.0", "1", false}
	others := map[string]nic{
		"enx001122334455": edgeUSB,
		"thunderbolt0":    {"pci0000:00/0000:00:0d.2/domain0/0-0/0-1/0-1.0", "1", false},
		"wlan0":           {"pci0000:00/0000:00:14.3", "1", true},
		"veth9":           {"virtual", "1", false},
		"lo":              {"virtual", "772", false},
		"wwan0":           {"pci0000:00/0000:00:1b.0/0000:01:00.0", "65534", false},
		"enp44s0":         dock,
	}
	with := func(m map[string]nic) map[string]nic {
		out := map[string]nic{}
		for k, v := range others {
			out[k] = v
		}
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	// The dock's tunnel: the kernel marks the device below the USB4 root
	// port removable.
	tree := func(m map[string]nic) string {
		root := sysNet(t, m)
		if err := os.WriteFile(filepath.Join(root, "devices", "pci0000:00/0000:00:07.0/0000:20:00.0", "removable"), []byte("removable\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return root
	}
	if got, err := Port1(tree(with(map[string]nic{"enp0s31f6": i219}))); got != "enp0s31f6" || err != nil {
		t.Fatalf("one fixed port beside a dock, the edge's adapter and the rest: %q, %v", got, err)
	}
	for name, m := range map[string]map[string]nic{
		"two fixed ports, port 1 sorting last":    {"enp0s31f6": i219, "enp1s0": onboard1c0},
		"two fixed ports, port 1 sorting first":   {"enp1s0": onboard1c0, "enp2s0": onboard1c1},
		"three fixed ports (edge on an onboard)":  {"enp0s31f6": i219, "enp1s0": onboard1c0, "enp2s0": onboard1c1},
		"no fixed port: only adapters and radios": {},
	} {
		if got, err := Port1(tree(with(m))); err == nil {
			t.Errorf("%s: chose %q", name, got)
		}
	}
	// #4881 L3 1: the two-port refusal tells the operator to replace the root step, since a drop-in
	// ExecStartPre= line alone appends after the image's, which refuses first.
	if _, err := Port1(tree(with(map[string]nic{"enp0s31f6": i219, "enp1s0": onboard1c0}))); err == nil ||
		!strings.Contains(err.Error(), `an empty "ExecStartPre=" line, then "ExecStartPre=+/usr/lib/agentos/agentos-port1 -iface <port>`) ||
		!strings.Contains(err.Error(), `"Environment=AGENTOS_PAGE_IFACE=<port>"`) {
		t.Errorf("two fixed ports: %v", err)
	}
	if got, err := Port1(t.TempDir()); err == nil {
		t.Fatalf("no sysfs tree named %q", got)
	}
	// The root step and the page's start-up read sysfs through this package,
	// not the route table (#5678: no second copy of Port1).
	for file, call := range map[string]string{"../../cmd/agentos-port1/main.go": "port1.Settled(", "../../cmd/agentos-localui/main.go": "port1.Port1("} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "/proc/net/route") || !strings.Contains(string(src), call) {
			t.Fatalf("%s does not pick port 1 with %s", file, call)
		}
	}
}

// HW12-port1-set (CH-9): a port 1 named on the unit opens the page's
// firewall rule only if it is a wired Ethernet link on this box: a radio,
// a missing link, a non-Ethernet link, loopback or a malformed name is
// refused with a reason that names it. A root-made veth (the harness's)
// and a kernel eth* name pass.
// REQ: CH-9
func TestWiredRefusesRadiosAndMissingLinks(t *testing.T) {
	type nic = struct {
		dev, typ string
		radio    bool
	}
	sys := sysNet(t, map[string]nic{
		"eth0":     {"pci0000:00/0000:00:1f.6", "1", false},
		"enowner0": {"virtual", "1", false},
		"wlan0":    {"pci0000:00/0000:00:14.3", "1", true},
		"wwan0":    {"pci0000:00/0000:00:1b.0/0000:01:00.0", "65534", false},
		"lo":       {"virtual", "772", false},
	})
	for _, ok := range []string{"eth0", "enowner0"} {
		if err := Wired(sys, ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for name, why := range map[string]string{
		"wlan0":   "radio",
		"wwan0":   "not Ethernet",
		"enp9s0":  "not a link",
		"lo":      "not an interface name",
		"":        "not an interface name",
		"a b":     "not an interface name",
		"../eth0": "not an interface name",
	} {
		err := Wired(sys, name)
		if err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%q: %v, want an error saying %q", name, err, why)
		}
	}
	// A wireless directory, not only phy80211, marks a radio.
	if err := os.Mkdir(filepath.Join(sys, "class", "net", "eth0", "wireless"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Wired(sys, "eth0"); err == nil {
		t.Error("eth0 with a wireless directory passed")
	}
}

// HW12-port1-set (CH-9): Settled admits port 1 only when two reads, a wait
// apart, agree; a fixed port that probes during the wait, or a stop, refuses
// (Security 4 on 713fd31, Security release 1 on e867557).
// REQ: CH-9, HW-15
func TestSettledRefusesAPortThatMoved(t *testing.T) {
	type nic = struct {
		dev, typ string
		radio    bool
	}
	sys := sysNet(t, map[string]nic{"enp1s0": {"pci0000:00/0000:00:1c.0/0000:01:00.0", "1", false}})
	if p, err := Settled(sys, func() bool { return true }); err != nil || p != "enp1s0" {
		t.Fatalf("port 1: %q, %v", p, err)
	}
	late := func() bool {
		dir := filepath.Join(sys, "devices", "pci0000:00/0000:00:1f.6", "net", "enp0s31f6")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "type"), []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("..", "..", "devices", "pci0000:00/0000:00:1f.6", "net", "enp0s31f6"), filepath.Join(sys, "class", "net", "enp0s31f6")); err != nil {
			t.Fatal(err)
		}
		return true
	}
	if q, err := Settled(sys, late); err == nil {
		t.Fatalf("a port that probed during start-up: chose %q", q)
	}
	if err := os.Remove(filepath.Join(sys, "class", "net", "enp0s31f6")); err != nil {
		t.Fatal(err)
	}
	if q, err := Settled(sys, func() bool { return false }); err == nil {
		t.Fatalf("stopped while settling: chose %q", q)
	}
}

// HW12-port1-set (CH-9): the admit script flushes the page set, then adds
// one element, in one transaction; it refuses loopback and malformed names.
// REQ: CH-9
func TestAdmitHoldsOneName(t *testing.T) {
	s, err := Admit("enp1s0")
	if err != nil || s != "flush set inet agentos_inbound page\nadd element inet agentos_inbound page { \"enp1s0\" }\n" {
		t.Fatalf("%q, %v", s, err)
	}
	for _, bad := range []string{"", "lo", "a b", "eth0\"", "a-very-long-interface", "eth0;flush"} {
		if _, err := Admit(bad); err == nil {
			t.Errorf("admitted %q", bad)
		}
	}
	if Close != "flush set inet agentos_inbound page\n" {
		t.Errorf("close script %q", Close)
	}
}

// HW12-port1-set (CH-9): each refusal names its own cause, so the journal
// says why the page serves nothing: a missing sysfs tree is that read's
// error, no fixed port says so, and Settled reports the read that failed
// without waiting, or a port that changed name while it waited (mutgate
// survivors on #5733).
// REQ: CH-9, HW-12
func TestRefusalsNameTheirCause(t *testing.T) {
	type nic = struct {
		dev, typ string
		radio    bool
	}
	if _, err := Port1(filepath.Join(t.TempDir(), "none")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("no sysfs tree: %v, want the read's not-exist error", err)
	}
	none := sysNet(t, map[string]nic{"wlan0": {"pci0000:00/0000:00:14.3", "1", true}})
	if _, err := Port1(none); err == nil || !strings.Contains(err.Error(), "no fixed PCI Ethernet port") {
		t.Errorf("no fixed port: %v", err)
	}
	waited := false
	if _, err := Settled(none, func() bool { waited = true; return true }); err == nil || waited {
		t.Errorf("no port 1: waited %v, %v", waited, err)
	}
	// Port 1 goes away during the wait: Port1's refusal, not a move.
	sys := sysNet(t, map[string]nic{"enp1s0": {"pci0000:00/0000:00:1c.0/0000:01:00.0", "1", false}})
	gone := func() bool { return os.Remove(filepath.Join(sys, "class", "net", "enp1s0")) == nil }
	if _, err := Settled(sys, gone); err == nil || !strings.Contains(err.Error(), "no fixed PCI Ethernet port") {
		t.Errorf("port 1 gone while settling: %v", err)
	}
	// Port 1 is renamed during the wait (one port before, another after).
	sys = sysNet(t, map[string]nic{"enp1s0": {"pci0000:00/0000:00:1c.0/0000:01:00.0", "1", false}})
	renamed := func() bool {
		return os.Rename(filepath.Join(sys, "class", "net", "enp1s0"), filepath.Join(sys, "class", "net", "eth0")) == nil
	}
	if p, err := Settled(sys, renamed); err == nil || !strings.Contains(err.Error(), "moved from enp1s0 to eth0") {
		t.Errorf("port 1 renamed while settling: %q, %v", p, err)
	}
}
