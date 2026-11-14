// Package port1 is the code the owner page's root step runs (KEY-9-reach-inbound-wiring,
// #5678): it picks port 1 from sysfs, checks a named one, renders the nft script that makes it
// the inbound page set's only element, and writes its name for the page (HW12-port1-set;
// CH-9, HW-12). It links only the standard library, and tools/trusted_core.txt counts it as a
// root of the trusted core, with cmd/agentos-port1, since it runs as root at every page start.
// netguard/inbound and the page (localui, cmd/agentos-localui) use its names; none is
// defined twice.
package port1

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// Table is the inbound nftables table (netguard/inbound's InboundTable).
const Table = "agentos_inbound"

// PageSet is the named set of the one interface the page's ports are open
// on (netguard/inbound's Inbound.Page).
const PageSet = "page"

// Close is the nft script that empties the page set, closing the page's
// ports on every link.
const Close = "flush set inet " + Table + " " + PageSet + "\n"

// ifaceRe is a Linux interface name.
var ifaceRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

// Admit renders the nft script that makes iface the page set's only
// element: a flush then an add in one nft -f transaction, so the set never
// holds two names, or none while it is being replaced. It refuses "lo" and
// any name ifaceRe refuses.
func Admit(iface string) (string, error) {
	if !ifaceRe.MatchString(iface) || iface == "lo" {
		return "", fmt.Errorf("netguard: %q is not an interface the page may serve on", iface)
	}
	return Close + fmt.Sprintf("add element inet %s %s { %q }\n", Table, PageSet, iface), nil
}

// Port1 is port 1's interface, read from the sysfs tree at sys (/sys on
// the box): the one Ethernet interface (type 1, no radio) on a fixed PCI
// device, leaving out virtual links, USB adapters (the edge's link cable,
// HW-15), Thunderbolt or USB4 networking and any device under a removable
// one, such as a PCIe NIC tunnelled through a dock (port 2's alternative,
// HW-12). It reads only what the box's hardware fixes, never DHCP or route
// state a peer on another port could set (WIFI-del-a3, CH-9). None, or
// more than one, is an error: nothing in sysfs says which jack the owner
// cabled to the enforcer, so a box with two fixed ports needs
// a drop-in that names the port for both of the unit's commands (an empty ExecStartPre= line, then the
// root step with -iface; and AGENTOS_PAGE_IFACE), or a board's .link name, and the page serves nothing rather than guess.
func Port1(sys string) (string, error) {
	ents, err := os.ReadDir(filepath.Join(sys, "class", "net"))
	if err != nil {
		return "", err
	}
	var found []string
	for _, e := range ents {
		dir := filepath.Join(sys, "class", "net", e.Name())
		path, err := filepath.EvalSymlinks(dir)
		if err != nil {
			continue
		}
		dev := filepath.Dir(filepath.Dir(path)) // .../<device>/net/<name>
		if !onPCIOnly(dev) || removable(dev) {
			continue
		}
		if t, err := os.ReadFile(filepath.Join(dir, "type")); err != nil || strings.TrimSpace(string(t)) != "1" {
			continue
		}
		if exists(filepath.Join(dir, "wireless")) || exists(filepath.Join(dir, "phy80211")) {
			continue
		}
		found = append(found, e.Name())
	}
	switch len(found) {
	case 0:
		return "", errors.New("localui: no fixed PCI Ethernet port to serve the page on")
	case 1:
		return found[0], nil
	}
	return "", errors.New("localui: more than one fixed Ethernet port (" + strings.Join(found, ", ") + "); name port 1 in a drop-in for agentos-localui.service that replaces its root step: an empty \"ExecStartPre=\" line, then \"ExecStartPre=+/usr/lib/agentos/agentos-port1 -iface <port> -port1-file /run/agentos-localui/port1\", and \"Environment=AGENTOS_PAGE_IFACE=<port>\" with the same port")
}

// Settled is Port1 read twice, wait apart, and only when both reads
// agree, so a port 1 whose driver probes after another port's within that
// wait refuses instead of serving on the other port until the watcher's
// first tick (Security release 1 on e867557). wait reports false when the
// caller is stopping.
func Settled(sys string, wait func() bool) (string, error) {
	p, err := Port1(sys)
	if err != nil {
		return "", err
	}
	if !wait() {
		return "", errors.New("stopped before port 1 settled")
	}
	q, err := Port1(sys)
	if err != nil {
		return "", err
	}
	if q != p {
		return "", errors.New("port 1 moved from " + p + " to " + q + " while starting; the unit picks again")
	}
	return p, nil
}

// Wired says why name, a port 1 named on the unit (-iface), is not a link
// the page's firewall rule may open: it must exist in the sysfs tree at sys
// and be Ethernet (type 1) with no radio, so a drop-in cannot open the
// page's ports on a radio or an access point (HW12-port1-set, CH-9). A
// root-made link, such as the harness's veth, qualifies.
func Wired(sys, name string) error {
	if !ifaceRe.MatchString(name) || name == "lo" {
		return errors.New("localui: " + strconv.Quote(name) + " is not an interface name")
	}
	dir := filepath.Join(sys, "class", "net", name)
	t, err := os.ReadFile(filepath.Join(dir, "type"))
	switch {
	case err != nil:
		return errors.New("localui: port 1 " + name + " is not a link I have")
	case strings.TrimSpace(string(t)) != "1":
		return errors.New("localui: port 1 " + name + " is not Ethernet")
	case exists(filepath.Join(dir, "wireless")) || exists(filepath.Join(dir, "phy80211")):
		return errors.New("localui: port 1 " + name + " is a radio; the page is never served on Wi-Fi")
	}
	return nil
}

// Write hands the page port 1's name in file. Root writes into the page
// user's runtime directory: a fresh file, never through a link left there.
// The unit's UMask=0077 binds `+` commands too, so the mode is set on the
// open file: the page reads it as another uid (#3382 L3 1, Security 1).
func Write(file, name string) error {
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString(name + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// removable: dev or a device above it says it is removable (the kernel's
// removable attribute: a Thunderbolt or USB4 tunnel, an ExpressCard).
func removable(dev string) bool {
	for d := dev; filepath.Base(d) != "devices" && d != filepath.Dir(d); d = filepath.Dir(d) {
		if b, err := os.ReadFile(filepath.Join(d, "removable")); err == nil && strings.TrimSpace(string(b)) == "removable" {
			return true
		}
	}
	return false
}

// onPCIOnly: dev is under a PCI root and under no USB, Thunderbolt or
// virtual device.
func onPCIOnly(dev string) bool {
	pci := false
	for _, seg := range strings.Split(filepath.ToSlash(dev), "/") {
		switch {
		case seg == "virtual", strings.HasPrefix(seg, "usb"), strings.HasPrefix(seg, "thunderbolt"), strings.HasPrefix(seg, "domain"):
			return false
		case strings.HasPrefix(seg, "pci"):
			pci = true
		}
	}
	return pci
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}
