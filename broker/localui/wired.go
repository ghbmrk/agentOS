package localui

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Page is where the owner page is served (CH-9, D-178): one wired
// interface, the core's port 1, its cable to the enforcer (HW-12). The
// enforcer routes the Owner network and its wired admin port to it; the
// core's address there comes from DHCP, so the page binds no fixed address
// and admits no subnet (WIFI-del-a3).
type Page struct {
	// Iface is port 1's interface (Port1 on the image).
	Iface string
	// PageName is the owner page's name over HTTPS (OWN-page-https,
	// #3153); DefaultPageName when empty.
	PageName string
}

// pageName is the page's name, DefaultPageName when unset.
func (p Page) pageName() string {
	if p.PageName == "" {
		return DefaultPageName
	}
	return p.PageName
}

// Validate refuses an interface the page could not be bound to alone, and
// a page name its authority could not admit (CH-9).
func (p Page) Validate() error {
	switch {
	case !ifaceRe.MatchString(p.Iface) || p.Iface == "lo":
		return errors.New("localui: the page's interface name")
	case len(p.pageName()) > 253 || !pageNameRe.MatchString(p.pageName()) || isAddr(p.pageName()):
		return errors.New("localui: page name")
	}
	return nil
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
// AGENTOS_PAGE_IFACE, the unit's -iface (or a board's .link name) and the page serves nothing rather than guess.
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
	return "", errors.New("localui: more than one fixed Ethernet port (" + strings.Join(found, ", ") + "); name port 1 with AGENTOS_PAGE_IFACE in a drop-in for agentos-localui.service (-iface)")
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
		return errors.New("localui: port 1 " + name + " is not a link on this box")
	case strings.TrimSpace(string(t)) != "1":
		return errors.New("localui: port 1 " + name + " is not Ethernet")
	case exists(filepath.Join(dir, "wireless")) || exists(filepath.Join(dir, "phy80211")):
		return errors.New("localui: port 1 " + name + " is a radio; the page is never served on Wi-Fi")
	}
	return nil
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

// reached is the address r's connection reached on the box, from the
// server's LocalAddrContextKey; invalid when the server set none.
func reached(r *http.Request) netip.AddrPort {
	a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return netip.AddrPort{}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// homeSource: r comes from a private IPv4 address (RFC 1918) that is none
// of the box's own, the one it reached included (CH-9), so no process on
// the box reaches the page by steering a connection onto port 1. The
// listener is already bound to port 1; the enforcer routes only the Owner
// network and its admin port there.
func homeSource(r *http.Request) bool {
	box := reached(r)
	from, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !box.IsValid() {
		return false
	}
	a := from.Addr().Unmap()
	if !a.Is4() || !a.IsPrivate() || a == box.Addr() {
		return false
	}
	own, err := ownAddrs()
	if err != nil {
		return false
	}
	for _, o := range own {
		if o.Unmap() == a {
			return false
		}
	}
	return true
}

// ownAddrs lists the box's own addresses (boxAddrs); a test replaces it.
var ownAddrs = boxAddrs

// reachedHost is the plain listener's IP-literal host for r: the address
// its connection reached, with the port unless it is 80. "" when unknown.
func reachedHost(r *http.Request) string {
	box := reached(r)
	if !box.IsValid() {
		return ""
	}
	if box.Port() == 80 {
		return box.Addr().String()
	}
	return box.String()
}
