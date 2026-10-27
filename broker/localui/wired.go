package localui

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
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
// the box): the Ethernet interface (type 1, no radio) whose device sits on
// the PCI bus at the lowest device path, leaving out virtual links, USB
// adapters (the edge's link cable, HW-15) and Thunderbolt or USB4
// networking (port 2's alternative, HW-12). It reads only what the box's
// hardware fixes, never DHCP or route state a peer on another port could
// set (WIFI-del-a3, CH-9). None is an error: the page serves nothing
// rather than guess.
func Port1(sys string) (string, error) {
	ents, err := os.ReadDir(filepath.Join(sys, "class", "net"))
	if err != nil {
		return "", err
	}
	found, at := "", ""
	for _, e := range ents {
		dir := filepath.Join(sys, "class", "net", e.Name())
		path, err := filepath.EvalSymlinks(dir)
		if err != nil {
			continue
		}
		dev := filepath.Dir(filepath.Dir(path)) // .../<device>/net/<name>
		if !onPCIOnly(dev) {
			continue
		}
		if t, err := os.ReadFile(filepath.Join(dir, "type")); err != nil || strings.TrimSpace(string(t)) != "1" {
			continue
		}
		if exists(filepath.Join(dir, "wireless")) || exists(filepath.Join(dir, "phy80211")) {
			continue
		}
		if found == "" || dev < at {
			found, at = e.Name(), dev
		}
	}
	if found == "" {
		return "", errors.New("localui: no PCI Ethernet port to serve the page on")
	}
	return found, nil
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
	own, err := boxAddrs()
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

// boxAddrs lists the box's own addresses; a test replaces it.
var boxAddrs = func() ([]netip.Addr, error) {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(as))
	for _, a := range as {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr())
		}
	}
	return out, nil
}

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
