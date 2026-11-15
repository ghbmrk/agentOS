package localui

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
)

// Page is where the owner page is served (CH-9, D-178): one wired
// interface, the core's port 1, its cable to the enforcer (HW-12). The
// enforcer routes the Owner network and its wired admin port to it; the
// core's address there comes from DHCP, so the page binds no fixed address
// and admits no subnet (WIFI-del-a3).
type Page struct {
	// Iface is port 1's interface (netguard/port1.Port1 on the image).
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
