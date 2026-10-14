package main

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/netjoin"
)

// neverOnlineAfter is how long a home network the helper answered saved
// for (netjoin L8.4) may stay without an uplink before setup tells the
// owner it never came online (P2-2w c4). The helper has already waited
// its own 25 s; this covers a slow DHCP lease.
const neverOnlineAfter = 90 * time.Second

// uplink is the box's home-network state as setup's progress shows it
// (ONB-4, P2-2w c4).
type uplink struct {
	online func() bool
	now    func() time.Time

	mu    sync.Mutex
	saved time.Time // the last join answered saved and no uplink since; zero otherwise
}

func newUplink() *uplink { return &uplink{online: routeOnline, now: time.Now} }

// progress is setup's progress: ready once the box has an uplink, offline
// before. The first-boot update (UPD-3) is not wired into setup mode, so
// Updated follows Online and AI waits for an uplink.
func (u *uplink) progress() localapi.SetupProgress {
	on := u.online()
	u.mu.Lock()
	defer u.mu.Unlock()
	if on {
		u.saved = time.Time{}
		return localapi.SetupProgress{Phase: "ready", Updated: true, Online: true}
	}
	p := localapi.SetupProgress{Phase: "offline"}
	p.NeverOnline = !u.saved.IsZero() && u.now().Sub(u.saved) >= neverOnlineAfter
	return p
}

// seen records a join's answer: saved starts the never-online wait,
// joined ends it, and any other answer leaves it as it was. A nil uplink
// records nothing.
func (u *uplink) seen(code netjoin.Code) {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	switch code {
	case netjoin.Saved:
		u.saved = u.now()
	case netjoin.Joined:
		u.saved = time.Time{}
	}
}

// routeOnline reports a default route from the kernel's route tables.
func routeOnline() bool {
	v4, _ := os.ReadFile("/proc/net/route")
	v6, _ := os.ReadFile("/proc/net/ipv6_route")
	return defaultRoute(string(v4), string(v6))
}

// Route flags (linux/route.h).
const (
	rtfUp     = 0x0001
	rtfReject = 0x0200
)

// defaultRoute reports an up, non-reject default route, IPv4 or IPv6, on
// an interface other than lo. The access point's subnet has no default
// route through the box, so only an uplink counts.
func defaultRoute(v4, v6 string) bool {
	for _, l := range strings.Split(v4, "\n") {
		f := strings.Fields(l)
		// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		if len(f) < 8 || f[0] == "lo" || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		if up(f[3]) {
			return true
		}
	}
	for _, l := range strings.Split(v6, "\n") {
		f := strings.Fields(l)
		// dest plen src splen nexthop metric refcnt use flags iface
		if len(f) < 10 || f[9] == "lo" || strings.Trim(f[0], "0") != "" || f[1] != "00" {
			continue
		}
		if up(f[8]) {
			return true
		}
	}
	return false
}

func up(flags string) bool {
	n, err := strconv.ParseUint(flags, 16, 32)
	return err == nil && n&rtfUp != 0 && n&rtfReject == 0
}
