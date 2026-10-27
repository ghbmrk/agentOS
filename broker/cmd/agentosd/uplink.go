package main

import (
	"os"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// progressOf is setup's progress: ready once the box has an uplink,
// offline before (ONB-4). The core's uplink is its cable to the enforcer
// (HW-12, D-178); the box joins no Wi-Fi. The first-boot update (UPD-3)
// is not wired into setup mode, so Updated follows Online and AI waits
// for an uplink.
func progressOf(online func() bool) func() localapi.SetupProgress {
	return func() localapi.SetupProgress {
		if online() {
			return localapi.SetupProgress{Phase: "ready", Updated: true, Online: true}
		}
		return localapi.SetupProgress{Phase: "offline"}
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
