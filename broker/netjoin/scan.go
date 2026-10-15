package netjoin

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/apnet"
)

// ScanNM is the scan's whole reach into NetworkManager. Each method is one
// property read or GetAllAccessPoints; none writes, requests a scan or
// needs a polkit action, and the join's NM is a separate seam.
type ScanNM interface {
	// Devices reads NetworkManager's Devices property.
	Devices(ctx context.Context) ([]string, error)
	// DeviceType reads a device's DeviceType property.
	DeviceType(ctx context.Context, dev string) (uint32, error)
	// AccessPoints is Device.Wireless.GetAllAccessPoints on a Wi-Fi device.
	AccessPoints(ctx context.Context, dev string) ([]string, error)
	// APSsid reads an access point's Ssid property.
	APSsid(ctx context.Context, ap string) ([]byte, error)
	// APStrength reads an access point's Strength property.
	APStrength(ctx context.Context, ap string) (uint8, error)
}

// DeviceWifi is NM_DEVICE_TYPE_WIFI.
const DeviceWifi uint32 = 2

// Scanner lists the home networks in range from what NetworkManager has
// already seen.
type Scanner struct {
	nm   ScanNM
	wait time.Duration
}

// NewScanner returns a Scanner over nm with the fixed ScanWait.
func NewScanner(nm ScanNM) *Scanner { return &Scanner{nm: nm, wait: ScanWait} }

// Scan returns at most MaxNetworks Showable names, each once at its best
// strength, strongest first and then by name. It leaves out the box's own
// networks, every name starting apnet.Prefix (the setup network's and the
// card's), so neither is offered as the home Wi-Fi (#1281). A read that fails skips its
// device or access point; a failed device list, or the wait running out
// first, gives fewer names or none.
func (s *Scanner) Scan(ctx context.Context) []string {
	ctx, cancel := context.WithTimeout(ctx, s.wait)
	defer cancel()
	devs, err := s.nm.Devices(ctx)
	if err != nil {
		return []string{}
	}
	best := map[string]uint8{}
	for _, d := range devs {
		if t, err := s.nm.DeviceType(ctx, d); err != nil || t != DeviceWifi {
			continue
		}
		aps, err := s.nm.AccessPoints(ctx, d)
		if err != nil {
			continue
		}
		for _, ap := range aps {
			ssid, err := s.nm.APSsid(ctx, ap)
			if err != nil || !Showable(ssid) || strings.HasPrefix(string(ssid), apnet.Prefix) {
				continue
			}
			st, err := s.nm.APStrength(ctx, ap)
			if err != nil {
				continue
			}
			if b, ok := best[string(ssid)]; !ok || st > b {
				best[string(ssid)] = st
			}
		}
	}
	out := make([]string, 0, len(best))
	for n := range best {
		out = append(out, n)
	}
	sort.Slice(out, func(i, k int) bool {
		if best[out[i]] != best[out[k]] {
			return best[out[i]] > best[out[k]]
		}
		return out[i] < out[k]
	})
	if len(out) > MaxNetworks {
		out = out[:MaxNetworks]
	}
	return out
}
