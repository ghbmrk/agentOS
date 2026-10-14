package localui

import (
	"os"
	"path/filepath"
)

// StationDevice reports whether netClass (the kernel's /sys/class/net)
// lists a wireless interface other than ap, the access point's: a second
// adapter, or a station interface on the access point's radio (#936).
// NetworkManager can join a home network only on such a device. An
// unreadable directory counts as none, so setup never offers a rejoin it
// cannot back (CH-12; P2-2w c4 r1).
func StationDevice(netClass, ap string) bool {
	entries, err := os.ReadDir(netClass)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name() == ap {
			continue
		}
		for _, mark := range []string{"wireless", "phy80211"} {
			if _, err := os.Stat(filepath.Join(netClass, e.Name(), mark)); err == nil {
				return true
			}
		}
	}
	return false
}
