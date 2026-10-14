package main

import (
	"os"
	"path/filepath"
	"testing"
)

// REQ: CH-12

// The page's station check reads the interfaces each time it is asked,
// so a Wi-Fi adapter plugged in after boot brings the rejoin back, and
// the access point's own interface never counts (P2-2w c4 r1).
func TestStationRereadsInterfaces(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "wlan0", "wireless"), 0o755); err != nil {
		t.Fatal(err)
	}
	has := station(dir, "wlan0")
	if has() {
		t.Fatal("the access point's interface counted as a station device")
	}
	if err := os.MkdirAll(filepath.Join(dir, "wlx001122", "wireless"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !has() {
		t.Fatal("an adapter added after boot was not seen")
	}
}
