package pubid

import "testing"

// REQ: OSS-6
func TestOSS6W5CountOK(t *testing.T) {
	if !countOK(nil) {
		t.Fatal("nil Verified must count (not wired yet)")
	}
	if !countOK(func() bool { return true }) {
		t.Fatal("verified must count")
	}
	if countOK(func() bool { return false }) {
		t.Fatal("unverified must not count")
	}
}
