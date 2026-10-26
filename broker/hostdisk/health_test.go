package hostdisk

import (
	"path/filepath"
	"testing"
)

// REQ: HW-8

// HOST-1a part 2 (H11): the boot health item is HostDisks().Health, read
// without probing any disk but the one under the running root, so the
// health check never opens a host disk.
func TestDriveHealthIsTheListingsHealth(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(h *fakeHost)
		want Health
	}{
		{"ok", func(*fakeHost) {}, HealthOK},
		{"mismatch", func(h *fakeHost) { h.efivar("00000000-1111-2222-3333-444444444444") }, HealthMismatch},
		{"no root", func(h *fakeHost) { h.mountRoot("0:31"); h.noEfivar() }, HealthNoRoot},
	} {
		h := newFakeHost(t)
		c.set(h)
		s := h.system()
		got := s.DriveHealth()
		for _, p := range h.opened {
			if filepath.Base(p) != "sda" {
				t.Errorf("%s: opened %s", c.name, p)
			}
		}
		l, err := s.HostDisks()
		if err != nil || got != c.want || l.Health != got {
			t.Errorf("%s: DriveHealth %q, listing %q (%v), want %q", c.name, got, l.Health, err, c.want)
		}
	}
}
