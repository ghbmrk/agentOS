package at

import (
	"os"
	"path/filepath"
	"testing"
)

// REQ: HW-2

// fakeUSB lays out sysfs for one USB device with ttyUSB interfaces.
func fakeUSB(t *testing.T, root, dev, vendor, bus, devnum string, ttys map[string]string) {
	t.Helper()
	d := filepath.Join(root, "sys/devices/pci0000:00/usb1", dev)
	write := func(p, s string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(d, "idVendor"), vendor)
	write(filepath.Join(d, "busnum"), bus)
	write(filepath.Join(d, "devnum"), devnum)
	links := filepath.Join(root, "sys/bus/usb-serial/devices")
	_ = os.MkdirAll(links, 0o755)
	for tty, intf := range ttys {
		idir := filepath.Join(d, dev+":1."+intf)
		write(filepath.Join(idir, "bInterfaceNumber"), "0"+intf)
		if err := os.MkdirAll(filepath.Join(idir, tty), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(idir, tty), filepath.Join(links, tty)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDiscoverFindsPortsAndTheMatchingSoundCard(t *testing.T) {
	root := t.TempDir()
	fakeUSB(t, root, "1-1", "2c7c", "1", "4", map[string]string{"ttyUSB0": "0", "ttyUSB1": "1", "ttyUSB2": "2", "ttyUSB3": "3"})
	fakeUSB(t, root, "1-2", "1e0e", "1", "5", map[string]string{"ttyUSB4": "0", "ttyUSB5": "1", "ttyUSB6": "2", "ttyUSB7": "3", "ttyUSB8": "4"})
	fakeUSB(t, root, "1-3", "12d1", "1", "6", map[string]string{"ttyUSB9": "2"}) // another vendor
	// Card 0 is the PC's own audio, card 1 the Quectel, card 2 a USB headset.
	for card, bus := range map[string]string{"1": "001/004", "2": "001/009"} {
		p := filepath.Join(root, "proc/asound/card"+card, "usbbus")
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, []byte(bus+"\n"), 0o644)
	}
	got := Discover(root)
	if len(got) != 2 {
		t.Fatalf("found %+v", got)
	}
	q, s := got[0], got[1]
	if q.Profile != Quectel || q.ATPort != filepath.Join(root, "dev/ttyUSB2") || q.AudioPort != "" || q.Card != "1" {
		t.Fatalf("Quectel: %+v", q)
	}
	if s.Profile != SIMCom || s.ATPort != filepath.Join(root, "dev/ttyUSB6") || s.AudioPort != filepath.Join(root, "dev/ttyUSB8") || s.Card != "" {
		t.Fatalf("SIMCom: %+v", s)
	}
}
