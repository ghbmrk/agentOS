package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// REQ: CH-9, HW-12, HW-15

// fakeLinks is a sysfs tree with add(name, dev, radio) placing one
// Ethernet-typed link at its device path, as Port1 and Wired read it.
func fakeLinks(t *testing.T) (string, func(name, dev string, radio bool)) {
	t.Helper()
	sys := t.TempDir()
	return sys, func(name, dev string, radio bool) {
		t.Helper()
		dir := filepath.Join(sys, "devices", dev, "net", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "type"), []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if radio {
			if err := os.Mkdir(filepath.Join(dir, "phy80211"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.MkdirAll(filepath.Join(sys, "class", "net"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("..", "..", "devices", dev, "net", name), filepath.Join(sys, "class", "net", name)); err != nil {
			t.Fatal(err)
		}
	}
}

// HW12-port1-set (CH-9, HW-12, HW-15; #3350 Security 1 and L3 1): the
// unit's root step opens the page's ports on port 1 alone, the same port
// the page chooses, and hands the page its name; a radio, a missing link,
// no port 1 or a failed load opens nothing and says why (moved from
// agentos-localui's -admit-port1 with the step, #5678; the page's side is
// agentos-localui's TestThePageServesOnlyOnTheAdmittedPort).
// REQ: CH-9, HW-12, HW-15
func TestAdmitPort1LoadsTheSetAndHandsOverTheName(t *testing.T) {
	sys, add := fakeLinks(t)
	add("eth0", "pci0000:00/0000:00:1c.0/0000:01:00.0", false)
	add("enx001122334455", "pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0", false)
	add("wlan0", "pci0000:00/0000:00:14.3", true)
	add("enowner0", "virtual", false)
	file := filepath.Join(t.TempDir(), "port1")
	var loaded []string
	nft := func(s string) error { loaded = append(loaded, s); return nil }
	now := func() bool { return true }

	p, err := admitPort1(sys, "", file, nft, now)
	if err != nil || p != "eth0" {
		t.Fatalf("port 1: %q, %v", p, err)
	}
	if want := "flush set inet agentos_inbound page\nadd element inet agentos_inbound page { \"eth0\" }\n"; len(loaded) != 1 || loaded[0] != want {
		t.Fatalf("loaded %q, want %q", loaded, want)
	}
	if b, err := os.ReadFile(file); err != nil || string(b) != "eth0\n" {
		t.Fatalf("hand-over file: %q, %v", b, err)
	}
	// The file is made fresh, never written through a link or over an old one.
	if _, err := admitPort1(sys, "eth0", file, nft, now); err == nil {
		t.Fatal("wrote over an existing hand-over file")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(filepath.Join(t.TempDir(), "target"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := admitPort1(sys, "eth0", link, nft, now); err == nil {
		t.Fatal("wrote through a symlink")
	}
	loaded = loaded[:1]
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	// A unit naming port 1 (the harness's veth) is admitted under that name.
	if p, err := admitPort1(sys, "enowner0", file, nft, now); err != nil || p != "enowner0" {
		t.Fatalf("named port 1: %q, %v", p, err)
	}

	loaded = nil
	for _, c := range []struct{ iface, file, why string }{
		{"wlan0", file, "radio"},
		{"enp9s0", file, "not a link"},
		{"lo", file, "not an interface name"},
		{"eth0", "", "needs -port1-file"},
	} {
		if p, err := admitPort1(sys, c.iface, c.file, nft, now); err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%q: admitted %q, %v; want an error saying %q", c.iface, p, err, c.why)
		}
	}
	if len(loaded) != 0 {
		t.Errorf("a refused port 1 still loaded %q", loaded)
	}
	// Port1 itself names none here: the USB adapter is left out, so only
	// eth0 counts; a second fixed port makes it refuse, and nothing loads.
	add("enp2s0", "pci0000:00/0000:00:1c.1/0000:02:00.0", false)
	if p, err := admitPort1(sys, "", file, nft, now); err == nil || len(loaded) != 0 || !strings.Contains(err.Error(), "more than one fixed Ethernet port") {
		t.Errorf("two fixed ports: admitted %q, %v, loaded %q; want Port1's refusal", p, err, loaded)
	}
	failing := func(string) error { return errors.New("no such table") }
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := admitPort1(sys, "eth0", file, failing, now); err == nil || !strings.Contains(err.Error(), "could not open the page's ports on port 1 eth0") {
		t.Errorf("a failed load: %v", err)
	}
	if _, err := os.Stat(file); err == nil {
		t.Error("a failed load still handed the page a port")
	}
}

// #3382 L3 1, Security 1: the unit's UMask=0077 binds the root step too,
// so the hand-over file's mode is set explicitly: the page, another uid,
// can read it. Run as root, it also reads it back as nobody.
// REQ: CH-9, HW-12
func TestAdmitPort1HandOverIsReadableUnderTheUnitsUmask(t *testing.T) {
	sys, add := fakeLinks(t)
	add("eth0", "pci0000:00/0000:00:1c.0/0000:01:00.0", false)
	// Not under t.TempDir, whose parent another uid cannot traverse.
	dir, err := os.MkdirTemp("", "port1-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "port1")
	old := syscall.Umask(0o077)
	_, err = admitPort1(sys, "", file, func(string) error { return nil }, func() bool { return true })
	syscall.Umask(old)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("hand-over file mode %v, want -rw-r--r--", fi.Mode())
	}
	if os.Geteuid() != 0 {
		return
	}
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Skip("no cat")
	}
	cmd := exec.Command(cat, file)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if out, err := cmd.CombinedOutput(); err != nil || string(out) != "eth0\n" {
		t.Fatalf("another uid reads %q, %v", out, err)
	}
}
