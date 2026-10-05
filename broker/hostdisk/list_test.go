package hostdisk

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

// REQ: HW-8, HW-8a

const driveESP = "4a1b2c3d-0000-4000-8000-00000000d71e"

// fakeHost is a /sys, /dev and mountinfo tree with an AgentOS Drive on sda
// (booted from the partition systemd-boot names), a Windows NVMe disk, a
// data disk, and the virtual devices the list must skip.
type fakeHost struct {
	t      *testing.T
	root   string
	images map[string][]byte
	opened []string
}

func newFakeHost(t *testing.T) *fakeHost {
	h := &fakeHost{t: t, root: t.TempDir(), images: map[string][]byte{}}
	h.disk("sda", "8:0", "SanDisk Extreme", 4096, gptDisk(512, 4096, "dddddddd-0000-4000-8000-000000000001", []tpart{
		{typ: tESP, start: 64, n: 128, sig: SigFAT, uuid: driveESP},
		{typ: tLinux, start: 192, n: 3000, sig: SigExt},
	}), "sda1:8:1", "sda2:8:2")
	h.disk("nvme0n1", "259:0", "Samsung SSD 970 EVO", 4096, windowsLaptop(512), "nvme0n1p1:259:1", "nvme0n1p3:259:3")
	h.disk("sdb", "8:16", "WDC WD20EZAZ", 4096, gptDisk(512, 4096, "eeeeeeee-0000-4000-8000-000000000002", []tpart{
		{typ: tBasic, start: 64, n: 3900, sig: SigNTFS, name: "Data"},
	}), "sdb1:8:17")
	for _, v := range []string{"loop0", "ram0", "zram0", "dm-0", "md0", "sr0", "nbd0"} {
		h.write("sys/block/"+v+"/dev", "1:1\n")
	}
	h.efivar(driveESP)
	h.mounts("8:2")
	return h
}

func (h *fakeHost) write(rel, s string) {
	p := filepath.Join(h.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) disk(name, dev, model string, sectors int64, img []byte, parts ...string) {
	h.write("sys/block/"+name+"/dev", dev+"\n")
	h.write("sys/block/"+name+"/size", strings.TrimSpace(itoa(sectors))+"\n")
	h.write("sys/block/"+name+"/device/model", model+"   \n")
	h.write("sys/block/"+name+"/queue/logical_block_size", "512\n")
	if err := os.MkdirAll(filepath.Join(h.root, "sys/block", name, "holders"), 0o755); err != nil {
		h.t.Fatal(err)
	}
	for _, p := range parts {
		f := strings.SplitN(p, ":", 2)
		h.write("sys/block/"+name+"/"+f[0]+"/dev", f[1]+"\n")
		h.write("sys/block/"+name+"/"+f[0]+"/partition", "1\n")
	}
	h.images[filepath.Join(h.root, "dev", name)] = img
}

func itoa(n int64) string {
	var b [20]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			return string(b[i:])
		}
	}
}

// efivar writes LoaderDevicePartUUID the way efivarfs shows it: four
// attribute bytes, then the GUID in upper case as NUL-terminated UTF-16LE.
func (h *fakeHost) efivar(uuid string) {
	var b bytes.Buffer
	b.Write([]byte{6, 0, 0, 0})
	for _, r := range utf16.Encode([]rune(strings.ToUpper(uuid) + "\x00")) {
		binary.Write(&b, binary.LittleEndian, r)
	}
	h.write("sys/firmware/efi/efivars/"+loaderDevicePartUUID, b.String())
}

func (h *fakeHost) mounts(devs ...string) {
	var s strings.Builder
	for i, d := range devs {
		s.WriteString(itoa(int64(20+i)) + " 1 " + d + " / /mnt rw,relatime - ext4 /dev/x rw\n")
	}
	s.WriteString("30 1 0:22 / /proc rw - proc proc rw\n")
	h.write("proc/self/mountinfo", s.String())
}

func (h *fakeHost) system() System {
	return System{
		Sys:       filepath.Join(h.root, "sys"),
		Dev:       filepath.Join(h.root, "dev"),
		Mountinfo: filepath.Join(h.root, "proc/self/mountinfo"),
		Open: func(path string) (Device, error) {
			h.opened = append(h.opened, path)
			img, ok := h.images[path]
			if !ok {
				return nil, os.ErrNotExist
			}
			return nopCloser{bytes.NewReader(img)}, nil
		},
	}
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

func names(ds []Disk) []string {
	var out []string
	for _, d := range ds {
		out = append(out, d.Name)
	}
	return out
}

// The HW-8a list is every host disk, described, and never the AgentOS
// Drive or a virtual device.
func TestHostDisksListsEveryHostDiskButTheDrive(t *testing.T) {
	h := newFakeHost(t)
	ds, err := h.system().HostDisks()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names(ds), ","); got != "nvme0n1,sdb" {
		t.Fatalf("host disks %s", got)
	}
	win, data := ds[0], ds[1]
	if win.Model != "Samsung SSD 970 EVO" || win.Size != 4096*512 || !win.HoldsWindows || !win.HasBitLocker || !win.NeedsSecondConfirm() {
		t.Errorf("windows disk %+v", win)
	}
	if data.Model != "WDC WD20EZAZ" || data.NeedsSecondConfirm() || len(data.Partitions) != 1 || data.Partitions[0].Name != "Data" {
		t.Errorf("data disk %+v", data)
	}
	for _, p := range h.opened {
		switch filepath.Base(p) {
		case "sda", "nvme0n1", "sdb":
		default:
			t.Errorf("opened %s", p)
		}
	}
}

// The drive is the disk holding the partition systemd-boot booted from.
// Without that variable (another loader, a damaged variable) the drive is
// the disk the system is running on: a partition mounted or held by
// device-mapper (dm-verity /usr). A disk is never classed as the drive
// for any other reason, so every other disk stays hidden.
func TestIsDrive(t *testing.T) {
	h := newFakeHost(t)
	s := h.system()
	for name, want := range map[string]bool{"sda": true, "nvme0n1": false, "sdb": false} {
		got, err := s.IsDrive(name)
		if err != nil || got != want {
			t.Errorf("%s: %v %v, want %v", name, got, err, want)
		}
	}

	// No loader variable: the in-use disk is the drive, by a mount or by
	// a device-mapper holder on one of its partitions.
	os.Remove(filepath.Join(h.root, "sys/firmware/efi/efivars", loaderDevicePartUUID))
	for name, want := range map[string]bool{"sda": true, "nvme0n1": false, "sdb": false} {
		if got, _ := s.IsDrive(name); got != want {
			t.Errorf("no efivar, mounted: %s = %v", name, got)
		}
	}
	h.mounts()
	h.write("sys/block/sda/sda2/holders/dm-0", "")
	for name, want := range map[string]bool{"sda": true, "nvme0n1": false, "sdb": false} {
		if got, _ := s.IsDrive(name); got != want {
			t.Errorf("no efivar, held: %s = %v", name, got)
		}
	}

	// A loader variable naming a partition on no disk falls back the same
	// way, so a mismatch never hides the drive the box runs on.
	h.efivar("00000000-1111-2222-3333-444444444444")
	if got, _ := s.IsDrive("sda"); !got {
		t.Error("unmatched efivar hid the running drive")
	}
	if got, _ := s.IsDrive("sdb"); got {
		t.Error("unmatched efivar exposed a host disk")
	}

	// A device name with path tricks is refused.
	for _, bad := range []string{"", "../sda", "sda/..", "a b", "sda\n"} {
		if _, err := s.IsDrive(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// An unreadable disk is still listed, as unreadable, needing the second
// confirmation: a disk the probe cannot describe is not taken lightly.
func TestHostDisksListsUnreadableDisk(t *testing.T) {
	h := newFakeHost(t)
	delete(h.images, filepath.Join(h.root, "dev", "sdb"))
	ds, err := h.system().HostDisks()
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 2 || ds[1].Name != "sdb" || ds[1].Unreadable == "" || !ds[1].NeedsSecondConfirm() {
		t.Fatalf("%+v", ds)
	}
}

// ClassifyEnv is what the udev helper prints: AGENTOS_DRIVE=1 for the
// drive, 0 for anything else, and 0 on any error, so a disk that cannot
// be classified is hidden.
func TestClassifyEnv(t *testing.T) {
	h := newFakeHost(t)
	s := h.system()
	for name, want := range map[string]string{
		"sda":     "AGENTOS_DRIVE=1\n",
		"nvme0n1": "AGENTOS_DRIVE=0\n",
		"sdb":     "AGENTOS_DRIVE=0\n",
		"../etc":  "AGENTOS_DRIVE=0\n",
		"nosuch":  "AGENTOS_DRIVE=0\n",
	} {
		if got := s.ClassifyEnv(name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
}
