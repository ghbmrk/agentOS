package hostdisk

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
)

// REQ: HW-8, HW-8a

const driveESP = "4a1b2c3d-0000-4000-8000-00000000d71e"

// fakeHost is a /sys, /dev and mountinfo tree laid out like the kernel's:
// /sys/block and /sys/dev/block are symlinks into /sys/devices. The
// AgentOS Drive is sda (a USB stick), booted from the ESP systemd-boot
// names, with root on sda2; the host has a Windows NVMe disk and a SATA
// data disk.
type fakeHost struct {
	t      *testing.T
	root   string
	images map[string][]byte
	opened []string
}

func newFakeHost(t *testing.T) *fakeHost {
	h := &fakeHost{t: t, root: t.TempDir(), images: map[string][]byte{}}
	h.disk("sda", "pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0/host0/target0:0:0/0:0:0:0", "8:0", "SanDisk Extreme", true,
		gptDisk(512, 4096, "dddddddd-0000-4000-8000-000000000001", []tpart{
			{typ: tESP, start: 64, n: 128, sig: SigFAT, uuid: driveESP},
			{typ: tLinux, start: 192, n: 3000, sig: SigExt},
		}), "sda1:8:1", "sda2:8:2")
	h.disk("nvme0n1", "pci0000:00/0000:00:1d.0/0000:3d:00.0/nvme/nvme0", "259:0", "Samsung SSD 970 EVO", false,
		windowsLaptop(512), "nvme0n1p1:259:1", "nvme0n1p3:259:3")
	h.disk("sdb", "pci0000:00/0000:00:17.0/ata1/host1/target1:0:0/1:0:0:0", "8:16", "WDC WD20EZAZ", false,
		gptDisk(512, 4096, "eeeeeeee-0000-4000-8000-000000000002", []tpart{
			{typ: tBasic, start: 64, n: 3900, sig: SigNTFS},
		}), "sdb1:8:17")
	for _, v := range []string{"loop0", "ram0", "zram0", "nbd0"} {
		h.disk(v, "virtual/block", "7:0", "", false, nil)
	}
	h.efivar(driveESP)
	h.mountRoot("8:2")
	return h
}

func (h *fakeHost) path(rel string) string { return filepath.Join(h.root, rel) }

func (h *fakeHost) write(rel, s string) {
	p := h.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) link(rel, target string) {
	p := h.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		h.t.Fatal(err)
	}
	os.Remove(p)
	if err := os.Symlink(target, p); err != nil {
		h.t.Fatal(err)
	}
}

// disk adds a disk under /sys/devices/<parent>/block/<name> with its
// partitions ("name:major:minor").
func (h *fakeHost) disk(name, parent, dev, model string, removable bool, img []byte, parts ...string) {
	d := "sys/devices/" + parent + "/block/" + name
	h.write(d+"/dev", dev+"\n")
	h.write(d+"/size", strconv.Itoa(len(img)/512)+"\n")
	h.write(d+"/device/model", model+"   \n")
	h.write(d+"/queue/logical_block_size", "512\n")
	rm := "0"
	if removable {
		rm = "1"
	}
	h.write(d+"/removable", rm+"\n")
	h.link("sys/block/"+name, h.path(d))
	h.link("sys/dev/block/"+dev, h.path(d))
	for _, p := range parts {
		f := strings.SplitN(p, ":", 2)
		h.write(d+"/"+f[0]+"/dev", f[1]+"\n")
		h.write(d+"/"+f[0]+"/partition", "1\n")
		h.link("sys/dev/block/"+f[1], h.path(d+"/"+f[0]))
	}
	if img != nil {
		h.images[h.path("dev/"+name)] = img
	}
}

// stacked adds a dm or md device built on the given partition or disk
// device directories (relative to /sys/block).
func (h *fakeHost) stacked(name, dev string, slaves ...string) {
	d := "sys/devices/virtual/block/" + name
	h.write(d+"/dev", dev+"\n")
	if err := os.MkdirAll(h.path(d+"/slaves"), 0o755); err != nil {
		h.t.Fatal(err)
	}
	for _, s := range slaves {
		real, err := filepath.EvalSymlinks(h.path("sys/block/" + s))
		if err != nil {
			h.t.Fatal(err)
		}
		h.link(d+"/slaves/"+filepath.Base(s), real)
	}
	h.link("sys/block/"+name, h.path(d))
	h.link("sys/dev/block/"+dev, h.path(d))
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

func (h *fakeHost) noEfivar() {
	os.Remove(h.path("sys/firmware/efi/efivars/" + loaderDevicePartUUID))
}

// mountRoot writes mountinfo with / on dev, plus other mounts.
func (h *fakeHost) mountRoot(dev string, others ...string) {
	s := "1 0 " + dev + " / / rw - ext4 /dev/root rw\n"
	for i, o := range others {
		s += strconv.Itoa(20+i) + " 1 " + o + " / /mnt/" + strconv.Itoa(i) + " rw - ntfs3 /dev/x rw\n"
	}
	s += "30 1 0:22 / /proc rw - proc proc rw\n"
	h.write("proc/self/mountinfo", s)
}

func (h *fakeHost) system() System {
	return System{
		Sys:       h.path("sys"),
		Dev:       h.path("dev"),
		Mountinfo: h.path("proc/self/mountinfo"),
		open: func(path string) (device, error) {
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

func names(ds []Disk) string {
	var out []string
	for _, d := range ds {
		out = append(out, d.Name)
	}
	return strings.Join(out, ",")
}

func classes(t *testing.T, s System, want map[string]Class) {
	t.Helper()
	for name, w := range want {
		if got := s.Classify(name); got != w {
			t.Errorf("%s: %s, want %s", name, got, w)
		}
	}
}

// The HW-8a list is every physical host disk, described with bus and
// removable flags, and never the AgentOS Drive or a virtual device.
func TestHostDisksListsEveryHostDiskButTheDrive(t *testing.T) {
	h := newFakeHost(t)
	l, err := h.system().HostDisks()
	if err != nil {
		t.Fatal(err)
	}
	if l.Health != HealthOK || names(l.Disks) != "nvme0n1,sdb" {
		t.Fatalf("listing %+v", l)
	}
	win, data := l.Disks[0], l.Disks[1]
	if win.Model != "Samsung SSD 970 EVO" || win.Size != 4096*512 || win.Bus != BusNVMe || win.Removable ||
		!win.HoldsWindows || !win.HasBitLocker || !win.NeedsSecondConfirm() {
		t.Errorf("windows disk %+v", win)
	}
	if data.Model != "WDC WD20EZAZ" || data.Bus != BusSATA || data.NeedsSecondConfirm() || len(data.Partitions) != 1 {
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

// Security H1 on HOST-1a: the drive is the disk holding the running root,
// cross-checked against systemd-boot's partition; dm and md devices take
// the class of the disks they are built on; removable media are host
// disks; virtual devices are not classified.
func TestClassify(t *testing.T) {
	h := newFakeHost(t)
	h.disk("sdc", "pci0000:00/0000:00:14.0/usb2/2-2/2-2:1.0/host2/target2:0:0/2:0:0:0", "8:32", "USB Flash", true,
		gptDisk(512, 1024, "cccccccc-0000-4000-8000-000000000003", []tpart{{typ: tBasic, start: 64, n: 900, sig: SigExFAT}}), "sdc1:8:33")
	h.stacked("dm-0", "253:0", "sda/sda2")
	h.stacked("dm-1", "253:1", "nvme0n1/nvme0n1p3")
	h.stacked("md0", "9:0", "sdb/sdb1", "sda/sda1")
	h.stacked("dm-2", "253:2")
	s := h.system()
	classes(t, s, map[string]Class{
		"sda": ClassDrive, "nvme0n1": ClassHost, "sdb": ClassHost, "sdc": ClassHost,
		"dm-0": ClassDrive, "dm-1": ClassHost, "md0": ClassHost, "dm-2": ClassUnknown,
		"loop0": ClassUnknown, "zram0": ClassUnknown, "nosuch": ClassUnknown,
		"": ClassUnknown, "../sda": ClassUnknown, "sda/..": ClassUnknown, "sda\n": ClassUnknown,
	})
	if got := s.ClassifyEnv("sda"); got != "AGENTOS_DISK=drive\n" {
		t.Errorf("env %q", got)
	}

	// Root on dm-crypt over a drive partition: still the drive.
	h.mountRoot("253:0")
	classes(t, s, map[string]Class{"sda": ClassDrive, "nvme0n1": ClassHost})

	// No loader variable: the root's disk is the drive.
	h.mountRoot("8:2")
	h.noEfivar()
	classes(t, s, map[string]Class{"sda": ClassDrive, "nvme0n1": ClassHost, "sdb": ClassHost})
}

// Mount state never makes a disk the drive: a host partition mounted (by
// mistake or attack) stays a host disk and stays listed.
func TestMountedHostPartitionStaysHost(t *testing.T) {
	h := newFakeHost(t)
	h.mountRoot("8:2", "259:3", "8:17")
	classes(t, h.system(), map[string]Class{"sda": ClassDrive, "nvme0n1": ClassHost, "sdb": ClassHost})
	h.noEfivar()
	classes(t, h.system(), map[string]Class{"sda": ClassDrive, "nvme0n1": ClassHost, "sdb": ClassHost})
	l, err := h.system().HostDisks()
	if err != nil || names(l.Disks) != "nvme0n1,sdb" {
		t.Fatalf("%v %+v", err, l)
	}
}

// When the root's disk lacks the partition systemd-boot booted from, there
// is no drive: a health item is raised, every other disk is a host disk,
// and the disk under the running root is "unknown" (not hidden, which
// would only stop the box booting) and never offered for HW-8a.
func TestDriveMismatch(t *testing.T) {
	h := newFakeHost(t)
	h.efivar("00000000-1111-2222-3333-444444444444")
	s := h.system()
	classes(t, s, map[string]Class{"sda": ClassUnknown, "nvme0n1": ClassHost, "sdb": ClassHost})
	l, err := s.HostDisks()
	if err != nil || l.Health != HealthMismatch || names(l.Disks) != "nvme0n1,sdb" {
		t.Fatalf("%v %+v", err, l)
	}

	// The loader names a partition on a host disk: still a mismatch, and
	// that disk does not become the drive.
	h.efivar("00000000-0000-0000-0000-0000000000a1") // windowsLaptop's ESP
	classes(t, s, map[string]Class{"sda": ClassUnknown, "nvme0n1": ClassHost})
}

// mountinfo writes mountinfo lines "mm point fstype superopts".
func (h *fakeHost) mountinfo(lines ...string) {
	var b strings.Builder
	for i, l := range lines {
		f := strings.Fields(l)
		b.WriteString(strconv.Itoa(20+i) + " 1 " + f[0] + " / " + f[1] + " rw - " + f[2] + " src " + f[3] + "\n")
	}
	h.write("proc/self/mountinfo", b.String())
}

// #41's layout (security F2 on #172): ESP, /usr A and B with verity
// partitions, root last; / on the root partition, /usr on dm-verity over
// the A slot and its hash partition, /efi on the ESP.
func TestClassifyImageLayout(t *testing.T) {
	h := newFakeHost(t)
	h.disk("sdd", "pci0000:00/0000:00:14.0/usb2/2-3/2-3:1.0/host3/target3:0:0/3:0:0:0", "8:48", "AgentOS Drive", true,
		gptDisk(512, 8192, "dddddddd-0000-4000-8000-0000000000d1", []tpart{
			{typ: tESP, start: 64, n: 128, sig: SigFAT, uuid: "11111111-0000-4000-8000-0000000000e5"},
		}), "sdd1:8:49", "sdd2:8:50", "sdd3:8:51", "sdd4:8:52", "sdd5:8:53", "sdd6:8:54")
	h.stacked("dm-0", "253:0", "sdd/sdd2", "sdd/sdd3")
	h.efivar("11111111-0000-4000-8000-0000000000e5")
	h.mountinfo("8:54 / ext4 rw", "253:0 /usr ext4 ro", "8:49 /efi vfat rw", "0:22 /proc proc rw", "0:25 /tmp tmpfs rw")
	s := h.system()
	classes(t, s, map[string]Class{"sdd": ClassDrive, "dm-0": ClassDrive, "sda": ClassHost, "nvme0n1": ClassHost, "sdb": ClassHost})
	if l, err := s.HostDisks(); err != nil || l.Health != HealthOK || names(l.Disks) != "nvme0n1,sda,sdb" {
		t.Fatalf("%v %+v", err, l)
	}

	// A volatile root (tmpfs) on the same image: the drive is the disk
	// under /usr, with or without the loader variable.
	h.mountinfo("0:30 / tmpfs rw", "253:0 /usr ext4 ro")
	classes(t, s, map[string]Class{"sdd": ClassDrive, "sda": ClassHost})
	h.noEfivar()
	classes(t, s, map[string]Class{"sdd": ClassDrive, "sda": ClassHost})
	h.efivar("11111111-0000-4000-8000-0000000000e5")

	// An overlay root: the drive is the disk under its upper and lower
	// directories.
	h.mountinfo("0:30 / overlay rw,lowerdir=/run/lower:/usr/share/base,upperdir=/var/upper/u,workdir=/var/upper/w",
		"8:54 /var ext4 rw", "253:0 /usr ext4 ro", "8:49 /run/lower vfat ro")
	classes(t, s, map[string]Class{"sdd": ClassDrive, "sda": ClassHost})

	// An overlay whose layers span two disks is not one disk: nothing is
	// the drive.
	h.mountinfo("0:30 / overlay rw,lowerdir=/mnt/x,upperdir=/var/u,workdir=/var/w",
		"8:54 /var ext4 rw", "8:17 /mnt/x ntfs3 ro", "253:0 /usr ext4 ro")
	if got := s.Classify("sdd"); got != ClassUnknown {
		t.Errorf("overlay over two disks: sdd %s", got)
	}
}

// With no root on a block device, the drive is the one disk holding the
// partition systemd-boot booted from; with no loader variable, or with
// two disks carrying it (every AgentOS drive has the same partition GUIDs,
// #41's fixed mkosi seed), nothing is the drive and every device is
// unknown.
func TestNoRootDisk(t *testing.T) {
	h := newFakeHost(t)
	h.mountRoot("0:31")
	s := h.system()
	classes(t, s, map[string]Class{"sda": ClassDrive, "nvme0n1": ClassHost})

	h.noEfivar()
	classes(t, s, map[string]Class{"sda": ClassUnknown, "nvme0n1": ClassUnknown})
	l, err := s.HostDisks()
	if err != nil || l.Health != HealthNoRoot || names(l.Disks) != "nvme0n1,sda,sdb" {
		t.Fatalf("%v %+v", err, l)
	}

	h.efivar(driveESP)
	h.disk("sdf", "pci0000:00/0000:00:14.0/usb2/2-4/2-4:1.0/host4/target4:0:0/4:0:0:0", "8:80", "Second AgentOS Drive", true,
		gptDisk(512, 1024, "ffffffff-0000-4000-8000-000000000001", []tpart{{typ: tESP, start: 64, n: 128, sig: SigFAT, uuid: driveESP}}), "sdf1:8:81")
	classes(t, s, map[string]Class{"sda": ClassUnknown, "sdf": ClassUnknown, "nvme0n1": ClassUnknown})

	// Root on dm over two disks is not one disk either.
	h.stacked("dm-3", "253:3", "sda/sda2", "sdb/sdb1")
	h.mountRoot("253:3")
	h.noEfivar()
	classes(t, s, map[string]Class{"sda": ClassUnknown, "sdb": ClassUnknown})
}

// Mountinfo escapes spaces and other characters in mount points.
func TestUnescape(t *testing.T) {
	if got := unescape(`/mnt/a\040b\134c`); got != `/mnt/a b\c` {
		t.Fatalf("%q", got)
	}
}

// Potency R1 on HOST-1a: a disk that cannot be read is listed, flagged,
// and needs the second confirmation.
func TestHostDisksListsUnreadableDisk(t *testing.T) {
	h := newFakeHost(t)
	delete(h.images, h.path("dev/sdb"))
	l, err := h.system().HostDisks()
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Disks) != 2 || l.Disks[1].Name != "sdb" || l.Disks[1].Problem != ProblemOpen || !l.Disks[1].NeedsSecondConfirm() {
		t.Fatalf("%+v", l)
	}
}

// Security H4: the listing carries no label, partition name or GUID.
func TestHostDisksKeepNoLabels(t *testing.T) {
	h := newFakeHost(t)
	h.images[h.path("dev/sdb")] = canaryDisk()
	l, err := h.system().HostDisks()
	if err != nil {
		t.Fatal(err)
	}
	leaksCanary(t, "listing", l)
	if got := cleanModel("WD\x1b[31m Blue\x00 " + strings.Repeat("x", 100)); strings.ContainsAny(got, "\x1b\x00") || len(got) > 64 {
		t.Errorf("model %q", got)
	}
}
