package hostdisk

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// loaderDevicePartUUID is systemd-boot's EFI variable naming the GPT
// partition the box booted from, under efivarfs.
const loaderDevicePartUUID = "LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"

// Device is a host disk opened for reading.
type Device interface {
	io.ReaderAt
	io.Closer
}

// OpenReadOnly opens a block device (or image file) read-only.
func OpenReadOnly(path string) (Device, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// System is where the disks are found. The zero value uses /sys, /dev,
// /proc/self/mountinfo and OpenReadOnly; tests point it at a fake tree.
type System struct {
	Sys       string
	Dev       string
	Mountinfo string
	Open      func(path string) (Device, error)
}

func (s System) fill() System {
	if s.Sys == "" {
		s.Sys = "/sys"
	}
	if s.Dev == "" {
		s.Dev = "/dev"
	}
	if s.Mountinfo == "" {
		s.Mountinfo = "/proc/self/mountinfo"
	}
	if s.Open == nil {
		s.Open = OpenReadOnly
	}
	return s
}

var (
	validName   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]*$`)
	validGUID   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	virtualDisk = []string{"loop", "ram", "zram", "dm-", "md", "sr", "nbd", "fd", "zd"}
)

// virtual reports whether a /sys/block name is a device the box itself
// makes (loop, device-mapper, RAM disks) or an optical drive, never a disk.
func virtual(name string) bool {
	for _, p := range virtualDisk {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// disks lists /sys/block, without virtual devices, sorted.
func (s System) disks() ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(s.Sys, "block"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if validName.MatchString(e.Name()) && !virtual(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s System) read(rel ...string) string {
	b, err := os.ReadFile(filepath.Join(append([]string{s.Sys, "block"}, rel...)...))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// describe reads one disk's model and size from sysfs and probes it.
func (s System) describe(name string) Disk {
	d := Disk{Name: name, Model: s.read(name, "device", "model"), Partitions: []Partition{}}
	sectors, err := strconv.ParseInt(s.read(name, "size"), 10, 64)
	if err != nil || sectors <= 0 {
		d.Unreadable = "size unknown"
		return d
	}
	d.Size = sectors * 512 // sysfs counts 512-byte units whatever the sector size
	lbs, err := strconv.Atoi(s.read(name, "queue", "logical_block_size"))
	if err != nil {
		lbs = 512
	}
	dev, err := s.Open(filepath.Join(s.Dev, name))
	if err != nil {
		d.Unreadable = err.Error()
		return d
	}
	defer dev.Close()
	p, err := Probe(dev, d.Size, lbs)
	p.Name, p.Model, p.Size = d.Name, d.Model, d.Size
	if err != nil && p.Unreadable == "" {
		p.Unreadable = err.Error()
	}
	return p
}

// loaderPartition returns the partition GUID systemd-boot booted from, or
// "" when the variable is absent or malformed.
func (s System) loaderPartition() string {
	b, err := os.ReadFile(filepath.Join(s.Sys, "firmware", "efi", "efivars", loaderDevicePartUUID))
	if err != nil || len(b) < 6 {
		return ""
	}
	b = b[4:] // attributes
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := uint16(b[i]) | uint16(b[i+1])<<8
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	g := strings.ToLower(strings.TrimSpace(string(utf16.Decode(u))))
	if !validGUID.MatchString(g) {
		return ""
	}
	return g
}

// inUse reports whether the system runs on the disk: the disk or one of
// its partitions is mounted, or held by another block device (dm-verity
// on /usr, a dm-crypt root).
func (s System) inUse(name string, mounted map[string]bool) bool {
	check := func(dir string) bool {
		if mounted[s.readAbs(filepath.Join(dir, "dev"))] {
			return true
		}
		hs, _ := os.ReadDir(filepath.Join(dir, "holders"))
		return len(hs) > 0
	}
	dir := filepath.Join(s.Sys, "block", name)
	if check(dir) {
		return true
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if _, err := os.Stat(filepath.Join(dir, e.Name(), "partition")); err == nil && check(filepath.Join(dir, e.Name())) {
			return true
		}
	}
	return false
}

func (s System) readAbs(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return "-"
	}
	return strings.TrimSpace(string(b))
}

// mounted returns the major:minor of every mounted device.
func (s System) mounted() map[string]bool {
	out := map[string]bool{}
	f, err := os.Open(s.Mountinfo)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if fs := strings.Fields(sc.Text()); len(fs) > 2 {
			out[fs[2]] = true
		}
	}
	return out
}

// drive picks the AgentOS Drive among names: the disk whose partition
// table lists the partition systemd-boot booted from. If the variable is
// missing or names no disk, the drive is every disk the system runs on
// (inUse). descs caches probes.
func (s System) drive(names []string, descs map[string]Disk) map[string]bool {
	out := map[string]bool{}
	if g := s.loaderPartition(); g != "" {
		for _, n := range names {
			if _, ok := descs[n]; !ok {
				descs[n] = s.describe(n)
			}
			if descs[n].HasPartition(g) {
				out[n] = true
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	m := s.mounted()
	for _, n := range names {
		if s.inUse(n, m) {
			out[n] = true
		}
	}
	return out
}

// IsDrive reports whether the named /sys/block disk is the AgentOS Drive.
func (s System) IsDrive(name string) (bool, error) {
	s = s.fill()
	if !validName.MatchString(name) {
		return false, fmt.Errorf("hostdisk: bad device name %q", name)
	}
	if _, err := os.Stat(filepath.Join(s.Sys, "block", name)); err != nil {
		return false, err
	}
	if virtual(name) {
		return false, errors.New("hostdisk: not a disk")
	}
	names, err := s.disks()
	if err != nil {
		return false, err
	}
	return s.drive(names, map[string]Disk{})[name], nil
}

// HostDisks describes every disk of the host other than the AgentOS
// Drive, for the HW-8a list. A disk that cannot be read is listed with
// Unreadable set.
func (s System) HostDisks() ([]Disk, error) {
	s = s.fill()
	names, err := s.disks()
	if err != nil {
		return nil, err
	}
	descs := map[string]Disk{}
	drive := s.drive(names, descs)
	out := []Disk{}
	for _, n := range names {
		if drive[n] {
			continue
		}
		d, ok := descs[n]
		if !ok {
			d = s.describe(n)
		}
		out = append(out, d)
	}
	return out, nil
}

// ClassifyEnv is the udev helper's output for a disk: AGENTOS_DRIVE=1 for
// the AgentOS Drive and AGENTOS_DRIVE=0 for anything else, including any
// disk it cannot classify, which the rule then hides.
func (s System) ClassifyEnv(name string) string {
	if ok, err := s.IsDrive(name); err == nil && ok {
		return "AGENTOS_DRIVE=1\n"
	}
	return "AGENTOS_DRIVE=0\n"
}
