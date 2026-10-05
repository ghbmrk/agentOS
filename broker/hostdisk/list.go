package hostdisk

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// loaderDevicePartUUID is systemd-boot's EFI variable naming the GPT
// partition the box booted from, under efivarfs.
const loaderDevicePartUUID = "LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"

// device is a host disk opened for reading. It never leaves the package.
type device interface {
	io.ReaderAt
	io.Closer
}

// openReadOnly opens a block device read-only. os.OpenFile adds
// O_CLOEXEC on Linux; a test checks the open file's flags.
func openReadOnly(path string) (device, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// System is where the disks are found. The zero value uses /sys, /dev and
// /proc/self/mountinfo.
type System struct {
	Sys       string
	Dev       string
	Mountinfo string
	open      func(path string) (device, error) // tests only
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
	if s.open == nil {
		s.open = openReadOnly
	}
	return s
}

// Class is what the udev helper says a block device is.
type Class string

const (
	ClassDrive   Class = "drive"   // on the AgentOS Drive: left alone
	ClassHost    Class = "host"    // a host disk: hidden (HW-8)
	ClassUnknown Class = "unknown" // cannot tell: kept from udisks only, so the box still boots
)

// Health is a problem finding the AgentOS Drive, for the box's health
// report. Any value but HealthOK means there is no drive: every disk but
// the one holding the running root is a host disk.
type Health string

const (
	HealthOK       Health = ""
	HealthNoRoot   Health = "root-disk-unknown" // the running root is on no single disk
	HealthMismatch Health = "drive-mismatch"    // the root's disk lacks the partition systemd-boot booted from
)

var (
	// A sysfs block name; "!" stands for "/" under /dev (cciss!c0d0 is
	// /dev/cciss/c0d0), and every segment starts with a letter or digit,
	// so none is "." or "..".
	validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]*(![A-Za-z0-9][A-Za-z0-9_.:-]*)*$`)
	validMM   = regexp.MustCompile(`^[0-9]+:[0-9]+$`)
	validGUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// Only these are the box's own virtual devices (security H7). md and
	// dm devices are classified by what they are built on.
	virtualPrefix = []string{"loop", "ram", "zram", "nbd"}
	stackedPrefix = []string{"dm-", "md"}
	// Optical drives are never opened: an open can close an ejected tray,
	// and a disc is not a disk the owner can give the box (L3 on #172).
	// udev still hides them as host.
	opticalPrefix = []string{"sr"}
)

// probeable reports whether name is a physical disk the list may open.
func probeable(name string) bool {
	return validName.MatchString(name) && !hasPrefix(name, virtualPrefix) && !hasPrefix(name, stackedPrefix) && !hasPrefix(name, opticalPrefix)
}

func hasPrefix(name string, ps []string) bool {
	for _, p := range ps {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func (s System) readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// diskOf resolves a sysfs block device directory to the physical disks it
// lives on: a partition to its disk, a dm or md device through its slaves.
func (s System) diskOf(dir string, depth int, out map[string]bool) bool {
	if depth > 16 {
		return false
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return false
	}
	if slaves, _ := os.ReadDir(filepath.Join(real, "slaves")); len(slaves) > 0 {
		for _, sl := range slaves {
			if !s.diskOf(filepath.Join(real, "slaves", sl.Name()), depth+1, out) {
				return false
			}
		}
		return true
	}
	name := filepath.Base(real)
	if hasPrefix(name, stackedPrefix) {
		return false // a dm or md device with no slaves yet: cannot tell
	}
	if _, err := os.Stat(filepath.Join(real, "partition")); err == nil {
		name = filepath.Base(filepath.Dir(real))
	}
	out[name] = true
	return true
}

// mount is one line of mountinfo.
type mount struct {
	mm, point, fstype, opts string
}

// unescape undoes mountinfo's octal escapes (\040 for a space).
func unescape(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func (s System) mounts() []mount {
	f, err := os.Open(s.Mountinfo)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []mount
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		pre, post, ok := strings.Cut(sc.Text(), " - ")
		fs, ps := strings.Fields(pre), strings.Fields(post)
		if !ok || len(fs) < 5 || len(ps) < 3 {
			continue
		}
		out = append(out, mount{mm: fs[2], point: unescape(fs[4]), fstype: ps[0], opts: ps[2]})
	}
	return out
}

// mountOf returns the mount in effect at path: the longest mount point
// that contains it, the last one listed when stacked.
func mountOf(ms []mount, path string) (mount, bool) {
	var best mount
	found := false
	for _, m := range ms {
		p := strings.TrimSuffix(m.point, "/")
		if path == m.point || path == p || strings.HasPrefix(path, p+"/") {
			if !found || len(m.point) >= len(best.point) {
				best, found = m, true
			}
		}
	}
	return best, found
}

// backing adds the physical disks under the file system mounted at path:
// a block device through sysfs (partitions to their disk, dm and md
// through their slaves), an overlay through its upper and lower
// directories. A tmpfs or other device-less file system adds nothing.
func (s System) backing(ms []mount, path string, depth int, out map[string]bool) bool {
	m, ok := mountOf(ms, path)
	if !ok || depth > 8 {
		return false
	}
	if validMM.MatchString(m.mm) && !strings.HasPrefix(m.mm, "0:") {
		return s.diskOf(filepath.Join(s.Sys, "dev", "block", m.mm), 0, out)
	}
	if m.fstype != "overlay" {
		return false
	}
	any := false
	for _, o := range strings.Split(m.opts, ",") {
		k, v, _ := strings.Cut(o, "=")
		if k != "upperdir" && k != "lowerdir" {
			continue
		}
		for _, dir := range strings.Split(v, ":") {
			if dir == "" || !strings.HasPrefix(dir, "/") {
				continue
			}
			if !s.backing(ms, dir, depth+1, out) {
				return false
			}
			any = true
		}
	}
	return any
}

// rootDisk returns the one physical disk the running system is on (security
// H1, F2 on #172): the disk backing /, or, for a root with no block device
// (tmpfs), the one backing /usr. When neither resolves to exactly one disk
// it is the disk holding systemd-boot's partition, if exactly one does.
func (s System) rootDisk() string {
	ms := s.mounts()
	one := func(set map[string]bool) string {
		if len(set) != 1 {
			return ""
		}
		for d := range set {
			return d
		}
		return ""
	}
	for _, p := range []string{"/", "/usr"} {
		set := map[string]bool{}
		if s.backing(ms, p, 0, set) {
			return one(set)
		}
	}
	want, ok := s.loaderPartition()
	if !ok {
		return ""
	}
	ents, _ := os.ReadDir(filepath.Join(s.Sys, "block"))
	set := map[string]bool{}
	for _, e := range ents {
		n := e.Name()
		if !probeable(n) {
			continue
		}
		if _, found := s.describe(n, want); found {
			set[n] = true
		}
	}
	return one(set)
}

// loaderPartition returns the partition systemd-boot booted from, in
// on-disk GUID form, or false when the variable is absent or malformed.
func (s System) loaderPartition() ([16]byte, bool) {
	b, err := os.ReadFile(filepath.Join(s.Sys, "firmware", "efi", "efivars", loaderDevicePartUUID))
	if err != nil || len(b) < 6 {
		return [16]byte{}, false
	}
	b = b[4:] // attributes
	var g []byte
	for i := 0; i+1 < len(b); i += 2 {
		if b[i+1] != 0 || b[i] == 0 {
			break
		}
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		g = append(g, c)
	}
	if !validGUID.Match(g) {
		return [16]byte{}, false
	}
	return onDisk(string(g)), true
}

// driveState is the AgentOS Drive (or none) and how it was found.
type driveState struct {
	root   string // the disk holding the running root, or ""
	drive  string // root, once the loader variable agrees; "" otherwise
	health Health
}

// findDrive applies security H1 on HOST-1a: the drive is the disk holding
// the running root. systemd-boot's LoaderDevicePartUUID, when present, is
// a cross-check: if the root's disk does not list that partition there is
// no drive. Mount state of any other disk never makes it the drive.
func (s System) findDrive() driveState {
	root := s.rootDisk()
	if root == "" {
		return driveState{health: HealthNoRoot}
	}
	st := driveState{root: root, drive: root}
	if want, ok := s.loaderPartition(); ok {
		_, found := s.describe(root, want)
		if !found {
			st.drive, st.health = "", HealthMismatch
		}
	}
	return st
}

// Classify says what the named /sys/block device is, for the udev rule.
func (s System) Classify(name string) Class {
	s = s.fill()
	name = strings.ReplaceAll(name, "/", "!") // udev's %k spells "!" as "/"
	if !validName.MatchString(name) || hasPrefix(name, virtualPrefix) {
		return ClassUnknown
	}
	if _, err := os.Stat(filepath.Join(s.Sys, "block", name)); err != nil {
		return ClassUnknown
	}
	disks := map[string]bool{}
	if !s.diskOf(filepath.Join(s.Sys, "block", name), 0, disks) || len(disks) == 0 {
		return ClassUnknown
	}
	st := s.findDrive()
	switch {
	case st.health == HealthNoRoot:
		return ClassUnknown
	case st.health == HealthOK && len(disks) == 1 && disks[st.drive]:
		return ClassDrive
	case st.health != HealthOK && len(disks) == 1 && disks[st.root]:
		// No drive, but hiding the disk the system runs on would only
		// stop it booting; the health item reports the disagreement.
		return ClassUnknown
	}
	return ClassHost
}

// ClassifyEnv is the udev helper's output line for a device.
func (s System) ClassifyEnv(name string) string {
	return "AGENTOS_DISK=" + string(s.Classify(name)) + "\n"
}

// Listing is the HW-8a disk list and the drive's health.
type Listing struct {
	Disks  []Disk `json:"disks"`
	Health Health `json:"health,omitempty"`
}

// HostDisks describes every physical disk of the host other than the one
// holding the running root, for the HW-8a list. Virtual, dm and md
// devices are left out: they are built on disks already listed. Optical
// drives are left out and never opened. A disk that cannot be read is
// listed with Problem set.
func (s System) HostDisks() (Listing, error) {
	s = s.fill()
	ents, err := os.ReadDir(filepath.Join(s.Sys, "block"))
	if err != nil {
		return Listing{}, err
	}
	st := s.findDrive()
	l := Listing{Disks: []Disk{}, Health: st.health}
	var names []string
	for _, e := range ents {
		n := e.Name()
		if probeable(n) && n != st.root {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		d, _ := s.describe(n, [16]byte{})
		l.Disks = append(l.Disks, d)
	}
	return l, nil
}

// describe reads one disk's model, size and bus from sysfs and probes it.
func (s System) describe(name string, want [16]byte) (Disk, bool) {
	dir := filepath.Join(s.Sys, "block", name)
	d := Disk{Name: name, Model: cleanModel(s.readTrim(filepath.Join(dir, "device", "model"))), Partitions: []Partition{}}
	d.Bus = s.bus(name)
	d.Removable = s.readTrim(filepath.Join(dir, "removable")) == "1" || d.Bus == BusUSB
	sectors, err := strconv.ParseInt(s.readTrim(filepath.Join(dir, "size")), 10, 64)
	if err != nil || sectors <= 0 || sectors > 1<<54 {
		d.Problem = ProblemSizeUnknown
		return d, false
	}
	d.Size = sectors * 512 // sysfs counts 512-byte units whatever the sector size
	lbs, err := strconv.Atoi(s.readTrim(filepath.Join(dir, "queue", "logical_block_size")))
	if err != nil {
		lbs = 512
	}
	dev, err := s.open(filepath.Join(s.Dev, strings.ReplaceAll(name, "!", "/")))
	if err != nil {
		d.Problem = ProblemOpen
		return d, false
	}
	defer dev.Close()
	p, found, _ := probe(dev, d.Size, lbs, want)
	p.Name, p.Model, p.Size, p.Bus, p.Removable = d.Name, d.Model, d.Size, d.Bus, d.Removable
	return p, found
}

func (s System) bus(name string) Bus {
	real, _ := filepath.EvalSymlinks(filepath.Join(s.Sys, "block", name))
	switch {
	case strings.Contains(real, "/usb"):
		return BusUSB
	case strings.HasPrefix(name, "nvme"):
		return BusNVMe
	case strings.HasPrefix(name, "mmcblk"):
		return BusMMC
	case strings.Contains(real, "/ata"):
		return BusSATA
	case strings.Contains(real, "/virtio"):
		return BusVirtIO
	case strings.Contains(real, "/host") && strings.Contains(real, "/target"):
		return BusSCSI
	}
	return BusOther
}

// cleanModel keeps a model string to printable ASCII, at most 64 bytes.
func cleanModel(m string) string {
	b := make([]byte, 0, len(m))
	for i := 0; i < len(m) && len(b) < 64; i++ {
		if m[i] >= 0x20 && m[i] < 0x7f {
			b = append(b, m[i])
		}
	}
	return strings.TrimSpace(string(b))
}
