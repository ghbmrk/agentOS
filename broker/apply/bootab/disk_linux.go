//go:build linux

package bootab

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf16"

	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/childproc"
)

// The GPT partition types of an x86-64 /usr slot (Discoverable Partitions
// Specification), as image/finish_image.py names them.
const (
	usrType       = "8484680c-9521-48c6-9c11-b0720656f69e"
	usrVerityType = "77ff5f63-e7b6-4633-acf4-1565b864c0e6"
)

// loaderGUID is the Boot Loader Interface's vendor GUID: systemd-boot's
// variables are <Name>-<loaderGUID> in efivarfs.
const loaderGUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"

// efiAttrs is non-volatile, boot service and runtime access, as bootctl
// writes LoaderEntryDefault.
const efiAttrs = 0x7

// fsImmutable is FS_IMMUTABLE_FL: efivarfs marks most variables
// immutable, and bootctl clears it before a write or delete.
const fsImmutable = 0x10

// The tools the adapter runs, by absolute path so no $PATH lookup picks
// them, and the whole environment they get (util-linux, cryptsetup-bin).
const (
	sfdisk      = "/usr/sbin/sfdisk"
	veritysetup = "/usr/sbin/veritysetup"
	toolPath    = "PATH=/usr/sbin:/usr/bin"
)

// maxGPTName is a GPT partition name's length in UTF-16 units; the
// adapter's labels are ASCII.
const maxGPTName = 36

// maxESPFile bounds an entry or loader.conf read.
const maxESPFile = 64 << 10

// entryName is an agentOS entry's file name: its version and the try
// counter systemd-boot keeps in the name (+LEFT or +LEFT-DONE). The image
// names its entry after build.sh's VERSION, YYYYMMDD.HHMMSS
// (finish_image.py); Install names one after the release's update
// version, the same digits without the dot (EntryID).
var entryName = regexp.MustCompile(`^agentos_([0-9]{1,19}(?:\.[0-9]{1,9})?)(\+([0-9]{1,9})(-[0-9]{1,9})?)?\.conf$`)

// Linux is the production Disk: the ESP's entries and loader.conf, the
// loader's EFI variables in efivarfs, and the /usr slots as GPT partitions
// of Device. It opens no path through a symlink, and it refuses to write a
// partition that is booted, mounted or held by dm-verity.
type Linux struct {
	// ESP is where the ESP is mounted (/boot, image/mkosi.repart).
	ESP string
	// EFIVars is the efivarfs mount (/sys/firmware/efi/efivars).
	EFIVars string
	// Proc is /proc; Sys is /sys.
	Proc, Sys string
	// Usr is the booted /usr: a path on it, or its block device node.
	Usr string
	// Device is the whole disk holding the slots.
	Device string
	// Run runs a tool (sfdisk, veritysetup) by absolute path and returns
	// its output; nil starts it through childproc.
	Run func(name string, arg ...string) ([]byte, error)

	mu    sync.Mutex
	parts map[[2]string]*partWriter
}

// partWriter is a partition open for writing, and the next write's offset.
type partWriter struct {
	f   *os.File
	off int64
}

// gptPart is one partition as sfdisk --json lists it.
type gptPart struct {
	Node string `json:"node"`
	Type string `json:"type"`
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

// slotParts is a slot's data and verity partitions and their numbers.
type slotParts struct {
	data, verity       gptPart
	dataNum, verityNum int
}

// NewLinux is the box's Disk: the ESP at /boot, efivarfs, and the disk
// that holds the booted /usr.
func NewLinux() (*Linux, error) {
	l := &Linux{ESP: "/boot", EFIVars: "/sys/firmware/efi/efivars", Proc: "/proc", Sys: "/sys", Usr: "/usr"}
	held, err := l.usrHolders()
	if err != nil {
		return nil, err
	}
	if len(held) == 0 {
		return nil, errors.New("bootab: /usr is not on a partition")
	}
	disk, err := os.Readlink(filepath.Join(l.Sys, "class/block", held[0]))
	if err != nil {
		return nil, err
	}
	// .../block/<disk>/<partition>: the partition's parent is the disk.
	l.Device = "/dev/" + filepath.Base(filepath.Dir(disk))
	return l, nil
}

func (l *Linux) run(name string, arg ...string) ([]byte, error) {
	if l.Run != nil {
		return l.Run(name, arg...)
	}
	var stderr bytes.Buffer
	cmd := childproc.Command(context.Background(), childproc.NewEnv(toolPath), childproc.Options{Stderr: &stderr}, name, arg...)
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("bootab: %s %s: %w: %s", name, strings.Join(arg, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// readBounded reads a regular file at path, never through a symlink in
// its last component.
func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("bootab: %s is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err == nil && int64(len(b)) > max {
		err = fmt.Errorf("bootab: %s is over %d bytes", path, max)
	}
	return b, err
}

// BootID is /proc/sys/kernel/random/boot_id.
func (l *Linux) BootID() (string, error) {
	b, err := readBounded(filepath.Join(l.Proc, "sys/kernel/random/boot_id"), 64)
	return strings.TrimSpace(string(b)), err
}

// Cmdline is /proc/cmdline.
func (l *Linux) Cmdline() (string, error) {
	b, err := readBounded(filepath.Join(l.Proc, "cmdline"), 1<<16)
	return strings.TrimSpace(string(b)), err
}

// efiVar reads a Boot Loader Interface variable's string; ok is false when
// it is unset.
func (l *Linux) efiVar(name string) (v string, ok bool, err error) {
	b, err := readBounded(filepath.Join(l.EFIVars, name+"-"+loaderGUID), 4096)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if len(b) < 4 || len(b)%2 != 0 {
		return "", false, fmt.Errorf("bootab: EFI variable %s is %d bytes, not UTF-16 after its attributes", name, len(b))
	}
	u := make([]uint16, (len(b)-4)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[4+2*i:])
	}
	if i := slices.Index(u, 0); i >= 0 {
		u = u[:i]
	}
	return string(utf16.Decode(u)), true, nil
}

// clearImmutable drops efivarfs's immutable flag on path, as bootctl does
// before a write or delete. A file system without the flag ioctl has
// nothing to clear.
func clearImmutable(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	flags, err := unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
	if errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
		return nil
	}
	if err != nil || flags&fsImmutable == 0 {
		return err
	}
	return unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, int(flags&^fsImmutable))
}

// setEFIVar writes name's string in one write, as efivarfs requires; ""
// deletes it.
func (l *Linux) setEFIVar(name, v string) error {
	path := filepath.Join(l.EFIVars, name+"-"+loaderGUID)
	if err := clearImmutable(path); err != nil {
		return err
	}
	if v == "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	b := binary.LittleEndian.AppendUint32(nil, efiAttrs)
	for _, c := range utf16.Encode([]rune(v + "\x00")) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// stripCounter is an entry ID without boot counting's +LEFT-DONE, which
// systemd 257 keeps in LoaderEntrySelected and 260 drops.
func stripCounter(id string) string {
	if m := entryName.FindStringSubmatch(id); m != nil {
		return "agentos_" + m[1] + ".conf"
	}
	return id
}

// Selected is LoaderEntrySelected, without a try counter. An unset
// variable is an error: the box was not booted by systemd-boot.
func (l *Linux) Selected() (string, error) {
	v, ok, err := l.efiVar("LoaderEntrySelected")
	if err == nil && !ok {
		err = errors.New("bootab: LoaderEntrySelected is unset")
	}
	return stripCounter(strings.ToLower(v)), err
}

// EFIDefault is LoaderEntryDefault, "" when unset.
func (l *Linux) EFIDefault() (string, error) {
	v, _, err := l.efiVar("LoaderEntryDefault")
	return v, err
}

// SetEFIDefault sets LoaderEntryDefault; "" deletes it.
func (l *Linux) SetEFIDefault(id string) error { return l.setEFIVar("LoaderEntryDefault", id) }

// table is the disk's slots: the i'th usr partition and the i'th
// usr-verity partition in partition order are slot i ("a", "b"). Labels
// change with each Install, so they never pair partitions.
func (l *Linux) table() (map[string]slotParts, error) {
	out, err := l.run(sfdisk, "--json", l.Device)
	if err != nil {
		return nil, err
	}
	var t struct {
		PartitionTable struct {
			Label      string    `json:"label"`
			Partitions []gptPart `json:"partitions"`
		} `json:"partitiontable"`
	}
	if err := json.Unmarshal(out, &t); err != nil {
		return nil, fmt.Errorf("bootab: sfdisk --json %s: %w", l.Device, err)
	}
	if t.PartitionTable.Label != "gpt" {
		return nil, fmt.Errorf("bootab: %s has no GPT", l.Device)
	}
	type numbered struct {
		p gptPart
		n int
	}
	var usr, verity []numbered
	for _, p := range t.PartitionTable.Partitions {
		i := len(p.Node)
		for i > 0 && p.Node[i-1] >= '0' && p.Node[i-1] <= '9' {
			i--
		}
		n, err := strconv.Atoi(p.Node[i:])
		if err != nil || n < 1 {
			return nil, fmt.Errorf("bootab: partition node %q has no number", p.Node)
		}
		p.UUID = strings.ToLower(p.UUID)
		switch strings.ToLower(p.Type) {
		case usrType:
			usr = append(usr, numbered{p, n})
		case usrVerityType:
			verity = append(verity, numbered{p, n})
		}
	}
	if len(usr) != 2 || len(verity) != 2 {
		return nil, fmt.Errorf("bootab: %s has %d usr and %d usr-verity partitions, want 2 of each", l.Device, len(usr), len(verity))
	}
	sorted := func(a, b numbered) int { return a.n - b.n }
	slices.SortFunc(usr, sorted)
	slices.SortFunc(verity, sorted)
	m := map[string]slotParts{}
	for i, s := range []string{"a", "b"} {
		m[s] = slotParts{data: usr[i].p, verity: verity[i].p, dataNum: usr[i].n, verityNum: verity[i].n}
	}
	return m, nil
}

// Slots is "a" and "b".
func (l *Linux) Slots() ([]string, error) {
	if _, err := l.table(); err != nil {
		return nil, err
	}
	return []string{"a", "b"}, nil
}

// usrHolders is the kernel names of the partitions the booted /usr runs
// from: the dm-verity device's data and hash devices, or the partition
// itself when /usr is not a device mapper target.
func (l *Linux) usrHolders() ([]string, error) {
	var st unix.Stat_t
	if err := unix.Stat(l.Usr, &st); err != nil {
		return nil, err
	}
	dev := st.Dev
	if st.Mode&unix.S_IFMT == unix.S_IFBLK {
		dev = st.Rdev
	}
	sys := filepath.Join(l.Sys, "dev/block", fmt.Sprintf("%d:%d", unix.Major(dev), unix.Minor(dev)))
	es, err := os.ReadDir(filepath.Join(sys, "slaves"))
	if errors.Is(err, os.ErrNotExist) || err == nil && len(es) == 0 {
		target, err := os.Readlink(sys)
		if err != nil {
			return nil, err
		}
		return []string{filepath.Base(target)}, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	return names, nil
}

// BootedSlot is the slot whose data or verity partition the running /usr
// comes from.
func (l *Linux) BootedSlot() (string, error) {
	held, err := l.usrHolders()
	if err != nil {
		return "", err
	}
	t, err := l.table()
	if err != nil {
		return "", err
	}
	// A slot is booted when /usr holds either of its partitions, so a
	// table that pairs the partitions otherwise than the image never
	// calls the booted hash partition inactive.
	var booted []string
	for s, p := range t {
		if slices.Contains(held, filepath.Base(p.data.Node)) || slices.Contains(held, filepath.Base(p.verity.Node)) {
			booted = append(booted, s)
		}
	}
	if len(booted) != 1 {
		return "", fmt.Errorf("bootab: /usr runs from %q, which is %d slots' data partition, want 1", held, len(booted))
	}
	return booted[0], nil
}

// espDir opens the ESP's directory rel ("loader/entries"), one component
// at a time, never through a symlink.
func (l *Linux) espDir(rel string) (int, error) {
	fd, err := unix.Open(l.ESP, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("bootab: ESP %s: %w", l.ESP, err)
	}
	for _, c := range strings.Split(rel, "/") {
		if c == "" {
			continue
		}
		next, err := unix.Openat(fd, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("bootab: ESP %s/%s: %w", l.ESP, rel, err)
		}
		fd = next
	}
	return fd, nil
}

// readAt reads the regular file name in directory dir, not through a
// symlink; ok is false when it does not exist.
func readAt(dir int, name string) (b []byte, ok bool, err error) {
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("bootab: %s: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if !fi.Mode().IsRegular() {
		return nil, false, fmt.Errorf("bootab: ESP file %s is not a regular file", name)
	}
	b, err = io.ReadAll(io.LimitReader(f, maxESPFile+1))
	if err == nil && len(b) > maxESPFile {
		err = fmt.Errorf("bootab: ESP file %s is over %d bytes", name, maxESPFile)
	}
	return b, err == nil, err
}

// writeAt replaces name in dir with b: a temporary file the loader does
// not read (no .conf), synced, then renamed over name.
func writeAt(dir int, name string, b []byte) error {
	tmp := "." + name + ".tmp"
	if err := unix.Unlinkat(dir, tmp, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	fd, err := unix.Openat(dir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tmp)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return unix.Renameat(dir, tmp, dir, name)
}

// espEntry is one entry file: its name on the ESP, its text and what it
// boots.
type espEntry struct {
	file, text string
	e          Entry
}

// optionWords is the entry's kernel command line: every options line's
// words, as systemd-boot joins them.
func optionWords(text string) []string {
	var w []string
	for _, ln := range strings.Split(text, "\n") {
		f := strings.Fields(ln)
		if len(f) > 0 && f[0] == "options" {
			w = append(w, f[1:]...)
		}
	}
	return w
}

// entryHash is the entry's single usrhash=.
func entryHash(text string) (string, error) {
	var hs []string
	for _, w := range optionWords(text) {
		if h, ok := strings.CutPrefix(w, "usrhash="); ok {
			hs = append(hs, h)
		}
	}
	if len(hs) != 1 {
		return "", fmt.Errorf("bootab: entry has %d usrhash=, want 1", len(hs))
	}
	if _, _, err := PartitionUUIDs(hs[0]); err != nil {
		return "", err
	}
	return hs[0], nil
}

// slotOf is the slot whose two partitions carry the UUIDs the initrd
// finds for root hash h, "" when none does.
func slotOf(t map[string]slotParts, h string) (string, error) {
	data, verity, err := PartitionUUIDs(h)
	if err != nil {
		return "", err
	}
	var on []string
	for s, p := range t {
		if p.data.UUID == data && p.verity.UUID == verity {
			on = append(on, s)
		}
	}
	if len(on) > 1 {
		return "", fmt.Errorf("bootab: both slots carry root hash %s's UUIDs", h)
	}
	if len(on) == 0 {
		return "", nil
	}
	return on[0], nil
}

// entries reads every entry file. A .conf file that is not an agentOS
// entry, or two files with one ID, is an error: the loader would offer
// it, and Install's reasoning covers only entries it can see.
func (l *Linux) entries() (map[string]espEntry, error) {
	t, err := l.table()
	if err != nil {
		return nil, err
	}
	fd, err := l.espDir("loader/entries")
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "loader/entries")
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	out := map[string]espEntry{}
	for _, n := range names {
		if !strings.HasSuffix(strings.ToLower(n), ".conf") {
			continue
		}
		m := entryName.FindStringSubmatch(n)
		if m == nil {
			return nil, fmt.Errorf("bootab: ESP entry %q is not agentos_<version>[+tries].conf", n)
		}
		id := stripCounter(n)
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("bootab: two ESP entry files have ID %s", id)
		}
		b, _, err := readAt(fd, n)
		if err != nil {
			return nil, err
		}
		h, err := entryHash(string(b))
		if err != nil {
			return nil, fmt.Errorf("bootab: entry %s: %w", n, err)
		}
		s, err := slotOf(t, h)
		if err != nil {
			return nil, err
		}
		tries := Blessed
		if m[3] != "" {
			tries, _ = strconv.Atoi(m[3])
		}
		out[id] = espEntry{file: n, text: string(b), e: Entry{Slot: s, UsrHash: h, Tries: tries}}
	}
	return out, nil
}

// loaderDefault is loader.conf's default pattern, "" when it has none.
func loaderDefault(conf string) string {
	def := ""
	for _, ln := range strings.Split(conf, "\n") {
		if f := strings.Fields(ln); len(f) >= 2 && f[0] == "default" {
			def = strings.Join(f[1:], " ")
		}
	}
	return def
}

// Entries is the agentOS entries on the ESP, by counter-less ID, and
// loader.conf's default.
func (l *Linux) Entries() (map[string]Entry, string, error) {
	es, err := l.entries()
	if err != nil {
		return nil, "", err
	}
	fd, err := l.espDir("loader")
	if err != nil {
		return nil, "", err
	}
	defer unix.Close(fd)
	conf, _, err := readAt(fd, "loader.conf")
	if err != nil {
		return nil, "", err
	}
	m := map[string]Entry{}
	for id, e := range es {
		m[id] = e.e
	}
	return m, loaderDefault(string(conf)), nil
}

// WriteEntry writes entry id (agentos_<version>.conf) as the file
// agentos_<version>+<tries>.conf, or with no counter when e.Tries is
// Blessed. Its title, sort-key and version lines are the image's
// (finish_image.py), so systemd-boot orders it by version among the
// entries that share the sort-key; its linux, initrd and options lines are
// the running entry's, with usrhash= set to e.UsrHash. e.Slot must be the
// slot whose partition UUIDs that hash finds.
func (l *Linux) WriteEntry(id string, e Entry) error {
	m := entryName.FindStringSubmatch(id)
	if m == nil || m[2] != "" {
		return fmt.Errorf("bootab: entry ID %q is not agentos_<version>.conf", id)
	}
	if e.Tries != Blessed && (e.Tries < 0 || e.Tries > 9) {
		return fmt.Errorf("bootab: entry %s tries %d out of range", id, e.Tries)
	}
	t, err := l.table()
	if err != nil {
		return err
	}
	if s, err := slotOf(t, e.UsrHash); err != nil || s != e.Slot || s == "" {
		return fmt.Errorf("bootab: entry %s names slot %q, but root hash %s's UUIDs are on slot %q (%v)", id, e.Slot, e.UsrHash, s, err)
	}
	cmd, err := l.Cmdline()
	if err != nil {
		return err
	}
	running, err := entryHash("options " + cmd)
	if err != nil {
		return fmt.Errorf("bootab: running command line: %w", err)
	}
	es, err := l.entries()
	if err != nil {
		return err
	}
	var tmpl []espEntry
	for _, x := range es {
		if x.e.UsrHash == running && x.e.Tries == Blessed {
			tmpl = append(tmpl, x)
		}
	}
	if len(tmpl) != 1 {
		return fmt.Errorf("bootab: %d blessed entries boot the running usrhash=%s, want 1 to copy the kernel from", len(tmpl), running)
	}
	lines := []string{"title AgentOS", "sort-key agentos", "version " + m[1]}
	for _, ln := range strings.Split(strings.TrimRight(tmpl[0].text, "\n"), "\n") {
		f := strings.Fields(ln)
		if len(f) == 0 || f[0] == "title" || f[0] == "version" || f[0] == "sort-key" {
			continue
		}
		if f[0] == "options" {
			for i, w := range f {
				if strings.HasPrefix(w, "usrhash=") {
					f[i] = "usrhash=" + e.UsrHash
				}
			}
			ln = strings.Join(f, " ")
		}
		lines = append(lines, ln)
	}
	text := strings.Join(lines, "\n") + "\n"
	if h, err := entryHash(text); err != nil || h != e.UsrHash {
		return fmt.Errorf("bootab: entry %s would boot usrhash=%s (%v), want %s", id, h, err, e.UsrHash)
	}
	name := "agentos_" + m[1] + ".conf"
	if e.Tries != Blessed {
		name = fmt.Sprintf("agentos_%s+%d.conf", m[1], e.Tries)
	}
	// Two files with one ID would stop every later read (entries), so a
	// different counter on an existing entry is refused; Install has
	// removed every entry on the slot before it writes one.
	if old, ok := es[id]; ok && old.file != name {
		return fmt.Errorf("bootab: entry %s exists as %s", id, old.file)
	}
	fd, err := l.espDir("loader/entries")
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return writeAt(fd, name, []byte(text))
}

// RemoveEntry removes entry id's file, whatever its try counter.
func (l *Linux) RemoveEntry(id string) error {
	es, err := l.entries()
	if err != nil {
		return err
	}
	e, ok := es[id]
	if !ok {
		return nil
	}
	fd, err := l.espDir("loader/entries")
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Unlinkat(fd, e.file, 0)
}

// SetDefault rewrites loader.conf with pattern as its only default line,
// or none when pattern is "".
func (l *Linux) SetDefault(pattern string) error {
	if strings.ContainsAny(pattern, "\n\r") {
		return fmt.Errorf("bootab: default pattern %q spans lines", pattern)
	}
	fd, err := l.espDir("loader")
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	conf, ok, err := readAt(fd, "loader.conf")
	if err != nil {
		return err
	}
	if !ok && pattern == "" {
		return nil
	}
	var lines []string
	for _, ln := range strings.Split(strings.TrimRight(string(conf), "\n"), "\n") {
		if f := strings.Fields(ln); ln == "" || len(f) > 0 && f[0] == "default" {
			continue
		}
		lines = append(lines, ln)
	}
	if pattern != "" {
		lines = append(lines, "default "+pattern)
	}
	return writeAt(fd, "loader.conf", []byte(strings.Join(lines, "\n")+"\n"))
}

// SyncESP flushes the ESP file system (syncfs).
func (l *Linux) SyncESP() error {
	fd, err := l.espDir("")
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Syncfs(fd)
}

// slot is slot s's partitions; it refuses the booted slot.
func (l *Linux) slot(s string) (slotParts, error) {
	t, err := l.table()
	if err != nil {
		return slotParts{}, err
	}
	p, ok := t[s]
	if !ok {
		return slotParts{}, fmt.Errorf("bootab: no slot %q", s)
	}
	booted, err := l.BootedSlot()
	if err != nil {
		return slotParts{}, err
	}
	if s == booted {
		return slotParts{}, fmt.Errorf("bootab: slot %s is booted", s)
	}
	return p, nil
}

// node is part's device node in slot p.
func (p slotParts) node(part string) (string, error) {
	switch part {
	case PartUsr:
		return p.data.Node, nil
	case PartVerity:
		return p.verity.Node, nil
	}
	return "", fmt.Errorf("bootab: no partition %q", part)
}

// TruncatePart opens slot s's partition part for writing from its start.
// O_EXCL on a block device fails with EBUSY while it is mounted or held by
// dm-verity, so the running /usr is never opened for writing.
func (l *Linux) TruncatePart(s, part string) error {
	p, err := l.slot(s)
	if err != nil {
		return err
	}
	n, err := p.node(part)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(n, os.O_WRONLY|os.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("bootab: open slot %s %s: %w", s, part, err)
	}
	if fi, err := f.Stat(); err != nil || fi.Mode()&os.ModeDevice == 0 || fi.Mode()&os.ModeCharDevice != 0 {
		f.Close()
		return fmt.Errorf("bootab: slot %s %s node %s is not a block device", s, part, n)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.parts == nil {
		l.parts = map[[2]string]*partWriter{}
	}
	if old := l.parts[[2]string{s, part}]; old != nil {
		old.f.Close()
	}
	l.parts[[2]string{s, part}] = &partWriter{f: f}
	return nil
}

// WritePart appends b to the partition TruncatePart opened.
func (l *Linux) WritePart(s, part string, b []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.parts[[2]string{s, part}]
	if w == nil {
		return fmt.Errorf("bootab: slot %s %s is not open for writing", s, part)
	}
	k, err := w.f.WriteAt(b, w.off)
	w.off += int64(k)
	return err
}

// SyncPart makes the partition's writes durable (fsync) and closes it.
func (l *Linux) SyncPart(s, part string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := [2]string{s, part}
	w := l.parts[k]
	if w == nil {
		return fmt.Errorf("bootab: slot %s %s is not open for writing", s, part)
	}
	delete(l.parts, k)
	err := w.f.Sync()
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// syncDevice flushes the disk after a GPT write.
func (l *Linux) syncDevice() error {
	f, err := os.OpenFile(l.Device, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// sfdiskSet sets one GPT field of partition n with sfdisk, which writes
// both GPT copies, and leaves the kernel's partitions as they are.
func (l *Linux) sfdiskSet(field string, n int, v string) error {
	_, err := l.run(sfdisk, "--no-reread", "--no-tell-kernel", "--"+field, l.Device, strconv.Itoa(n), v)
	return err
}

// SetSlotUUIDs sets slot s's data and verity partition UUIDs.
func (l *Linux) SetSlotUUIDs(s, data, verity string) error {
	p, err := l.slot(s)
	if err != nil {
		return err
	}
	if err := l.sfdiskSet("part-uuid", p.dataNum, data); err != nil {
		return err
	}
	if err := l.sfdiskSet("part-uuid", p.verityNum, verity); err != nil {
		return err
	}
	return l.syncDevice()
}

// SetSlotLabel labels slot s as the image does: the data partition label,
// the verity partition label + "_verity", and EmptyLabel on both.
func (l *Linux) SetSlotLabel(s, label string) error {
	vl := label + "_verity"
	if label == EmptyLabel {
		vl = EmptyLabel
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(label) || len(vl) > maxGPTName {
		return fmt.Errorf("bootab: label %q (verity %q) is not a GPT name of at most %d ASCII characters", label, vl, maxGPTName)
	}
	p, err := l.slot(s)
	if err != nil {
		return err
	}
	if err := l.sfdiskSet("part-label", p.dataNum, label); err != nil {
		return err
	}
	if err := l.sfdiskSet("part-label", p.verityNum, vl); err != nil {
		return err
	}
	return l.syncDevice()
}

// VerifySlot runs veritysetup verify on slot s's data and verity
// partitions against rootHash.
func (l *Linux) VerifySlot(s, rootHash string) error {
	if _, _, err := PartitionUUIDs(rootHash); err != nil {
		return err
	}
	p, err := l.slot(s)
	if err != nil {
		return err
	}
	_, err = l.run(veritysetup, "verify", p.data.Node, p.verity.Node, rootHash)
	return err
}
