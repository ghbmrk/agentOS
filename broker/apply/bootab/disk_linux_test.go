//go:build linux

package bootab_test

// REQ: UPD-1, UPD-1a

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"unicode/utf16"

	"github.com/ghbmrk/agentos/broker/apply/bootab"
)

const loaderGUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"

// Two root hashes for the fixture's releases.
var (
	hashN  = strings.Repeat("a1", 16) + strings.Repeat("b2", 16)
	hashN1 = strings.Repeat("c3", 16) + strings.Repeat("d4", 16)
)

// gptLayout is the image's slot layout (10-usr-a.conf to
// 13-usr-b-verity.conf) at test sizes, behind an ESP-typed partition so
// partition numbers do not start at the slots.
const gptLayout = `label: gpt
size=1M, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name=esp
size=8M, type=8484680C-9521-48C6-9C11-B0720656F69E, name=agentos_1
size=2M, type=77FF5F63-E7B6-4633-ACF4-1565B864C0E6, name=agentos_1_verity
size=8M, type=8484680C-9521-48C6-9C11-B0720656F69E, name=_empty
size=2M, type=77FF5F63-E7B6-4633-ACF4-1565B864C0E6, name=_empty
`

func need(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
}

func run(t *testing.T, stdin string, name string, arg ...string) string {
	t.Helper()
	cmd := exec.Command(name, arg...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(arg, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// efiVar is efivarfs's encoding of s: attributes, then UTF-16LE with a NUL.
func efiVar(s string) []byte {
	b := binary.LittleEndian.AppendUint32(nil, 7)
	for _, c := range utf16.Encode([]rune(s + "\x00")) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

func entryText(version int, hash string) string {
	return fmt.Sprintf("title agentOS\nsort-key agentos\nversion %d\nlinux /EFI/Linux/vmlinuz-6.12\ninitrd /EFI/Linux/initrd-6.12\noptions quiet usrhash=%s console=ttyS0\n", version, hash)
}

// fixture is a Linux over device (a new GPT image file when "") with
// slot a holding the release of root hash booted (its UUIDs set from it),
// an ESP with its blessed entry, efivarfs and /proc
// as plain directories, booted on N.
func fixture(t *testing.T, device, booted string) *bootab.Linux {
	t.Helper()
	dir := t.TempDir()
	if device == "" {
		device = filepath.Join(dir, "disk.img")
		if err := os.WriteFile(device, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(device, 24<<20); err != nil {
			t.Fatal(err)
		}
		run(t, gptLayout, "sfdisk", "-q", device)
	}
	data, verity, err := bootab.PartitionUUIDs(booted)
	if err != nil {
		t.Fatal(err)
	}
	run(t, "", "sfdisk", "-q", "--no-reread", "--no-tell-kernel", "--part-uuid", device, "2", data)
	run(t, "", "sfdisk", "-q", "--no-reread", "--no-tell-kernel", "--part-uuid", device, "3", verity)
	l := &bootab.Linux{
		ESP: filepath.Join(dir, "esp"), EFIVars: filepath.Join(dir, "efivars"),
		Proc: filepath.Join(dir, "proc"), Sys: "/sys", Usr: "/usr", Device: device,
	}
	for _, d := range []string{filepath.Join(l.ESP, "loader/entries"), l.EFIVars, filepath.Join(l.Proc, "sys/kernel/random")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(l.ESP, "loader/loader.conf"):                  "timeout 0\neditor no\nsecure-boot-enroll off\n",
		filepath.Join(l.ESP, "loader/entries/agentos_1.conf"):       entryText(1, booted),
		filepath.Join(l.Proc, "cmdline"):                            "quiet usrhash=" + booted + " console=ttyS0\n",
		filepath.Join(l.Proc, "sys/kernel/random/boot_id"):          "0f2c9d1e-1111-4222-8333-944455556666\n",
		filepath.Join(l.EFIVars, "LoaderEntrySelected-"+loaderGUID): string(efiVar("agentos_1.conf")),
	}
	for p, s := range files {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

func readESP(t *testing.T, l *bootab.Linux, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(l.ESP, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestLinuxBootFacts: BootID, Cmdline and Selected come from /proc and
// efivarfs, and Selected drops systemd 257's try counter, so one entry
// keeps one ID while its tries count down.
func TestLinuxBootFacts(t *testing.T) {
	need(t, "sfdisk")
	l := fixture(t, "", hashN)
	if id, err := l.BootID(); err != nil || id != "0f2c9d1e-1111-4222-8333-944455556666" {
		t.Errorf("BootID = %q, %v", id, err)
	}
	if c, err := l.Cmdline(); err != nil || !strings.Contains(c, "usrhash="+hashN) {
		t.Errorf("Cmdline = %q, %v", c, err)
	}
	sel := filepath.Join(l.EFIVars, "LoaderEntrySelected-"+loaderGUID)
	for v, want := range map[string]string{"agentos_7+2-1.conf": "agentos_7.conf", "Agentos_7+0.conf": "agentos_7.conf", "agentos_7.conf": "agentos_7.conf"} {
		if err := os.WriteFile(sel, efiVar(v), 0o644); err != nil {
			t.Fatal(err)
		}
		if got, err := l.Selected(); err != nil || got != want {
			t.Errorf("Selected with %q = %q, %v; want %q", v, got, err, want)
		}
	}
	os.Remove(sel)
	if _, err := l.Selected(); err == nil {
		t.Error("Selected with LoaderEntrySelected unset succeeded")
	}
	if err := os.WriteFile(sel, []byte{7, 0, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Selected(); err == nil {
		t.Error("Selected of a malformed variable succeeded")
	}
}

// TestLinuxEFIDefault: LoaderEntryDefault is read, written in efivarfs's
// encoding and deleted; unset reads as "".
func TestLinuxEFIDefault(t *testing.T) {
	need(t, "sfdisk")
	l := fixture(t, "", hashN)
	if v, err := l.EFIDefault(); err != nil || v != "" {
		t.Fatalf("unset EFIDefault = %q, %v", v, err)
	}
	if err := l.SetEFIDefault("agentos_1.conf"); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(l.EFIVars, "LoaderEntryDefault-"+loaderGUID)
	if b, _ := os.ReadFile(p); !bytes.Equal(b, efiVar("agentos_1.conf")) {
		t.Errorf("LoaderEntryDefault bytes %x", b)
	}
	if v, err := l.EFIDefault(); err != nil || v != "agentos_1.conf" {
		t.Errorf("EFIDefault = %q, %v", v, err)
	}
	if err := l.SetEFIDefault(""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("LoaderEntryDefault not deleted: %v", err)
	}
	if err := l.SetEFIDefault(""); err != nil {
		t.Errorf("deleting an unset LoaderEntryDefault: %v", err)
	}
}

// TestLinuxEntries: the menu is read with counter-less IDs, tries from
// the file name, and each entry's slot from the partition UUIDs its
// usrhash= finds; WriteEntry writes the image's sort-key and version
// lines over the running entry's title and kernel; RemoveEntry and
// SetDefault edit the ESP.
func TestLinuxEntries(t *testing.T) {
	need(t, "sfdisk")
	l := fixture(t, "", hashN)
	if s, err := l.Slots(); err != nil || strings.Join(s, ",") != "a,b" {
		t.Fatalf("Slots = %q, %v", s, err)
	}
	es, def, err := l.Entries()
	if err != nil || def != "" || len(es) != 1 || es["agentos_1.conf"] != (bootab.Entry{Slot: "a", UsrHash: hashN, Tries: bootab.Blessed}) {
		t.Fatalf("Entries = %+v, %q, %v", es, def, err)
	}

	// N+1's entry, before and after slot b carries its UUIDs.
	e := bootab.Entry{Slot: "b", UsrHash: hashN1, Tries: bootab.Tries}
	if err := l.WriteEntry("agentos_2.conf", e); err == nil {
		t.Error("WriteEntry for a slot whose UUIDs do not match its hash succeeded")
	}
	data, verity, _ := bootab.PartitionUUIDs(hashN1)
	run(t, "", "sfdisk", "-q", "--part-uuid", l.Device, "4", data)
	run(t, "", "sfdisk", "-q", "--part-uuid", l.Device, "5", verity)
	if err := l.WriteEntry("agentos_2.conf", bootab.Entry{Slot: "a", UsrHash: hashN1, Tries: 3}); err == nil {
		t.Error("WriteEntry naming the wrong slot succeeded")
	}
	for _, bad := range []string{"agentos_2+3.conf", "other.conf", "agentos_x.conf"} {
		if err := l.WriteEntry(bad, e); err == nil {
			t.Errorf("WriteEntry(%q) succeeded", bad)
		}
	}
	if err := l.WriteEntry("agentos_2.conf", e); err != nil {
		t.Fatal(err)
	}
	got := readESP(t, l, "loader/entries/agentos_2+3.conf")
	if want := entryText(2, hashN1); got != want {
		t.Errorf("entry text:\n%s\nwant:\n%s", got, want)
	}
	// The sort-key and version lines order N+1 before N (#889 comment
	// 6510350627 point 1).
	for _, ln := range []string{"sort-key agentos\n", "version 2\n", "linux /EFI/Linux/vmlinuz-6.12\n"} {
		if !strings.Contains(got, ln) {
			t.Errorf("entry lacks %q", ln)
		}
	}
	es, _, err = l.Entries()
	if err != nil || es["agentos_2.conf"] != e {
		t.Fatalf("Entries after WriteEntry = %+v, %v", es, err)
	}
	if err := l.WriteEntry("agentos_2.conf", bootab.Entry{Slot: "b", UsrHash: hashN1, Tries: 2}); err == nil {
		t.Error("WriteEntry with a second counter for one ID succeeded")
	}

	// A counted-down file keeps its ID.
	if err := os.Rename(filepath.Join(l.ESP, "loader/entries/agentos_2+3.conf"), filepath.Join(l.ESP, "loader/entries/agentos_2+1-2.conf")); err != nil {
		t.Fatal(err)
	}
	if es, _, _ := l.Entries(); es["agentos_2.conf"].Tries != 1 {
		t.Errorf("tries after count-down = %+v", es["agentos_2.conf"])
	}

	if err := l.SetDefault("agentos_1.conf"); err != nil {
		t.Fatal(err)
	}
	if _, def, _ := l.Entries(); def != "agentos_1.conf" {
		t.Errorf("default = %q", def)
	}
	if err := l.SetDefault(""); err != nil {
		t.Fatal(err)
	}
	if got := readESP(t, l, "loader/loader.conf"); got != "timeout 0\neditor no\nsecure-boot-enroll off\n" {
		t.Errorf("loader.conf after removing the default:\n%s", got)
	}
	if err := l.RemoveEntry("agentos_2.conf"); err != nil {
		t.Fatal(err)
	}
	if err := l.RemoveEntry("agentos_2.conf"); err != nil {
		t.Errorf("removing an absent entry: %v", err)
	}
	if es, _, _ := l.Entries(); len(es) != 1 {
		t.Errorf("entries after RemoveEntry: %+v", es)
	}
	if err := l.SyncESP(); err != nil {
		t.Error(err)
	}
	if ents, _ := os.ReadDir(filepath.Join(l.ESP, "loader/entries")); len(ents) != 1 {
		t.Errorf("ESP entries dir holds %d files, want 1 (no temporary file left)", len(ents))
	}
}

// TestLinuxReadsTheShippedEntry: the entry the image ships is named after
// build.sh's dotted VERSION (finish_image.py: agentos_<VERSION>+3.conf);
// the adapter reads it under one ID while its tries count down and once
// blessed, and copies its kernel into the next release's entry.
func TestLinuxReadsTheShippedEntry(t *testing.T) {
	need(t, "sfdisk")
	l := fixture(t, "", hashN)
	dir := filepath.Join(l.ESP, "loader/entries")
	shipped := strings.Replace(entryText(1, hashN), "version 1", "version 20261030.013400", 1)
	if err := os.Remove(filepath.Join(dir, "agentos_1.conf")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		file  string
		tries int
	}{{"agentos_20261030.013400+3.conf", 3}, {"agentos_20261030.013400+1-2.conf", 1}, {"agentos_20261030.013400.conf", bootab.Blessed}} {
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			os.Remove(filepath.Join(dir, e.Name()))
		}
		if err := os.WriteFile(filepath.Join(dir, c.file), []byte(shipped), 0o644); err != nil {
			t.Fatal(err)
		}
		es, _, err := l.Entries()
		if want := (bootab.Entry{Slot: "a", UsrHash: hashN, Tries: c.tries}); err != nil || len(es) != 1 || es["agentos_20261030.013400.conf"] != want {
			t.Errorf("%s: Entries = %+v, %v; want %+v", c.file, es, err, want)
		}
	}
	if err := os.WriteFile(filepath.Join(l.EFIVars, "LoaderEntrySelected-"+loaderGUID), efiVar("agentos_20261030.013400+2-1.conf"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := l.Selected(); err != nil || got != "agentos_20261030.013400.conf" {
		t.Errorf("Selected = %q, %v", got, err)
	}
	data, verity, _ := bootab.PartitionUUIDs(hashN1)
	run(t, "", "sfdisk", "-q", "--part-uuid", l.Device, "4", data)
	run(t, "", "sfdisk", "-q", "--part-uuid", l.Device, "5", verity)
	if err := l.WriteEntry(bootab.EntryID(20261031120000), bootab.Entry{Slot: "b", UsrHash: hashN1, Tries: bootab.Tries}); err != nil {
		t.Fatal(err)
	}
	if got, want := readESP(t, l, "loader/entries/agentos_20261031120000+3.conf"), strings.Replace(entryText(1, hashN1), "version 1", "version 20261031120000", 1); got != want {
		t.Errorf("entry text:\n%s\nwant:\n%s", got, want)
	}
}

// TestLinuxRefusesLongLabels: a label whose verity name ("_verity"
// appended) would pass GPT's 36 characters, or that is not plain ASCII,
// is refused before the GPT is touched, so the two labels never diverge
// by truncation (Security point 3 on #4003).
func TestLinuxRefusesLongLabels(t *testing.T) {
	need(t, "sfdisk")
	l := fixture(t, "", hashN)
	before := run(t, "", "sfdisk", "--json", l.Device)
	for _, label := range []string{strings.Repeat("x", 30), "agentos 1", "agentos_é", ""} {
		// Refused for the label itself, not by a later step.
		if err := l.SetSlotLabel("b", label); err == nil || !strings.Contains(err.Error(), "is not a GPT name") {
			t.Errorf("SetSlotLabel(%q) = %v, want a refusal of the label", label, err)
		}
	}
	if after := run(t, "", "sfdisk", "--json", l.Device); after != before {
		t.Error("a refused label changed the GPT")
	}
}

// TestLinuxRefusesUnknownEntries: an entry file the activator cannot read
// as agentOS's, two files with one ID, or an entry with no single
// usrhash= stops every read, so Install never reasons over a menu it
// cannot see.
func TestLinuxRefusesUnknownEntries(t *testing.T) {
	need(t, "sfdisk")
	for name, files := range map[string]map[string]string{
		"foreign":       {"debian.conf": entryText(1, hashN)},
		"duplicate ID":  {"agentos_1+3.conf": entryText(1, hashN)},
		"no usrhash":    {"agentos_5.conf": "title x\nlinux /k\noptions quiet\n"},
		"two usrhash":   {"agentos_5.conf": "options usrhash=" + hashN + "\noptions usrhash=" + hashN1 + "\n"},
		"short usrhash": {"agentos_5.conf": "options usrhash=abcd\n"},
	} {
		t.Run(name, func(t *testing.T) {
			l := fixture(t, "", hashN)
			for n, s := range files {
				if err := os.WriteFile(filepath.Join(l.ESP, "loader/entries", n), []byte(s), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if es, _, err := l.Entries(); err == nil {
				t.Errorf("Entries = %+v, want an error", es)
			}
		})
	}
}

// TestLinuxRefusesLinks: a symlink planted as the ESP, a directory on it,
// an entry, loader.conf or an EFI variable is never followed.
func TestLinuxRefusesLinks(t *testing.T) {
	need(t, "sfdisk")
	link := func(t *testing.T, path string) {
		t.Helper()
		real := path + ".real"
		if err := os.Rename(path, real); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, path); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name  string
		path  func(*bootab.Linux) string
		op    func(*bootab.Linux) error
		errno syscall.Errno
	}{
		{"ESP", func(l *bootab.Linux) string { return l.ESP }, func(l *bootab.Linux) error { _, _, err := l.Entries(); return err }, syscall.ENOTDIR},
		{"ESP sync", func(l *bootab.Linux) string { return l.ESP }, func(l *bootab.Linux) error { return l.SyncESP() }, syscall.ENOTDIR},
		{"entries dir", func(l *bootab.Linux) string { return filepath.Join(l.ESP, "loader/entries") }, func(l *bootab.Linux) error { return l.RemoveEntry("agentos_1.conf") }, syscall.ENOTDIR},
		{"entry", func(l *bootab.Linux) string { return filepath.Join(l.ESP, "loader/entries/agentos_1.conf") }, func(l *bootab.Linux) error { _, _, err := l.Entries(); return err }, syscall.ELOOP},
		{"loader.conf", func(l *bootab.Linux) string { return filepath.Join(l.ESP, "loader/loader.conf") }, func(l *bootab.Linux) error { return l.SetDefault("") }, syscall.ELOOP},
		{"loader dir", func(l *bootab.Linux) string { return filepath.Join(l.ESP, "loader") }, func(l *bootab.Linux) error { return l.SetDefault("x") }, syscall.ENOTDIR},
		{"EFI variable", func(l *bootab.Linux) string { return filepath.Join(l.EFIVars, "LoaderEntrySelected-"+loaderGUID) }, func(l *bootab.Linux) error { _, err := l.Selected(); return err }, syscall.ELOOP},
		{"cmdline", func(l *bootab.Linux) string { return filepath.Join(l.Proc, "cmdline") }, func(l *bootab.Linux) error { _, err := l.Cmdline(); return err }, syscall.ELOOP},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := fixture(t, "", hashN)
			link(t, c.path(l))
			// The open's own errno, not a later step's on a bad descriptor.
			if err := c.op(l); !errors.Is(err, c.errno) {
				t.Errorf("err = %v, want %v: a symlink is never followed", err, c.errno)
			}
		})
	}
	t.Run("EFI default write", func(t *testing.T) {
		l := fixture(t, "", hashN)
		target := filepath.Join(t.TempDir(), "target")
		os.WriteFile(target, []byte("keep"), 0o644)
		if err := os.Symlink(target, filepath.Join(l.EFIVars, "LoaderEntryDefault-"+loaderGUID)); err != nil {
			t.Fatal(err)
		}
		if err := l.SetEFIDefault("agentos_1.conf"); !errors.Is(err, syscall.ELOOP) {
			t.Errorf("SetEFIDefault through a symlinked variable: %v, want ELOOP", err)
		}
		if b, _ := os.ReadFile(target); string(b) != "keep" {
			t.Errorf("link target changed to %q", b)
		}
	})
}

// loopDisk is the fixture's layout on a loop device with partition nodes,
// and slot a formatted as a verity release opened as /usr would be: the
// booted slot, held by dm-verity. It needs root, losetup, veritysetup and
// udev; the image job runs it (AGENTOS_BOOTAB_LOOP=1).
func loopDisk(t *testing.T) (l *bootab.Linux, rootA, rootB string, img []byte, verityB []byte) {
	t.Helper()
	if os.Getenv("AGENTOS_BOOTAB_LOOP") != "1" {
		t.Skip("AGENTOS_BOOTAB_LOOP=1 runs the loop-device test (root; the image job)")
	}
	need(t, "sfdisk", "losetup", "veritysetup", "udevadm")
	file := filepath.Join(t.TempDir(), "disk.img")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(file, 24<<20); err != nil {
		t.Fatal(err)
	}
	run(t, gptLayout, "sfdisk", "-q", file)
	dev := run(t, "", "losetup", "--show", "-P", "-f", file)
	t.Cleanup(func() { exec.Command("losetup", "-d", dev).Run() })
	run(t, "", "udevadm", "settle")
	part := func(n int) string { return fmt.Sprintf("%sp%d", dev, n) }

	// Each slot's release: random data and its verity hash tree, built in
	// files, so the root hash is veritysetup's own.
	release := func(n int) (root string, data, hash []byte) {
		dir := t.TempDir()
		data = make([]byte, 4<<20)
		rand.Read(data)
		os.WriteFile(filepath.Join(dir, "usr.img"), data, 0o600)
		os.WriteFile(filepath.Join(dir, "usr.verity"), nil, 0o600)
		out := run(t, "", "veritysetup", "format", filepath.Join(dir, "usr.img"), filepath.Join(dir, "usr.verity"))
		m := regexp.MustCompile(`Root hash:\s+([0-9a-f]{64})`).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("veritysetup format printed no root hash:\n%s", out)
		}
		hash, _ = os.ReadFile(filepath.Join(dir, "usr.verity"))
		return m[1], data, hash
	}
	rootA, dataA, hashA := release(1)
	rootB, img, verityB = release(2)
	for n, b := range map[int][]byte{2: dataA, 3: hashA} {
		f, err := os.OpenFile(part(n), os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(b); err != nil {
			t.Fatal(err)
		}
		f.Sync()
		f.Close()
	}
	name := "bootabtest" + filepath.Base(dev)
	run(t, "", "veritysetup", "open", part(2), name, part(3), rootA)
	t.Cleanup(func() { exec.Command("veritysetup", "close", name).Run() })

	l = fixture(t, dev, rootA)
	l.Usr = "/dev/mapper/" + name
	return l, rootA, rootB, img, verityB
}

// TestLinuxSlotsOnALoopDevice: the booted slot is the one dm-verity holds;
// every slot write refuses it; a busy partition is refused even when the
// slot is not booted; the inactive slot is written, synced, verified,
// relabelled and given the UUIDs its root hash finds, after which its
// entry is on it.
func TestLinuxSlotsOnALoopDevice(t *testing.T) {
	l, rootA, rootB, img, verityB := loopDisk(t)
	if s, err := l.BootedSlot(); err != nil || s != "a" {
		t.Fatalf("BootedSlot = %q, %v", s, err)
	}

	// The booted slot is refused by every write.
	for name, op := range map[string]func() error{
		"TruncatePart": func() error { return l.TruncatePart("a", bootab.PartUsr) },
		"verity":       func() error { return l.TruncatePart("a", bootab.PartVerity) },
		"SetSlotUUIDs": func() error {
			return l.SetSlotUUIDs("a", "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002")
		},
		"SetSlotLabel": func() error { return l.SetSlotLabel("a", bootab.EmptyLabel) },
		"VerifySlot":   func() error { return l.VerifySlot("a", rootA) },
	} {
		if err := op(); err == nil {
			t.Errorf("%s on the booted slot succeeded", name)
		}
	}

	// A partition another opener holds exclusively (as dm-verity or a
	// mount does) is refused by O_EXCL, whatever BootedSlot says.
	nodeB := l.Device + "p4"
	held, err := os.OpenFile(nodeB, os.O_RDONLY|syscall.O_EXCL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.TruncatePart("b", bootab.PartUsr); err == nil {
		t.Error("TruncatePart on a partition held open exclusively succeeded")
	}
	held.Close()

	// Write slot b as Install does.
	write := func(part string, b []byte) {
		t.Helper()
		if err := l.TruncatePart("b", part); err != nil {
			t.Fatal(err)
		}
		for len(b) > 0 {
			k := min(len(b), 1<<20)
			if err := l.WritePart("b", part, b[:k]); err != nil {
				t.Fatal(err)
			}
			b = b[k:]
		}
		if err := l.SyncPart("b", part); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.SetSlotLabel("b", bootab.EmptyLabel); err != nil {
		t.Fatal(err)
	}
	write(bootab.PartUsr, img[:len(img)/2])
	write(bootab.PartVerity, verityB)
	if err := l.VerifySlot("b", rootB); err == nil {
		t.Error("VerifySlot passed on a short data write")
	}
	write(bootab.PartUsr, img)
	if err := l.VerifySlot("b", rootA); err == nil {
		t.Error("VerifySlot passed against another release's root hash")
	}
	if err := l.VerifySlot("b", rootB); err != nil {
		t.Fatalf("VerifySlot on the written slot: %v", err)
	}
	if err := l.WritePart("b", bootab.PartUsr, []byte("x")); err == nil {
		t.Error("WritePart after SyncPart succeeded")
	}
	data, verity, _ := bootab.PartitionUUIDs(rootB)
	if err := l.SetSlotUUIDs("b", data, verity); err != nil {
		t.Fatal(err)
	}
	if err := l.SetSlotLabel("b", bootab.Label(2)); err != nil {
		t.Fatal(err)
	}
	out := run(t, "", "sfdisk", "--json", l.Device)
	for _, w := range []string{`"name": "agentos_2"`, `"name": "agentos_2_verity"`, strings.ToUpper(data), strings.ToUpper(verity)} {
		if !strings.Contains(out, w) {
			t.Errorf("GPT lacks %s:\n%s", w, out)
		}
	}
	e := bootab.Entry{Slot: "b", UsrHash: rootB, Tries: bootab.Tries}
	if err := l.WriteEntry("agentos_2.conf", e); err != nil {
		t.Fatal(err)
	}
	if es, _, err := l.Entries(); err != nil || es["agentos_2.conf"] != e || es["agentos_1.conf"].Slot != "a" {
		t.Errorf("Entries = %+v, %v", es, err)
	}
	if s, err := l.BootedSlot(); err != nil || s != "a" {
		t.Errorf("BootedSlot after the GPT writes = %q, %v", s, err)
	}
}

// TestLinuxReadBounds: /proc files, EFI variables, entries and loader.conf
// are read whole up to their bound and refused one byte over it; an EFI
// variable of attributes alone, or of a NUL alone, reads as "".
func TestLinuxReadBounds(t *testing.T) {
	need(t, "sfdisk")
	l := fixture(t, "", hashN)
	id := filepath.Join(l.Proc, "sys/kernel/random/boot_id")
	if err := os.WriteFile(id, []byte(strings.Repeat("f", 64)), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := l.BootID(); err != nil || got != strings.Repeat("f", 64) {
		t.Errorf("BootID of 64 bytes = %q, %v", got, err)
	}
	if err := os.WriteFile(id, []byte(strings.Repeat("f", 65)), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := l.BootID(); err == nil {
		t.Errorf("BootID of 65 bytes = %q, want an error", got)
	}

	def := filepath.Join(l.EFIVars, "LoaderEntryDefault-"+loaderGUID)
	for _, b := range [][]byte{{7, 0, 0, 0}, efiVar("")} {
		if err := os.WriteFile(def, b, 0o644); err != nil {
			t.Fatal(err)
		}
		if v, err := l.EFIDefault(); err != nil || v != "" {
			t.Errorf("EFIDefault of %x = %q, %v; want \"\"", b, v, err)
		}
	}

	// loader.conf of exactly the bound, its last line unterminated, is
	// kept whole when a default is added.
	const maxESPFile = 64 << 10
	conf := filepath.Join(l.ESP, "loader/loader.conf")
	body := "timeout 0\n# " + strings.Repeat("x", maxESPFile-len("timeout 0\n# ")-1) + "y"
	if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := l.SetDefault("agentos_1.conf"); err != nil {
		t.Fatalf("SetDefault over a loader.conf of %d bytes: %v", len(body), err)
	}
	if got := readESP(t, l, "loader/loader.conf"); got != body+"\ndefault agentos_1.conf\n" {
		t.Errorf("loader.conf lost bytes: %d bytes, ends %q", len(got), got[max(0, len(got)-30):])
	}
	if err := os.WriteFile(conf, []byte(body+"z"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := l.SetDefault("agentos_1.conf"); err == nil {
		t.Error("SetDefault over a loader.conf one byte over the bound succeeded")
	}
}

// TestLinuxSetDefaultEdits: loader.conf keeps every line but its default
// lines (a blank-looking line too), a stale temporary file does not stop
// the write, and with no loader.conf a default creates it while removing
// one leaves it absent.
func TestLinuxSetDefaultEdits(t *testing.T) {
	need(t, "sfdisk")
	l := fixture(t, "", hashN)
	conf := filepath.Join(l.ESP, "loader/loader.conf")
	if err := os.WriteFile(conf, []byte("timeout 0\n   \ndefault old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(l.ESP, "loader/.loader.conf.tmp"), []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := l.SetDefault("new"); err != nil {
		t.Fatal(err)
	}
	if got := readESP(t, l, "loader/loader.conf"); got != "timeout 0\n   \ndefault new\n" {
		t.Errorf("loader.conf = %q", got)
	}
	if err := os.Remove(conf); err != nil {
		t.Fatal(err)
	}
	if err := l.SetDefault(""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(conf); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("removing the default created loader.conf: %v", err)
	}
	if err := l.SetDefault("new"); err != nil {
		t.Fatal(err)
	}
	if got := readESP(t, l, "loader/loader.conf"); got != "default new\n" {
		t.Errorf("loader.conf created as %q", got)
	}
}

// TestLinuxEntryTries: WriteEntry takes tries 0 to 9 and Blessed, and
// refuses any other count.
func TestLinuxEntryTries(t *testing.T) {
	need(t, "sfdisk")
	l := fixture(t, "", hashN)
	data, verity, _ := bootab.PartitionUUIDs(hashN1)
	run(t, "", "sfdisk", "-q", "--part-uuid", l.Device, "4", data)
	run(t, "", "sfdisk", "-q", "--part-uuid", l.Device, "5", verity)
	for tries, file := range map[int]string{0: "agentos_2+0.conf", 9: "agentos_2+9.conf", bootab.Blessed: "agentos_2.conf"} {
		if err := l.WriteEntry("agentos_2.conf", bootab.Entry{Slot: "b", UsrHash: hashN1, Tries: tries}); err != nil {
			t.Errorf("WriteEntry with tries %d: %v", tries, err)
		}
		if err := os.Remove(filepath.Join(l.ESP, "loader/entries", file)); err != nil {
			t.Errorf("tries %d: %v", tries, err)
		}
	}
	for _, tries := range []int{-2, 10} {
		if err := l.WriteEntry("agentos_2.conf", bootab.Entry{Slot: "b", UsrHash: hashN1, Tries: tries}); err == nil {
			t.Errorf("WriteEntry with tries %d succeeded", tries)
		}
	}
}

// TestLinuxSlotsByPartitionNumber: slots pair partitions by number, not
// by the order sfdisk lists them in, for any node name that ends in the
// number (sda9, nvme0n1p10, or the number alone).
func TestLinuxSlotsByPartitionNumber(t *testing.T) {
	need(t, "sfdisk")
	l := fixture(t, "", hashN)
	data, verity, _ := bootab.PartitionUUIDs(hashN)
	other, otherVerity, _ := bootab.PartitionUUIDs(hashN1)
	part := func(node, typ, uuid string) string {
		return fmt.Sprintf(`{"node": %q, "type": %q, "uuid": %q}`, node, typ, uuid)
	}
	const usr, usrVerity = "8484680C-9521-48C6-9C11-B0720656F69E", "77FF5F63-E7B6-4633-ACF4-1565B864C0E6"
	table := `{"partitiontable": {"label": "gpt", "partitions": [` + strings.Join([]string{
		part("/dev/nvme0n1p10", usr, other), part("20", usrVerity, otherVerity),
		part("/dev/sda9", usr, data), part("19", usrVerity, verity),
	}, ",") + `]}}`
	l.Run = func(name string, arg ...string) ([]byte, error) {
		if name != "/usr/sbin/sfdisk" || strings.Join(arg, " ") != "--json "+l.Device {
			return nil, fmt.Errorf("unexpected %s %v", name, arg)
		}
		return []byte(table), nil
	}
	es, _, err := l.Entries()
	if err != nil || es["agentos_1.conf"].Slot != "a" {
		t.Errorf("Entries = %+v, %v; want agentos_1.conf on slot a (partitions 9 and 19)", es, err)
	}
}
