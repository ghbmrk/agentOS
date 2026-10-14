package main

// REQ: HW-10, HW-1, A1

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/firstboot"
)

// needTools skips where e2fsprogs is missing, except in CI, which must
// run these tests.
func needTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"mkfs.ext4", "debugfs", "e2fsck"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("CI") != "" {
				t.Fatalf("%s is missing in CI", tool)
			}
			t.Skipf("%s not installed", tool)
		}
	}
}

const sector = 512

// guidOnDisk is a GUID in GPT's mixed-endian form.
func guidOnDisk(s string) []byte {
	h, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(h) != 16 {
		panic(s)
	}
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:], binary.BigEndian.Uint32(h[0:]))
	binary.LittleEndian.PutUint16(b[4:], binary.BigEndian.Uint16(h[4:]))
	binary.LittleEndian.PutUint16(b[6:], binary.BigEndian.Uint16(h[6:]))
	copy(b[8:], h[8:])
	return b
}

const (
	typeESP  = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
	typeUsr  = "8484680c-9521-48c6-9c11-b0720656f69e"
	typeRoot = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"
)

type part struct {
	typ  string
	body []byte // the partition's content; its length is its size
}

// gptDisk lays parts out from LBA 2048 with a protective MBR and both GPT
// copies, as systemd-repart does.
func gptDisk(parts []part) []byte {
	const entries, entrySize = 128, 128
	tableSectors := int64(entries * entrySize / sector)
	lba := int64(2048)
	type span struct{ first, last int64 }
	var spans []span
	for _, p := range parts {
		n := (int64(len(p.body)) + sector - 1) / sector
		spans = append(spans, span{lba, lba + n - 1})
		lba += n
	}
	total := lba + tableSectors + 1
	disk := make([]byte, total*sector)
	for i, p := range parts {
		copy(disk[spans[i].first*sector:], p.body)
	}
	table := make([]byte, entries*entrySize)
	for i, p := range parts {
		e := table[i*entrySize:]
		copy(e[0:], guidOnDisk(p.typ))
		copy(e[16:], guidOnDisk(fmt.Sprintf("ca7a%04x-2222-4333-8444-555566667777", i)))
		binary.LittleEndian.PutUint64(e[32:], uint64(spans[i].first))
		binary.LittleEndian.PutUint64(e[40:], uint64(spans[i].last))
	}
	mbr := disk[:sector]
	mbr[446+4] = 0xEE
	binary.LittleEndian.PutUint32(mbr[446+8:], 1)
	binary.LittleEndian.PutUint32(mbr[446+12:], uint32(total-1))
	mbr[510], mbr[511] = 0x55, 0xAA
	header := func(self, alt, tableLBA int64) []byte {
		h := make([]byte, sector)
		copy(h, "EFI PART")
		binary.LittleEndian.PutUint32(h[8:], 0x00010000)
		binary.LittleEndian.PutUint32(h[12:], 92)
		binary.LittleEndian.PutUint64(h[24:], uint64(self))
		binary.LittleEndian.PutUint64(h[32:], uint64(alt))
		binary.LittleEndian.PutUint64(h[40:], 2+uint64(tableSectors))
		binary.LittleEndian.PutUint64(h[48:], uint64(total-tableSectors-2))
		copy(h[56:], guidOnDisk("ca7a9999-2222-4333-8444-555566667777"))
		binary.LittleEndian.PutUint64(h[72:], uint64(tableLBA))
		binary.LittleEndian.PutUint32(h[80:], entries)
		binary.LittleEndian.PutUint32(h[84:], entrySize)
		binary.LittleEndian.PutUint32(h[88:], crc32.ChecksumIEEE(table))
		binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h[:92]))
		return h
	}
	copy(disk[1*sector:], header(1, total-1, 2))
	copy(disk[2*sector:], table)
	copy(disk[(total-1-tableSectors)*sector:], table)
	copy(disk[(total-1)*sector:], header(total-1, 1, total-1-tableSectors))
	return disk
}

// ext4 makes a small ext4 file system holding tree.
func ext4(t *testing.T, tree map[string]string) []byte {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	for p, body := range tree {
		full := filepath.Join(root, p)
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	img := filepath.Join(dir, "fs.img")
	if out, err := exec.Command("mkfs.ext4", "-q", "-F", "-d", root, img, "16M").CombinedOutput(); err != nil {
		t.Fatalf("mkfs.ext4: %v: %s", err, out)
	}
	b, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rootTree is an image's root file system: /usr is excluded and
// /var/lib/agentos is not shipped (image/mkosi/mkosi.repart/30-root.conf,
// mkosi.finalize).
var rootTree = map[string]string{
	"etc/hostname": "agentos\n",
	"var/lib/":     "",
	"efi/":         "",
	"boot/":        "",
}

// writeImage writes disk as agentos_1.raw beside a SHA256SUMS for it.
func writeImage(t *testing.T, disk []byte) (img, sums string) {
	t.Helper()
	dir := t.TempDir()
	img = filepath.Join(dir, "agentos_1.raw")
	if err := os.WriteFile(img, disk, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(disk)
	sums = filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sums, []byte(fmt.Sprintf("%x  other.raw\n%x  agentos_1.raw\n", sha256.Sum256(nil), sum)), 0o644); err != nil {
		t.Fatal(err)
	}
	return img, sums
}

func standardDisk(t *testing.T, tree map[string]string) []byte {
	return gptDisk([]part{
		{typeESP, make([]byte, 1<<20)},
		{typeUsr, make([]byte, 1<<20)},
		{typeRoot, ext4(t, tree)},
	})
}

func runPrep(img, sums, out string) error {
	return prep(prepConfig{Image: img, Sums: sums, Out: out, Log: &bytes.Buffer{}})
}

// entries lists every path in the root file system with its mode and
// owner, through debugfs.
func entries(t *testing.T, img string, off int64) map[string]string {
	t.Helper()
	out := map[string]string{}
	var walk func(dir string)
	walk = func(dir string) {
		b, err := exec.Command("debugfs", "-R", "ls -p "+dir, fmt.Sprintf("%s?offset=%d", img, off)).Output()
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Split(line, "/")
			if len(f) < 7 || f[5] == "." || f[5] == ".." {
				continue
			}
			p := strings.TrimSuffix(dir, "/") + "/" + f[5]
			out[p] = f[2] + " " + f[3] + ":" + f[4]
			if strings.HasPrefix(f[2], "04") {
				walk(p)
			}
		}
	}
	walk("/")
	return out
}

func dump(t *testing.T, img string, off int64, path string) []byte {
	t.Helper()
	b, err := exec.Command("debugfs", "-R", "cat "+path, fmt.Sprintf("%s?offset=%d", img, off)).Output()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var codeLineRe = regexp.MustCompile(`(?m)^AgentOS claim code: ([A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4})$`)

// Acceptance 1: an image that fails a check gets no box image and no
// sticker.
func TestPrepRefuses(t *testing.T) {
	needTools(t)
	good := standardDisk(t, rootTree)
	held := map[string]string{"var/lib/agentos/claim.json": `{"salt":"AAAA"}`}
	heldNet := map[string]string{"var/lib/agentos/setup-net.json": `{}`}
	for k, v := range rootTree {
		held[k] = v
		heldNet[k] = v
	}
	cases := map[string]func() (string, string){
		"checksum mismatch": func() (string, string) {
			img, sums := writeImage(t, good)
			if err := os.WriteFile(img, append(good[:len(good):len(good)], 0), 0o644); err != nil {
				t.Fatal(err)
			}
			return img, sums
		},
		"no checksum line": func() (string, string) {
			img, sums := writeImage(t, good)
			if err := os.WriteFile(sums, []byte("00  agentos_2.raw\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return img, sums
		},
		"no partition table": func() (string, string) {
			return writeImage(t, make([]byte, 4<<20))
		},
		"no ext4 root": func() (string, string) {
			return writeImage(t, gptDisk([]part{{typeESP, make([]byte, 1<<20)}, {typeRoot, make([]byte, 1<<20)}}))
		},
		"two ext4 volumes": func() (string, string) {
			fs := ext4(t, rootTree)
			return writeImage(t, gptDisk([]part{{typeUsr, fs}, {typeRoot, fs}}))
		},
		"root not last": func() (string, string) {
			return writeImage(t, gptDisk([]part{{typeRoot, ext4(t, rootTree)}, {typeUsr, make([]byte, 1<<20)}}))
		},
		"already holds a claim state": func() (string, string) {
			return writeImage(t, standardDisk(t, held))
		},
		"already holds a setup network": func() (string, string) {
			return writeImage(t, standardDisk(t, heldNet))
		},
		"no /var/lib": func() (string, string) {
			return writeImage(t, standardDisk(t, map[string]string{"etc/hostname": "x\n"}))
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			img, sums := mk()
			out := filepath.Join(t.TempDir(), "box1")
			if err := runPrep(img, sums, out); err == nil {
				t.Fatal("prep accepted it")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatalf("prep left %s behind: %v", out, err)
			}
		})
	}
	t.Run("out exists", func(t *testing.T) {
		img, sums := writeImage(t, good)
		out := t.TempDir()
		if err := runPrep(img, sums, out); err == nil {
			t.Fatal("prep wrote into an existing directory")
		}
	})
}

// Acceptance 2 and 3: one new file, root-owned 0600, that opens unclaimed
// and that the sticker's code claims; no plaintext code outside the
// sticker files.
func TestPrepSealsOneState(t *testing.T) {
	needTools(t)
	disk := standardDisk(t, rootTree)
	img, sums := writeImage(t, disk)
	out := filepath.Join(t.TempDir(), "box1")
	if err := runPrep(img, sums, out); err != nil {
		t.Fatal(err)
	}
	box := filepath.Join(out, "box.raw")
	off, err := rootOffset(box)
	if err != nil {
		t.Fatal(err)
	}
	before, after := entries(t, img, off), entries(t, box, off)
	var added []string
	for p, v := range after {
		if w, ok := before[p]; !ok {
			added = append(added, p+" "+v)
		} else if w != v {
			t.Errorf("%s changed: %s -> %s", p, w, v)
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			t.Errorf("%s removed", p)
		}
	}
	want := map[string]bool{
		"/var/lib/agentos 040700 0:0":      true,
		claim.StatePath + " 100600 0:0":    true,
		claim.SetupNetPath + " 100600 0:0": true,
	}
	if len(added) != len(want) {
		t.Fatalf("added %v, want %v", added, want)
	}
	for _, a := range added {
		if !want[a] {
			t.Fatalf("added %v, want %v", added, want)
		}
	}
	if out, err := exec.Command("e2fsck", "-fn", fmt.Sprintf("%s?offset=%d", box, off)).CombinedOutput(); err != nil {
		t.Fatalf("e2fsck: %v: %s", err, out)
	}

	txt, err := os.ReadFile(filepath.Join(out, "sticker.txt"))
	if err != nil {
		t.Fatal(err)
	}
	m := codeLineRe.FindStringSubmatch(string(txt))
	if m == nil {
		t.Fatalf("no code in sticker.txt: %q", txt)
	}
	code := m[1]

	st := &change.MemStore{}
	if err := st.Save(dump(t, box, off, claim.StatePath)); err != nil {
		t.Fatal(err)
	}
	cl, err := claim.Open(claim.Config{Store: st, BootID: func() (string, error) { return "boot-1", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if s := cl.Status(); s.Claimed || s.Locked {
		t.Fatalf("status %+v, want unclaimed", s)
	}
	if _, err := cl.Try(code); err != nil {
		t.Fatalf("the sticker's code does not claim the box: %v", err)
	}

	// No plaintext code on the box image (HW-1: the image holds no secret
	// beyond the salted verifier).
	raw, err := os.ReadFile(box)
	if err != nil {
		t.Fatal(err)
	}
	for _, form := range []string{code, claim.Normalize(code), claim.Normalize(code)[:claim.PrefixSymbols]} {
		if bytes.Contains(raw, []byte(form)) {
			t.Fatalf("box image holds the code as %q", form)
		}
	}
	// The code is only in the sticker files, which only their owner reads.
	ents, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range ents {
		names[e.Name()] = true
		fi, err := os.Stat(filepath.Join(out, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(out, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		holds := bytes.Contains(b, []byte(code))
		if holds != strings.HasPrefix(e.Name(), "sticker.") {
			t.Errorf("%s holds the code: %v", e.Name(), holds)
		}
		if holds && fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, want 0600", e.Name(), fi.Mode().Perm())
		}
	}
	for _, n := range []string{"box.raw", "SHA256SUMS", "sticker.txt", "sticker.html"} {
		if !names[n] {
			t.Errorf("no %s in %v", n, names)
		}
	}
	if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("out dir mode: %v %v", fi.Mode(), err)
	}
	// The box image's SHA256SUMS is what write checks against.
	if err := checkSum(box, filepath.Join(out, "SHA256SUMS")); err != nil {
		t.Fatal(err)
	}

	// Acceptance 3: the QR is the claim page with the code, drawn by the
	// card's encoder the setup page uses.
	html, err := os.ReadFile(filepath.Join(out, "sticker.html"))
	if err != nil {
		t.Fatal(err)
	}
	qr, err := card.QRSVG("http://" + card.BoxAddr + "/claim?code=" + code)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(html, []byte(qr)) {
		t.Fatal("sticker.html lacks the claim QR")
	}

	// The setup network the phone joins before the card exists (CH-7, §8.1
	// step 4): sealed beside the claim state, root-owned 0600, and printed
	// on the sticker as its name, password and Wi-Fi QR.
	net, err := claim.ParseSetupNet(dump(t, box, off, claim.SetupNetPath))
	if err != nil {
		t.Fatal(err)
	}
	if net.Password == code || claim.Normalize(net.Password)[:claim.PrefixSymbols] == claim.Normalize(code)[:claim.PrefixSymbols] {
		t.Fatal("the setup password is the claim code")
	}
	wq, err := card.QRSVG(card.WiFiQR(net.SSID, net.Password))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range [][]byte{[]byte(wq), []byte(net.SSID), []byte(net.Password)} {
		if !bytes.Contains(html, want) {
			t.Fatalf("sticker.html lacks %.60q", want)
		}
	}
	for _, want := range []string{"Wi-Fi network: " + net.SSID + "\n", "Wi-Fi password: " + net.Password + "\n"} {
		if !strings.Contains(string(txt), want) {
			t.Fatalf("sticker.txt lacks %q: %q", want, txt)
		}
	}
	// The password is on the box only in the setup file (SAE needs it in
	// the clear), never in the claim state.
	if bytes.Contains(dump(t, box, off, claim.StatePath), []byte(claim.Normalize(net.Password))) {
		t.Fatal("the claim state holds the setup password")
	}

	// A second prep of the prepared image is refused: it holds a state.
	if err := runPrep(box, filepath.Join(out, "SHA256SUMS"), filepath.Join(t.TempDir(), "again")); err == nil {
		t.Fatal("prep resealed a prepared image")
	}
}

// Acceptance 4: write copies the image and read-verifies it, and refuses a
// mounted or too small target or a mismatched image.
func TestWrite(t *testing.T) {
	requireBlock = false
	t.Cleanup(func() { requireBlock = true })
	dir := t.TempDir()
	img := filepath.Join(dir, "box.raw")
	body := bytes.Repeat([]byte("synthetic image 0123456789\n"), 200000)
	if err := os.WriteFile(img, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sums := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sums, []byte(fmt.Sprintf("%x  box.raw\n", sha256.Sum256(body))), 0o600); err != nil {
		t.Fatal(err)
	}
	mounts := filepath.Join(dir, "mounts")
	if err := os.WriteFile(mounts, []byte("proc /proc proc rw 0 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mountsPath, swapsPath = mounts, filepath.Join(dir, "no-swaps")
	t.Cleanup(func() { mountsPath, swapsPath = "/proc/self/mounts", "/proc/swaps" })
	target := func(size int) string {
		p := filepath.Join(t.TempDir(), "disk")
		if err := os.WriteFile(p, bytes.Repeat([]byte{0xA5}, size), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	log := &bytes.Buffer{}

	dev := target(len(body) + 4096)
	if err := write(img, sums, dev, log); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dev)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:len(body)], body) {
		t.Fatal("target differs from the image")
	}

	small := target(len(body) - 1)
	if err := write(img, sums, small, log); err == nil {
		t.Fatal("wrote to a target smaller than the image")
	}
	if b, _ := os.ReadFile(small); b[0] != 0xA5 {
		t.Fatal("a refused target was written")
	}

	mounted := target(len(body))
	if err := os.WriteFile(mounts, []byte(mounted+"2 /mnt ext4 rw 0 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := write(img, sums, mounted, log); err == nil {
		t.Fatal("wrote to a target with a mounted partition")
	}
	if err := os.WriteFile(mounts, []byte("proc /proc proc rw 0 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A different disk whose name starts with the target's is not it (sda
	// and sdaa).
	if err := os.WriteFile(mounts, []byte(mounted+"a /mnt ext4 rw 0 0\n"+mounted+"p1 /x ext4 rw 0 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := write(img, sums, mounted, log); err != nil {
		t.Fatalf("refused for another disk's mount: %v", err)
	}

	bad := filepath.Join(dir, "BADSUMS")
	if err := os.WriteFile(bad, []byte(fmt.Sprintf("%x  box.raw\n", sha256.Sum256(nil))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := write(img, bad, target(len(body)), log); err == nil {
		t.Fatal("wrote an image that does not match its checksum")
	}

	// The read-back catches a target that does not hold what was written.
	flipped := target(len(body))
	if err := os.WriteFile(flipped, body, 0o600); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(body)
	if err := verify(flipped, int64(len(body)), want[:]); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(flipped, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{'X'}, int64(len(body)/2)); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := verify(flipped, int64(len(body)), want[:]); err == nil {
		t.Fatal("verify passed a target that differs")
	}
}

func TestIsPartition(t *testing.T) {
	for _, c := range []struct {
		dev, p string
		want   bool
	}{
		{"/dev/sda", "/dev/sda1", true},
		{"/dev/sda", "/dev/sda12", true},
		{"/dev/sda", "/dev/sdaa", false},
		{"/dev/sda", "/dev/sdaa1", false},
		{"/dev/sda", "/dev/sda", false},
		{"/dev/nvme0n1", "/dev/nvme0n1p2", true},
		{"/dev/nvme0n1", "/dev/nvme0n10", false},
		{"/dev/nvme0n1", "/dev/nvme0n1", false},
		{"/dev/mmcblk0", "/dev/mmcblk0p1", true},
	} {
		if got := isPartition(c.dev, c.p); got != c.want {
			t.Errorf("isPartition(%s, %s) = %v", c.dev, c.p, got)
		}
	}
	if got := unescape(`/mnt/a\040b`); got != "/mnt/a b" {
		t.Errorf("unescape: %q", got)
	}
}

func TestRequireBlockRefusesAFile(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "box.raw")
	if err := os.WriteFile(img, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sums := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sums, []byte(fmt.Sprintf("%x  box.raw\n", sha256.Sum256([]byte("x")))), 0o600); err != nil {
		t.Fatal(err)
	}
	dev := filepath.Join(dir, "disk")
	if err := os.WriteFile(dev, make([]byte, 16), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := write(img, sums, dev, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "block device") {
		t.Fatalf("wrote to a regular file: %v", err)
	}
}

func TestUsage(t *testing.T) {
	var stderr bytes.Buffer
	if run(nil, &bytes.Buffer{}, &stderr) != 2 || !strings.Contains(stderr.String(), "prep") {
		t.Fatalf("usage: %q", stderr.String())
	}
	if run([]string{"prep"}, &bytes.Buffer{}, &stderr) != 2 {
		t.Fatal("prep without flags ran")
	}
}

// #1270 (HW-10): the files the seller seals route the box to the claim on
// the shipped image, which is not the download's (BoxConfig.Download
// unset): the claim screen first and the sticker's setup network, never
// the download path's pairing.
func TestASealedBoxRoutesToTheClaim(t *testing.T) {
	needTools(t)
	img, sums := writeImage(t, standardDisk(t, rootTree))
	out := filepath.Join(t.TempDir(), "box1")
	if err := runPrep(img, sums, out); err != nil {
		t.Fatal(err)
	}
	box := filepath.Join(out, "box.raw")
	off, err := rootOffset(box)
	if err != nil {
		t.Fatal(err)
	}
	var state, setup, latch change.MemStore
	if err := state.Save(dump(t, box, off, claim.StatePath)); err != nil {
		t.Fatal(err)
	}
	if err := setup.Save(dump(t, box, off, claim.SetupNetPath)); err != nil {
		t.Fatal(err)
	}
	fb, err := firstboot.Begin(firstboot.BoxConfig{
		Claim:    claim.Config{Store: &state, BootID: func() (string, error) { return "boot-1", nil }},
		Latch:    &latch,
		SetupNet: &setup,
		Reset:    func() error { return nil },
		Card:     card.DisplayConfig{Provision: func(*card.Card) error { return nil }},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fb.Route != firstboot.RouteClaim || fb.Claim == nil || fb.Claim.Status().Claimed {
		t.Fatalf("route %q, claim %+v", fb.Route, fb.Claim)
	}
	if n, err := fb.Network(); err != nil || n == nil {
		t.Fatalf("setup network %v, %v", n, err)
	}
}

// The sticker's two codes share one format and one style, so each carries
// its own label right above it: "Wi-Fi password" over the setup network's
// password and "Claim code" over the claim code. An owner who types the
// password into /claim spends one of the claim's shared tries (K9).
// REQ: HW-10, CH-12, A1
func TestStickerLabelsItsCodes(t *testing.T) {
	out := t.TempDir()
	net := claim.SetupNet{SSID: "agentos-setup-test", Password: "PWPW-PWPW-PWPW-PWPW"}
	code := "CCCC-CCCC-CCCC-CCCC"
	if err := writeSticker(out, code, net); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(out, "sticker.html"))
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	// Each code's nearest label above it is its own.
	labelOver := func(value string) string {
		i := strings.Index(html, value)
		if i < 0 {
			t.Fatalf("sticker.html lacks %q", value)
		}
		re := regexp.MustCompile(`<div class="label">([^<]*)</div>`)
		last := ""
		for _, m := range re.FindAllStringSubmatchIndex(html[:i], -1) {
			last = html[m[2]:m[3]]
		}
		return last
	}
	if got := labelOver(">" + net.Password + "<"); got != "Wi-Fi password" {
		t.Fatalf("label above the Wi-Fi password = %q, want %q", got, "Wi-Fi password")
	}
	if got := labelOver(">" + code + "<"); got != "Claim code" {
		t.Fatalf("label above the claim code = %q, want %q", got, "Claim code")
	}
}
