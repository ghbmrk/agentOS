package main

// REQ: HW-10, HW-1, A1, CH-7, CH-12

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/claim"
)

// ext4Sif is ext4(t, tree) with each "sif" debugfs command applied, so a
// test sets an owner or mode mkfs.ext4 -d copies from the test's user.
func ext4Sif(t *testing.T, tree map[string]string, cmds ...string) []byte {
	t.Helper()
	img := filepath.Join(t.TempDir(), "fs.img")
	if err := os.WriteFile(img, ext4(t, tree), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("debugfs", "-w", "-f", "-", img)
	cmd.Stdin = strings.NewReader(strings.Join(cmds, "\n") + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("debugfs: %v: %s", err, out)
	}
	b, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// #1162: an image that already has /var/lib/agentos is refused unless it
// is root:root 0700, so the seller's image does not rely on the box's
// tmpfiles line to fix it at boot; a root:root 0700 one is sealed into.
func TestPrepChecksAnExistingSealDir(t *testing.T) {
	needTools(t)
	dir := sealDirs[0]
	tree := map[string]string{dir[1:] + "/": ""}
	for k, v := range rootTree {
		tree[k] = v
	}
	owned := func(mode, uid, gid string) []byte {
		return gptDisk([]part{
			{typeESP, make([]byte, 1<<20)},
			{typeUsr, make([]byte, 1<<20)},
			{typeRoot, ext4Sif(t, tree, "sif "+dir+" mode "+mode, "sif "+dir+" uid "+uid, "sif "+dir+" gid "+gid)},
		})
	}
	for name, disk := range map[string][]byte{
		"mode 0755":      owned("040755", "0", "0"),
		"mode 0770":      owned("040770", "0", "0"),
		"owner not root": owned("040700", "1000", "0"),
		"group not root": owned("040700", "0", "1000"),
	} {
		t.Run(name, func(t *testing.T) {
			img, sums := writeImage(t, disk)
			out := filepath.Join(t.TempDir(), "box1")
			err := runPrep(img, sums, out)
			if err == nil || !strings.Contains(err.Error(), sealDirMode) {
				t.Fatalf("prep = %v, want a refusal naming %s", err, sealDirMode)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatalf("prep left %s behind: %v", out, err)
			}
		})
	}
	t.Run("root:root 0700", func(t *testing.T) {
		img, sums := writeImage(t, owned("040700", "0", "0"))
		out := filepath.Join(t.TempDir(), "box1")
		if err := runPrep(img, sums, out); err != nil {
			t.Fatal(err)
		}
		box := filepath.Join(out, "box.raw")
		off, err := rootOffset(box)
		if err != nil {
			t.Fatal(err)
		}
		got := entries(t, box, off)
		if got[dir] != sealDirMode || got[claim.StatePath] != "100600 0:0" {
			t.Fatalf("%s = %q, %s = %q", dir, got[dir], claim.StatePath, got[claim.StatePath])
		}
	})
}

// #1164: write refuses a mismatched image through checkSum, the one
// SHA256SUMS check prep also uses, before touching the target.
func TestWriteChecksThroughCheckSum(t *testing.T) {
	img, sums := writeImage(t, []byte("image"))
	if err := os.WriteFile(img, []byte("other"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, want := checkSum(img, sums)
	if want == nil {
		t.Fatal("checkSum accepted a mismatched image")
	}
	dev := filepath.Join(t.TempDir(), "missing-dev")
	if err := write(img, sums, dev, &strings.Builder{}); err == nil || err.Error() != want.Error() {
		t.Fatalf("write = %v, want %v", err, want)
	}
}

// #1364: the sticker is the first printed guide on the preloaded path,
// and the setup network is WPA3-SAE only (CH-9), so step 1 carries the
// Owner Card's minimum-phone line before step 2.
func TestStickerCarriesTheWPA3Line(t *testing.T) {
	out := t.TempDir()
	net := claim.SetupNet{SSID: "agentos-setup-test", Password: "PWPW-PWPW-PWPW-PWPW"}
	if err := writeSticker(out, "CCCC-CCCC-CCCC-CCCC", net); err != nil {
		t.Fatal(err)
	}
	const line = "Phone won't join: it needs WPA3."
	for _, f := range []struct{ name, step1, step2 string }{
		{"sticker.html", "1. Join the enforcer's setup Wi-Fi", "2. Back on the Owner network"},
		{"sticker.txt", "1. Join the enforcer's setup Wi-Fi", "2. Back on the Owner network"},
	} {
		b, err := os.ReadFile(filepath.Join(out, f.name))
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		i, j, k := strings.Index(s, f.step1), strings.Index(s, line), strings.Index(s, f.step2)
		if i < 0 || j < 0 || k < 0 || !(i < j && j < k) {
			t.Fatalf("%s: want %q inside step 1 (at %d, %d, %d):\n%s", f.name, line, i, j, k, s)
		}
	}
}
