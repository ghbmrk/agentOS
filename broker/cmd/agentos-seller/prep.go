package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/hostdisk"
)

type prepConfig struct {
	Image, Sums, Out string
	Log              io.Writer // progress; never the code
	Rand             io.Reader // crypto/rand.Reader when nil
}

// stateTemp is the sealed state's name in Out while debugfs copies it in.
// It holds the salted verifier only, never the code.
const stateTemp = ".claim-state"

// prep seals a new claim code into a copy of the image and writes the
// sticker. On any failure it removes Out, so no box image or sticker is
// left behind (HW-10).
func prep(c prepConfig) (err error) {
	logf := func(format string, a ...any) {
		if c.Log != nil {
			fmt.Fprintf(c.Log, format+"\n", a...)
		}
	}
	if strings.Contains(c.Image, "?") || strings.Contains(c.Out, "?") {
		return errors.New("paths with '?' are not supported (debugfs reads it as an option)")
	}
	want, err := sumFor(c.Image, c.Sums)
	if err != nil {
		return err
	}
	if got, err := fileSum(c.Image); err != nil {
		return err
	} else if !bytes.Equal(got, want) {
		return fmt.Errorf("%s does not match its line in %s", c.Image, c.Sums)
	}
	logf("image matches %s", c.Sums)
	off, err := rootOffset(c.Image)
	if err != nil {
		return err
	}
	dirExists, err := preflight(c.Image, off)
	if err != nil {
		return err
	}

	if err := os.Mkdir(c.Out, 0o700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(c.Out)
		}
	}()
	// Mkdir's mode is masked by the umask; the sticker's directory is the
	// owner's only.
	if err := os.Chmod(c.Out, 0o700); err != nil {
		return err
	}
	box := filepath.Join(c.Out, "box.raw")
	if err := copyFile(c.Image, box); err != nil {
		return err
	}
	if got, err := fileSum(box); err != nil {
		return err
	} else if !bytes.Equal(got, want) {
		return errors.New("the copy differs from the image")
	}

	code, err := claim.NewCode(c.Rand)
	if err != nil {
		return err
	}
	st := &change.MemStore{}
	if err := claim.Seal(st, code, c.Rand, nil); err != nil {
		return err
	}
	state, err := st.Load()
	if err != nil {
		return err
	}
	if err := sealInto(box, off, c.Out, state, dirExists); err != nil {
		return err
	}
	if err := checkSealed(box, off, state, code, dirExists); err != nil {
		return err
	}
	logf("sealed a claim state into %s at %s", box, claim.StatePath)

	sum, err := fileSum(box)
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(c.Out, "SHA256SUMS"), []byte(fmt.Sprintf("%x  box.raw\n", sum))); err != nil {
		return err
	}
	if err := writeSticker(c.Out, code); err != nil {
		return err
	}
	logf("wrote %s: print sticker.html at 100%%, then delete the directory", c.Out)
	return nil
}

// rootOffset is the byte offset of the image's root file system: the one
// ext4 volume, which is the last partition (image/mkosi/mkosi.repart/
// 30-root.conf). Anything else is not an image this tool knows.
func rootOffset(image string) (int64, error) {
	f, err := os.Open(image)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	d, err := hostdisk.Probe(f, fi.Size(), 512)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", image, err)
	}
	if d.Table != hostdisk.TableGPT {
		return 0, fmt.Errorf("%s has no GPT", image)
	}
	var root *hostdisk.Partition
	var last int64 = -1
	for i, p := range d.Partitions {
		if p.Signature == hostdisk.SigExt {
			if root != nil {
				return 0, fmt.Errorf("%s has more than one ext4 volume", image)
			}
			root = &d.Partitions[i]
		}
		if p.Start > last {
			last = p.Start
		}
	}
	if root == nil {
		return 0, fmt.Errorf("%s has no ext4 root volume", image)
	}
	if root.Start != last {
		return 0, fmt.Errorf("%s: the ext4 volume is not the last partition", image)
	}
	return root.Start, nil
}

// entry is one directory entry as debugfs's "ls -p" prints it.
type entry struct{ mode, uid, gid string }

func (e entry) String() string { return e.mode + " " + e.uid + ":" + e.gid }

func (e entry) dir() bool { return strings.HasPrefix(e.mode, "04") }

func fsSpec(image string, off int64) string { return fmt.Sprintf("%s?offset=%d", image, off) }

// lookup finds p in the file system through its parent's listing. debugfs
// exits 0 for a missing path, so a missing entry is an empty listing.
func lookup(image string, off int64, p string) (entry, bool, error) {
	out, err := exec.Command("debugfs", "-R", "ls -p "+path.Dir(p), fsSpec(image, off)).Output()
	if err != nil {
		return entry{}, false, fmt.Errorf("debugfs: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, "/")
		if len(f) >= 7 && f[5] == path.Base(p) {
			return entry{f[2], f[3], f[4]}, true, nil
		}
	}
	return entry{}, false, nil
}

// preflight refuses an image without /var/lib or that already holds a
// claim state, and reports whether /var/lib/agentos exists.
func preflight(image string, off int64) (bool, error) {
	lib, ok, err := lookup(image, off, "/var/lib")
	if err != nil {
		return false, err
	}
	if !ok || !lib.dir() {
		return false, fmt.Errorf("%s has no /var/lib in its root file system", image)
	}
	dir := path.Dir(claim.StatePath)
	d, ok, err := lookup(image, off, dir)
	if err != nil || !ok {
		return false, err
	}
	if !d.dir() {
		return false, fmt.Errorf("%s: %s is not a directory", image, dir)
	}
	if _, held, err := lookup(image, off, claim.StatePath); err != nil {
		return false, err
	} else if held {
		return false, fmt.Errorf("%s already holds a claim state", image)
	}
	return true, nil
}

// sealInto writes state at claim.StatePath, root:root 0600, creating
// /var/lib/agentos root:root 0700 if the image has none.
func sealInto(box string, off int64, tmpDir string, state []byte, dirExists bool) error {
	tmp := filepath.Join(tmpDir, stateTemp)
	if err := writeNew(tmp, state); err != nil {
		return err
	}
	defer os.Remove(tmp)
	dir, name := path.Dir(claim.StatePath), path.Base(claim.StatePath)
	var cmds []string
	if !dirExists {
		cmds = append(cmds,
			"mkdir "+dir,
			"sif "+dir+" mode 040700",
			"sif "+dir+" uid 0",
			"sif "+dir+" gid 0")
	}
	cmds = append(cmds,
		"cd "+dir,
		"write "+stateTemp+" "+name,
		"sif "+claim.StatePath+" mode 0100600",
		"sif "+claim.StatePath+" uid 0",
		"sif "+claim.StatePath+" gid 0")
	cmd := exec.Command("debugfs", "-w", "-f", "-", fsSpec(box, off))
	cmd.Dir = tmpDir // write reads stateTemp relative to here
	cmd.Stdin = strings.NewReader(strings.Join(cmds, "\n") + "\n")
	// debugfs exits 0 when a command fails; checkSealed reads it all back.
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("debugfs: %v: %s", err, out)
	}
	return nil
}

// checkSealed reads the state back: owner and mode, the bytes, a clean
// file system, and a state the box opens unclaimed and the code claims.
func checkSealed(box string, off int64, state []byte, code string, dirExisted bool) error {
	want := map[string]string{claim.StatePath: "100600 0:0"}
	if !dirExisted {
		want[path.Dir(claim.StatePath)] = "040700 0:0"
	}
	for p, w := range want {
		e, ok, err := lookup(box, off, p)
		if err != nil {
			return err
		}
		if !ok || e.String() != w {
			return fmt.Errorf("%s was not written as %s", p, w)
		}
	}
	got, err := exec.Command("debugfs", "-R", "cat "+claim.StatePath, fsSpec(box, off)).Output()
	if err != nil {
		return fmt.Errorf("debugfs: %w", err)
	}
	if !bytes.Equal(got, state) {
		return fmt.Errorf("%s does not read back as written", claim.StatePath)
	}
	if out, err := exec.Command("e2fsck", "-fn", fsSpec(box, off)).CombinedOutput(); err != nil {
		return fmt.Errorf("e2fsck after sealing: %v: %s", err, out)
	}
	// Open a copy as the box will, and claim it with the sticker's code.
	st := &change.MemStore{}
	if err := st.Save(got); err != nil {
		return err
	}
	cl, err := claim.Open(claim.Config{Store: st, BootID: func() (string, error) { return "seller", nil }})
	if err != nil {
		return fmt.Errorf("the sealed state does not open: %w", err)
	}
	if s := cl.Status(); s.Claimed || s.Locked {
		return errors.New("the sealed state does not open unclaimed")
	}
	if _, err := cl.Try(code); err != nil {
		return fmt.Errorf("the code does not claim the sealed state: %w", err)
	}
	if bytes.Contains(got, []byte(claim.Normalize(code)[:claim.PrefixSymbols])) {
		return errors.New("the sealed state holds the code")
	}
	return nil
}

// copyFile copies src to a new file dst, 0600.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// writeNew writes a new file, 0600.
func writeNew(p string, b []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
