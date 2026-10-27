package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/childproc"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/hostdisk"
)

type prepConfig struct {
	Image, Sums, Out string
	Log              io.Writer // progress; never the code
	Rand             io.Reader // crypto/rand.Reader when nil
}

// stateTemp is the sealed state's name in Out while debugfs copies it
// in. The state holds the salted verifier only, never the code.
const stateTemp = ".claim-state"

// enforcerNetFile, in Out, hands the setup network the sticker prints to
// the enforcer's preload (D-178): the core serves no network.
const enforcerNetFile = "enforcer-setup-net.json"

// sealed is one file sealInto writes, root:root 0600.
type sealed struct {
	path, temp string
	data       []byte
}

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
	missing, err := preflight(c.Image, off)
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
	files := []sealed{{claim.StatePath, stateTemp, state}}
	if err := sealInto(box, off, c.Out, files, missing); err != nil {
		return err
	}
	if err := checkSealed(box, off, files, code, missing); err != nil {
		return err
	}
	logf("sealed a claim state into %s at %s", box, path.Dir(claim.StatePath))

	// The enforcer's setup network, which the phone joins first (D-178,
	// §12.1 step 1): per box, drawn apart from the code, handed to the
	// enforcer and printed on the sticker, never sealed into the core.
	setup, err := claim.NewSetupNet(c.Rand)
	if err != nil {
		return err
	}
	if err := writeEnforcerNet(c.Out, setup); err != nil {
		return err
	}

	sum, err := fileSum(box)
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(c.Out, "SHA256SUMS"), []byte(fmt.Sprintf("%x  box.raw\n", sum))); err != nil {
		return err
	}
	if err := writeSticker(c.Out, code, setup); err != nil {
		return err
	}
	logf("wrote %s: run agentos-seller write with box.raw, print sticker.html at 100%%, load %s into the enforcer, then delete the directory", c.Out, enforcerNetFile)
	return nil
}

// writeEnforcerNet writes the setup network for the enforcer's preload,
// 0600, refusing an existing file.
func writeEnforcerNet(dir string, net claim.SetupNet) error {
	b, err := net.Marshal()
	if err != nil {
		return err
	}
	return writeNew(filepath.Join(dir, enforcerNetFile), b)
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

// tool runs debugfs or e2fsck with only a fixed PATH and LANG, never this
// process's environment (childproc).
func tool(o childproc.Options, name string, args ...string) *childproc.Cmd {
	env := childproc.NewEnv("PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C")
	return childproc.Command(context.Background(), env, o, name, args...)
}

func fsSpec(image string, off int64) string { return fmt.Sprintf("%s?offset=%d", image, off) }

// lookup finds p in the file system through its parent's listing. debugfs
// exits 0 for a missing path, so a missing entry is an empty listing.
func lookup(image string, off int64, p string) (entry, bool, error) {
	out, err := tool(childproc.Options{}, "debugfs", "-R", "ls -p "+path.Dir(p), fsSpec(image, off)).Output()
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

// sealDirs are the directories the sealed files go in, each in its
// parent: only the claim state's.
var sealDirs = []string{path.Dir(claim.StatePath)}

// preflight refuses an image without /var/lib or that already holds a
// claim state, and reports which of sealDirs it lacks, in order. Once one
// is missing, so is every one below it.
func preflight(image string, off int64) ([]string, error) {
	lib, ok, err := lookup(image, off, "/var/lib")
	if err != nil {
		return nil, err
	}
	if !ok || !lib.dir() {
		return nil, fmt.Errorf("%s has no /var/lib in its root file system", image)
	}
	var missing []string
	for _, dir := range sealDirs {
		if len(missing) > 0 {
			missing = append(missing, dir)
			continue
		}
		d, ok, err := lookup(image, off, dir)
		if err != nil {
			return nil, err
		}
		if !ok {
			missing = append(missing, dir)
			continue
		}
		if !d.dir() {
			return nil, fmt.Errorf("%s: %s is not a directory", image, dir)
		}
	}
	if !slices.Contains(missing, path.Dir(claim.StatePath)) {
		if _, held, err := lookup(image, off, claim.StatePath); err != nil {
			return nil, err
		} else if held {
			return nil, fmt.Errorf("%s already holds a claim state", image)
		}
	}
	return missing, nil
}

// sealInto writes each file at its path, root:root 0600, first creating
// each missing directory root:root 0700. Every file is in one of
// sealDirs.
func sealInto(box string, off int64, tmpDir string, files []sealed, missing []string) error {
	var cmds []string
	for _, dir := range missing {
		cmds = append(cmds,
			"mkdir "+dir,
			"sif "+dir+" mode 040700",
			"sif "+dir+" uid 0",
			"sif "+dir+" gid 0")
	}
	for _, f := range files {
		dir := path.Dir(f.path)
		if !slices.Contains(sealDirs, dir) {
			return fmt.Errorf("%s is not in %v", f.path, sealDirs)
		}
		tmp := filepath.Join(tmpDir, f.temp)
		if err := writeNew(tmp, f.data); err != nil {
			return err
		}
		defer os.Remove(tmp)
		cmds = append(cmds,
			"cd "+dir,
			"write "+f.temp+" "+path.Base(f.path),
			"sif "+f.path+" mode 0100600",
			"sif "+f.path+" uid 0",
			"sif "+f.path+" gid 0")
	}
	// write reads each temp name relative to Dir.
	cmd := tool(childproc.Options{Dir: tmpDir, Stdin: strings.NewReader(strings.Join(cmds, "\n") + "\n")},
		"debugfs", "-w", "-f", "-", fsSpec(box, off))
	// debugfs exits 0 when a command fails; checkSealed reads it all back.
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("debugfs: %v: %s", err, out)
	}
	return nil
}

// checkSealed reads the files back: owner and mode, the bytes, a clean
// file system, and a state the box opens unclaimed and the code claims.
func checkSealed(box string, off int64, files []sealed, code string, missing []string) error {
	want := map[string]string{}
	for _, f := range files {
		want[f.path] = "100600 0:0"
	}
	for _, dir := range missing {
		want[dir] = "040700 0:0"
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
	read := map[string][]byte{}
	for _, f := range files {
		got, err := tool(childproc.Options{}, "debugfs", "-R", "cat "+f.path, fsSpec(box, off)).Output()
		if err != nil {
			return fmt.Errorf("debugfs: %w", err)
		}
		if !bytes.Equal(got, f.data) {
			return fmt.Errorf("%s does not read back as written", f.path)
		}
		read[f.path] = got
	}
	got := read[claim.StatePath]
	if out, err := tool(childproc.Options{}, "e2fsck", "-fn", fsSpec(box, off)).CombinedOutput(); err != nil {
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
