package main

// REQ: HW-10, HW-1, A1
//
// #6594: each step of prep and write that can fail is made to fail, by
// input or through a fault seam (faults.go), and the test checks that the
// command stops there with that step's error and leaves nothing behind.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/childproc"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/hostdisk"
	"golang.org/x/sys/unix"
)

var errFault = errors.New("injected fault")

// swap sets *p to v for the rest of the test.
func swap[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

// openFDs is how many descriptors this process holds: a dropped Close
// leaves one more.
func openFDs(t *testing.T) int {
	t.Helper()
	es, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(es)
}

// closesItsFiles fails if f leaves a descriptor open.
func closesItsFiles(t *testing.T, name string, f func()) {
	t.Helper()
	before := openFDs(t)
	f()
	if after := openFDs(t); after != before {
		t.Errorf("%s: %d descriptors open before, %d after", name, before, after)
	}
}

// toolCalls replaces tool: each call is recorded as its name and its
// arguments before the file system, and a call fail matches runs a tool
// that does not exist.
func toolCalls(t *testing.T, fail func(call string) bool) *[]string {
	t.Helper()
	real := tool
	var calls []string
	swap(t, &tool, func(o childproc.Options, name string, args ...string) *childproc.Cmd {
		call := strings.Join(append([]string{name}, args[:len(args)-1]...), " ")
		calls = append(calls, call)
		if fail != nil && fail(call) {
			name = "/nonexistent/" + name
		}
		return real(o, name, args...)
	})
	return &calls
}

// sealDirTree is rootTree with an existing /var/lib/agentos, plus extra.
func sealDirTree(extra map[string]string) map[string]string {
	tree := map[string]string{sealDirs[0][1:] + "/": ""}
	for k, v := range rootTree {
		tree[k] = v
	}
	for k, v := range extra {
		tree[k] = v
	}
	return tree
}

// rootOwnedSealDir is a disk whose root file system is tree with
// /var/lib/agentos root:root 0700, as preflight accepts it.
func rootOwnedSealDir(t *testing.T, tree map[string]string) []byte {
	dir := sealDirs[0]
	return gptDisk([]part{
		{typeESP, make([]byte, 1<<20)},
		{typeUsr, make([]byte, 1<<20)},
		{typeRoot, ext4Sif(t, tree, "sif "+dir+" mode 040700", "sif "+dir+" uid 0", "sif "+dir+" gid 0")},
	})
}

func gone(t *testing.T, out string) {
	t.Helper()
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("prep left %s behind: %v", out, err)
	}
}

func TestRunReportsUsageAndFlags(t *testing.T) {
	for _, cmd := range []string{"prep", "write"} {
		var stdout, stderr bytes.Buffer
		if got := run([]string{cmd, "-bogus"}, &stdout, &stderr); got != 2 {
			t.Fatalf("%s -bogus = %d, want 2", cmd, got)
		}
		s := stderr.String()
		if !strings.Contains(s, "flag provided but not defined: -bogus") || !strings.HasSuffix(s, usage+"\n") {
			t.Fatalf("%s -bogus: stderr %q", cmd, s)
		}
	}
	var stderr bytes.Buffer
	if got := run([]string{"flash"}, &bytes.Buffer{}, &stderr); got != 2 || stderr.String() != usage+"\n" {
		t.Fatalf("flash = %d, %q", got, stderr.String())
	}
	img, sums := writeImage(t, []byte("not an image"))
	stderr.Reset()
	if got := run([]string{"prep", "-image", img, "-sums", sums, "-out", filepath.Join(t.TempDir(), "o")}, &bytes.Buffer{}, &stderr); got != 1 ||
		!strings.HasPrefix(stderr.String(), "agentos-seller: ") {
		t.Fatalf("prep of a non-image = %d, %q", got, stderr.String())
	}
	stderr.Reset()
	if got := run([]string{"write", "-image", img, "-sums", sums, "-device", filepath.Join(t.TempDir(), "none")}, &bytes.Buffer{}, &stderr); got != 1 ||
		!strings.Contains(stderr.String(), "none") {
		t.Fatalf("write to a missing device = %d, %q", got, stderr.String())
	}
}

func TestPrepLogsAndLeavesOnlyItsFiles(t *testing.T) {
	needTools(t)
	img, sums := writeImage(t, standardDisk(t, rootTree))
	out := filepath.Join(t.TempDir(), "box1")
	log := &bytes.Buffer{}
	if err := prep(prepConfig{Image: img, Sums: sums, Out: out, Log: log}); err != nil {
		t.Fatal(err)
	}
	box := filepath.Join(out, "box.raw")
	want := fmt.Sprintf("image matches %s\nsealed a claim state into %s at %s\nwrote %s: run agentos-seller write with box.raw, print sticker.html at 100%%, load %s into the enforcer, then delete the directory\n",
		sums, box, sealDirs[0], out, enforcerNetFile)
	if log.String() != want {
		t.Fatalf("log:\n%s\nwant:\n%s", log, want)
	}
	es, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	if w := []string{"SHA256SUMS", "box.raw", enforcerNetFile, "sticker.html", "sticker.txt"}; !slices.Equal(names, w) {
		t.Fatalf("%s holds %v, want %v", out, names, w)
	}
	// No Log is no log, not a crash.
	img2, sums2 := writeImage(t, standardDisk(t, rootTree))
	if err := prep(prepConfig{Image: img2, Sums: sums2, Out: filepath.Join(t.TempDir(), "box2")}); err != nil {
		t.Fatal(err)
	}
}

// Each refusal names its reason, and leaves no Out.
func TestPrepRefusesWithItsReason(t *testing.T) {
	needTools(t)
	good := standardDisk(t, rootTree)
	cases := []struct {
		name string
		disk func() []byte
		out  string
		want func(error) bool
	}{
		{"a '?' in Out", func() []byte { return good }, "box?1", func(err error) bool {
			return err.Error() == "paths with '?' are not supported (debugfs reads it as an option)"
		}},
		{"shorter than a sector", func() []byte { return make([]byte, 100) }, "", func(err error) bool {
			return errors.Is(err, hostdisk.ErrUnreadableTable)
		}},
		{"no partition table", func() []byte { return make([]byte, 4<<20) }, "", func(err error) bool {
			return strings.HasSuffix(err.Error(), " has no GPT")
		}},
		{"no /var/lib", func() []byte { return standardDisk(t, map[string]string{"etc/hostname": "x\n"}) }, "", func(err error) bool {
			return strings.HasSuffix(err.Error(), " has no /var/lib in its root file system")
		}},
		{"/var/lib a file", func() []byte { return standardDisk(t, map[string]string{"var/lib": "x"}) }, "", func(err error) bool {
			return strings.HasSuffix(err.Error(), " has no /var/lib in its root file system")
		}},
		{"/var/lib/agentos a file", func() []byte {
			return standardDisk(t, map[string]string{"var/lib/agentos": "x", "var/lib/x/": ""})
		}, "", func(err error) bool {
			return strings.HasSuffix(err.Error(), ": /var/lib/agentos is not a directory")
		}},
		{"already holds a claim state", func() []byte {
			return rootOwnedSealDir(t, sealDirTree(map[string]string{claim.StatePath[1:]: `{"salt":"AAAA"}`}))
		}, "", func(err error) bool {
			return strings.HasSuffix(err.Error(), " already holds a claim state")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			img, sums := writeImage(t, c.disk())
			name := c.out
			if name == "" {
				name = "box1"
			}
			out := filepath.Join(t.TempDir(), name)
			if err := runPrep(img, sums, out); err == nil || !c.want(err) {
				t.Fatalf("prep = %v", err)
			}
			gone(t, out)
		})
	}
	t.Run("checksum mismatch", func(t *testing.T) {
		img, sums := writeImage(t, good)
		other := slices.Clone(good)
		other[len(other)/2] ^= 1
		if err := os.WriteFile(img, other, 0o644); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "box1")
		if err := runPrep(img, sums, out); err == nil || !strings.HasSuffix(err.Error(), " does not match its line in "+sums) {
			t.Fatalf("prep = %v", err)
		}
		gone(t, out)
	})
}

// countingReader counts what it hands out.
type countingReader struct{ n int }

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := rand.Read(p)
	r.n += n
	return n, err
}

// failingReader hands out left bytes, then fails.
type failingReader struct{ left int }

func (r *failingReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, errFault
	}
	if len(p) > r.left {
		p = p[:r.left]
	}
	n, err := rand.Read(p)
	r.left -= n
	return n, err
}

// loadFails is a store whose Load fails after its first.
type loadFails struct {
	change.MemStore
	loads int
}

func (s *loadFails) Load() ([]byte, error) {
	if s.loads++; s.loads > 1 {
		return nil, errFault
	}
	return s.MemStore.Load()
}

// Each step after Out is made fails in turn: prep returns that step's
// error and removes Out.
func TestPrepRemovesOutOnEachLateFailure(t *testing.T) {
	needTools(t)
	disk := standardDisk(t, rootTree)
	// What sealing draws before the setup network does.
	cr := &countingReader{}
	code, err := claim.NewCode(cr)
	if err != nil {
		t.Fatal(err)
	}
	if err := claim.Seal(&change.MemStore{}, code, cr, nil); err != nil {
		t.Fatal(err)
	}
	beforeNet := cr.n
	cases := []struct {
		name  string
		setup func(t *testing.T, box string)
		rand  io.Reader
		want  func(error) bool
	}{
		{"chmod", func(t *testing.T, box string) {
			swap(t, &chmod, func(string, os.FileMode) error { return errFault })
		}, nil, nil},
		{"the copy differs", func(t *testing.T, box string) {
			real := copyBuf
			swap(t, &copyBuf, func(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
				if f, ok := dst.(*os.File); ok && f.Name() == box {
					n, err := real(dst, src, buf)
					if err == nil {
						_, err = f.WriteAt([]byte{0xFF}, 0)
					}
					return n, err
				}
				return real(dst, src, buf)
			})
		}, nil, func(err error) bool { return err.Error() == "the copy differs from the image" }},
		{"the box's last sum", func(t *testing.T, box string) {
			real, sums := copyBuf, 0
			swap(t, &copyBuf, func(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
				if f, ok := src.(*os.File); ok && f.Name() == box {
					if sums++; sums == 2 {
						return 0, errFault
					}
				}
				return real(dst, src, buf)
			})
		}, nil, nil},
		{"no randomness for the code", nil, &failingReader{}, nil},
		{"no randomness for the setup network", nil, &failingReader{left: beforeNet}, nil},
		{"the sealed state does not load", func(t *testing.T, box string) {
			swap(t, &newStore, func() change.Store { return &loadFails{} })
		}, nil, nil},
		{"e2fsck finds a fault", func(t *testing.T, box string) {
			toolCalls(t, func(call string) bool { return strings.HasPrefix(call, "e2fsck") })
		}, nil, func(err error) bool { return strings.HasPrefix(err.Error(), "e2fsck after sealing: ") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			img, sums := writeImage(t, disk)
			out := filepath.Join(t.TempDir(), "box1")
			if c.setup != nil {
				c.setup(t, filepath.Join(out, "box.raw"))
			}
			err := prep(prepConfig{Image: img, Sums: sums, Out: out, Rand: c.rand})
			want := c.want
			if want == nil {
				want = func(err error) bool { return errors.Is(err, errFault) }
			}
			if err == nil || !want(err) {
				t.Fatalf("prep = %v", err)
			}
			gone(t, out)
		})
	}
}

// sealedBox is a box image with a claim state sealed for code, and the
// state's bytes.
func sealedBox(t *testing.T, code string, state []byte) (box string, off int64, files []sealed) {
	t.Helper()
	box, _ = writeImage(t, standardDisk(t, rootTree))
	off, err := rootOffset(box)
	if err != nil {
		t.Fatal(err)
	}
	files = []sealed{{claim.StatePath, stateTemp, state}}
	if err := sealInto(box, off, t.TempDir(), files, sealDirs); err != nil {
		t.Fatal(err)
	}
	return box, off, files
}

func stateFor(t *testing.T, code string) []byte {
	t.Helper()
	st := &change.MemStore{}
	if err := claim.Seal(st, code, nil, nil); err != nil {
		t.Fatal(err)
	}
	b, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func debugfsW(t *testing.T, box string, off int64, cmds ...string) {
	t.Helper()
	cmd := exec.Command("debugfs", "-w", "-f", "-", fsSpec(box, off))
	cmd.Stdin = strings.NewReader(strings.Join(cmds, "\n") + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("debugfs: %v: %s", err, out)
	}
}

// checkSealed catches each way a seal can come out wrong.
func TestCheckSealedCatchesABadSeal(t *testing.T) {
	needTools(t)
	code, err := claim.NewCode(nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := claim.NewCode(nil)
	if err != nil {
		t.Fatal(err)
	}
	good := stateFor(t, code)
	claimed := func() []byte {
		st := &change.MemStore{}
		if err := st.Save(good); err != nil {
			t.Fatal(err)
		}
		cl, err := claim.Open(claim.Config{Store: st, BootID: func() (string, error) { return "t", nil }})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cl.Try(code); err != nil {
			t.Fatal(err)
		}
		b, err := st.Load()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}()
	withCode := append([]byte(`{"note":"`+claim.Normalize(code)[:claim.PrefixSymbols]+`",`), good[1:]...)

	box, off, files := sealedBox(t, code, good)
	if err := checkSealed(box, off, files, code, sealDirs); err != nil {
		t.Fatalf("a good seal: %v", err)
	}
	cases := []struct {
		name  string
		state []byte
		code  string
		after func(t *testing.T, box string, off int64)
		check []byte // the bytes checkSealed expects, when not state
		want  string
	}{
		{"file mode", good, code, func(t *testing.T, box string, off int64) {
			debugfsW(t, box, off, "sif "+claim.StatePath+" mode 0100644")
		}, nil, claim.StatePath + " was not written as 100600 0:0"},
		{"file owner", good, code, func(t *testing.T, box string, off int64) {
			debugfsW(t, box, off, "sif "+claim.StatePath+" uid 1000")
		}, nil, claim.StatePath + " was not written as 100600 0:0"},
		{"dir mode", good, code, func(t *testing.T, box string, off int64) {
			debugfsW(t, box, off, "sif "+sealDirs[0]+" mode 040755")
		}, nil, sealDirs[0] + " was not written as " + sealDirMode},
		{"no file", good, code, func(t *testing.T, box string, off int64) {
			debugfsW(t, box, off, "rm "+claim.StatePath)
		}, nil, claim.StatePath + " was not written as 100600 0:0"},
		{"bytes", good, code, nil, []byte("other bytes"), claim.StatePath + " does not read back as written"},
		{"not a state", []byte("garbage"), code, nil, nil, "the sealed state does not open: "},
		{"claimed", claimed, code, nil, nil, "the sealed state does not open unclaimed"},
		{"another code", good, other, nil, nil, "the code does not claim the sealed state: "},
		{"holds the code", withCode, code, nil, nil, "the sealed state holds the code"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			box, off, files := sealedBox(t, c.code, c.state)
			if c.after != nil {
				c.after(t, box, off)
			}
			if c.check != nil {
				files = []sealed{{claim.StatePath, stateTemp, c.check}}
			}
			if err := checkSealed(box, off, files, c.code, sealDirs); err == nil || !strings.HasPrefix(err.Error(), c.want) {
				t.Fatalf("checkSealed = %v, want %q", err, c.want)
			}
		})
	}
	for _, c := range []struct{ name, fail, want string }{
		{"debugfs cat fails", "debugfs -R cat ", "debugfs: "},
		{"debugfs ls fails", "debugfs -R ls -p ", "debugfs: "},
	} {
		t.Run(c.name, func(t *testing.T) {
			toolCalls(t, func(call string) bool { return strings.HasPrefix(call, c.fail) })
			if err := checkSealed(box, off, files, code, sealDirs); err == nil || !strings.HasPrefix(err.Error(), c.want) {
				t.Fatalf("checkSealed = %v", err)
			}
		})
	}
}

// preflight stops at a failed listing, and lists nothing below a missing
// directory.
func TestPreflightListsOnlyWhatItNeeds(t *testing.T) {
	needTools(t)
	plain, _ := writeImage(t, standardDisk(t, rootTree))
	held, _ := writeImage(t, rootOwnedSealDir(t, sealDirTree(nil)))
	for _, c := range []struct{ name, img, fail string }{
		{"/var", plain, "debugfs -R ls -p /var"},
		{"/var/lib", plain, "debugfs -R ls -p /var/lib"},
		{"/var/lib/agentos", held, "debugfs -R ls -p /var/lib/agentos"},
	} {
		t.Run(c.name, func(t *testing.T) {
			off, err := rootOffset(c.img)
			if err != nil {
				t.Fatal(err)
			}
			toolCalls(t, func(call string) bool { return call == c.fail })
			if _, err := preflight(c.img, off); err == nil || !strings.HasPrefix(err.Error(), "debugfs: ") {
				t.Fatalf("preflight = %v", err)
			}
		})
	}
	t.Run("below a missing directory", func(t *testing.T) {
		off, err := rootOffset(plain)
		if err != nil {
			t.Fatal(err)
		}
		dirs := []string{sealDirs[0], sealDirs[0] + "/ap"}
		swap(t, &sealDirs, dirs)
		calls := toolCalls(t, nil)
		missing, err := preflight(plain, off)
		if err != nil || !slices.Equal(missing, dirs) {
			t.Fatalf("preflight = %v, %v", missing, err)
		}
		if w := []string{"debugfs -R ls -p /var", "debugfs -R ls -p /var/lib"}; !slices.Equal(*calls, w) {
			t.Fatalf("debugfs ran %q, want %q", *calls, w)
		}
	})
}

func TestSealIntoRefusesAFileOutsideSealDirs(t *testing.T) {
	tmp := t.TempDir()
	err := sealInto(filepath.Join(tmp, "none.raw"), 0, tmp, []sealed{{"/etc/x", "x", []byte("x")}}, nil)
	if err == nil || err.Error() != fmt.Sprintf("/etc/x is not in %v", sealDirs) {
		t.Fatalf("sealInto = %v", err)
	}
	if es, _ := os.ReadDir(tmp); len(es) != 0 {
		t.Fatalf("sealInto left %v", es)
	}
}

func TestSmallStepsFail(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	notExist := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), missing) {
			t.Errorf("%s = %v, want %s not to exist", name, err, missing)
		}
	}
	_, err := sumFor(file, missing)
	notExist("sumFor", err)
	_, err = fileSum(missing)
	notExist("fileSum", err)
	_, err = checkSum(file, missing)
	notExist("checkSum without sums", err)
	sums := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sums, []byte(fmt.Sprintf("%x  missing\n", sha256.Sum256(nil))), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = checkSum(missing, sums)
	notExist("checkSum without the image", err)
	_, err = rootOffset(missing)
	notExist("rootOffset", err)
	notExist("copyFile", copyFile(missing, filepath.Join(dir, "copy")))
	notExist("verify", verify(missing, 1, nil))

	if _, err := sumFor(file, dir); !errors.Is(err, syscall.EISDIR) {
		t.Errorf("sumFor of a directory = %v", err)
	}
	for body, want := range map[string]string{
		"zz  file\n":  sums + ": the line for file is not a SHA-256",
		"00  file\n":  sums + ": the line for file is not a SHA-256",
		"00  other\n": sums + " has 0 lines for file, want 1",
		fmt.Sprintf("%x  file\n%x  *file\n", sha256.Sum256(nil), sha256.Sum256(nil)): sums + " has 2 lines for file, want 1",
	} {
		if err := os.WriteFile(sums, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := sumFor(file, sums); err == nil || err.Error() != want {
			t.Errorf("sumFor(%q) = %v, want %s", body, err, want)
		}
	}

	if err := copyFile(file, file); !errors.Is(err, fs.ErrExist) {
		t.Errorf("copyFile onto an existing file = %v", err)
	}
	if err := writeNew(file, nil); !errors.Is(err, fs.ErrExist) {
		t.Errorf("writeNew onto an existing file = %v", err)
	}
	if err := writeEnforcerNet(dir, claim.SetupNet{}); err == nil {
		t.Error("writeEnforcerNet wrote an empty setup network")
	} else if _, err := os.Stat(filepath.Join(dir, enforcerNetFile)); !os.IsNotExist(err) {
		t.Errorf("writeEnforcerNet left a file: %v", err)
	}
	long := strings.Repeat("A", 4000)
	if err := writeSticker(dir, long, claim.SetupNet{SSID: "s", Password: "p"}); err == nil {
		t.Error("writeSticker wrote a code no QR code holds")
	}
	if err := writeSticker(dir, "CCCC-CCCC-CCCC-CCCC", claim.SetupNet{SSID: "s", Password: long}); err == nil {
		t.Error("writeSticker wrote a password no QR code holds")
	}
	if _, err := os.Stat(filepath.Join(dir, "sticker.html")); !os.IsNotExist(err) {
		t.Errorf("writeSticker left a sticker: %v", err)
	}

	// Each fault alone, so a step that goes on past its own failure meets
	// no other; none leaves a descriptor open.
	for _, c := range []struct {
		name  string
		fault func(t *testing.T)
		step  func(t *testing.T) error
	}{
		{"copyFile's sync", func(t *testing.T) { swap(t, &syncFile, func(*os.File) error { return errFault }) },
			func(t *testing.T) error { return copyFile(file, filepath.Join(t.TempDir(), "c")) }},
		{"copyFile's copy", func(t *testing.T) {
			swap(t, &copyBuf, func(io.Writer, io.Reader, []byte) (int64, error) { return 0, errFault })
		}, func(t *testing.T) error { return copyFile(file, filepath.Join(t.TempDir(), "c")) }},
		{"writeNew's sync", func(t *testing.T) { swap(t, &syncFile, func(*os.File) error { return errFault }) },
			func(t *testing.T) error { return writeNew(filepath.Join(t.TempDir(), "w"), []byte("x")) }},
		{"rootOffset's stat", func(t *testing.T) {
			swap(t, &statFile, func(*os.File) (os.FileInfo, error) { return nil, errFault })
		}, func(t *testing.T) error { _, err := rootOffset(file); return err }},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.fault(t)
			var err error
			closesItsFiles(t, c.name, func() { err = c.step(t) })
			if !errors.Is(err, errFault) {
				t.Errorf("%s = %v", c.name, err)
			}
		})
	}
	// The real cache drop refuses a file that is not a block device.
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := flushBuf(int(f.Fd())); !errors.Is(err, syscall.ENOTTY) {
		t.Errorf("flushBuf on a file = %v", err)
	}

	t.Run("descriptors", func(t *testing.T) {
		if err := os.WriteFile(sums, []byte(fmt.Sprintf("%x  file\n", sha256.Sum256([]byte("file\n")))), 0o600); err != nil {
			t.Fatal(err)
		}
		closesItsFiles(t, "checkSum", func() {
			if _, err := checkSum(file, sums); err != nil {
				t.Error(err)
			}
		})
		closesItsFiles(t, "rootOffset", func() { rootOffset(file) })
		closesItsFiles(t, "copyFile", func() {
			if err := copyFile(file, filepath.Join(t.TempDir(), "c")); err != nil {
				t.Error(err)
			}
		})
		closesItsFiles(t, "firstFields", func() {
			if _, err := firstFields(sums); err != nil {
				t.Error(err)
			}
		})
	})

	if _, err := firstFields(filepath.Join(file, "x")); !errors.Is(err, syscall.ENOTDIR) {
		t.Errorf("firstFields under a file = %v", err)
	}
	if isPartition("/dev/sda", "7") {
		t.Error("isPartition took a name that is not under the disk")
	}
	if got := unescape(`a\0b\040c\x`); got != `a\0b c\x` {
		t.Errorf("unescape: %q", got)
	}
}

// writeFixture is an image, its sums and a target large enough, with no
// mounts or swap listed and requireBlock off.
func writeFixture(t *testing.T) (img, sums, dev string, body []byte) {
	t.Helper()
	swap(t, &requireBlock, false)
	dir := t.TempDir()
	body = bytes.Repeat([]byte("synthetic image 0123456789\n"), 4000)
	img = filepath.Join(dir, "box.raw")
	if err := os.WriteFile(img, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sums = filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sums, []byte(fmt.Sprintf("%x  box.raw\n", sha256.Sum256(body))), 0o600); err != nil {
		t.Fatal(err)
	}
	swap(t, &mountsPath, filepath.Join(dir, "no-mounts"))
	swap(t, &swapsPath, filepath.Join(dir, "no-swaps"))
	dev = filepath.Join(dir, "disk")
	if err := os.WriteFile(dev, make([]byte, len(body)+512), 0o600); err != nil {
		t.Fatal(err)
	}
	return img, sums, dev, body
}

func TestWriteStopsAtEachFailure(t *testing.T) {
	t.Run("logs", func(t *testing.T) {
		img, sums, dev, body := writeFixture(t)
		log := &bytes.Buffer{}
		closesItsFiles(t, "write", func() {
			if err := write(img, sums, dev, log); err != nil {
				t.Fatal(err)
			}
		})
		want := fmt.Sprintf("writing %s to %s (%d bytes)\nreading %s back\n%s holds the image\n", img, dev, len(body), dev, dev)
		if log.String() != want {
			t.Fatalf("log %q, want %q", log, want)
		}
	})
	t.Run("a refused target closes it", func(t *testing.T) {
		img, sums, _, body := writeFixture(t)
		small := filepath.Join(t.TempDir(), "small")
		if err := os.WriteFile(small, make([]byte, len(body)-1), 0o600); err != nil {
			t.Fatal(err)
		}
		closesItsFiles(t, "write", func() {
			if err := write(img, sums, small, io.Discard); err == nil {
				t.Fatal("wrote to a small target")
			}
		})
	})
	t.Run("a missing device", func(t *testing.T) {
		img, sums, _, _ := writeFixture(t)
		dev := filepath.Join(t.TempDir(), "gone")
		if err := write(img, sums, dev, io.Discard); !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), dev) {
			t.Fatalf("write = %v", err)
		}
	})
	t.Run("a directory", func(t *testing.T) {
		img, sums, _, _ := writeFixture(t)
		if err := write(img, sums, t.TempDir(), io.Discard); !errors.Is(err, syscall.EISDIR) {
			t.Fatalf("write = %v", err)
		}
	})
	t.Run("mounts unreadable", func(t *testing.T) {
		img, sums, dev, _ := writeFixture(t)
		swap(t, &mountsPath, t.TempDir())
		if err := write(img, sums, dev, io.Discard); !errors.Is(err, syscall.EISDIR) {
			t.Fatalf("write = %v", err)
		}
	})
	t.Run("mounted through a link", func(t *testing.T) {
		img, sums, dev, _ := writeFixture(t)
		link := filepath.Join(t.TempDir(), "by-id")
		if err := os.Symlink(dev, link); err != nil {
			t.Fatal(err)
		}
		mounts := filepath.Join(t.TempDir(), "mounts")
		if err := os.WriteFile(mounts, []byte(link+" /mnt ext4 rw 0 0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		swap(t, &mountsPath, mounts)
		if err := write(img, sums, dev, io.Discard); err == nil || !strings.Contains(err.Error(), " is mounted ") {
			t.Fatalf("write = %v", err)
		}
	})
	t.Run("the target does not hold the image", func(t *testing.T) {
		img, sums, dev, _ := writeFixture(t)
		real := copyBuf
		swap(t, &copyBuf, func(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
			n, err := real(dst, src, buf)
			if _, sum := dst.(hash.Hash); err == nil && !sum {
				var f *os.File
				if f, err = os.OpenFile(dev, os.O_WRONLY, 0); err == nil {
					_, err = f.WriteAt([]byte("X"), 0)
					f.Close()
				}
			}
			return n, err
		})
		if err := write(img, sums, dev, io.Discard); err == nil || err.Error() != dev+" does not hold the image after writing" {
			t.Fatalf("write = %v", err)
		}
	})
	for _, c := range []struct {
		name  string
		fault func(t *testing.T)
	}{
		{"stat", func(t *testing.T) { swap(t, &statPath, func(string) (os.FileInfo, error) { return nil, errFault }) }},
		{"open the image", func(t *testing.T) { swap(t, &openFile, func(string) (*os.File, error) { return nil, errFault }) }},
		{"stat the image", func(t *testing.T) {
			swap(t, &statFile, func(*os.File) (os.FileInfo, error) { return nil, errFault })
		}},
		{"seek", func(t *testing.T) {
			swap(t, &seekFile, func(*os.File, int64, int) (int64, error) { return 0, errFault })
		}},
		{"copy", func(t *testing.T) {
			swap(t, &copyBuf, func(io.Writer, io.Reader, []byte) (int64, error) { return 0, errFault })
		}},
		{"sync", func(t *testing.T) { swap(t, &syncFile, func(*os.File) error { return errFault }) }},
		{"close", func(t *testing.T) {
			swap(t, &closeFile, func(f *os.File) error { f.Close(); return errFault })
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			img, sums, dev, _ := writeFixture(t)
			c.fault(t)
			log := &bytes.Buffer{}
			if err := write(img, sums, dev, log); !errors.Is(err, errFault) {
				t.Fatalf("write = %v", err)
			}
			if strings.Contains(log.String(), "holds the image") {
				t.Fatalf("log %q", log)
			}
		})
	}
	// A block device is opened O_EXCL, its cache dropped before the read
	// back, which drops its pages too.
	t.Run("a block device", func(t *testing.T) {
		img, sums, dev, body := writeFixture(t)
		swap(t, &requireBlock, true)
		swap(t, &isBlock, func(os.FileMode) bool { return true })
		var flags int
		real := openDev
		swap(t, &openDev, func(p string, f int, m os.FileMode) (*os.File, error) {
			flags = f
			return real(p, f, m)
		})
		flushed := 0
		swap(t, &flushBuf, func(int) error { flushed++; return nil })
		var advice [][2]int64
		realAdvise := fadvise
		swap(t, &fadvise, func(fd int, off, n int64, a int) error {
			advice = append(advice, [2]int64{n, int64(a)})
			return realAdvise(fd, off, n, a)
		})
		if err := write(img, sums, dev, io.Discard); err != nil {
			t.Fatal(err)
		}
		if flags != os.O_WRONLY|unix.O_EXCL || flushed != 1 {
			t.Fatalf("flags %#x, flushed %d", flags, flushed)
		}
		if w := [][2]int64{{int64(len(body)), unix.FADV_DONTNEED}}; !slices.Equal(advice, w) {
			t.Fatalf("fadvise %v, want %v", advice, w)
		}
		swap(t, &flushBuf, func(int) error { return errFault })
		if err := write(img, sums, dev, io.Discard); !errors.Is(err, errFault) || !strings.HasPrefix(err.Error(), "flushing "+dev+"'s cache: ") {
			t.Fatalf("write = %v", err)
		}
	})
	t.Run("verify closes the target", func(t *testing.T) {
		_, _, dev, _ := writeFixture(t)
		closesItsFiles(t, "verify", func() { verify(dev, 1, nil) })
	})
}
