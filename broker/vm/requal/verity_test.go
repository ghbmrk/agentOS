package requal

// REQ: UPD-5

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ghbmrk/agentos/broker/update"
)

const usrHash = "5a" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"

// signedUsr publishes a release whose /usr image and hash tree are signed
// files and returns the box's check of it and the source it read.
func signedUsr(t *testing.T, files map[string][]byte) (*update.Verified, update.Source) {
	t.Helper()
	d := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	key := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		pub, pk, err := ed25519.GenerateKey(rand.Reader)
		must(err)
		return pub, pk
	}
	p1, k1 := key()
	p2, k2 := key()
	sp, sk := key()
	tp, tk := key()
	repo, err := update.Init(filepath.Join(d, "repo"), update.RootConfig{
		Root: []ed25519.PublicKey{p1, p2}, Targets: []ed25519.PublicKey{p1, p2},
		Snapshot: []ed25519.PublicKey{sp}, Timestamp: []ed25519.PublicKey{tp}, RootThreshold: 2, TargetsThreshold: 2})
	must(err)
	sign := func(role string) {
		must(repo.Sign(role, k1))
		must(repo.Sign(role, k2))
	}
	sign("root")
	sign("targets")
	must(repo.Publish(sk, tk))
	rel := update.Manifest{Version: 2, Channel: update.ChannelStable, UsrRootHash: usrHash}
	local := map[string]string{}
	for p, b := range files {
		f := filepath.Join(d, fmt.Sprint(len(local)))
		must(os.WriteFile(f, b, 0o600))
		rel.Files = append(rel.Files, p)
		local[p] = f
	}
	must(repo.AddRelease(rel, local))
	sign("targets")
	must(repo.Publish(sk, tk))
	root, err := os.ReadFile(filepath.Join(repo.Dir, "metadata", "1.root.json"))
	must(err)
	st, err := update.InitStore(filepath.Join(d, "box"), root, 0)
	must(err)
	src := update.DirSource(repo.Dir)
	res, err := st.Check(src, update.Options{})
	must(err)
	if res.Release == nil {
		t.Fatal("no release")
	}
	return res.Release, src
}

var usrFiles = map[string][]byte{"host-image/usr.img": []byte("erofs image"), "host-image/usr.verity": []byte("hash tree")}

// toolLog records the tools and mounts VerityImages uses, in order.
type toolLog struct {
	calls []string
	fail  string // a call starting with this fails
	seen  map[string][]byte
}

func (l *toolLog) images(v *VerityImages) *VerityImages {
	l.seen = map[string][]byte{}
	v.Run = func(_ context.Context, name string, arg ...string) error {
		c := strings.Join(append([]string{name}, arg...), " ")
		if len(arg) > 3 && arg[0] == "open" {
			for _, p := range []string{arg[1], arg[3]} {
				l.seen[filepath.Base(p)], _ = os.ReadFile(p)
			}
		}
		return l.call(c)
	}
	v.mount = func(src, dst, fstype string, flags uintptr) error {
		return l.call(fmt.Sprintf("mount %s %s %s %#x", src, filepath.Base(dst), fstype, flags))
	}
	v.unmount = func(dst string) error { return l.call("umount " + filepath.Base(dst)) }
	return v
}

func (l *toolLog) call(c string) error {
	l.calls = append(l.calls, c)
	if l.fail != "" && strings.HasPrefix(c, l.fail) {
		return errors.New("tool failed")
	}
	return nil
}

// TestCandidateUsrIsCheckedAgainstItsRootHash: a candidate's /usr and hash
// tree are fetched by their signed hashes, opened by dm-verity under the
// manifest's root hash and mounted read-only with no set-id or devices;
// unmounting closes the device and removes the fetched files.
func TestCandidateUsrIsCheckedAgainstItsRootHash(t *testing.T) {
	rel, src := signedUsr(t, usrFiles)
	staging := t.TempDir()
	var l toolLog
	v := l.images(&VerityImages{Source: src, Staging: staging})
	at := filepath.Join(t.TempDir(), "usr")
	unmount, err := v.Mount(context.Background(), rel, at)
	if err != nil {
		t.Fatal(err)
	}
	if string(l.seen["usr.img"]) != "erofs image" || string(l.seen["usr.verity"]) != "hash tree" {
		t.Fatalf("veritysetup opened %q", l.seen)
	}
	if len(l.calls) != 2 || !strings.HasPrefix(l.calls[0], veritysetup+" open ") || !strings.HasSuffix(l.calls[0], " "+usrHash) {
		t.Fatalf("calls %q", l.calls)
	}
	dev := strings.Fields(l.calls[0])[3]
	if want := fmt.Sprintf("mount /dev/mapper/%s usr erofs %#x", dev, syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV); l.calls[1] != want {
		t.Fatalf("mount %q, want %q", l.calls[1], want)
	}
	if err := unmount(); err != nil {
		t.Fatal(err)
	}
	if got := l.calls[2:]; len(got) != 2 || got[0] != "umount usr" || got[1] != veritysetup+" close "+dev {
		t.Fatalf("unmount calls %q", got)
	}
	if es, _ := os.ReadDir(staging); len(es) != 0 {
		t.Fatalf("staging holds %d entries after unmount", len(es))
	}
}

// TestCandidateMountUnwinds: a failed fetch, open or mount leaves no
// device open and no file in staging.
func TestCandidateMountUnwinds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string][]byte
		fail  string
		want  []string
	}{
		{"no hash tree", map[string][]byte{"host-image/usr.img": []byte("x")}, "", nil},
		{"open fails", usrFiles, veritysetup + " open", []string{"open", "close"}},
		{"mount fails", usrFiles, "mount", []string{"open", "mount", "close"}},
	} {
		rel, src := signedUsr(t, tc.files)
		staging := t.TempDir()
		l := toolLog{fail: tc.fail}
		v := l.images(&VerityImages{Source: src, Staging: staging})
		if _, err := v.Mount(context.Background(), rel, t.TempDir()); err == nil {
			t.Fatalf("%s: Mount passed", tc.name)
		}
		var got []string
		for _, c := range l.calls {
			f := strings.Fields(c)
			if f[0] == veritysetup {
				got = append(got, f[1])
			} else {
				got = append(got, f[0])
			}
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Fatalf("%s: calls %q, want %q", tc.name, got, tc.want)
		}
		if es, _ := os.ReadDir(staging); len(es) != 0 {
			t.Fatalf("%s: staging holds %d entries", tc.name, len(es))
		}
	}
}

// TestCandidateUnmountRetriesFromWhereItStopped: an unmount whose device
// close failed goes on with the close when called again, never a second
// unmount.
func TestCandidateUnmountRetriesFromWhereItStopped(t *testing.T) {
	rel, src := signedUsr(t, usrFiles)
	staging := t.TempDir()
	l := toolLog{}
	v := l.images(&VerityImages{Source: src, Staging: staging})
	unmount, err := v.Mount(context.Background(), rel, filepath.Join(t.TempDir(), "usr"))
	if err != nil {
		t.Fatal(err)
	}
	l.fail = veritysetup + " close"
	if err := unmount(); err == nil {
		t.Fatal("unmount passed a failed close")
	}
	l.fail = ""
	if err := unmount(); err != nil {
		t.Fatal(err)
	}
	var umounts int
	for _, c := range l.calls {
		if strings.HasPrefix(c, "umount") {
			umounts++
		}
	}
	if umounts != 1 || !strings.HasPrefix(l.calls[len(l.calls)-1], veritysetup+" close") {
		t.Fatalf("calls %q, want one umount and the close retried", l.calls)
	}
	if es, _ := os.ReadDir(staging); len(es) != 0 {
		t.Fatalf("staging holds %d entries", len(es))
	}
}

func TestCandidateMountNeedsARunner(t *testing.T) {
	rel, src := signedUsr(t, usrFiles)
	staging := t.TempDir()
	v := &VerityImages{Source: src, Staging: staging}
	if _, err := v.Mount(context.Background(), rel, t.TempDir()); err == nil {
		t.Fatal("Mount passed with no veritysetup runner")
	}
	if es, _ := os.ReadDir(staging); len(es) != 0 {
		t.Fatalf("staging holds %d entries", len(es))
	}
}

// TestCutOffOpenClosesWithItsOwnContext: an open cut off by the run's
// context still closes the device it may have made, on a context of its
// own.
func TestCutOffOpenClosesWithItsOwnContext(t *testing.T) {
	rel, src := signedUsr(t, usrFiles)
	ctx, cancel := context.WithCancel(context.Background())
	var closeErr error = errors.New("close not called")
	v := &VerityImages{Source: src, Staging: t.TempDir(), Run: func(c context.Context, _ string, arg ...string) error {
		if arg[0] == "open" {
			cancel()
			return c.Err()
		}
		closeErr = c.Err()
		return nil
	}}
	if _, err := v.Mount(ctx, rel, t.TempDir()); err == nil {
		t.Fatal("Mount passed a cut-off open")
	}
	if closeErr != nil {
		t.Fatalf("device close: %v, want a live context", closeErr)
	}
}

// TestCandidateUnmountStopsAtABusyMount: an unmount that fails leaves the
// device open and the files in place, and a later call finishes; once
// done, a further call closes nothing twice.
func TestCandidateUnmountStopsAtABusyMount(t *testing.T) {
	rel, src := signedUsr(t, usrFiles)
	staging := t.TempDir()
	l := toolLog{}
	v := l.images(&VerityImages{Source: src, Staging: staging})
	unmount, err := v.Mount(context.Background(), rel, filepath.Join(t.TempDir(), "usr"))
	if err != nil {
		t.Fatal(err)
	}
	l.fail = "umount"
	if err := unmount(); err == nil {
		t.Fatal("unmount passed a busy mount")
	}
	if last := l.calls[len(l.calls)-1]; last != "umount usr" {
		t.Fatalf("after a failed umount: %q", l.calls)
	}
	if es, _ := os.ReadDir(staging); len(es) != 1 {
		t.Fatalf("staging holds %d entries under a mounted device, want 1", len(es))
	}
	l.fail = ""
	if err := unmount(); err != nil {
		t.Fatal(err)
	}
	if err := unmount(); err != nil {
		t.Fatal(err)
	}
	var closes int
	for _, c := range l.calls {
		if strings.HasPrefix(c, veritysetup+" close") {
			closes++
		}
	}
	if closes != 1 {
		t.Fatalf("%d device closes, want 1: %q", closes, l.calls)
	}
}

func TestUncheckedReleaseIsNotMounted(t *testing.T) {
	var l toolLog
	v := l.images(&VerityImages{Staging: t.TempDir()})
	if _, err := v.Mount(context.Background(), &update.Verified{}, t.TempDir()); err == nil || len(l.calls) != 0 {
		t.Fatalf("Mount = %v after %q", err, l.calls)
	}
}

// TestInstalledUsrIsTheBootedOne: the baseline binds the running /usr
// read-only only when the booted usrhash is the installed release's.
func TestInstalledUsrIsTheBootedOne(t *testing.T) {
	hash := func(h string, err error) func(context.Context) (string, error) {
		return func(context.Context) (string, error) { return h, err }
	}
	for _, tc := range []struct {
		name              string
		installed, booted func(context.Context) (string, error)
		ok                bool
	}{
		{"same", hash(usrHash, nil), hash(usrHash, nil), true},
		{"other boot", hash(usrHash, nil), hash(strings.Repeat("1", 64), nil), false},
		{"none installed", hash("", nil), hash("", nil), false},
		{"not a hash", hash("x", nil), hash("x", nil), false},
		{"installed errs", hash(usrHash, errors.New("store")), hash(usrHash, nil), false},
		{"booted errs", hash(usrHash, nil), hash(usrHash, errors.New("efi")), false},
		{"no installed", nil, hash(usrHash, nil), false},
		{"no booted", hash(usrHash, nil), nil, false},
	} {
		var l toolLog
		v := l.images(&VerityImages{Installed: tc.installed, Booted: tc.booted, Usr: "/run/usr"})
		unmount, err := v.Mount(context.Background(), nil, "/s/usr")
		if (err == nil) != tc.ok {
			t.Fatalf("%s: Mount = %v", tc.name, err)
		}
		if !tc.ok {
			if len(l.calls) != 0 {
				t.Fatalf("%s: calls %q", tc.name, l.calls)
			}
			continue
		}
		want := []string{
			fmt.Sprintf("mount /run/usr usr  %#x", syscall.MS_BIND),
			fmt.Sprintf("mount  usr  %#x", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV),
		}
		if strings.Join(l.calls, "|") != strings.Join(want, "|") {
			t.Fatalf("calls %q, want %q", l.calls, want)
		}
		if err := unmount(); err != nil || l.calls[2] != "umount usr" {
			t.Fatalf("unmount: %v, %q", err, l.calls)
		}
	}
	// A failed remount leaves nothing bound.
	l := toolLog{fail: "mount  usr"}
	v := l.images(&VerityImages{Installed: hash(usrHash, nil), Booted: hash(usrHash, nil)})
	if _, err := v.Mount(context.Background(), nil, "/s/usr"); err == nil || l.calls[len(l.calls)-1] != "umount usr" {
		t.Fatalf("failed remount: %v, %q", err, l.calls)
	}
}
