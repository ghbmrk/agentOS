package run

// REQ: CLK-1, STO-2

import (
	"errors"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/privfile"
)

func clerkDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "clerk")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// open loads dir's store; err is nil only when it holds exactly slot "web".
func loadsWhole(dir string) error {
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		return err
	}
	if sec.Len() != 1 || !sec.Has("web") {
		return errors.New("store lost its slot")
	}
	return nil
}

// A write cut off after any of its steps, as a crash would, leaves the old
// form or the new one, each whole, and the next write goes through; a torn
// temporary file is never read (#2643 c).
func TestSecretsWriteStoppedAtEveryStepLeavesAWholeForm(t *testing.T) {
	for i := 0; i < 6; i++ {
		dir := clerkDir(t)
		sec, err := OpenSecrets(dir, testSealer())
		if err != nil {
			t.Fatal(err)
		}
		if err := sec.Put("web", clerk.KindStatic, []byte("old-secret")); err != nil {
			t.Fatal(err)
		}
		next, err := sec.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if err := privfile.WriteAtomic(dir, secretsName, next, func(j int) bool { return j == i }); !errors.Is(err, privfile.ErrStopped) {
			t.Fatalf("step %d: %v, want stopped", i, err)
		}
		if err := loadsWhole(dir); err != nil {
			t.Fatalf("stopped after step %d: %v", i, err)
		}
		// A temporary torn mid-write is never read, and the next write
		// replaces it.
		if err := os.WriteFile(filepath.Join(dir, secretsName+".tmp"), next[:len(next)/2], 0o600); err != nil {
			t.Fatal(err)
		}
		if err := loadsWhole(dir); err != nil {
			t.Fatalf("with a torn temporary after step %d: %v", i, err)
		}
		if err := privfile.WriteAtomic(dir, secretsName, next, nil); err != nil {
			t.Fatalf("write after a stop at step %d: %v", i, err)
		}
		if err := loadsWhole(dir); err != nil {
			t.Fatalf("after the next write: %v", err)
		}
	}
}

// A writer process killed at random points, mid-write included, always leaves
// a Secrets file that loads whole (#2643 c).
func TestSecretsKilledWriterLeavesAWholeForm(t *testing.T) {
	dir := clerkDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := sec.Put("web", clerk.KindStatic, []byte("first")); err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 25; i++ {
		cmd := exec.Command(os.Args[0])
		cmd.Env = append(os.Environ(), roleEnv+"=writer", "RUN_DIR="+dir)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Duration(5+r.IntN(40)) * time.Millisecond)
		cmd.Process.Signal(syscall.SIGKILL)
		cmd.Wait()
		if err := loadsWhole(dir); err != nil {
			t.Fatalf("after kill %d: %v", i, err)
		}
	}
}

// The slot-to-blob form from before slot kinds is refused, not migrated, and
// the file is left as it was (#2643 d).
func TestSecretsOldFormatRefused(t *testing.T) {
	dir := clerkDir(t)
	old := []byte(`{"web":"c2VhbGVkLWJsb2I="}`)
	path := filepath.Join(dir, secretsName)
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSecrets(dir, testSealer()); !errors.Is(err, ErrOldFormat) {
		t.Fatalf("old form: %v, want %v", err, ErrOldFormat)
	}
	if b, _ := os.ReadFile(path); string(b) != string(old) {
		t.Fatal("refusing the old form changed the file")
	}
	// A kind that is missing or relabelled does not open either.
	for _, bad := range []string{`{"web":{"blob":"c2VhbGVk"}}`, `not json`} {
		os.WriteFile(path, []byte(bad), 0o600)
		if _, err := OpenSecrets(dir, testSealer()); err == nil {
			t.Fatalf("%s loaded", bad)
		}
	}
}

// A store sealed under one key does not open under another.
func TestSecretsWrongKeyRefused(t *testing.T) {
	dir := clerkDir(t)
	sec, _ := OpenSecrets(dir, testSealer())
	if err := sec.Put("web", clerk.KindStatic, []byte("s")); err != nil {
		t.Fatal(err)
	}
	other, _ := clerk.NewAESSealer([]byte(strings.Repeat("k", 32)))
	if _, err := OpenSecrets(dir, other); err == nil {
		t.Fatal("store opened under another key")
	}
}

// A clerk's Secrets live in its own directory, closed to every other uid: a
// directory or file open to others, a symlink, or one owned by another uid is
// refused, so no clerk process loads another's store (CLK-1). As root the
// test also shows another uid cannot open the file.
func TestSecretsFileIsTheClerksOwn(t *testing.T) {
	dir := clerkDir(t)
	sec, _ := OpenSecrets(dir, testSealer())
	if err := sec.Put("web", clerk.KindStatic, []byte("s")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, secretsName)
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("secrets file mode %v, want 0600", fi.Mode().Perm())
	}
	try := func(what string, mod, undo func()) {
		t.Helper()
		mod()
		defer undo()
		if _, err := OpenSecrets(dir, testSealer()); err == nil {
			t.Fatalf("%s: opened", what)
		}
	}
	try("directory open to others", func() { os.Chmod(dir, 0o755) }, func() { os.Chmod(dir, 0o700) })
	try("file open to others", func() { os.Chmod(path, 0o640) }, func() { os.Chmod(path, 0o600) })
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(dir, link)
	if _, err := OpenSecrets(link, testSealer()); err == nil {
		t.Fatal("opened through a symlinked directory")
	}
	if err := loadsWhole(dir); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		t.Log("not root: the other-uid cases need root")
		return
	}
	const nobody = 65534
	os.Chmod(filepath.Dir(dir), 0o755)
	out, err := exec.Command("setpriv", "--reuid", "65534", "--regid", "65534", "--clear-groups", "cat", path).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "denied") {
		t.Fatalf("uid %d read the file: %v %s", nobody, err, out)
	}
	try("directory owned by another uid", func() { os.Chown(dir, nobody, nobody) }, func() { os.Chown(dir, 0, 0) })
	try("file owned by another uid", func() { os.Chown(path, nobody, nobody) }, func() { os.Chown(path, 0, 0) })
}
