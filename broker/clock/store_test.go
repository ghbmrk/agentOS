package clock

// REQ: TIM-1

import (
	"bufio"
	"errors"
	"go/build"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestTIM1ClockImportsNoOldCore: the guard links none of the old core
// (D-139, #5147 a), so the kernel's process can read time through it.
func TestTIM1ClockImportsNoOldCore(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "tools", "old_core.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var old []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		if l := strings.TrimSpace(s.Text()); l != "" && !strings.HasPrefix(l, "#") {
			old = append(old, "github.com/ghbmrk/agentos/"+l)
		}
	}
	if len(old) == 0 {
		t.Fatal("tools/old_core.txt lists nothing")
	}
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range pkg.Imports {
		for _, o := range old {
			if imp == o || strings.HasPrefix(imp, o+"/") {
				t.Errorf("broker/clock imports old core %s", imp)
			}
		}
	}
}

// restrictedSave makes a guard on path see a 2 h disagreement, so it saves
// a restriction, and returns the rig.
func restrictedSave(t *testing.T, path string, logf func(string, ...any)) *rig {
	t.Helper()
	r := newRig()
	r.carrier = r.carrier.Add(2 * time.Hour)
	g := r.guard(t, func(c *Config) {
		c.StatePath = path
		if logf != nil {
			c.Logf = logf
		}
	})
	g.Check(bg)
	return r
}

func TestTIM1StaleTempReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clock.json")
	if err := os.WriteFile(path+".tmp", []byte("{half a write"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := restrictedSave(t, path, nil)
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("crash temporary still there: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", fi, err)
	}
	r.mu.Lock()
	r.carrier = time.Time{}
	r.mu.Unlock()
	g := r.guard(t, func(c *Config) { c.StatePath = path })
	if _, err := g.Now(bg); !errors.Is(err, ErrRestricted) {
		t.Fatalf("after restart: %v", err)
	}
}

func TestTIM1SaveRefusesSharedDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "clock.json")
	var mu sync.Mutex
	var logged []string
	restrictedSave(t, path, func(f string, a ...any) {
		mu.Lock()
		logged = append(logged, f)
		mu.Unlock()
	})
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state written into a directory other uids can write: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, l := range logged {
		if strings.Contains(l, "state not saved") {
			return
		}
	}
	t.Fatalf("failed save not logged: %q", logged)
}
