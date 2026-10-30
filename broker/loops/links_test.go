package loops

// REQ: KRN-2

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The corpus and the machine's cgroup files are read without following a
// link planted at the name (REV-CHK-links-daemon-a, #3944).
func TestPlantedLinksAreNotRead(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cg := t.TempDir()
	for _, f := range []string{"memory.max", "cpu.stat", "cpuset.cpus.effective"} {
		if err := os.Symlink(real, filepath.Join(cg, f)); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := cgroupInt(cg, "memory.max"); ok {
		t.Error("cgroupInt read through a link")
	}
	if _, err := cgroupCounter(cg, "cpu.stat", ""); !errors.Is(err, syscall.ELOOP) {
		t.Errorf("cgroupCounter through a link: %v, want ELOOP", err)
	}
	if _, err := cpusEffective(cg); err == nil {
		t.Error("cpusEffective read through a link")
	}
	corpus := filepath.Join(dir, "items.json")
	if err := os.Symlink(real, corpus); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCorpus(corpus); !errors.Is(err, syscall.ELOOP) {
		t.Errorf("LoadCorpus through a link: %v, want ELOOP", err)
	}
}
