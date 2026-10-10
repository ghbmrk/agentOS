package vm

// REQ: CAP-12, CAP-8, CAP-1, ARC-6

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
)

// inside reports whether path a is b or lies under it.
func inside(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	rel, err := filepath.Rel(b, a)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../") && !filepath.IsAbs(rel)
}

// A guest, its forks and its workers running at once share no host path
// the runtime gives them, other than the read-only image: no machine
// directory, writable layer, root, cgroup or services directory of one lies
// in another's. Workers get no services directory at all. Information can
// move between them only through broker tools (CAP-12).
func TestCAP12MachinesRunningTogetherShareNoHostPath(t *testing.T) {
	e := newEnv(t, 8192)
	svc := &recServices{root: t.TempDir(), open: map[string]bool{}}
	e.cfg.Services = svc
	e.open()
	guest := e.create("guest", admission.Accepted, 256)
	_, err := e.m.Checkpoint(bg, "guest")
	must(t, err)
	_, err = e.m.Fork(bg, "guest", []string{"f1", "f2"})
	must(t, err)
	for _, id := range []string{"wk-1", "wk-2", "wk-3"} {
		_, err := e.m.CreateWorker(bg, id, guest.Lineage, workerSpec(Private))
		must(t, err)
	}

	e.rt.mu.Lock()
	running := make([]Launch, 0, len(e.rt.running))
	for _, l := range e.rt.running {
		running = append(running, l)
	}
	e.rt.mu.Unlock()
	if len(running) != 6 {
		t.Fatalf("%d machines running, want 6", len(running))
	}
	paths := func(l Launch) map[string]string {
		return map[string]string{"dir": l.Dir, "upper": l.Upper, "work": l.Work, "root": l.Root, "cgroup": l.Cgroup, "services": l.Services}
	}
	for _, a := range running {
		if a.Lower != e.img {
			t.Errorf("%s's lower layer is %q, want the read-only image", a.ID, a.Lower)
		}
		worker := strings.HasPrefix(a.ID, WorkerPrefix)
		if worker != (a.Services == "") {
			t.Errorf("%s: services %q; want one only for a non-worker", a.ID, a.Services)
		}
		for _, b := range running {
			if a.ID == b.ID {
				continue
			}
			for ka, pa := range paths(a) {
				for kb, pb := range paths(b) {
					if inside(pa, pb) {
						t.Errorf("%s's %s %q lies in %s's %s %q", a.ID, ka, pa, b.ID, kb, pb)
					}
				}
			}
		}
	}
}
