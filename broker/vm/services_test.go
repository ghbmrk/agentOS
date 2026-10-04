package vm

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
)

// REQ: ARC-5
// SPEC v0.12 IDs (PR #15; move into REQ when it merges): ARC-6

// recServices records Open and Close calls.
type recServices struct {
	root   string
	mu     sync.Mutex
	open   map[string]bool
	closed []string
	fail   bool
}

func (s *recServices) Open(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return "", errors.New("no socket")
	}
	s.open[id] = true
	return filepath.Join(s.root, id), nil
}

func (s *recServices) Close(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.open, id)
	s.closed = append(s.closed, id)
}

// TestARC6EachLaunchGetsItsOwnServicesDirectory: every start, restore, and
// fork hands the runtime that machine's own services directory, never its
// source's; removal closes it (V15).
func TestARC6EachLaunchGetsItsOwnServicesDirectory(t *testing.T) {
	e := newEnv(t, 4096)
	svc := &recServices{root: t.TempDir(), open: map[string]bool{}}
	e.cfg.Services = svc
	e.open()
	ctx := context.Background()
	e.create("m1", admission.Accepted, 256)
	_, err := e.m.Checkpoint(ctx, "m1")
	must(t, err)
	_, err = e.m.Fork(ctx, "m1", []string{"f1", "f2"})
	must(t, err)
	must(t, e.m.Rebuild(ctx, "m1"))
	for _, l := range e.rt.launches {
		if want := filepath.Join(svc.root, l.ID); l.Services != want {
			t.Errorf("launch of %s got services %q, want %q", l.ID, l.Services, want)
		}
	}
	must(t, e.m.Destroy(ctx, "f1"))
	if svc.open["f1"] {
		t.Fatal("destroy left f1's services open")
	}
	if !svc.open["m1"] || !svc.open["f2"] {
		t.Fatal("destroying f1 closed another machine's services")
	}
}

// TestARC6NoServicesNoStart: a machine whose services cannot be opened does
// not start, and its admission is released.
func TestARC6NoServicesNoStart(t *testing.T) {
	e := newEnv(t, 4096)
	svc := &recServices{root: t.TempDir(), open: map[string]bool{}, fail: true}
	e.cfg.Services = svc
	e.open()
	if _, err := e.m.Create(context.Background(), "m1", Spec{Image: "base", Class: admission.Accepted, MemMB: 256}); err == nil {
		t.Fatal("machine started without its services")
	}
	if len(e.rt.launches) != 0 {
		t.Fatal("runtime was started")
	}
	if len(e.m.Machines()) != 0 {
		t.Fatal("failed machine still listed")
	}
	svc.fail = false
	e.create("m1", admission.Accepted, 4096) // the whole capacity: the failed attempt released it
}
