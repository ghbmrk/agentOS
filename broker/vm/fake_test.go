package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
)

// fakeRuntime stands in for gVisor. Each machine's "memory" is one integer,
// which Checkpoint saves and Restore loads, so tests can tell a memory
// restore from a cold start. The guest's file writes go straight into the
// machine's upper layer, as they would through the overlay mount.
type fakeRuntime struct {
	mu       sync.Mutex
	running  map[string]Launch
	paused   map[string]bool
	mem      map[string]int
	launches []Launch
	kills    int
	failNext error
	failKill error           // Kill's error, after it kills
	onPause  func(id string) // runs as the guest is paused
	onCkpt   func(id string) // runs during a memory checkpoint
}

func newFake() *fakeRuntime {
	return &fakeRuntime{running: map[string]Launch{}, paused: map[string]bool{}, mem: map[string]int{}}
}

func (f *fakeRuntime) take() error {
	err := f.failNext
	f.failNext = nil
	return err
}

func (f *fakeRuntime) Start(_ context.Context, l Launch) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.take(); err != nil {
		return err
	}
	if _, ok := f.running[l.ID]; ok {
		return fmt.Errorf("fake: %s already running", l.ID)
	}
	f.running[l.ID], f.mem[l.ID] = l, 0
	f.launches = append(f.launches, l)
	return nil
}

func (f *fakeRuntime) Restore(_ context.Context, l Launch, image string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.take(); err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(image, "mem"))
	if err != nil {
		return err
	}
	n, _ := strconv.Atoi(string(b))
	f.running[l.ID], f.mem[l.ID] = l, n
	f.launches = append(f.launches, l)
	return nil
}

func (f *fakeRuntime) Pause(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.running[id]; !ok {
		return fmt.Errorf("fake: pause %s: not running", id)
	}
	if f.onPause != nil {
		f.onPause(id)
	}
	f.paused[id] = true
	return nil
}

func (f *fakeRuntime) Resume(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.paused, id)
	return nil
}

func (f *fakeRuntime) Checkpoint(_ context.Context, id, image string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.paused[id] {
		return errors.New("fake: checkpoint of a machine that is not paused")
	}
	if f.onCkpt != nil {
		f.onCkpt(id)
	}
	return os.WriteFile(filepath.Join(image, "mem"), []byte(strconv.Itoa(f.mem[id])), 0o600)
}

func (f *fakeRuntime) Kill(_ context.Context, l Launch) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.running[l.ID]; ok {
		f.kills++
	}
	delete(f.running, l.ID)
	delete(f.paused, l.ID)
	delete(f.mem, l.ID)
	return f.failKill
}

// work simulates guest computation: it changes the machine's memory.
func (f *fakeRuntime) work(id string, n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mem[id] += n
}

func (f *fakeRuntime) memOf(id string) (int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.running[id]
	return f.mem[id], ok
}

type env struct {
	t    *testing.T
	rt   *fakeRuntime
	adm  *admission.Controller
	m    *Manager
	img  string
	cfg  Config
	cgrp string
}

// preempter forwards to the manager once it exists (admission is built first).
type preempter struct{ m **Manager }

func (p preempter) Preempt(id string) error { return (*p.m).Preempt(id) }

func newEnv(t *testing.T, capacityMB int64) *env {
	t.Helper()
	e := &env{t: t, rt: newFake(), img: t.TempDir()}
	write(t, e.img, "etc/os-release", "image v1")
	write(t, e.img, "app/main", "main v1")
	adm, err := admission.New(admission.Config{CapacityMB: capacityMB, HeadroomMB: 0}, preempter{&e.m})
	must(t, err)
	e.adm = adm
	e.cfg = Config{
		StateDir:  filepath.Join(t.TempDir(), "state"),
		Images:    map[string]string{"base": e.img},
		Runtime:   e.rt,
		Admit:     e.adm,
		NoCgroups: true,
		// Disk quota tests set Quota (diskquota_test.go).
		NoQuota: true,
		// Unit tests don't depend on the host's disk; RES-4 tests set this.
		FreeBytes: func(string) (int64, error) { return 1 << 50, nil },
	}
	e.open()
	return e
}

func (e *env) open() {
	e.t.Helper()
	m, err := Open(context.Background(), e.cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	e.m = m
}

func (e *env) create(id string, c admission.Class, mb int64) Machine {
	e.t.Helper()
	mc, err := e.m.Create(context.Background(), id, Spec{Image: "base", Class: c, MemMB: mb})
	if err != nil {
		e.t.Fatalf("create %s: %v", id, err)
	}
	return mc
}

// guestWrite is a guest writing a file in its root.
func (e *env) guestWrite(id, rel, s string) {
	e.t.Helper()
	write(e.t, filepath.Join(e.cfg.StateDir, "machines", id, "disk", "upper"), rel, s)
}

// guestRead returns what the guest sees at rel ("" if absent).
func (e *env) guestRead(id, rel string) string {
	e.t.Helper()
	for _, root := range []string{filepath.Join(e.cfg.StateDir, "machines", id, "disk", "upper"), e.img} {
		if b, err := os.ReadFile(filepath.Join(root, rel)); err == nil {
			return string(b)
		}
	}
	return ""
}

func write(t *testing.T, root, rel, s string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// upper is a path in machine id's layer, for a guest's deletions.
func (e *env) upper(id, rel string) string {
	return filepath.Join(e.cfg.StateDir, "machines", id, "disk", "upper", rel)
}

// Exec runs a few commands against the machine's upper layer: "echo"
// prints its arguments, "write PATH" stores stdin, "cat PATH" prints the
// file, "sleep" waits for the context, "hang" ignores it for a second, and
// "exit N" exits N.
func (f *fakeRuntime) Exec(ctx context.Context, id string, c Command) (ExecResult, error) {
	f.mu.Lock()
	l, ok := f.running[id]
	f.mu.Unlock()
	if !ok {
		return ExecResult{}, fmt.Errorf("fake: exec %s: not running", id)
	}
	out := func(b []byte) ExecResult {
		r := ExecResult{Stdout: b}
		if c.MaxOutput > 0 && len(b) > c.MaxOutput {
			r.Stdout, r.Truncated = b[:c.MaxOutput], true
		}
		return r
	}
	switch a := c.Argv; a[0] {
	case "echo":
		return out([]byte(strings.Join(a[1:], " ") + "\n")), nil
	case "write":
		p := filepath.Join(l.Upper, a[1])
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return ExecResult{}, err
		}
		return ExecResult{}, os.WriteFile(p, c.Stdin, 0o644)
	case "cat":
		for _, root := range []string{l.Upper, l.Lower} {
			if b, err := os.ReadFile(filepath.Join(root, a[1])); err == nil {
				return out(b), nil
			}
		}
		return ExecResult{ExitCode: 1, Stderr: []byte("no such file\n")}, nil
	case "sleep":
		<-ctx.Done()
		return ExecResult{ExitCode: -1}, ctx.Err()
	case "hang": // a runtime that ignores cancellation
		time.Sleep(time.Second)
		return ExecResult{}, ctx.Err()
	case "exit":
		n, _ := strconv.Atoi(a[1])
		return ExecResult{ExitCode: n}, nil
	}
	return ExecResult{ExitCode: 127, Stderr: []byte("not found\n")}, nil
}
