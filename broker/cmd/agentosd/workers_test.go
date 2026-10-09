package main

// REQ: CAP-8, OP-6, RES-4, CAP-1

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/daemon"
)

// Worker tools are offered only with a registered worker image.
func TestCAP8WorkerToolsNeedARegisteredImage(t *testing.T) {
	imgs := images{"base": "/img"}
	if workerTools(nil, imgs, "", "sleep infinity", 2048, workerGates{}) != nil {
		t.Fatal("worker tools offered with no worker image")
	}
	if workerTools(nil, imgs, "missing", "sleep infinity", 2048, workerGates{}) != nil {
		t.Fatal("worker tools offered with an unregistered image")
	}
	if workerTools(nil, imgs, "base", "sleep infinity", 2048, workerGates{}) == nil {
		t.Fatal("worker tools missing with a registered image")
	}
}

// The tools refuse commands while the engine's STOP holds: workerTools
// wires the predicate it is given (security R2 on #146).
func TestOP6WorkerToolsTakeTheStopPredicate(t *testing.T) {
	stopped := false
	wt := workerTools(nil, images{"base": "/img"}, "base", "sleep infinity", 2048, workerGates{stopped: func() bool { return stopped }})
	if wt.Stopped == nil || wt.Stopped() {
		t.Fatal("worker tools do not read STOP")
	}
	stopped = true
	if !wt.Stopped() {
		t.Fatal("worker tools missed STOP")
	}
}

type ender struct{ n atomic.Int32 }

func (e *ender) EndCommands() int { e.n.Add(1); return 1 }

type noReap struct{}

func (noReap) Reap(context.Context) []string { return nil }

// While STOP holds, the reaper ends worker commands on every tick; without
// STOP it ends none (security R2 on #146, OP-6).
func TestOP6ReaperEndsCommandsWhileStopped(t *testing.T) {
	var stopped atomic.Bool
	e := &ender{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reapWorkers(ctx, noReap{}, e, stopped.Load, 5*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	if e.n.Load() != 0 {
		t.Fatal("commands ended without STOP")
	}
	stopped.Store(true)
	deadline := time.Now().Add(2 * time.Second)
	for e.n.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the reaper did not end commands under STOP")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// -worker-layer-mb: MiB to bytes, 0 or less no cap, huge values clamped
// instead of overflowing (security R3 on #146, RES-4).
func TestRES4WorkerLayerFlag(t *testing.T) {
	for _, c := range []struct{ mb, want int64 }{
		{4096, 4096 << 20}, {1, 1 << 20}, {0, 0}, {-5, 0}, {1 << 62, 1 << 50},
	} {
		if got := workerLayerBytes(c.mb); got != c.want {
			t.Errorf("workerLayerBytes(%d) = %d, want %d", c.mb, got, c.want)
		}
	}
}

// The tools size forks from admission's room and measured free memory:
// MemAvailable less the headroom (CAP-1).
func TestCAP1WorkerToolsReadRoomAndMeasuredMemory(t *testing.T) {
	p := filepath.Join(t.TempDir(), "meminfo")
	if err := os.WriteFile(p, []byte("MemTotal: 8000000 kB\nMemAvailable: 2097152 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	room := func(c admission.Class) int64 { return 777 }
	wt := workerTools(nil, images{"base": "/img"}, "base", "sleep infinity", 2048, workerGates{room: room, avail: measuredFree(p, 600)})
	if wt.Free == nil || wt.Free(admission.Experiment) != 777 {
		t.Fatal("worker tools do not read admission's room")
	}
	if mb, err := wt.Avail(); err != nil || mb != 2048-600 {
		t.Fatalf("measured free = %d, %v; want %d", mb, err, 2048-600)
	}
	if mb, err := measuredFree(p, 4096)(); err != nil || mb != 0 {
		t.Fatalf("headroom past MemAvailable = %d, %v; want 0", mb, err)
	}
	if _, err := measuredFree(filepath.Join(t.TempDir(), "none"), 0)(); err == nil {
		t.Fatal("missing meminfo read as a value")
	}
}

// main wires the daemon's own STOP, admission room and headroom into the
// worker gates (L3 SHOULD-7 on #158).
func TestCAP1BoxGatesReadTheRunningDaemon(t *testing.T) {
	dir := t.TempDir()
	cfg := daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := daemon.Run(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "meminfo")
	if err := os.WriteFile(p, []byte("MemAvailable: 2097152 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g := boxGates(d, p, cfg.Admission.HeadroomMB)
	if _, err := d.Admission().Admit(admission.Request{ID: "x", Class: admission.Experiment, MemMB: 1000}); err != nil {
		t.Fatal(err)
	}
	if got := g.room(admission.Experiment); got != 2900 {
		t.Fatalf("room = %d, want admission's 3900 - 1000", got)
	}
	if got := g.room(admission.Accepted); got != 3900 {
		t.Fatalf("accepted room = %d, want 3900 with the experiment preemptible", got)
	}
	if mb, err := g.avail(); err != nil || mb != 2048-600 {
		t.Fatalf("avail = %d, %v; want MemAvailable less 600 headroom", mb, err)
	}
	if g.stopped() {
		t.Fatal("stopped before STOP")
	}
	if _, err := d.Engine().Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if !g.stopped() {
		t.Fatal("stopped does not read the daemon's STOP")
	}
}
