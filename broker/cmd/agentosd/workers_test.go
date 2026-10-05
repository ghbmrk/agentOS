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
