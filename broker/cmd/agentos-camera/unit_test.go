package main

// REQ: CLK-1, NET-2, RES-2

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/camera"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

// TestDecodersLeaveTheUnitsGroup: before anything else the clerk moves
// itself into its leaf of -cgroup, and its decoders run rootless under
// runsc with -runsc-root's state (CAM-host-11).
func TestDecodersLeaveTheUnitsGroup(t *testing.T) {
	cg := t.TempDir()
	rt, err := decoders(config{runsc: "/r", runscRoot: "/rr", cgr: cg})
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(cg, leaf, "cgroup.procs")); err != nil || string(b) != "0" {
		t.Fatalf("leaf's cgroup.procs = %q, %v; want the clerk itself (0)", b, err)
	}
	if !rt.Rootless || rt.Bin != "/r" || rt.StateDir != "/rr" || rt.Platform != "systrap" {
		t.Fatalf("runtime %+v", rt)
	}
	// A group the clerk cannot join refuses the start.
	if _, err := decoders(config{cgr: filepath.Join(cg, "missing")}); err == nil {
		t.Fatal("a missing group was joined")
	}
}

// TestDecoderStartsInTheUnitsSandbox runs inside the image's own
// agentos-keeper-camera.service, as the clerk's user (its User=, which
// tests/test_image_camera.py holds), with only ExecStart=
// and the key's OpenFile= replaced (CI's camera unit step): the clerk's
// group is the unit's delegated group, which the unit's -cgroup names; it
// leaves it for its leaf, and a decoder sandbox starts under runsc beside
// it, held to its memory cap, with no network, and is gone after its stop.
func TestDecoderStartsInTheUnitsSandbox(t *testing.T) {
	bin, cg, state, root := os.Getenv("AGENTOS_RUNSC"), os.Getenv("AGENTOS_CAMERA_CGROUP"),
		os.Getenv("AGENTOS_RUNSC_ROOT"), os.Getenv("AGENTOS_DECODE_ROOT")
	if bin == "" || cg == "" || state == "" || root == "" {
		t.Skip("set AGENTOS_RUNSC, AGENTOS_CAMERA_CGROUP, AGENTOS_RUNSC_ROOT and AGENTOS_DECODE_ROOT, and run in the camera unit (CI)")
	}
	if got := ownCgroup(t); got != cg {
		t.Fatalf("the clerk runs in %s; the unit's -cgroup names %s", got, cg)
	}
	rt, err := decoders(config{runsc: bin, runscRoot: state, cgr: cg})
	if err != nil {
		t.Fatal(err)
	}
	if got := ownCgroup(t); got != filepath.Join(cg, leaf) {
		t.Fatalf("after the join the clerk runs in %s", got)
	}
	start := camera.GVisor(rt)
	s := gvisor.Stream{Name: "camdecode-unit", Root: root, Argv: []string{"/oneshot", "echo"},
		MemBytes: camera.DefaultDecodeMem, Cgroup: cg}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p, err := start(ctx, s)
	if err != nil {
		t.Fatalf("decoder sandbox: %v", err)
	}
	group := filepath.Join(cg, "stream-"+s.Name)
	if b, err := os.ReadFile(filepath.Join(group, "memory.max")); err != nil || strings.TrimSpace(string(b)) != strconv.Itoa(camera.DefaultDecodeMem) {
		t.Errorf("the sandbox's memory.max = %q, %v", b, err)
	}
	if _, err := p.In().Write([]byte("frame\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(p.Out()).ReadString('\n')
	if err != nil || line != "frame\n" {
		t.Fatalf("decoder answered %q, %v", line, err)
	}
	p.Stop()
	<-p.Done()
	if _, err := os.Stat(group); !os.IsNotExist(err) {
		t.Errorf("the sandbox's group is left: %v", err)
	}

	// No network in the sandbox, though the unit reaches the home ranges.
	s.Name, s.Argv = "camdecode-net", []string{"/oneshot", "net", "192.168.1.1:80"}
	p, err = start(ctx, s)
	if err != nil {
		t.Fatalf("decoder sandbox: %v", err)
	}
	p.In().(io.Closer).Close()
	out, _ := io.ReadAll(p.Out())
	<-p.Done()
	if !strings.Contains(string(out), "dial failed") {
		t.Errorf("the decoder dialled out: %q", out)
	}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(l, "iface ") && l != "iface lo" {
			t.Errorf("the decoder sees %q", l)
		}
	}
}

// ownCgroup is this process's cgroup v2 group, as a path under
// /sys/fs/cgroup.
func ownCgroup(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(l, "0::"); ok {
			return filepath.Join("/sys/fs/cgroup", p)
		}
	}
	t.Fatalf("no cgroup v2 line in %q", b)
	return ""
}
