// Package cgroup enforces agent-machine memory budgets with cgroup v2 and
// reads memory pressure (SPEC RES-1, RES-2). It also sets CPU and I/O
// weights and a per-machine process cap, so no machine can starve the
// broker of CPU, disk or tasks.
//
// It is file I/O only: no child processes and no system calls beyond the
// file system, so it can sit on the broker's control path (ARC-2). Each
// machine gets one group. memory.max is its declared budget and memory.high
// sits below it, so the kernel throttles the machine before the hard limit,
// where S3 measured a reclaim stall instead of an OOM kill. Swap is off.
package cgroup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Group is one cgroup v2 directory.
type Group struct{ Path string }

// Limits is a machine's memory budget in bytes.
type Limits struct {
	MaxBytes int64 // hard limit (memory.max)
	// HighBytes is the throttle point (memory.high). Zero means MaxBytes
	// minus 1/16, which keeps the machine out of the hard-limit stall.
	HighBytes int64
	// MinBytes is protected memory (memory.min), used by Component only.
	MinBytes int64
	// CPUWeight and IOWeight are the group's share against its siblings
	// under contention (cpu.weight, io.weight: 1..10000, kernel default
	// 100). Child requires both; Component leaves zero at the default.
	CPUWeight, IOWeight int
	// Pids caps the group's tasks (pids.max), threads included. Child
	// requires it; Component writes it only when set.
	Pids int64
}

// Controllers are the controllers Open requires and enables for children.
var Controllers = []string{"cpu", "io", "memory", "pids"}

// ErrNotV2 means the path is not a usable cgroup v2 group.
var ErrNotV2 = errors.New("cgroup: not a cgroup v2 group with the cpu, io, memory and pids controllers")

// Open checks that path is a cgroup v2 group whose children can use every
// controller in Controllers, enabling the missing ones for them in one
// write (the kernel applies it all or nothing).
func Open(path string) (*Group, error) {
	ctl, err := os.ReadFile(filepath.Join(path, "cgroup.controllers"))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrNotV2, path)
	}
	for _, c := range Controllers {
		if !hasWord(string(ctl), c) {
			return nil, fmt.Errorf("%w: %s lacks %s", ErrNotV2, path, c)
		}
	}
	g := &Group{Path: path}
	sub, err := os.ReadFile(filepath.Join(path, "cgroup.subtree_control"))
	if err != nil {
		return nil, err
	}
	var enable []string
	for _, c := range Controllers {
		if !hasWord(string(sub), c) {
			enable = append(enable, "+"+c)
		}
	}
	if len(enable) > 0 {
		if err := g.write("cgroup.subtree_control", strings.Join(enable, " ")); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// Child creates (or reuses) child name with limits applied.
func (g *Group) Child(name string, l Limits) (*Group, error) {
	if name == "" || strings.ContainsAny(name, "/.") {
		return nil, fmt.Errorf("cgroup: bad group name %q", name)
	}
	if l.MaxBytes <= 0 {
		return nil, fmt.Errorf("cgroup: %s: a budget is required (RES-2)", name)
	}
	if l.Pids <= 0 || l.CPUWeight == 0 || l.IOWeight == 0 {
		return nil, fmt.Errorf("cgroup: %s: a process cap and CPU and I/O weights are required (RES-2)", name)
	}
	shares, err := l.shares()
	if err != nil {
		return nil, fmt.Errorf("cgroup: %s: %w", name, err)
	}
	high := l.HighBytes
	if high <= 0 || high > l.MaxBytes {
		high = l.MaxBytes - l.MaxBytes/16
	}
	c := &Group{Path: filepath.Join(g.Path, name)}
	if err := os.Mkdir(c.Path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	// memory.max first, so high is never above max while being set.
	kvs := append([][2]string{
		{"memory.max", strconv.FormatInt(l.MaxBytes, 10)},
		{"memory.high", strconv.FormatInt(high, 10)},
		{"memory.swap.max", "0"},
		// An OOM kill takes the whole machine, never one process of it, so
		// the sandbox is never left half alive.
		{"memory.oom.group", "1"},
	}, shares...)
	if err := c.writeAll(kvs); err != nil {
		c.Remove()
		return nil, err
	}
	return c, nil
}

// shares are l's weight and process-cap files, for the weights and cap
// that are set. A weight outside the kernel's 1..10000 is an error.
func (l Limits) shares() ([][2]string, error) {
	var kvs [][2]string
	for _, w := range []struct {
		file, prefix string
		v            int
	}{{"cpu.weight", "", l.CPUWeight}, {"io.weight", "default ", l.IOWeight}} {
		if w.v == 0 {
			continue
		}
		if w.v < 1 || w.v > 10000 {
			return nil, fmt.Errorf("%s %d outside 1..10000", w.file, w.v)
		}
		kvs = append(kvs, [2]string{w.file, w.prefix + strconv.Itoa(w.v)})
	}
	if l.Pids > 0 {
		kvs = append(kvs, [2]string{"pids.max", strconv.FormatInt(l.Pids, 10)})
	}
	return kvs, nil
}

// writeAll writes each file in order. Two files a kernel may lack are
// skipped: memory.swap.max without swap accounting (there is no swap to
// use), and io.weight without iocost (BFQ's io.bfq.weight is not written);
// the CPU weight and process cap still hold (budget R12).
func (g *Group) writeAll(kvs [][2]string) error {
	for _, kv := range kvs {
		if err := g.write(kv[0], kv[1]); err != nil {
			if (kv[0] == "memory.swap.max" || kv[0] == "io.weight") && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
	}
	return nil
}

// Populated reports whether any process is still in the group.
func (g *Group) Populated() (bool, error) {
	v, err := g.event("populated")
	return v == 1, err
}

// Freeze stops every process in the group and returns once the kernel
// reports the group frozen, or ctx ends.
func (g *Group) Freeze(ctx context.Context) error {
	if err := g.write("cgroup.freeze", "1"); err != nil {
		return err
	}
	return g.waitEvent(ctx, "frozen", 1)
}

// Thaw undoes Freeze.
func (g *Group) Thaw() error { return g.write("cgroup.freeze", "0") }

// Kill kills every process in the group and returns once it is empty, so the
// memory charged to it has been released (cgroup.kill, Linux 5.14+).
func (g *Group) Kill(ctx context.Context) error {
	if err := g.write("cgroup.kill", "1"); err != nil {
		return err
	}
	return g.waitEvent(ctx, "populated", 0)
}

// Remove deletes an empty group. A missing group is not an error.
func (g *Group) Remove() error {
	err := os.Remove(g.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Pressure is the group's memory pressure: PSI "some avg10", in percent.
func (g *Group) Pressure() (float64, error) {
	return ReadPressure(filepath.Join(g.Path, "memory.pressure"))
}

// ReadPressure parses a PSI file (memory.pressure or /proc/pressure/memory)
// and returns "some avg10", the share of the last 10 s in which at least one
// task stalled on memory.
func ReadPressure(path string) (float64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) == 0 || fields[0] != "some" {
			continue
		}
		for _, kv := range fields[1:] {
			if v, ok := strings.CutPrefix(kv, "avg10="); ok {
				p, err := strconv.ParseFloat(v, 64)
				if err != nil || p < 0 || math.IsNaN(p) {
					return 0, fmt.Errorf("cgroup: bad PSI value %q in %s", v, path)
				}
				return p, nil
			}
		}
	}
	if err := s.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("cgroup: no \"some avg10\" in %s", path)
}

// PressureSource returns an admission pressure input for path. A source that
// worked and then fails reads as maximal pressure, so admission fails closed
// (only foreground is admitted) rather than admitting blind. ok is false when
// the file cannot be read at all, i.e. the kernel has no PSI.
func PressureSource(path string) (read func() float64, ok bool) {
	if _, err := ReadPressure(path); err != nil {
		return nil, false
	}
	return func() float64 {
		p, err := ReadPressure(path)
		if err != nil {
			return math.Inf(1)
		}
		return p
	}, true
}

func (g *Group) write(file, v string) error {
	return os.WriteFile(filepath.Join(g.Path, file), []byte(v), 0o644)
}

func (g *Group) event(key string) (int, error) {
	b, err := os.ReadFile(filepath.Join(g.Path, "cgroup.events"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, key+" "); ok {
			return strconv.Atoi(strings.TrimSpace(v))
		}
	}
	return 0, fmt.Errorf("cgroup: no %q in %s/cgroup.events", key, g.Path)
}

// waitEvent polls cgroup.events. Polling at 1 ms keeps this package free of
// inotify system calls; preemption targets are hundreds of milliseconds.
func (g *Group) waitEvent(ctx context.Context, key string, want int) error {
	t := time.NewTicker(time.Millisecond)
	defer t.Stop()
	for {
		v, err := g.event(key)
		if err != nil {
			return err
		}
		if v == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("cgroup: %s: waiting for %s=%d: %w", g.Path, key, want, ctx.Err())
		case <-t.C:
		}
	}
}

func hasWord(s, w string) bool {
	for _, f := range strings.Fields(s) {
		if f == w {
			return true
		}
	}
	return false
}
