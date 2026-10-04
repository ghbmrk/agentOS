// Package cgroup enforces agent-machine memory budgets with cgroup v2 and
// reads memory pressure (SPEC RES-1, RES-2).
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
}

// ErrNotV2 means the path is not a usable cgroup v2 group.
var ErrNotV2 = errors.New("cgroup: not a cgroup v2 group with the memory controller")

// Open checks that path is a cgroup v2 group whose children can use the
// memory controller, enabling it for them if needed.
func Open(path string) (*Group, error) {
	ctl, err := os.ReadFile(filepath.Join(path, "cgroup.controllers"))
	if err != nil || !hasWord(string(ctl), "memory") {
		return nil, fmt.Errorf("%w: %s", ErrNotV2, path)
	}
	g := &Group{Path: path}
	sub, err := os.ReadFile(filepath.Join(path, "cgroup.subtree_control"))
	if err != nil {
		return nil, err
	}
	if !hasWord(string(sub), "memory") {
		if err := g.write("cgroup.subtree_control", "+memory"); err != nil {
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
	high := l.HighBytes
	if high <= 0 || high > l.MaxBytes {
		high = l.MaxBytes - l.MaxBytes/16
	}
	c := &Group{Path: filepath.Join(g.Path, name)}
	if err := os.Mkdir(c.Path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	// memory.max first, so high is never above max while being set.
	for _, kv := range [][2]string{
		{"memory.max", strconv.FormatInt(l.MaxBytes, 10)},
		{"memory.high", strconv.FormatInt(high, 10)},
		{"memory.swap.max", "0"},
		// An OOM kill takes the whole machine, never one process of it, so
		// the sandbox is never left half alive.
		{"memory.oom.group", "1"},
	} {
		if err := c.write(kv[0], kv[1]); err != nil {
			if kv[0] == "memory.swap.max" && errors.Is(err, os.ErrNotExist) {
				continue // kernel without swap accounting: there is no swap to use
			}
			c.Remove()
			return nil, err
		}
	}
	return c, nil
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
