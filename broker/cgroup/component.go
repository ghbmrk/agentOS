package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Component creates (or reuses) the group of one of the host's declared
// components (RES-2): the broker, local inference, the credentialed browser,
// or the agent-machine pool. A component with MaxBytes gets a hard limit
// with memory.high 1/16 below it, as machines do. A component with only
// MinBytes gets no hard limit and protected memory instead: that is the
// broker, which must never be OOM-killed by its own group or lose its pages
// to reclaim. Unlike Child, memory.oom.group stays off, because a component
// holds independent children (the pool holds every machine).
func (g *Group) Component(name string, l Limits) (*Group, error) {
	if name == "" || strings.ContainsAny(name, "/.") {
		return nil, fmt.Errorf("cgroup: bad group name %q", name)
	}
	if l.MaxBytes <= 0 && l.MinBytes <= 0 {
		return nil, fmt.Errorf("cgroup: %s: a budget or a protection is required (RES-2)", name)
	}
	shares, err := l.shares()
	if err != nil {
		return nil, fmt.Errorf("cgroup: %s: %w", name, err)
	}
	c := &Group{Path: filepath.Join(g.Path, name)}
	if err := os.Mkdir(c.Path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	var kvs [][2]string
	if l.MaxBytes > 0 {
		high := l.HighBytes
		if high <= 0 || high > l.MaxBytes {
			high = l.MaxBytes - l.MaxBytes/16
		}
		kvs = append(kvs,
			[2]string{"memory.max", strconv.FormatInt(l.MaxBytes, 10)},
			[2]string{"memory.high", strconv.FormatInt(high, 10)})
	} else {
		kvs = append(kvs, [2]string{"memory.max", "max"})
	}
	if l.MinBytes > 0 {
		kvs = append(kvs, [2]string{"memory.min", strconv.FormatInt(l.MinBytes, 10)})
	}
	kvs = append(kvs, [2]string{"memory.swap.max", "0"})
	if err := c.writeAll(append(kvs, shares...)); err != nil {
		return nil, err
	}
	return c, nil
}

// Join moves process pid into the group.
func (g *Group) Join(pid int) error {
	return g.write("cgroup.procs", strconv.Itoa(pid))
}

// OOMKills is the number of processes the kernel has OOM-killed in the group
// and its descendants (memory.events oom_kill).
func (g *Group) OOMKills() (int64, error) {
	b, err := os.ReadFile(filepath.Join(g.Path, "memory.events"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "oom_kill "); ok {
			return strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		}
	}
	return 0, fmt.Errorf("cgroup: no oom_kill in %s/memory.events", g.Path)
}
