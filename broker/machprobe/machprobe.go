// Package machprobe is LOOP-7's in-guest tamper and pressure scripts
// (P3-4b-4b). It runs inside an agent machine with guest authority only.
// The scripts are fixed (D-067): they write a fixed marker to the paths
// they are given and apply bounded CPU, memory, disk and process
// pressure. Whether a write landed, and whether the broker held its
// targets, is judged broker-side (loops.TamperProbe, loops.ExhaustProbe);
// nothing this package says is trusted.
package machprobe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Marker is what a tamper write puts in a path.
const Marker = "agentos-tamper-probe\n"

// Tamper tries to change each path: a directory gets a new file, anything
// else is overwritten. It returns how many writes the guest's own view
// accepted.
func Tamper(paths []string) int {
	n := 0
	for _, p := range paths {
		target := p
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			target = filepath.Join(p, ".agentos-tamper")
		}
		if os.WriteFile(target, []byte(Marker), 0o644) == nil {
			n++
		}
	}
	return n
}

// Kinds are the pressures Press applies.
var Kinds = []string{"cpu", "memory", "disk", "processes"}

// Options bounds the pressure. Memory and disk stay under the machine's
// limits so the round measures the broker, not an OOM kill; Child is the
// command each pressure process runs (it should idle until killed).
type Options struct {
	MemMB  int
	DiskMB int
	Dir    string // where disk pressure writes
	Procs  int
	Child  []string
}

// Press applies one kind of pressure until d passes or ctx ends, then
// releases it.
func Press(ctx context.Context, kind string, d time.Duration, o Options) error {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	switch kind {
	case "cpu":
		for range runtime.NumCPU() {
			go spin(ctx)
		}
	case "memory":
		held := make([][]byte, 0, o.MemMB)
		for range o.MemMB {
			b := make([]byte, 1<<20)
			for i := 0; i < len(b); i += 4096 {
				b[i] = 1
			}
			held = append(held, b)
		}
		defer runtime.KeepAlive(held)
	case "disk":
		p := filepath.Join(o.Dir, "agentos-pressure")
		defer os.Remove(p)
		if err := fill(p, o.DiskMB); err != nil {
			return err
		}
	case "processes":
		if len(o.Child) == 0 {
			return errors.New("machprobe: no child command")
		}
		var ps []*os.Process
		defer func() {
			for _, p := range ps {
				p.Kill()
				p.Wait()
			}
		}()
		for range o.Procs {
			p, err := os.StartProcess(o.Child[0], o.Child, &os.ProcAttr{})
			if err != nil {
				break // the process limit stopped it: pressure reached
			}
			ps = append(ps, p)
		}
	default:
		return fmt.Errorf("machprobe: unknown pressure %q", kind)
	}
	<-ctx.Done()
	return nil
}

func spin(ctx context.Context) {
	for x := 0; ctx.Err() == nil; x++ {
		for range 1 << 16 {
			x ^= x << 1
		}
	}
}

// fill writes up to mb MiB; a full disk or quota ends it early, which is
// the pressure the round wants.
func fill(path string, mb int) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 1<<20)
	for i := range buf {
		buf[i] = byte(i) | 1
	}
	for range mb {
		if _, err := f.Write(buf); err != nil {
			return nil
		}
	}
	return f.Sync()
}
