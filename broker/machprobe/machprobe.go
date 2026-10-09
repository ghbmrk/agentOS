// Package machprobe is LOOP-7's in-guest tamper and pressure scripts
// (P3-4b-4b). It runs inside an agent machine with guest authority only.
// The scripts are fixed (D-067): they write a fixed marker beside the
// paths they are given and apply bounded CPU, memory, disk and process
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
	"regexp"
	"runtime"
	"time"

	"github.com/ghbmrk/agentos/broker/childproc"
)

// Marker starts what a tamper write puts in a path; the round's nonce
// follows it.
const Marker = "agentos-tamper-probe "

// nonce is the broker's per-round marker: lowercase hex, so it is safe in
// a file name.
var nonce = regexp.MustCompile(`^[0-9a-f]{1,64}$`)

// Sibling is the name of the file a tamper write creates for a round:
// the broker looks for it, and removes it, by this name.
func Sibling(round string) string { return ".agentos-tamper-" + round }

// Tamper tries to change each path with the round's nonce without
// touching what is there (P3-4b-4c-restore): it creates a new sibling
// named by Sibling, exclusively, holding the marker; a file's sibling
// goes in the file's directory, a directory's inside it. It never opens
// a path for writing, truncates or removes one, and skips a path it
// cannot see. It returns how many writes the guest's own view accepted;
// a malformed nonce writes nothing.
func Tamper(round string, paths []string) int {
	if !nonce.MatchString(round) {
		return 0
	}
	n := 0
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		dir := filepath.Dir(p)
		if fi.IsDir() {
			dir = p
		}
		f, err := os.OpenFile(filepath.Join(dir, Sibling(round)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			continue
		}
		_, err = f.WriteString(Marker + round + "\n")
		if f.Close() == nil && err == nil {
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
// releases it. A duration, or the kind's options, unset, zero or negative
// is an error before anything is pressed.
func Press(ctx context.Context, kind string, d time.Duration, o Options) error {
	if d <= 0 {
		return errors.New("machprobe: no duration")
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	switch kind {
	case "cpu":
		for range runtime.NumCPU() {
			go spin(ctx)
		}
	case "memory":
		if o.MemMB <= 0 {
			return errors.New("machprobe: no memory size")
		}
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
		if o.Dir == "" {
			return errors.New("machprobe: no disk directory")
		}
		p := filepath.Join(o.Dir, "agentos-pressure")
		defer os.Remove(p)
		if err := fill(p, o.DiskMB); err != nil {
			return err
		}
	case "processes":
		if len(o.Child) == 0 || o.Child[0] == "" {
			return errors.New("machprobe: no child command")
		}
		if o.Procs <= 0 {
			return errors.New("machprobe: no process count")
		}
		var ps []*childproc.Cmd
		defer func() {
			for _, p := range ps {
				p.Kill()
				p.Wait()
			}
		}()
		for range o.Procs {
			// An empty environment: the child only idles, and the
			// caller's would otherwise pass to it (P3-4b-3r-env).
			p := childproc.Command(context.Background(), childproc.NewEnv(), childproc.Options{}, o.Child[0], o.Child[1:]...)
			if err := p.Start(); err != nil {
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
// the pressure the round wants. A size that is not positive is an error.
func fill(path string, mb int) error {
	if mb <= 0 {
		return errors.New("machprobe: no disk size")
	}
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
