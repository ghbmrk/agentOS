package loops

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/machprobe"
)

// LOOP-7 machine probes (P3-4b-4b): fixed scripts run with guest
// authority in a throwaway agent machine. The guest only acts; the
// verdict is taken broker-side from what the broker itself can see, so
// nothing the guest says is trusted (Security #515).
const (
	CheckTamper  Check = "tamper"     // a guest write changed an evaluator, grader or snapshot path
	CheckExhaust Check = "exhaustion" // guest pressure found no limit, or the broker missed its response or preemption target
)

// ownerWord is a subject name the owner reads as is.
var ownerWord = regexp.MustCompile(`^[a-z][a-z-]{0,31}$`)

// TamperTarget is one broker-held path a guest must not change. Name is
// the owner word reports use; Path is never reported. Guest lists further
// paths where the deployment shows the target inside a machine, such as
// a read-only mount; the guest tries those too.
type TamperTarget struct {
	Name  string
	Path  string
	Guest []string
}

// TamperProbe has a guest try to write each target where it might reach
// it, then checks broker-side that no target changed. Attempt runs the
// guest's scripted writes with the round's nonce as their marker and
// returns the machine that ran them, which must be a fresh one each round
// (P3-4b-4c-fresh); Journal records one refusal per unchanged target.
//
// Control is the round's positive control (P3-4b-4c-fresh): a broker-made
// directory the wiring mounts writable into the probe machine. Its paths
// go to the guest mixed in with the targets', and it must change every
// round, so a guest that skips its writes fails the round instead of
// closing findings. Its Name is unused; it is never checked, journaled or
// reported.
//
// Quiesce, when set, holds the broker's own writers of the targets (such
// as checkpoints into snapshots) from the first digest to the last, so a
// broker write is never taken for a guest's (P3-4b-4c-attrib).
type TamperProbe struct {
	Interval time.Duration
	Targets  []TamperTarget
	Control  TamperTarget
	Attempt  func(ctx context.Context, nonce string, paths []string) (machine string, err error)
	Journal  func(machine, target string) error
	Quiesce  func(ctx context.Context) (resume func(), err error)

	last lastMachine
}

func (p *TamperProbe) Check() Check         { return CheckTamper }
func (p *TamperProbe) Every() time.Duration { return p.Interval }

// lastMachine holds the machine a probe's previous round ran in, so a
// round in the same machine fails: a round must start from the signed
// image, not from what an earlier round's guest left (P3-4b-4c-fresh).
// Producing the fresh machine is the wiring's job; this holds it to it.
type lastMachine struct {
	mu sync.Mutex
	id string
}

// fresh records id as this round's machine and fails if it names no
// machine or the previous round's.
func (l *lastMachine) fresh(id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if id == "" {
		return errors.New("no machine named")
	}
	prev := l.id
	l.id = id
	if id == prev {
		return errors.New("same machine as the last round")
	}
	return nil
}

// tamperRoots are where a guest might reach a host path: as named, and
// through a process root link that escapes a chroot.
var tamperRoots = []string{"", "/proc/self/root", "/proc/1/root"}

// tamperNonce is a round's marker: fresh from the broker each round, so a
// write that lands always changes its target, even one that landed the
// same way last round (L3 #548 point 1), and the guest cannot predict it.
var tamperNonce = regexp.MustCompile(`^[0-9a-f]{32}$`)

func newTamperNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// tamperPaths are the paths a guest tries for t.
func tamperPaths(t TamperTarget) ([]string, error) {
	var paths []string
	for _, r := range tamperRoots {
		paths = append(paths, r+filepath.Clean(t.Path))
	}
	for _, g := range t.Guest {
		if !filepath.IsAbs(g) {
			return nil, errors.New("bad guest path")
		}
		paths = append(paths, filepath.Clean(g))
	}
	return paths, nil
}

// shuffle puts paths in an order drawn from crypto/rand, so the guest
// cannot tell the control's from the targets' by position.
func shuffle(paths []string) error {
	for i := len(paths) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		paths[i], paths[j.Int64()] = paths[j.Int64()], paths[i]
	}
	return nil
}

// Run holds the broker's writers, digests every target and the control,
// has a fresh machine's guest try them, and digests again. A changed
// target is a High finding; an unchanged one is a journaled refusal. An
// unchanged control, a reused machine, a missing target, a failed attempt
// or quiesce, or a refusal the journal does not take fails the run, which
// then closes nothing. The siblings the guest's writes left are removed.
func (p *TamperProbe) Run(ctx context.Context) (ProbeResult, error) {
	if len(p.Targets) == 0 || p.Attempt == nil || p.Journal == nil || !filepath.IsAbs(p.Control.Path) {
		return ProbeResult{}, errors.New("tamper probe: not configured")
	}
	var paths []string
	for i, t := range p.Targets {
		if !ownerWord.MatchString(t.Name) || !filepath.IsAbs(t.Path) {
			return ProbeResult{}, fmt.Errorf("tamper probe: bad target %d", i)
		}
		tp, err := tamperPaths(t)
		if err != nil {
			return ProbeResult{}, fmt.Errorf("tamper probe: %s: %w", t.Name, err)
		}
		paths = append(paths, tp...)
	}
	cp, err := tamperPaths(p.Control)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("tamper probe: control: %w", err)
	}
	paths = append(paths, cp...)
	if err := shuffle(paths); err != nil {
		return ProbeResult{}, fmt.Errorf("tamper probe: order: %w", err)
	}
	if p.Quiesce != nil {
		resume, err := p.Quiesce(ctx)
		if err != nil {
			return ProbeResult{}, fmt.Errorf("tamper probe: quiesce: %w", err)
		}
		if resume != nil {
			defer resume()
		}
	}
	before := make([][]byte, len(p.Targets))
	for i, t := range p.Targets {
		d, err := targetDigest(t.Path)
		if err != nil {
			return ProbeResult{}, fmt.Errorf("tamper probe: target %s: %w", t.Name, err)
		}
		before[i] = d
	}
	control, err := targetDigest(p.Control.Path)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("tamper probe: control: %w", err)
	}
	nonce, err := newTamperNonce()
	if err != nil {
		return ProbeResult{}, fmt.Errorf("tamper probe: nonce: %w", err)
	}
	defer p.removeSiblings(nonce)
	machine, err := p.Attempt(ctx, nonce, paths)
	fresh := p.last.fresh(machine)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("tamper probe: attempt: %w", err)
	}
	if fresh != nil {
		return ProbeResult{}, fmt.Errorf("tamper probe: %w", fresh)
	}
	if err := ctx.Err(); err != nil {
		return ProbeResult{}, err
	}
	if d, err := targetDigest(p.Control.Path); err == nil && string(d) == string(control) {
		return ProbeResult{}, errors.New("tamper probe: the control did not change: the guest's writes did not run")
	}
	after := make([][]byte, len(p.Targets))
	for i, t := range p.Targets {
		d, err := targetDigest(t.Path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			// Removed from inside the machine is changed.
		case err != nil:
			return ProbeResult{}, fmt.Errorf("tamper probe: target %s: %w", t.Name, err)
		}
		after[i] = d
	}
	var res ProbeResult
	for i, t := range p.Targets {
		if after[i] != nil && string(after[i]) == string(before[i]) {
			if err := p.Journal(machine, t.Name); err != nil {
				return ProbeResult{}, fmt.Errorf("tamper probe: journal %s: %w", t.Name, err)
			}
		} else {
			res.Found = append(res.Found, Finding{Check: CheckTamper, Subject: t.Name, Detail: "writable", Severity: High})
		}
		res.Checked = append(res.Checked, t.Name)
	}
	return res, nil
}

// targetDigest is treeDigest of path and, for anything but a directory,
// the names in its parent directory, so a sibling the guest's write
// created beside a file target is a change (P3-4b-4c-restore).
func targetDigest(path string) ([]byte, error) {
	d, err := treeDigest(path)
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		return d, nil
	}
	ents, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(d)
	for _, e := range ents {
		fmt.Fprintf(h, "%q\n", e.Name())
	}
	return h.Sum(nil), nil
}

// removeSiblings removes the files the round's guest writes may have left
// beside or inside each target and the control. A target the guest
// reached may still need restoring from a broker copy if something other
// than the fixed script wrote it (loops S33).
func (p *TamperProbe) removeSiblings(nonce string) {
	for _, t := range append(slices.Clone(p.Targets), p.Control) {
		dir := filepath.Dir(t.Path)
		if fi, err := os.Stat(t.Path); err == nil && fi.IsDir() {
			dir = t.Path
		}
		os.Remove(filepath.Join(dir, machprobe.Sibling(nonce)))
	}
}

// treeDigest hashes a file or directory tree: names, types, modes and
// contents, without following symbolic links.
func treeDigest(root string) ([]byte, error) {
	if _, err := os.Lstat(root); err != nil {
		return nil, err
	}
	h := sha256.New()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		fmt.Fprintf(h, "%q %v %d\n", rel, info.Mode(), info.Size())
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			l, err := os.Readlink(path)
			if err != nil {
				return err
			}
			fmt.Fprintf(h, "-> %q\n", l)
		case info.Mode().IsRegular():
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			_, err = io.Copy(h, f)
			f.Close()
			return err
		}
		return nil
	})
	return h.Sum(nil), err
}

// Pressure kinds an exhaustion round applies, and the subjects for the
// broker's own targets.
var pressureKinds = []string{"cpu", "memory", "disk", "processes"}

// PressedMachine is the machine a round pressed: its cgroup directory and
// its disk budget, both as the broker set them.
type PressedMachine struct {
	ID        string
	Cgroup    string
	DiskBytes int64
}

// ExhaustProbe has a guest press CPU, memory, disk and processes inside
// its machine's cgroup for Hold. Meanwhile it times the broker's answers;
// then it reads the machine's limits and times its preemption.
type ExhaustProbe struct {
	Interval       time.Duration
	Hold           time.Duration
	ResponseTarget time.Duration
	PreemptTarget  time.Duration
	// BrokerWeight is the broker's cpu.weight; a machine at or above it
	// can starve the broker.
	BrokerWeight int
	Press        func(ctx context.Context, kinds []string) (PressedMachine, error)
	Ping         func(ctx context.Context) error
	Preempt      func(id string) error
}

func (p *ExhaustProbe) Check() Check         { return CheckExhaust }
func (p *ExhaustProbe) Every() time.Duration { return p.Interval }

// Run presses, times and preempts. A missing limit is a High "no limit"
// finding on the resource; a slow answer or preemption a High "slow" one.
// A failed press, ping or preemption fails the run; a pressed machine is
// preempted either way.
func (p *ExhaustProbe) Run(ctx context.Context) (res ProbeResult, err error) {
	if p.Press == nil || p.Ping == nil || p.Preempt == nil || p.Hold <= 0 || p.ResponseTarget <= 0 || p.PreemptTarget <= 0 || p.BrokerWeight <= 0 {
		return ProbeResult{}, errors.New("exhaustion probe: not configured")
	}
	m, err := p.Press(ctx, pressureKinds)
	if err != nil {
		if m.ID != "" {
			p.Preempt(m.ID)
		}
		return ProbeResult{}, fmt.Errorf("exhaustion probe: press: %w", err)
	}
	preempted := false
	defer func() {
		if !preempted {
			p.Preempt(m.ID)
		}
	}()
	slow, err := p.timePings(ctx)
	if err != nil {
		return ProbeResult{}, err
	}
	for _, k := range pressureKinds {
		if !p.limited(m, k) {
			res.Found = append(res.Found, Finding{Check: CheckExhaust, Subject: k, Detail: "no limit", Severity: High})
		}
	}
	if slow {
		res.Found = append(res.Found, Finding{Check: CheckExhaust, Subject: "response", Detail: "slow", Severity: High})
	}
	start := time.Now()
	preempted = true
	if err := p.Preempt(m.ID); err != nil {
		return ProbeResult{}, fmt.Errorf("exhaustion probe: preempt: %w", err)
	}
	if time.Since(start) > p.PreemptTarget {
		res.Found = append(res.Found, Finding{Check: CheckExhaust, Subject: "preemption", Detail: "slow", Severity: High})
	}
	res.Checked = append(append(res.Checked, pressureKinds...), "response", "preemption")
	return res, nil
}

// timePings pings the broker until Hold has passed and says whether any
// answer took longer than ResponseTarget. A ping that outlasts four
// targets is slow and ends the timing.
func (p *ExhaustProbe) timePings(ctx context.Context) (bool, error) {
	end := time.Now().Add(p.Hold)
	for first := true; first || time.Now().Before(end); first = false {
		pctx, cancel := context.WithTimeout(ctx, 4*p.ResponseTarget)
		start := time.Now()
		err := p.Ping(pctx)
		took := time.Since(start)
		cancel()
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if err != nil && errors.Is(pctx.Err(), context.DeadlineExceeded) {
			return true, nil
		}
		if err != nil {
			return false, fmt.Errorf("exhaustion probe: ping: %w", err)
		}
		if took > p.ResponseTarget {
			return true, nil
		}
	}
	return false, nil
}

// limited says whether the broker set a limit on kind for m.
func (p *ExhaustProbe) limited(m PressedMachine, kind string) bool {
	switch kind {
	case "disk":
		return m.DiskBytes > 0
	case "cpu":
		w, ok := cgroupInt(m.Cgroup, "cpu.weight")
		return ok && w < int64(p.BrokerWeight)
	case "memory":
		_, ok := cgroupInt(m.Cgroup, "memory.max")
		return ok
	case "processes":
		_, ok := cgroupInt(m.Cgroup, "pids.max")
		return ok
	}
	return false
}

// cgroupInt reads a cgroup v2 file holding one positive integer; "max",
// a missing file or no cgroup is no value.
func cgroupInt(dir, file string) (int64, bool) {
	if dir == "" {
		return 0, false
	}
	b, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n, err == nil && n > 0
}
