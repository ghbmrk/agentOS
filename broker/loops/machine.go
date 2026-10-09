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
	"math"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LOOP-7 machine probes (P3-4b-4b): fixed scripts run with guest
// authority in a throwaway agent machine. The guest only acts; the
// verdict is taken broker-side from what the broker itself can see, so
// nothing the guest says is trusted (Security #515).
const (
	CheckTamper  Check = "tamper"     // a guest write changed an evaluator, grader or snapshot path
	CheckExhaust Check = "exhaustion" // a machine limit unset or above budget, or the broker missed its response or preemption target
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
	switch d, err := targetDigest(p.Control.Path); {
	case errors.Is(err, fs.ErrNotExist):
		// Removed from inside the machine is changed.
	case err != nil:
		return ProbeResult{}, fmt.Errorf("tamper probe: control: %w", err)
	case string(d) == string(control):
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
// the tamper-sibling names in its parent directory, so a sibling the
// guest's write created beside a file target is a change
// (P3-4b-4c-restore). Other names there are left out: the broker may
// write beside a target it does not hold (#584 L3 1), and a replaced
// target still changes treeDigest.
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
		if strings.HasPrefix(e.Name(), tamperSibling("")) {
			fmt.Fprintf(h, "%q\n", e.Name())
		}
	}
	return h.Sum(nil), nil
}

// tamperSibling is the file the guest's fixed script creates for a round
// (machprobe.Sibling; a test holds the two equal). loops does not import
// machprobe: the control path links no process-starting code (ARC-2).
func tamperSibling(nonce string) string { return ".agentos-tamper-" + nonce }

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
		os.Remove(filepath.Join(dir, tamperSibling(nonce)))
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

// sandboxThreads is the subject of the pids.max check. Under gVisor a
// guest process is a task inside the sentry, not a host task, so the
// machine cgroup's pids.max bounds the sandbox's host threads, not guest
// processes (RES-2, S35): a round checks that limit under this name and
// never claims "processes" (P3-4b-4c-pids-r1 owns a guest bound).
const sandboxThreads = "sandbox threads"

// limitKinds are the limits a round reads, in report order.
var limitKinds = []string{"cpu", "memory", "disk", sandboxThreads}

// maxCPUs caps a machine's CPU count: no kernel writes a larger
// cpuset, and a count over it could wrap the sum or Hold × CPUs (#599
// Security L1).
const maxCPUs = 1 << 16

// PressedMachine is the machine a round presses: its cgroup directory,
// its disk budget as the file system holds it, and its disk quota's
// usage, all read broker-side. DiskUsed reads the quota's counter, never
// the guest's tree, which a guest could make slow to walk.
type PressedMachine struct {
	ID        string
	Cgroup    string
	DiskBytes int64
	DiskUsed  func() (int64, error)
}

// MachineBudget is the per-machine limits the broker writes when it
// creates a machine: memory.max, pids.max and the disk quota.
type MachineBudget struct {
	MemoryBytes int64
	Pids        int64
	DiskBytes   int64
}

// PressScript is what the fixed press script holds in a machine: its
// memory and disk pressure (machprobe.Options MemMB and DiskMB, in
// bytes). A round's memory and disk counters must rise by half of it for
// its guest to have pressed (S35).
type PressScript struct {
	MemoryBytes int64
	DiskBytes   int64
}

// cpuFloor is the least CPU time a round's minimum may ask for: over twice
// what four `runsc exec` presses that exit at once used on CI (0.44 s; S35).
const cpuFloor = time.Second

// scriptFloor is the least memory and disk a press script may hold: half
// of it, the round's minimum, is over twice the largest rise presses that
// exited at once left on CI (shmem 5.1 MiB, disk 4 KiB; S35), so a guest
// that idles cannot meet it, as it could with Script{2, 2}'s 1-byte
// minimums.
var scriptFloor = PressScript{MemoryBytes: 24 << 20, DiskBytes: 1 << 20}

// ExhaustProbe has a fresh machine's guest press CPU, memory, disk and
// processes inside its machine's cgroup for Hold. Meanwhile it times the
// broker's answers; then it checks the guest pressed, reads the machine's
// limits against Budget and times its preemption.
type ExhaustProbe struct {
	Interval       time.Duration
	Hold           time.Duration
	ResponseTarget time.Duration
	PreemptTarget  time.Duration
	// BrokerWeight is the broker's cpu.weight; a machine at or above it
	// can starve the broker.
	BrokerWeight int
	Budget       MachineBudget
	Script       PressScript
	// Machine starts a fresh machine, idle; Press has its guest start
	// pressing kinds and returns while it presses.
	Machine func(ctx context.Context) (PressedMachine, error)
	Press   func(ctx context.Context, id string, kinds []string) error
	Ping    func(ctx context.Context) error
	Preempt func(id string) error

	last lastMachine
}

func (p *ExhaustProbe) Check() Check         { return CheckExhaust }
func (p *ExhaustProbe) Every() time.Duration { return p.Interval }

// Run presses, times and preempts. A limit unset or above Budget is a
// High "above budget" finding on the resource (pids.max's is
// sandboxThreads); a slow answer or
// preemption a High "slow" one. A failed machine, press, ping or
// preemption, a machine the last round used, or a counter that did not
// rise by its minimum over the hold (the guest did not press: half of
// Script for memory and disk, half of Hold on every CPU the machine may
// run on in CPU time, at least cpuFloor) fails the run, which then
// closes nothing; a machine is preempted either way. Guest processes are
// pressed but not checked, so a round never closes a "processes" finding.
func (p *ExhaustProbe) Run(ctx context.Context) (res ProbeResult, err error) {
	b := p.Budget
	if p.Machine == nil || p.Press == nil || p.Ping == nil || p.Preempt == nil || p.Hold <= 0 || p.ResponseTarget <= 0 || p.PreemptTarget <= 0 || p.BrokerWeight <= 0 ||
		b.MemoryBytes <= 0 || b.Pids <= 0 || b.DiskBytes <= 0 ||
		p.Script.MemoryBytes < scriptFloor.MemoryBytes || p.Script.MemoryBytes > b.MemoryBytes ||
		p.Script.DiskBytes < scriptFloor.DiskBytes || p.Script.DiskBytes > b.DiskBytes {
		return ProbeResult{}, errors.New("exhaustion probe: not configured")
	}
	m, err := p.Machine(ctx)
	fresh := p.last.fresh(m.ID)
	preempted := m.ID == ""
	defer func() {
		if !preempted {
			p.Preempt(m.ID)
		}
	}()
	if err != nil {
		return ProbeResult{}, fmt.Errorf("exhaustion probe: machine: %w", err)
	}
	if fresh != nil {
		return ProbeResult{}, fmt.Errorf("exhaustion probe: %w", fresh)
	}
	// The machine's CPU count sets the CPU minimum; unreadable, the round
	// cannot show the guest pressed, as with an unreadable counter.
	cpus, rerr := cpusEffective(m.Cgroup)
	var cpuRise time.Duration
	if rerr == nil {
		if time.Duration(cpus) > math.MaxInt64/p.Hold {
			return ProbeResult{}, fmt.Errorf("exhaustion probe: a %v hold on %d CPUs overflows", p.Hold, cpus)
		}
		if cpuRise = p.Hold * time.Duration(cpus) / 2; cpuRise < cpuFloor {
			return ProbeResult{}, fmt.Errorf("exhaustion probe: a %v hold on %d CPUs asks under %v of CPU time", p.Hold, cpus, cpuFloor)
		}
	}
	var before map[string]int64
	if rerr == nil {
		before, rerr = p.usage(m)
	}
	if err := p.Press(ctx, m.ID, pressureKinds); err != nil {
		return ProbeResult{}, fmt.Errorf("exhaustion probe: press: %w", err)
	}
	slow, err := p.timePings(ctx)
	if err != nil {
		return ProbeResult{}, err
	}
	if rerr == nil {
		var after map[string]int64
		if after, rerr = p.usage(m); rerr == nil {
			least := map[string]int64{"cpu": cpuRise.Microseconds(), "memory": p.Script.MemoryBytes / 2, "disk": p.Script.DiskBytes / 2}
			for _, k := range pressureKinds {
				if want, ok := least[k]; ok && after[k]-before[k] < want {
					rerr = errors.Join(rerr, fmt.Errorf("%s rose %d, under %d", k, after[k]-before[k], want))
				}
			}
		}
	}
	for _, k := range limitKinds {
		if !p.limited(m, k) {
			res.Found = append(res.Found, Finding{Check: CheckExhaust, Subject: k, Detail: "above budget", Severity: High})
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
	if rerr != nil {
		// What was found stands; nothing closes (runProbe).
		return res, fmt.Errorf("exhaustion probe: the guest did not press: %w", rerr)
	}
	res.Checked = append(append(res.Checked, limitKinds...), "response", "preemption")
	return res, nil
}

// cpusEffective counts the CPUs a machine's cgroup may run on, read
// broker-side from cpuset.cpus.effective: the group's own, or, where it
// does not enable cpuset, its nearest ancestor's within the cgroup tree.
// None found is an error.
func cpusEffective(dir string) (int, error) {
	if dir == "" {
		return 0, errors.New("no cgroup")
	}
	for d := dir; ; d = filepath.Dir(d) {
		b, err := os.ReadFile(filepath.Join(d, "cpuset.cpus.effective"))
		if err == nil {
			return cpuCount(strings.TrimSpace(string(b)))
		}
		parent := filepath.Dir(d)
		if _, err := os.Stat(filepath.Join(parent, "cgroup.controllers")); parent == d || err != nil {
			return 0, errors.New("no cpuset.cpus.effective")
		}
	}
}

// cpuCount counts a cpuset list such as "0-3,6". Over maxCPUs is an
// error, checked while summing so the sum cannot wrap first.
func cpuCount(list string) (int, error) {
	n := 0
	for part := range strings.SplitSeq(list, ",") {
		lo, hi, ranged := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		b := a
		if err == nil && ranged {
			b, err = strconv.Atoi(hi)
		}
		if err != nil || a < 0 || b < a {
			return 0, fmt.Errorf("bad cpuset %q", list)
		}
		if b-a >= maxCPUs-n {
			return 0, fmt.Errorf("cpuset over %d CPUs", maxCPUs)
		}
		n += b - a + 1
	}
	return n, nil
}

// usage reads machine m's counters, broker-side: cpu.stat usage_usec,
// memory.stat shmem and the disk quota's usage; a negative one is an
// error, as from cgroupCounter. Processes have none: under
// gVisor a guest process is not a host task, so pids.current does not
// count them (S35).
func (p *ExhaustProbe) usage(m PressedMachine) (map[string]int64, error) {
	u := map[string]int64{}
	var err error
	if u["cpu"], err = cgroupCounter(m.Cgroup, "cpu.stat", "usage_usec"); err != nil {
		return nil, err
	}
	// Guest memory only: gVisor backs it with a memfd, which the host
	// counts as shmem; memory.current would also count the disk press's
	// file cache (S35).
	if u["memory"], err = cgroupCounter(m.Cgroup, "memory.stat", "shmem"); err != nil {
		return nil, err
	}
	if m.DiskUsed == nil {
		return nil, errors.New("no disk usage")
	}
	if u["disk"], err = m.DiskUsed(); err != nil {
		return nil, fmt.Errorf("disk usage: %w", err)
	}
	if u["disk"] < 0 {
		return nil, errors.New("disk usage: negative")
	}
	return u, nil
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

// limited says whether the broker set a limit on kind for m at or under
// Budget; for cpu, a weight below the broker's. An unknown kind,
// "processes" included, is not limited.
func (p *ExhaustProbe) limited(m PressedMachine, kind string) bool {
	switch kind {
	case "disk":
		return m.DiskBytes > 0 && m.DiskBytes <= p.Budget.DiskBytes
	case "cpu":
		w, ok := cgroupInt(m.Cgroup, "cpu.weight")
		return ok && w < int64(p.BrokerWeight)
	case "memory":
		n, ok := cgroupInt(m.Cgroup, "memory.max")
		return ok && n <= p.Budget.MemoryBytes
	case sandboxThreads:
		n, ok := cgroupInt(m.Cgroup, "pids.max")
		return ok && n <= p.Budget.Pids
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

// cgroupCounter reads a cgroup v2 counter: the file's one integer, or with
// key the integer on its "key N" line. No cgroup, a missing file, no
// such line or a negative value, which the kernel never writes, is an
// error (#599 Security L2: a negative baseline inflates a rise).
func cgroupCounter(dir, file, key string) (int64, error) {
	if dir == "" {
		return 0, errors.New("no cgroup")
	}
	b, err := os.ReadFile(filepath.Join(dir, file))
	if pe := (*fs.PathError)(nil); errors.As(err, &pe) {
		err = pe.Err // no host path in the run's error
	}
	if err != nil {
		return 0, fmt.Errorf("%s: %w", file, err)
	}
	v, found := strings.TrimSpace(string(b)), key == ""
	for line := range strings.Lines(v) {
		if k, rest, ok := strings.Cut(strings.TrimSpace(line), " "); ok && key != "" && k == key {
			v, found = rest, true
			break
		}
	}
	if !found {
		return 0, fmt.Errorf("%s: no %s", file, key)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", file, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("%s: negative", file)
	}
	return n, nil
}
