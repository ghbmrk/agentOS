// Package loop7 is a Loop 2 source for LOOP-7's off-the-shelf checks
// (P3-4b-3): bounded rounds of the broker's Go native fuzz targets, and
// rounds of the in-guest socket probe (broker/sockprobe, run through
// Config.Probe), run in spare
// capacity (LOOP-1). A crash or a probe failure enters LOOP-9's chain as a
// finding through Report; the crashing input stays in the target's corpus
// as evidence and as a regression replayed every round, and the finding
// is resolved once the regression passes.
//
// Nothing here writes or chooses test input (D-067): the fuzz engine is
// Go's own, the targets and seeds are the repository's, and the probe's
// frames are fixed.
package loop7

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// Reporter is Loop 2's in-process entry point (*loops.Guard).
type Reporter interface {
	Report(ctx context.Context, f loops.Finding) (loops.Record, error)
	Resolve(id string, r loops.Replay) error
	CloseTarget(id string, c loops.Closure) error
	OpenReported(c loops.Check) []loops.Finding
}

// Target is one fuzz target, built as a test binary (`go test -c`).
type Target struct {
	Pkg    string // the package's short name, as in "sockets"
	Name   string // the fuzz function, as in "FuzzRequest"
	Binary string // the compiled test binary
	// Dir is the binary's working directory. Its testdata/fuzz/<Name>
	// holds the seed corpus; a crashing input is written there, kept,
	// and replayed every round.
	Dir string
}

func (t Target) subject() string { return t.Pkg + "." + t.Name }

// ProbeRun runs the socket probe in an agent machine with guest
// authority, and returns the machine and the failures the probe reported
// (sockprobe.Result.Failures). loop7 does not import sockprobe, whose
// in-guest dialer agentosd must not link (ARC-2, daemon
// TestAgentosdLinksNoInference; P3-4b-3a).
type ProbeRun func(ctx context.Context) (machine string, failures []string, err error)

// Config wires the source.
type Config struct {
	// Inner is Loop 2's passive checks (*loops.Guard). There is one
	// source per loop, so this source offers Inner's work first.
	Inner   loops.Source
	Report  Reporter
	Targets []Target
	// FuzzTime bounds one fuzz job. Default 30 s.
	FuzzTime time.Duration
	// ReplayTime bounds a whole corpus replay, and the fuzz step's run
	// past FuzzTime. Default 1 m.
	ReplayTime time.Duration
	// InputTime bounds one stored input replayed alone. Default 10 s.
	InputTime time.Duration
	// Every is the gap between two LOOP-7 jobs. Default 1 h.
	Every time.Duration
	// Release is the directory of release-listed fuzz binaries
	// (/usr/lib/agentos/fuzz in the image): every target's Binary must be
	// a <name>.test file directly in it (ARC-2, P3-4b-3a). agentosd sets
	// it from a constant, never from configuration or state.
	Release string
	// CacheDir holds the fuzz engine's generated corpus and each child's
	// scratch directory.
	CacheDir string
	// CacheCap bounds one package's generated corpus (CacheDir/fuzz/<pkg>)
	// and CacheTotal the whole of CacheDir/fuzz; each fuzz step prunes the
	// oldest entries past them first (F15). Defaults 64 MiB and 512 MiB.
	CacheCap, CacheTotal int64
	// Jail confines every child; agentosd's wiring sets it (L7-6). Nil
	// (tests, dev builds) runs children as the daemon's own user, group
	// and network.
	Jail *Jail
	// Probe and Trail run the socket probe and read the journal; both or
	// neither.
	Probe ProbeRun
	Trail func() []journal.Record
	// Want is the refusal code each of the probe's frames must provoke,
	// from the broker's own probe set (sockprobe.Frames' Want), never
	// from what the guest reports; required with Probe.
	Want []sockets.Code
	// Window is the journal's coalescing window for refusals. Default 1 m.
	Window time.Duration
	Now    func() time.Time
}

// Source is Loop 2's source with LOOP-7 rounds added.
type Source struct {
	cfg Config
	// base is the tree root does its file work in for the children: the
	// jail's State, or / with no jail (Source.tree).
	base string

	mu   sync.Mutex
	next time.Time
	turn int // which LOOP-7 job comes next: the probe, then each target
	// fuzzed is when a fuzz step last completed, or when the source was
	// built; failing counts each target's turns in a row that failed to
	// run (P3-4b-3r-pass).
	fuzzed  time.Time
	failing map[int]int
}

// New checks cfg and returns the source.
func New(cfg Config) (*Source, error) {
	if cfg.Inner == nil || cfg.Report == nil {
		return nil, errors.New("loop7: Inner and Report are required")
	}
	if (cfg.Probe == nil) != (cfg.Trail == nil) || (cfg.Probe != nil) != (len(cfg.Want) > 0) {
		return nil, errors.New("loop7: Probe, Trail and Want go together")
	}
	if cfg.Inner.Loop() != loops.Secure {
		return nil, errors.New("loop7: Inner must be Loop 2's source")
	}
	for _, t := range cfg.Targets {
		if t.Pkg == "" || !fuzzName.MatchString(t.Name) || t.Binary == "" || t.Dir == "" {
			return nil, fmt.Errorf("loop7: bad target %+v", t)
		}
		if err := released(cfg.Release, t.Binary); err != nil {
			return nil, err
		}
	}
	if len(cfg.Targets) > 0 && !filepath.IsAbs(cfg.CacheDir) {
		return nil, errors.New("loop7: fuzz targets need an absolute CacheDir")
	}
	base := "/"
	if j := cfg.Jail; j != nil {
		if j.UID == 0 {
			return nil, errors.New("loop7: a jail needs an unprivileged user")
		}
		if !filepath.IsAbs(j.State) || filepath.Clean(j.State) != j.State {
			return nil, fmt.Errorf("loop7: jail state %q is not an absolute clean path", j.State)
		}
		base = j.State
	}
	for _, p := range targetDirs(cfg.Targets, cfg.CacheDir) {
		if !within(base, p) {
			return nil, fmt.Errorf("loop7: %q is outside %s, the tree the children may write", p, base)
		}
	}
	if cfg.CacheCap <= 0 {
		cfg.CacheCap = 64 << 20
	}
	if cfg.CacheTotal <= 0 {
		cfg.CacheTotal = 512 << 20
	}
	if cfg.FuzzTime <= 0 {
		cfg.FuzzTime = 30 * time.Second
	}
	if cfg.ReplayTime <= 0 {
		cfg.ReplayTime = time.Minute
	}
	if cfg.InputTime <= 0 {
		cfg.InputTime = 10 * time.Second
	}
	if cfg.Every <= 0 {
		cfg.Every = time.Hour
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Source{cfg: cfg, base: base, fuzzed: cfg.Now(), failing: map[int]int{}}, nil
}

// targetDirs are the cache and each target's directory, which the
// children write; none without targets.
func targetDirs(ts []Target, cache string) []string {
	if len(ts) == 0 {
		return nil
	}
	ds := []string{cache}
	for _, t := range ts {
		ds = append(ds, t.Dir)
	}
	return ds
}

// within reports that p is base or lies under it.
func within(base, p string) bool {
	rel, err := filepath.Rel(base, p)
	return err == nil && filepath.IsAbs(p) && rel != ".." && !strings.HasPrefix(rel, "../")
}

// tree opens the directory root does its file work in for the children:
// the jail's State, which the jail's user owns, or / with no jail. Every
// path root uses there resolves through the os.Root, so no link a child
// planted takes root's reads, writes, chowns or removals out of it (L3 1
// on #588).
func (s *Source) tree() (*os.Root, error) { return os.OpenRoot(s.base) }

// in is p, checked within s.base by New, relative to the tree.
func (s *Source) in(p string) string {
	rel, err := filepath.Rel(s.base, p)
	if err != nil {
		return p
	}
	return rel
}

var fuzzName = regexp.MustCompile(`^Fuzz[A-Za-z0-9_]*$`)

// binName is a release binary's file name; pkgPath is a target's package,
// relative to broker/.
var (
	binName = regexp.MustCompile(`^[a-z0-9_]+\.test$`)
	pkgPath = regexp.MustCompile(`^[a-z0-9]+(/[a-z0-9]+)*$`)
)

// released checks that bin names a test binary directly in the release
// directory, which must be absolute and clean.
func released(release, bin string) error {
	if release == "" || !filepath.IsAbs(release) || filepath.Clean(release) != release {
		return fmt.Errorf("loop7: release directory %q is not an absolute clean path", release)
	}
	if filepath.Dir(bin) != release || !binName.MatchString(filepath.Base(bin)) {
		return fmt.Errorf("loop7: %q is not a binary the release lists", bin)
	}
	return nil
}

// Recheck is how long a target waits between two of its rounds: one
// LOOP-7 job runs per Every, taking turns over the targets and the probe,
// whose slot is counted even while no probe is wired (P3-4b-3a).
func (s *Source) Recheck() time.Duration {
	return time.Duration(len(s.cfg.Targets)+1) * s.cfg.Every
}

// manifest is the release's list of fuzz targets (image/fuzz-targets.json,
// shipped as <release>/manifest.json).
type manifest struct {
	Targets []struct {
		Pkg    string `json:"pkg"`
		Name   string `json:"name"`
		Binary string `json:"binary"`
	} `json:"targets"`
}

// Load reads release/manifest.json and returns its targets. Each runs in
// state/targets/<pkg>, never in the read-only release: the release's seed
// corpus (release/corpus/<pkg>/<Name>) is copied there, file by file,
// where no file of that name exists, so a crash input found on this box
// stays across updates. state's parent must not be writable by the jail's
// user: state itself becomes that user's (Jail.Own), so Load writes in it
// only through an os.Root, which no link the user plants can lead out of.
func Load(release, state string) ([]Target, error) {
	b, err := os.ReadFile(filepath.Join(release, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("loop7: manifest: %w", err)
	}
	if len(m.Targets) == 0 {
		return nil, errors.New("loop7: manifest lists no targets")
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(state)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var out []Target
	for _, e := range m.Targets {
		if !pkgPath.MatchString(e.Pkg) || !fuzzName.MatchString(e.Name) || !binName.MatchString(e.Binary) {
			return nil, fmt.Errorf("loop7: bad manifest entry %+v", e)
		}
		t := Target{Pkg: e.Pkg, Name: e.Name, Binary: filepath.Join(release, e.Binary), Dir: filepath.Join(state, "targets", filepath.FromSlash(e.Pkg))}
		if err := seed(r, filepath.Join(release, "corpus", filepath.FromSlash(e.Pkg), e.Name), filepath.Join("targets", filepath.FromSlash(e.Pkg), "testdata", "fuzz", e.Name)); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// seed copies each regular file in from that to, a path in r, lacks.
func seed(r *os.Root, from, to string) error {
	if err := r.MkdirAll(to, 0o700); err != nil {
		return err
	}
	es, err := os.ReadDir(from)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	for _, e := range es {
		if !e.Type().IsRegular() {
			continue
		}
		data, err := readSeed(filepath.Join(from, e.Name()))
		if err != nil {
			return err
		}
		// O_EXCL: a file or link of that name, even a dangling one, stays.
		f, err := r.OpenFile(filepath.Join(to, e.Name()), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		} else if err != nil {
			return err
		}
		_, err = f.Write(data)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// readSeed reads one of the release's seeds, within inputCap.
func readSeed(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := capped(f)
	if err != nil {
		return nil, fmt.Errorf("loop7: release seed %s: %w", p, err)
	}
	return data, nil
}

// Loop is Loop 2.
func (s *Source) Loop() loops.Loop { return loops.Secure }

// Urgent is Inner's: a LOOP-7 round is never urgent.
func (s *Source) Urgent() bool {
	u, ok := s.cfg.Inner.(loops.Urgent)
	return ok && u.Urgent()
}

// Digest is Inner's digest lines (loops.Digester), which the scheduler
// reads for STATUS, then one line when fuzzing is configured but no fuzz
// step has completed for longer than Recheck, and one when a target
// failed to run on each of its turns for a full cycle. Neither names a
// target (P3-4b-3r-pass).
func (s *Source) Digest() []string {
	var out []string
	if d, ok := s.cfg.Inner.(loops.Digester); ok {
		out = d.Digest()
	}
	if len(s.cfg.Targets) == 0 {
		return out
	}
	s.mu.Lock()
	since := s.cfg.Now().Sub(s.fuzzed)
	broken := false
	for _, n := range s.failing {
		broken = broken || n >= 2
	}
	s.mu.Unlock()
	if since > s.Recheck() {
		out = append(out, "Loop 2: my fuzz self-tests have not run for "+span(since)+".")
	}
	if broken {
		out = append(out, "Loop 2: one of my fuzz self-tests cannot run.")
	}
	return out
}

// span is d in whole days, or whole hours under a day.
func span(d time.Duration) string {
	n, unit := int(d/(24*time.Hour)), "day"
	if n == 0 {
		n, unit = int(d/time.Hour), "hour"
	}
	if n != 1 {
		unit += "s"
	}
	return strconv.Itoa(n) + " " + unit
}

// stepped records how fuzz step i ended: completion time is taken when a
// step ends with ctx live and no error, never when it is offered, so a
// preempted step is not progress; a step that errors is a failed turn.
func (s *Source) stepped(ctx context.Context, i int, err error) {
	if ctx.Err() != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.failing[i]++
		return
	}
	delete(s.failing, i)
	s.fuzzed = s.cfg.Now()
}

// Measured is Inner's (loops.Measured): LOOP-7 jobs do not change how
// Loop 2's return is measured.
func (s *Source) Measured() bool {
	m, ok := s.cfg.Inner.(loops.Measured)
	return !ok || m.Measured()
}

// Next offers Inner's work first, then one LOOP-7 job per Every. Neither
// makes model calls. A job that is preempted is offered again at once.
func (s *Source) Next(ctx context.Context, modelOK bool) (loops.Job, bool) {
	if j, ok := s.cfg.Inner.Next(ctx, modelOK); ok {
		return j, true
	}
	jobs := len(s.cfg.Targets)
	if s.cfg.Probe != nil {
		jobs++
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	if jobs == 0 || now.Before(s.next) {
		return loops.Job{}, false
	}
	at := s.turn % jobs
	s.turn++
	s.next = now.Add(s.cfg.Every)
	// A preempted job is offered again at once.
	retry := func(ctx context.Context) {
		if ctx.Err() != nil {
			s.mu.Lock()
			s.turn, s.next = at, time.Time{}
			s.mu.Unlock()
		}
	}
	i := at
	if s.cfg.Probe != nil {
		if i == 0 {
			return loops.Job{Name: "probe", Run: func(ctx context.Context) loops.Result {
				n, err := s.probe(ctx)
				retry(ctx)
				return loops.Result{Value: float64(n), Err: err}
			}}, true
		}
		i--
	}
	t := s.cfg.Targets[i]
	return loops.Job{Name: "fuzz", Run: func(ctx context.Context) loops.Result {
		n, err := s.Fuzz(ctx, t)
		s.stepped(ctx, i, err)
		retry(ctx)
		return loops.Result{Value: float64(n), Err: err}
	}}, true
}

// Fuzz is one round for t: replay its corpus, fuzz it for FuzzTime, and
// replay again if the fuzzing failed. Each failing corpus input is
// reported; each open finding for t whose input passes is resolved. A
// target whose corpus still fails is not fuzzed: the engine stops at a
// failing seed. Every child has a deadline, and one that runs past it is
// a finding, never a held slot (LOOP-1). It returns the number of
// failures, and returns soon after ctx ends.
func (s *Source) Fuzz(ctx context.Context, t Target) (int, error) {
	n, err := s.replay(ctx, t)
	if err != nil || n > 0 || ctx.Err() != nil {
		return n, err
	}
	if err := s.prune(t.Pkg); err != nil {
		return 0, fmt.Errorf("loop7: pruning the fuzz cache: %w", err)
	}
	fctx, cancel := context.WithTimeout(ctx, s.cfg.FuzzTime+s.cfg.ReplayTime)
	start := time.Now()
	out, err := s.run(fctx, t, "-test.run=^$", "-test.fuzz=^"+t.Name+"$",
		"-test.fuzztime="+s.cfg.FuzzTime.String(), "-test.parallel=1",
		// An honest worker call then returns within a progress period,
		// minimizing included, so a count flat for one is a hang (F12).
		"-test.fuzzminimizetime="+minimizeTime.String(),
		"-test.fuzzcachedir="+filepath.Join(s.cfg.CacheDir, "fuzz", filepath.FromSlash(t.Pkg)))
	overran := fctx.Err() != nil
	cancel()
	if err != nil && exited(err) && !overran && time.Since(start) >= s.cfg.FuzzTime && stoppedAtDeadline(out, t.Name) {
		// The engine stopped at its own -test.fuzztime but lost a race
		// with its own cancellation and failed with "context deadline
		// exceeded" (P3-4b-3r-confine l9): judged as the clean stop it
		// is, by its progress (F12).
		err = nil
	}
	switch {
	case ctx.Err() != nil:
		return 0, nil
	case overran && (err == nil || exited(err)):
		// The engine's own -test.fuzztime did not stop it. A clean step
		// later never replays what kept it running, so it never resolves
		// this finding (delta L3 on #560); only a good step of another
		// release binary closes it (closeHangs).
		return 1, s.hang(ctx, t, loops.FuzzOverrunDetail)
	case err == nil:
		p := progressOf(out)
		if p.stalled() {
			// A fuzzed input hung the worker: the engine stopped at its
			// deadline, passed and stored no input (P3-4b-3r-fuzz).
			return 1, s.hang(ctx, t, loops.FuzzStallDetail)
		}
		if p.moved() {
			return 0, s.closeHangs(t, p)
		}
		return 0, nil
	case !bytes.Contains(out, []byte("Failing input written to")):
		return 0, fmt.Errorf("loop7: fuzzing %s did not run: %v: %q", t.subject(), err, tail(out))
	}
	return s.replay(ctx, t)
}

// Target findings, a failure no stored input can be named for, have the
// details loops words and closes: loops.FuzzNoInputDetail, and the hangs
// loops.FuzzOverrunDetail and loops.FuzzStallDetail.

// Go's own progress lines for a fuzz step (internal/fuzz's logStats,
// written by the coordinator): the baseline, "K/K completed" once it is
// gathered, then the exec count, which counts the baseline's runs.
var (
	baselineLine = regexp.MustCompile(`^fuzz: elapsed: \S+, (?:gathering baseline coverage|testing seed corpus): (\d+)/(\d+) completed`)
	execsLine    = regexp.MustCompile(`^fuzz: elapsed: (\S+), execs: (\d+) \(`)
)

// stepProgress is what a fuzz step's output says of its progress: the
// baseline input count, the last exec count, and for how long by the
// lines' own elapsed fields that count had stood when the last line was
// printed; -1 where no such line was printed.
type stepProgress struct {
	baseline, execs int
	flat            time.Duration
}

// progressPeriod is how often the engine prints an exec count line
// (internal/fuzz's statTicker).
const progressPeriod = 3 * time.Second

// minimizeTime bounds each minimizing call of the engine's one worker
// (-test.fuzzminimizetime, 60 s by default), well under progressPeriod.
const minimizeTime = time.Second

// progressOf reads a fuzz step's output. The lines come from the child's
// combined output, the regexes are line-anchored and the last match
// wins, so a target that prints a line shaped like the engine's can move
// the parse (F12): a forged stall only opens a finding, and a forged
// good step closes one only from a release binary other than the
// producer loops holds (F13).
func progressOf(out []byte) stepProgress {
	p := stepProgress{-1, -1, -1}
	var since time.Duration // elapsed at the first line of the last count
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if m := baselineLine.FindStringSubmatch(sc.Text()); m != nil && m[1] == m[2] {
			p.baseline, _ = strconv.Atoi(m[1])
		} else if m := execsLine.FindStringSubmatch(sc.Text()); m != nil {
			n, _ := strconv.Atoi(m[2])
			at, err := time.ParseDuration(m[1])
			switch {
			case err != nil:
				// No time to measure from: judged by the baseline only.
				p.flat, since = -1, -1
			case p.execs != n || since < 0 || at < since:
				p.flat, since = 0, at
			default:
				p.flat = at - since
			}
			p.execs = n
		}
	}
	return p
}

// stalled: the step printed its baseline and an exec count, and the count
// never moved past the baseline; or its last count had stood for a whole
// progress period (3h-r1). With one worker, whose calls return every
// 100 ms of fuzzing, a count flat for a period means one input ran that
// long (F12). A step too short to print either is no stall, and no good
// step either.
func (p stepProgress) stalled() bool {
	return p.baseline >= 0 && p.execs >= 0 && p.execs <= p.baseline || p.execs >= 0 && p.flat >= progressPeriod
}

// moved: the step's exec count moved past its baseline.
func (p stepProgress) moved() bool { return p.baseline >= 0 && p.execs > p.baseline }

// binaryDigest is the SHA-256 of the file at path.
func binaryDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hang reports a hang of t with the SHA-256 of the binary that produced
// it, which loops holds on the finding's record (F13). A hang seen again
// reports the newer binary: a lucky good step of a build that hung closes
// nothing.
func (s *Source) hang(ctx context.Context, t Target, detail string) error {
	d, err := binaryDigest(t.Binary)
	if err != nil {
		return err
	}
	_, err = s.cfg.Report.Report(ctx, loops.Finding{Check: loops.CheckFuzz, Subject: t.subject(), Severity: loops.High, Detail: detail, Producer: d})
	return err
}

// closeHangs offers good step p of t's binary to close each of t's open
// hang findings. It passes only the step's own digest and counts: loops
// compares the digest against the producer on its own record and closes
// only on another binary (CloseTarget, S30), so a refusal is the rule
// working, not an error.
func (s *Source) closeHangs(t Target, p stepProgress) error {
	var open []loops.Finding
	for _, f := range s.cfg.Report.OpenReported(loops.CheckFuzz) {
		if f.Subject == t.subject() && (f.Detail == loops.FuzzOverrunDetail || f.Detail == loops.FuzzStallDetail) {
			open = append(open, f)
		}
	}
	if len(open) == 0 {
		return nil
	}
	d, err := binaryDigest(t.Binary)
	if err != nil {
		return err
	}
	var errs []error
	for _, f := range open {
		c := loops.Closure{Kind: loops.ClosureStep, Binary: d, Execs: p.execs, Baseline: p.baseline, At: s.cfg.Now()}
		if err := s.cfg.Report.CloseTarget(f.ID, c); err != nil && !errors.Is(err, loops.ErrFinding) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// stoppedAtDeadline reports output whose one failure is fuzz target
// name's "context deadline exceeded" and nothing after it but FAIL: what
// Go's coordinator prints when its done channel closes before its
// workers' context is cancelled, so its own -test.fuzztime reads as an
// error. A step that stored an input or failed otherwise is not one.
func stoppedAtDeadline(out []byte, name string) bool {
	if bytes.Contains(out, []byte("Failing input written to")) {
		return false
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	at := -1
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "--- FAIL: ") {
			if at >= 0 || !strings.HasPrefix(l, "--- FAIL: "+name+" (") {
				return false
			}
			at = i
		}
	}
	if at < 0 {
		return false
	}
	rest := lines[at+1:]
	if n := len(rest); n > 0 && strings.TrimSpace(rest[n-1]) == "FAIL" {
		rest = rest[:n-1]
	}
	return len(rest) == 1 && strings.TrimSpace(rest[0]) == context.DeadlineExceeded.Error()
}

// failLine and passLine are a seed subtest failing or passing under
// -test.v.
var (
	failLine = regexp.MustCompile(`^\s*--- FAIL: (Fuzz[A-Za-z0-9_]*)/([^\s/]+) `)
	passLine = regexp.MustCompile(`^\s*--- PASS: (Fuzz[A-Za-z0-9_]*)/([^\s/]+) `)
)

// replay runs t's corpus files, reports each failing one and resolves
// t's open findings whose stored input it replayed and passed. A run that
// fails with no "--- FAIL" line (a runtime fatal error, out of memory,
// os.Exit, or a hang past ReplayTime) is replayed input by input to name
// the failing ones; if none fails alone, the target itself is reported.
func (s *Source) replay(ctx context.Context, t Target) (int, error) {
	rctx, cancel := context.WithTimeout(ctx, s.cfg.ReplayTime)
	out, runErr := s.run(rctx, t, "-test.run=^"+t.Name+"$", "-test.v", "-test.timeout="+s.cfg.ReplayTime.String())
	cancel()
	if ctx.Err() != nil {
		return 0, nil
	}
	failing, ran := map[string]bool{}, map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if m := failLine.FindStringSubmatch(sc.Text()); m != nil && m[1] == t.Name {
			failing[m[2]] = true
		} else if m := passLine.FindStringSubmatch(sc.Text()); m != nil && m[1] == t.Name {
			ran[m[2]] = true
		}
	}
	if runErr != nil && !exited(runErr) {
		return 0, fmt.Errorf("loop7: replaying %s: %w", t.subject(), runErr)
	}
	noInput := false
	if runErr != nil && len(failing) == 0 {
		if failing, ran, runErr = s.eachInput(ctx, t); runErr != nil || ctx.Err() != nil {
			return 0, runErr
		}
		noInput = len(failing) == 0
	}
	// A PASS line for an input that also failed is not a pass (the
	// decoder's own output can print one).
	for f := range failing {
		delete(ran, f)
	}
	// Each stored input whose own subtest passed in this run: only such a
	// replay closes a finding. An input that never ran (a panic stops the
	// binary before later seeds) or was removed keeps its finding open.
	// Every input is read before anything is reported: one root cannot
	// read within the tree (a link out of it, a FIFO) fails the round as
	// the runner's error, never as a finding or a resolution (F16).
	passed, crashed := map[string]bool{}, []string{}
	oversize := false
	for _, file := range append(sortedKeys(ran), sortedKeys(failing)...) {
		data, err := s.input(t, file)
		switch {
		case errors.Is(err, errTooLarge):
			oversize = true
			continue
		case errors.Is(err, os.ErrNotExist):
			// An f.Add seed, not a file: a failing one is reported by name.
			data = []byte(file)
		case err != nil:
			return 0, fmt.Errorf("loop7: reading %s's stored input %q: %w", t.subject(), file, err)
		}
		if failing[file] {
			crashed = append(crashed, crashDetail(data))
		} else if err == nil {
			passed[crashDetail(data)] = true
		}
	}
	var errs []error
	for _, d := range crashed {
		errs = append(errs, s.report(ctx, t, d))
	}
	if oversize {
		errs = append(errs, s.report(ctx, t, loops.FuzzOversizeDetail))
	}
	if noInput {
		errs = append(errs, s.report(ctx, t, loops.FuzzNoInputDetail))
	} else if runErr == nil {
		passed[loops.FuzzNoInputDetail] = true // the whole replay passed
		if !oversize {
			passed[loops.FuzzOversizeDetail] = true // and read every input it named
		}
	}
	for _, f := range s.cfg.Report.OpenReported(loops.CheckFuzz) {
		if f.Subject == t.subject() && passed[f.Detail] {
			r := loops.Replay{Evidence: f.Detail, Passed: true, At: s.cfg.Now()}
			errs = append(errs, s.cfg.Report.Resolve(f.ID, r))
		}
	}
	n := len(crashed)
	if noInput {
		n = 1
	}
	if oversize {
		n++
	}
	return n, errors.Join(errs...)
}

// eachInput replays each stored input of t alone, within InputTime: one
// that exits non-zero or runs past it fails; one that exits zero passed.
func (s *Source) eachInput(ctx context.Context, t Target) (failing, ran map[string]bool, err error) {
	failing, ran = map[string]bool{}, map[string]bool{}
	r, err := s.tree()
	if err != nil {
		return nil, nil, err
	}
	es, err := fs.ReadDir(r.FS(), filepath.ToSlash(s.in(corpusDir(t))))
	r.Close()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	for _, e := range es {
		if !e.Type().IsRegular() {
			continue
		}
		ictx, cancel := context.WithTimeout(ctx, s.cfg.InputTime)
		_, err := s.run(ictx, t, "-test.run=^"+t.Name+"$/^"+regexp.QuoteMeta(e.Name())+"$", "-test.v",
			"-test.timeout="+s.cfg.InputTime.String())
		cancel()
		if ctx.Err() != nil {
			return failing, ran, nil
		}
		if err != nil && !exited(err) {
			return nil, nil, fmt.Errorf("loop7: replaying %s: %w", t.subject(), err)
		}
		if err != nil {
			failing[e.Name()] = true
		} else {
			ran[e.Name()] = true
		}
	}
	return failing, ran, nil
}

// corpusDir holds t's stored inputs, crash inputs among them.
func corpusDir(t Target) string { return filepath.Join(t.Dir, "testdata", "fuzz", t.Name) }

// inputCap bounds one stored input root reads (F16): Go's fuzz inputs are
// small, and the fuzz user can grow any file in its tree.
const inputCap = 1 << 20

// errTooLarge is an input past inputCap.
var errTooLarge = fmt.Errorf("loop7: input larger than %d bytes", inputCap)

// input reads one of t's stored inputs, through the tree. It refuses
// anything but a regular file within inputCap by its Lstat, before
// opening it (a FIFO would block the open), and reads at most
// inputCap+1, so a file grown since the stat is refused too. Nothing can
// swap the file between the two: no process of the jail's user lives
// while root reads (run empties the leaf after every child).
func (s *Source) input(t Target, file string) ([]byte, error) {
	r, err := s.tree()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	p := filepath.Join(s.in(corpusDir(t)), file)
	fi, err := r.Lstat(p)
	switch {
	case err != nil:
		return nil, err
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("loop7: %s is not a regular file", p)
	case fi.Size() > inputCap:
		return nil, errTooLarge
	}
	f, err := r.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return capped(f)
}

// capped reads r to its end, refusing more than inputCap bytes.
func capped(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, inputCap+1))
	if err == nil && len(data) > inputCap {
		err = errTooLarge
	}
	return data, err
}

// exited reports that a child ran and exited non-zero or was killed: a
// failure of the target. Anything else (refused before exec, could not
// start) is the runner's error, never a finding.
func exited(err error) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee)
}

// report reports a High fuzz finding for t.
func (s *Source) report(ctx context.Context, t Target, detail string) error {
	_, err := s.cfg.Report.Report(ctx, loops.Finding{Check: loops.CheckFuzz, Subject: t.subject(), Severity: loops.High, Detail: detail})
	return err
}

// crashDetail names a crashing input by its digest; the input itself
// stays in the corpus.
func crashDetail(data []byte) string {
	h := sha256.Sum256(data)
	return "crash input sha256:" + hex.EncodeToString(h[:])
}

// waitDelay bounds the wait for a killed child's pipes.
const waitDelay = 200 * time.Millisecond

// run runs t's binary with args and returns its combined output. This is
// loop7's one exec (ARC-2, daemon escapeOK): the binary must be a regular
// file the release lists, not a link, checked before exec; the child gets
// a minimal environment and a scratch directory of its own, never the
// daemon's environment (#515 Security 2), and runs in its own process
// group, which cancelling kills whole: the fuzz engine runs workers as
// children, and a job must yield within the preemption target (LOOP-1).
// With a Jail, the child also starts as its user in an empty network
// namespace, inside its cgroup leaf (F2, F7).
func (s *Source) run(ctx context.Context, t Target, args ...string) ([]byte, error) {
	if err := released(s.cfg.Release, t.Binary); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(t.Binary); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("loop7: %s is not a regular file", t.Binary)
	}
	// No process of the jail's user may live while root works in its
	// tree: one could swap a path root is about to use (L3 1 on #588).
	if err := s.cfg.Jail.empty(); err != nil {
		return nil, err
	}
	r, err := s.tree()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	name, err := runName()
	if err != nil {
		return nil, err
	}
	rel := filepath.Join(s.in(s.cfg.CacheDir), name)
	if err := r.MkdirAll(filepath.Dir(rel), 0o700); err != nil {
		return nil, err
	}
	if err := r.Mkdir(rel, 0o700); err != nil {
		return nil, err
	}
	scratch := filepath.Join(s.cfg.CacheDir, name)
	attr := &syscall.SysProcAttr{Setpgid: true}
	if j := s.cfg.Jail; j != nil {
		// rel and the cache above it, which root may just have made on a
		// fresh state, are the user's (Security B3 on #588).
		if err := j.ownPath(r, rel); err != nil {
			r.RemoveAll(rel)
			return nil, err
		}
		leaf, err := j.attr(attr)
		if err != nil {
			r.RemoveAll(rel)
			return nil, err
		}
		if leaf != nil {
			defer leaf.Close()
		}
	}
	cmd := exec.CommandContext(ctx, t.Binary, args...)
	cmd.Dir = t.Dir
	cmd.Env = childEnv(scratch)
	cmd.SysProcAttr = attr
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = waitDelay
	// The broker keeps at most outputCap of the output, which the leaf's
	// memory.max does not bound; the pipe is drained to its end.
	buf := &capBuffer{}
	cmd.Stdout, cmd.Stderr = buf, buf
	err = startNoNewPrivs(cmd)
	if err == nil {
		err = cmd.Wait()
	}
	out := buf.Bytes()
	// Whatever left the process group (setsid) dies with the run, before
	// root removes the scratch directory or prunes the cache. A failure
	// here is the runner's, never a finding: it is not an ExitError.
	if kerr := s.cfg.Jail.empty(); kerr != nil {
		return nil, fmt.Errorf("loop7: emptying the fuzz leaf: %w", kerr)
	}
	if rerr := r.RemoveAll(rel); rerr != nil && err == nil {
		err = rerr
	}
	return out, err
}

// startNoNewPrivs starts cmd with no_new_privs set, so neither the child
// nor anything it execs gains privileges through a setuid or
// file-capability binary (F2; #588 Security R1). The flag is per thread
// and is inherited across clone and kept across execve (prctl(2)). Go's
// forkExec clones the child from the calling thread: syscall's
// forkAndExecInChild issues clone or clone3 inline, without switching
// threads, which is why SysProcAttr.Pdeathsig ties the child to "the
// creating thread" and asks for runtime.LockOSThread. So the start runs
// on a goroutine locked to its thread, which sets the flag first, and
// that goroutine exits still locked: the runtime then ends the thread
// (runtime.LockOSThread), or, if it is the process's main thread, wedges
// it for good with no goroutine on it (runtime.mexit), so the flag never
// reaches a thread that starts another child
// (TestNoNewPrivsStaysOffTheDaemonsOtherThreads).
func startNoNewPrivs(cmd *exec.Cmd) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// No UnlockOSThread: the thread must die with this goroutine.
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			done <- fmt.Errorf("loop7: setting no_new_privs: %w", err)
			return
		}
		done <- cmd.Start()
	}()
	return <-done
}

// outputCap bounds the output the broker keeps of one child (F12): its
// first outputHead bytes, where the fuzz step's baseline line is, and its
// last bytes, where its last exec count and a failure's reason are. A 30 s
// step's progress lines are a few KiB.
const (
	outputCap  = 1 << 20
	outputHead = 64 << 10
)

// capBuffer keeps a child's output within outputCap: the head, then a
// ring of the tail. Writes never fail, so the child is never blocked.
type capBuffer struct {
	head, ring []byte
	next       int  // where the ring is written next, once full
	cut        bool // bytes between the head and the ring were dropped
}

func (b *capBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if k := min(outputHead-len(b.head), len(p)); k > 0 {
		b.head, p = append(b.head, p[:k]...), p[k:]
	}
	const size = outputCap - outputHead - 1 // one byte for Bytes' line end
	if len(p) >= size {
		b.cut = b.cut || len(b.ring) > 0 || len(p) > size
		b.ring, b.next, p = append(b.ring[:0], p[len(p)-size:]...), 0, nil
	}
	if k := min(size-len(b.ring), len(p)); k > 0 {
		b.ring, p = append(b.ring, p[:k]...), p[k:]
	}
	for len(p) > 0 {
		b.cut = true
		c := copy(b.ring[b.next:], p)
		p, b.next = p[c:], (b.next+c)%size
	}
	return n, nil
}

// Bytes is the output kept, in order. Where bytes were dropped, the head
// ends its line, so no line joins the head's end to the tail's start.
func (b *capBuffer) Bytes() []byte {
	out := append([]byte{}, b.head...)
	if b.cut && len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	out = append(out, b.ring[b.next:]...)
	return append(out, b.ring[:b.next]...)
}

// ownPath gives rel and each directory above it in the tree, up to the
// tree itself, to the jail's user, through r: none follows a link.
func (j *Jail) ownPath(r *os.Root, rel string) error {
	for p := rel; p != "." && p != "/"; p = filepath.Dir(p) {
		if err := r.Lchown(p, int(j.UID), int(j.GID)); err != nil {
			return err
		}
	}
	return nil
}

// trailer is a line a Go test binary prints after its reason: the bare
// FAIL or PASS, or "exit status N".
var trailer = regexp.MustCompile(`^(FAIL|PASS|exit status \d+)$`)

// tail is the end of a child's output, without its trailing trailer
// lines, at most 200 bytes, so a runner error says why the engine stopped
// (L3 delta on #588: the bare FAIL alone says nothing).
func tail(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for len(lines) > 0 && trailer.MatchString(strings.TrimSpace(lines[len(lines)-1])) {
		lines = lines[:len(lines)-1]
	}
	t := strings.TrimSpace(strings.Join(lines, "\n"))
	if len(t) > 200 {
		t = t[len(t)-200:]
	}
	return t
}

// runName is a fresh scratch directory's name.
func runName() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "run-" + hex.EncodeToString(b), nil
}

// emptyWait bounds empty's whole run, the kill included, so a cancelled
// job hands the agent the box back within LOOP-1's 2 s: run's last empty
// follows a killed child by at most waitDelay (F16). It is empty's own
// bound, not the caller's context, which is cancelled exactly when the
// leaf must still be emptied.
const emptyWait = 1500 * time.Millisecond

// freezeWait bounds the freeze within emptyWait, so a freeze that cannot
// complete still leaves time to kill.
const freezeWait = 500 * time.Millisecond

// freeze freezes the leaf; a test replaces it with a freeze that cannot
// complete.
var freeze = func(ctx context.Context, g *cgroup.Group) error { return g.Freeze(ctx) }

// empty kills every process left in the jail's leaf and waits until the
// kernel reports it empty, all within emptyWait. It freezes the leaf, so
// nothing in it can fork, SIGKILLs each process cgroup.procs lists (a
// fatal signal reaches a frozen task), thaws it and waits for populated
// 0. When the freeze fails or does not complete within freezeWait, it
// kills all the same, and on every later read of cgroup.procs until the
// leaf is empty: without the freeze a fork can race a pass, but pids.max
// bounds the set each pass faces. Only processes still alive at the
// deadline make it fail, and the error names them (F16). It does not
// write cgroup.kill: on CI's kernel a child started into a group by
// CLONE_INTO_CGROUP after a cgroup.kill there is killed at once (on #588
// every jailed child then died with "signal: killed"). With no jail or no
// leaf (tests, dev builds) there is nothing to empty: agentosd always sets
// the leaf (L7-6), and without one a child that leaves its process group
// outlives its run.
func (j *Jail) empty() error {
	if j == nil || j.Leaf == "" {
		return nil
	}
	deadline := time.Now().Add(emptyWait)
	g := &cgroup.Group{Path: j.Leaf}
	ctx, cancel := context.WithTimeout(context.Background(), freezeWait)
	ferr := freeze(ctx, g)
	cancel()
	killLeaf(j.Leaf)
	terr := g.Thaw()
	for {
		p, err := g.Populated()
		if err != nil {
			return err
		}
		if !p {
			return terr
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("loop7: fuzz leaf %s did not empty within %v: pids %v survive (freeze: %v, thaw: %v)", j.Leaf, emptyWait, killLeaf(j.Leaf), ferr, terr)
		}
		time.Sleep(time.Millisecond)
		killLeaf(j.Leaf)
	}
}

// killLeaf is one kill pass: it SIGKILLs each process leaf's cgroup.procs
// lists and returns their pids. A pid is signalled within the pass that
// read it, far sooner than the kernel hands a freed pid out again (F16).
// A test wraps it to see what each pass found.
var killLeaf = func(leaf string) []int {
	b, _ := os.ReadFile(filepath.Join(leaf, "cgroup.procs"))
	var pids []int
	for _, f := range strings.Fields(string(b)) {
		if pid, err := strconv.Atoi(f); err == nil && pid > 0 {
			syscall.Kill(pid, syscall.SIGKILL)
			pids = append(pids, pid)
		}
	}
	return pids
}

// Jail confines fuzz children (P3-4b-3r-confine; F2, F7): a decoder bug
// a fuzz input reaches runs as an unprivileged user with no capabilities
// and no network, and a child that blows memory or forks is stopped by
// its own cgroup leaf, never by the broker's.
type Jail struct {
	// Leaf is the cgroup v2 leaf each child starts in, through
	// CLONE_INTO_CGROUP (SysProcAttr.CgroupFD), so no child runs a moment
	// in the broker's group. agentosd always sets it (L7-6); empty starts
	// children in the daemon's group.
	Leaf string
	// UID and GID are the user children run as, with no supplementary
	// groups: setting a non-zero UID from root clears every capability
	// across exec, and no ambient capability is raised. UID 0 is refused.
	UID, GID uint32
	// State is the tree the user owns: the targets' directories and the
	// cache lie in it (New checks), and root works in it only through an
	// os.Root opened there (Source.tree, Load), with no process of the
	// user alive (empty). Its parent must not be writable by the user.
	State string
	// Disk, if set, bounds State's disk use (RES-4): Own calls it on State
	// once the leaf is empty, before giving the tree to the user.
	// agentosd always sets it (L7-6).
	Disk func(state string) error
}

// attr sets the jail on a child's attributes; the returned leaf, if any,
// must stay open until the child has started.
func (j *Jail) attr(a *syscall.SysProcAttr) (*os.File, error) {
	a.Credential = &syscall.Credential{Uid: j.UID, Gid: j.GID, Groups: []uint32{}}
	// An empty network namespace: only a loopback device, which is down.
	// An IPC namespace of its own, whose SysV segments and POSIX queues
	// die with its last process, so none stays charged to the leaf after
	// empty. A user namespace mapping only the jail's user and group to
	// themselves: the child keeps its ids and gains no capability across
	// exec, and the kernel refuses a project ID change from outside the
	// initial namespace, so the child cannot retag its tree out of its
	// quota (RES-4), which an owner otherwise may.
	a.Cloneflags = syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUSER
	a.UidMappings = []syscall.SysProcIDMap{{ContainerID: int(j.UID), HostID: int(j.UID), Size: 1}}
	a.GidMappings = []syscall.SysProcIDMap{{ContainerID: int(j.GID), HostID: int(j.GID), Size: 1}}
	// Setgroups stays allowed, so the child's group list is emptied
	// rather than kept from the daemon.
	a.GidMappingsEnableSetgroups = true
	if j.Leaf == "" {
		return nil, nil
	}
	leaf, err := os.Open(j.Leaf)
	if err != nil {
		return nil, err
	}
	a.UseCgroupFD, a.CgroupFD = true, int(leaf.Fd())
	return leaf, nil
}

// Own gives the jail's State to its user, which the children write their
// crash inputs and cache into (F9). It runs at start-up, after emptying
// the leaf, so a tree written by root before the jail stays readable. It
// works through an os.Root and never follows a link, and leaves a file
// with more than one link alone, so nothing a child planted can hand it a
// file from outside.
func (j *Jail) Own() error {
	if err := j.empty(); err != nil {
		return err
	}
	if j.Disk != nil {
		if err := j.Disk(j.State); err != nil {
			return err
		}
	}
	r, err := os.OpenRoot(j.State)
	if err != nil {
		return err
	}
	defer r.Close()
	return fs.WalkDir(r.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := r.Lstat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || d.Type()&os.ModeSymlink != 0 || (fi.Mode().IsRegular() && st.Nlink > 1) {
			return nil
		}
		if st.Uid == j.UID && st.Gid == j.GID {
			return nil
		}
		return r.Lchown(p, int(j.UID), int(j.GID))
	})
}

// pruneWalked, when set by a test, runs between prune's walk and its
// removals, where a child could swap a directory for a link.
var pruneWalked func()

// cached is one file of the fuzz engine's generated corpus.
type cached struct {
	path string
	size int64
	mod  time.Time
}

// prune keeps the fuzz cache within its caps before pkg's fuzz step
// (F15): pkg's own entries (CacheDir/fuzz/<pkg>/Fuzz*, so not a nested
// package's) to CacheCap, then the whole cache to CacheTotal, removing
// the oldest first. It walks only CacheDir/fuzz: crash inputs live in the
// targets' testdata, which is evidence and never pruned (F3, F9). It
// walks and removes through the tree, after the last run emptied the
// leaf, so no link takes a removal out of the cache.
func (s *Source) prune(pkg string) error {
	r, err := s.tree()
	if err != nil {
		return err
	}
	defer r.Close()
	root := filepath.Join(s.in(s.cfg.CacheDir), "fuzz")
	own := filepath.Join(root, filepath.FromSlash(pkg))
	var mine, all []cached
	err = fs.WalkDir(r.FS(), filepath.ToSlash(root), func(p string, d fs.DirEntry, err error) error {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		c := cached{p, fi.Size(), fi.ModTime()}
		all = append(all, c)
		if rel, err := filepath.Rel(own, p); err == nil && fuzzName.MatchString(strings.Split(rel, string(filepath.Separator))[0]) {
			mine = append(mine, c)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if pruneWalked != nil {
		pruneWalked()
	}
	gone := map[string]bool{}
	trim := func(cs []cached, limit int64) error {
		sort.Slice(cs, func(i, k int) bool { return cs[i].mod.Before(cs[k].mod) })
		var total int64
		for _, c := range cs {
			if !gone[c.path] {
				total += c.size
			}
		}
		for _, c := range cs {
			if total <= limit {
				break
			}
			if gone[c.path] {
				continue
			}
			if err := r.Remove(c.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			gone[c.path], total = true, total-c.size
		}
		return nil
	}
	if err := trim(mine, s.cfg.CacheCap); err != nil {
		return err
	}
	return trim(all, s.cfg.CacheTotal)
}

// childEnv is all of a child's environment: a fixed PATH, HOME and TMPDIR
// in its scratch directory, no build cache, no GOFLAGS.
func childEnv(scratch string) []string {
	return []string{"PATH=/usr/bin:/bin", "HOME=" + scratch, "TMPDIR=" + scratch, "GOCACHE=off", "GOFLAGS="}
}

// probe is one probe round: run it in a guest, check the journal against
// what it sent, report a failure, or resolve the machine's open probe
// findings on a clean round.
func (s *Source) probe(ctx context.Context) (int, error) {
	start := s.cfg.Now()
	machine, failures, err := s.cfg.Probe(ctx)
	if ctx.Err() != nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("loop7: probe: %w", err)
	}
	fails := append(failures, Journaled(machine, s.cfg.Want, s.cfg.Trail(), start, s.cfg.Now(), s.cfg.Window)...)
	subject := "socket." + machine
	var errs []error
	detail := ""
	if len(fails) > 0 {
		detail = probeDetail(fails)
		f := loops.Finding{Check: loops.CheckProbe, Subject: subject, Severity: loops.High, Detail: detail}
		if _, err := s.cfg.Report.Report(ctx, f); err != nil {
			errs = append(errs, err)
		}
	}
	for _, f := range s.cfg.Report.OpenReported(loops.CheckProbe) {
		// A clean round replays the probe's frames: the only pass that
		// closes a probe finding.
		if f.Subject == subject && len(fails) == 0 {
			r := loops.Replay{Evidence: f.Detail, Passed: true, At: s.cfg.Now()}
			errs = append(errs, s.cfg.Report.Resolve(f.ID, r))
		}
	}
	return len(fails), errors.Join(errs...)
}

// maxDetail bounds a probe finding's evidence text.
const maxDetail = 1024

func probeDetail(fails []string) string {
	d := "probe failures: " + strings.Join(fails, "; ")
	if len(d) > maxDetail {
		d = d[:maxDetail]
	}
	return d
}

// Journaled is the broker side of a probe round on machine between start
// and end: each refusal code in want, the probe set's, is journaled (a socket-refusal note
// for the machine and code, at most window before start, since notes are
// coalesced per window), and no frame had an effect (no intent from the
// machine in the round). It returns the failures in plain words.
func Journaled(machine string, codes []sockets.Code, trail []journal.Record, start, end time.Time, window time.Duration) []string {
	// The codes come from the broker's own probe set, never from what the
	// guest says it sent: an empty Result must not pass the round.
	want := map[sockets.Code]bool{}
	for _, c := range codes {
		want[c] = true
	}
	var fails []string
	for _, r := range trail {
		if r.At.Before(start.Add(-window)) || r.At.After(end) {
			continue
		}
		if r.Type == journal.RecEgress && r.Egress != nil && r.Egress.Adapter == sockets.RefusalNote && r.Egress.Machine == machine {
			for c := range want {
				if r.Egress.Operation == c.Token() {
					delete(want, c)
				}
			}
		}
		if r.Intent != nil && r.Intent.Machine == machine && !r.At.Before(start) {
			fails = append(fails, fmt.Sprintf("a probe round on %s journaled intent %s", machine, r.Intent.Action))
		}
	}
	for _, c := range sortedKeys(want) {
		fails = append(fails, fmt.Sprintf("refusal %q on %s was not journaled", c, machine))
	}
	return fails
}

func sortedKeys[K ~string, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
