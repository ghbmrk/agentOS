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
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// Reporter is Loop 2's in-process entry point (*loops.Guard).
type Reporter interface {
	Report(ctx context.Context, f loops.Finding) (loops.Record, error)
	Resolve(id string, r loops.Replay) error
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
	// oldest entries past them first (F14). Defaults 64 MiB and 512 MiB.
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
	return &Source{cfg: cfg, base: base}, nil
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
		data, err := os.ReadFile(filepath.Join(from, e.Name()))
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

// Loop is Loop 2.
func (s *Source) Loop() loops.Loop { return loops.Secure }

// Urgent is Inner's: a LOOP-7 round is never urgent.
func (s *Source) Urgent() bool {
	u, ok := s.cfg.Inner.(loops.Urgent)
	return ok && u.Urgent()
}

// Digest is Inner's digest lines (loops.Digester), which the scheduler
// reads for STATUS.
func (s *Source) Digest() []string {
	d, ok := s.cfg.Inner.(loops.Digester)
	if !ok {
		return nil
	}
	return d.Digest()
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
	out, err := s.run(fctx, t, "-test.run=^$", "-test.fuzz=^"+t.Name+"$",
		"-test.fuzztime="+s.cfg.FuzzTime.String(), "-test.parallel=1",
		"-test.fuzzcachedir="+filepath.Join(s.cfg.CacheDir, "fuzz", filepath.FromSlash(t.Pkg)))
	overran := fctx.Err() != nil
	cancel()
	switch {
	case ctx.Err() != nil:
		return 0, nil
	case overran && (err == nil || exited(err)):
		// The engine's own -test.fuzztime did not stop it. A clean step
		// later never replays what kept it running, so this finding is
		// not resolved here (delta L3 on #560): it stays open for
		// P3-4b-3c's rules.
		return 1, s.report(ctx, t, overrunDetail)
	case err == nil:
		return 0, nil
	case !bytes.Contains(out, []byte("Failing input written to")):
		return 0, fmt.Errorf("loop7: fuzzing %s did not run: %v", t.subject(), err)
	}
	return s.replay(ctx, t)
}

// Target findings: a failure no stored input can be named for.
const (
	noInputDetail = "the target failed before any stored input could be named (a seed added in code, or a crash at start)"
	overrunDetail = "the fuzz engine did not stop within its bound"
)

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
	var errs []error
	// Each stored input whose own subtest passed in this run: only such a
	// replay closes a finding. An input that never ran (a panic stops the
	// binary before later seeds) or was removed keeps its finding open.
	passed := map[string]bool{}
	for _, file := range sortedKeys(ran) {
		if data, err := s.input(t, file); err == nil {
			passed[crashDetail(data)] = true
		}
	}
	for _, file := range sortedKeys(failing) {
		data, err := s.input(t, file)
		if err != nil {
			// A failing f.Add seed, not a file: report it by name.
			data = []byte(file)
		}
		errs = append(errs, s.report(ctx, t, crashDetail(data)))
	}
	if noInput {
		errs = append(errs, s.report(ctx, t, noInputDetail))
	} else if runErr == nil {
		passed[noInputDetail] = true // the whole replay passed
	}
	for _, f := range s.cfg.Report.OpenReported(loops.CheckFuzz) {
		if f.Subject == t.subject() && passed[f.Detail] {
			r := loops.Replay{Evidence: f.Detail, Passed: true, At: s.cfg.Now()}
			errs = append(errs, s.cfg.Report.Resolve(f.ID, r))
		}
	}
	n := len(failing)
	if noInput {
		n = 1
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

// input reads one of t's stored inputs, through the tree.
func (s *Source) input(t Target, file string) ([]byte, error) {
	r, err := s.tree()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return r.ReadFile(filepath.Join(s.in(corpusDir(t)), file))
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
	out, err := cmd.CombinedOutput()
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

// runName is a fresh scratch directory's name.
func runName() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "run-" + hex.EncodeToString(b), nil
}

// killWait bounds the wait for the leaf to empty.
const killWait = 5 * time.Second

// empty kills every process left in the jail's leaf and waits until the
// kernel reports it empty (cgroup.kill). With no jail or no leaf (tests,
// dev builds) there is nothing to empty: agentosd always sets the leaf
// (L7-6), and without one a child that leaves its process group outlives
// its run.
func (j *Jail) empty() error {
	if j == nil || j.Leaf == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), killWait)
	defer cancel()
	return (&cgroup.Group{Path: j.Leaf}).Kill(ctx)
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
}

// attr sets the jail on a child's attributes; the returned leaf, if any,
// must stay open until the child has started.
func (j *Jail) attr(a *syscall.SysProcAttr) (*os.File, error) {
	a.Credential = &syscall.Credential{Uid: j.UID, Gid: j.GID, Groups: []uint32{}}
	// An empty network namespace: only a loopback device, which is down.
	a.Cloneflags = syscall.CLONE_NEWNET
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

// cached is one file of the fuzz engine's generated corpus.
type cached struct {
	path string
	size int64
	mod  time.Time
}

// prune keeps the fuzz cache within its caps before pkg's fuzz step
// (F14): pkg's own entries (CacheDir/fuzz/<pkg>/Fuzz*, so not a nested
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
