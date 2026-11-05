// Package run keeps the enforcer's dnsmasq instances running, each from
// its generated file (broker/enforcer/dns, ASSUMPTIONS ENF-f-1), and
// changes them in step with the firewall (ENF-l-dns-step, #4464): every
// instance whose file changes is stopped before the new ruleset loads and
// started on its new file only after the load, so no instance still
// running an old list fills an allow set of the new ruleset with a name
// the new document dropped (NET-2 The core's list, NET-3).
//
// It is the third enforcer package that starts a process, beside the
// firewall loader and the radio launcher (broker/daemon/arc2_test.go
// enforcerExec): the daemon itself starts none. Each instance runs as the
// daemon's own user (dnsmasq changes user only when started as root,
// which the daemon refuses), in the foreground, with an empty environment
// and no pid file. Its assumptions are in the dns package's ASSUMPTIONS.md
// (ENF-f-9).
package run

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/dns"
)

// StopWait is how long a stopped instance has to exit after SIGTERM
// before it is killed.
const StopWait = 5 * time.Second

var stopWait = StopWait // the tests' seam

// Restart bounds the wait before an instance that exited on its own is
// started again: it starts at RestartMin and doubles up to RestartMax.
const (
	RestartMin = time.Second
	RestartMax = 30 * time.Second
)

// ErrRun is a refused configuration or start.
var ErrRun = errors.New("dns/run: refused")

// Set is the running instances. Use New.
type Set struct {
	bin, dir string
	logf     func(string)

	mu    sync.Mutex
	procs map[string]*proc // by instance name
	// want is each instance's file that matches the ruleset in force:
	// an instance is started, or started again after it exits, only on
	// its file there. Apply narrows it to the instances it keeps until
	// its load is done, so nothing starts on a file of either document
	// in the meantime.
	want   map[string]string
	closed bool
}

type proc struct {
	conf string
	cmd  *exec.Cmd
	done chan struct{} // closed when the process has exited
}

// New is a set that runs bin (the image's dnsmasq, an absolute path) on
// files kept in dir, which must be an existing directory only its owner
// can reach.
func New(bin, dir string, logf func(string)) (*Set, error) {
	if !filepath.IsAbs(bin) {
		return nil, fmt.Errorf("%w: dnsmasq must be an absolute path", ErrRun)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s must be a directory with no group or other access", ErrRun, dir)
	}
	if logf == nil {
		logf = func(string) {}
	}
	return &Set{bin: bin, dir: dir, logf: logf, procs: map[string]*proc{}, want: map[string]string{}}, nil
}

// Names is each instance's name and file: the listed instances by
// interface, then people, then dhcp. An instance with an empty file is
// left out, so it never runs: dnsmasq on an empty file is an open
// resolver on every interface (dns.Files{} stops every instance).
func Names(f dns.Files) map[string]string {
	m := make(map[string]string, len(f.Listed)+2)
	add := func(name, conf string) {
		if conf != "" {
			m[name] = conf
		}
	}
	for _, l := range f.Listed {
		add("listed-"+l.Iface, l.Conf)
	}
	add("people", f.People)
	add("dhcp", f.DHCP)
	return m
}

// Apply moves the instances to f around load, the firewall's load of the
// same document: it stops every instance whose file changes or that f no
// longer has, and waits for each to exit; it calls load; then it starts
// every instance of f not running. If load fails, the previous ruleset
// stays (nft's transaction), and the instances stopped are started again
// on their previous files, which match it. Apply returns load's error
// alone: an instance that fails to start is logged and started again
// with the backoff an exited one gets, so a start failure never reads as
// a refused load.
// An instance whose file is unchanged keeps running: it fills the sets of
// the same names, which the load keeps (nft.Reload).
func (s *Set) Apply(f dns.Files, load func() error) error {
	next := Names(f)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("%w: closed", ErrRun)
	}
	prev := s.want
	kept := map[string]string{}
	for name, c := range prev {
		if next[name] == c {
			kept[name] = c
		}
	}
	s.want = kept
	var stop []*proc
	for name, p := range s.procs {
		if kept[name] != p.conf {
			stop = append(stop, p)
			delete(s.procs, name)
		}
	}
	s.mu.Unlock()
	haltAll(stop)
	in := next
	err := load()
	if err != nil {
		in = prev
	}
	s.mu.Lock()
	s.want = in
	s.mu.Unlock()
	s.startAll(in)
	s.prune(in)
	return err
}

// prune removes the files of documents no longer in force.
func (s *Set) prune(in map[string]string) {
	keep := map[string]bool{}
	for name, c := range in {
		keep[confPath(s.dir, name, c)] = true
	}
	old, _ := filepath.Glob(filepath.Join(s.dir, "*.conf"))
	for _, f := range old {
		if !keep[f] {
			os.Remove(f)
		}
	}
}

// confPath is an instance's file for one content: a start on an older
// file never overwrites the one in force.
func confPath(dir, name, conf string) string {
	sum := sha256.Sum256([]byte(conf))
	return filepath.Join(dir, name+"-"+hex.EncodeToString(sum[:8])+".conf")
}

// startAll starts each named instance on its file. One that fails is
// logged and tried again (retry); the others still start.
func (s *Set) startAll(m map[string]string) {
	for _, name := range slices.Sorted(maps.Keys(m)) {
		if err := s.start(name, m[name], RestartMin); err != nil {
			s.logf("dns: " + name + ": " + err.Error())
			go s.retry(name, m[name], RestartMin)
		}
	}
}

// retry starts name on conf after backoff, doubling it up to RestartMax
// after each failure, until it runs or conf is no longer its file in
// force (start then does nothing).
func (s *Set) retry(name, conf string, backoff time.Duration) {
	for {
		s.logf(fmt.Sprintf("dns: %s: starting it again in %s", name, backoff))
		time.Sleep(backoff)
		backoff = min(2*backoff, RestartMax)
		err := s.start(name, conf, backoff)
		if err == nil {
			return
		}
		s.logf("dns: " + name + ": " + err.Error())
	}
}

// start starts name on conf if that is its file in force and it is not
// running. The check, the file's write and the start are one step under
// s.mu, so no start on a file no longer in force slips past an Apply.
func (s *Set) start(name, conf string, backoff time.Duration) error {
	s.mu.Lock()
	if _, running := s.procs[name]; s.closed || running || s.want[name] != conf {
		s.mu.Unlock()
		return nil
	}
	path := confPath(s.dir, name, conf)
	if err := writeFile(path, conf); err != nil {
		s.mu.Unlock()
		return err
	}
	cmd := exec.Command(s.bin, "--keep-in-foreground", "--pid-file=", "--conf-file="+path)
	cmd.Env = []string{}
	cmd.Dir = s.dir
	// A process the instance left holding its standard error cannot hold
	// Wait, and so a stop, past this.
	cmd.WaitDelay = time.Second
	// Its own process group, so a stop reaches its TCP children too, and
	// killed if the daemon dies before the service manager stops it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Stderr = &lineLog{logf: s.logf, prefix: "dns: " + name + ": "}
	if err := cmd.Start(); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: %v", ErrRun, err)
	}
	p := &proc{conf: conf, cmd: cmd, done: make(chan struct{})}
	s.procs[name] = p
	s.mu.Unlock()
	go s.watch(name, p, backoff)
	return nil
}

// watch logs an instance's output and, when it exits without being asked
// to, starts it again on the same file after a wait that doubles each
// time, up to RestartMax. It is not started again once its file is no
// longer the one in force (Set.want).
func (s *Set) watch(name string, p *proc, backoff time.Duration) {
	err := p.cmd.Wait()
	close(p.done)
	s.mu.Lock()
	again := !s.closed && s.procs[name] == p
	if again {
		delete(s.procs, name)
	}
	s.mu.Unlock()
	if !again {
		return
	}
	s.logf(fmt.Sprintf("dns: %s exited (%v)", name, err))
	s.retry(name, p.conf, backoff)
}

// halt stops p's process group and waits for p to exit: SIGTERM, then
// SIGKILL after StopWait, then SIGKILL for anything left in the group.
func halt(p *proc) {
	pg := -p.cmd.Process.Pid // the instance's process group (Setpgid)
	_ = syscall.Kill(pg, syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(stopWait):
		_ = syscall.Kill(pg, syscall.SIGKILL)
		<-p.done
	}
	// dnsmasq forks a child per TCP query, which holds the same nftset
	// lines: none may outlive its parent into the next load (Security
	// 6655916292 release point).
	_ = syscall.Kill(pg, syscall.SIGKILL)
}

// Close stops every instance and waits for each to exit.
func (s *Set) Close() {
	s.mu.Lock()
	s.closed = true
	procs := slices.Collect(maps.Values(s.procs))
	s.mu.Unlock()
	haltAll(procs)
}

// haltAll halts ps at once, so instances that ignore SIGTERM cost one
// stop wait together, not one each.
func haltAll(ps []*proc) {
	var wg sync.WaitGroup
	for _, p := range ps {
		wg.Add(1)
		go func() { defer wg.Done(); halt(p) }()
	}
	wg.Wait()
}

// writeFile replaces path with b, readable by its owner only.
func writeFile(path, b string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// lineLog is an instance's standard error, one log line per line, each
// cut at 512 bytes so an instance cannot fill the log with one line.
type lineLog struct {
	logf   func(string)
	prefix string
	buf    []byte
}

func (l *lineLog) Write(p []byte) (int, error) {
	l.buf = append(l.buf, p...)
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			if len(l.buf) > 512 {
				l.logf(l.prefix + string(l.buf[:512]))
				l.buf = l.buf[:0]
			}
			return len(p), nil
		}
		line := l.buf[:i]
		if len(line) > 512 {
			line = line[:512]
		}
		l.logf(l.prefix + string(line))
		l.buf = l.buf[i+1:]
	}
}
