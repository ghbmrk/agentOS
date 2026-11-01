// Package push carries the access point's configuration (enforcer/ap) to
// the access point over SSH on the wired admin port (SPEC NET-3; briefs/
// ENF.md slice g), with the access point's host key pinned: it reads every
// file back, writes only what differs, applies, and reads back again, so a
// changed file on the access point is put back at the next Sync.
//
// It is the only enforcer package that links a third-party package,
// golang.org/x/crypto/ssh (broker/daemon/arc2_test.go): OpenWrt's admin
// paths are SSH or HTTP, the enforcer links no HTTP client, and an SSH
// client is not code to write again. Every command it runs is one of
// four fixed strings over a path from ap.Paths, a hash and a Sync's
// token; file contents go only on stdin, never into a command.
package push

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ghbmrk/agentos/broker/enforcer/ap"
)

var (
	ErrPath   = errors.New("push: not an access point path")
	ErrVerify = errors.New("push: access point does not hold what was written")
	// ErrSuperseded is a Sync whose write or reload the access point
	// refused because a later claim holds it (exit status refusedExit):
	// a claim of an earlier Sync that timed out waiting for the lock
	// landed after this Sync's own. It wrote nothing more, and the next
	// Sync, at Watch's next tick, claims afresh.
	ErrSuperseded = errors.New("push: a later claim holds the access point")
)

// refusedExit is the exit status of a write or reload the access point
// refuses because its Sync's token is no longer the newest claim:
// EX_TEMPFAIL, which no command push runs uses for anything else (a
// failed cat, hash check, flock or mv is 1; a missing command 127; a
// command a signal ended 128 and up).
const refusedExit = 75

// reloadBound is how long the reload may hold the access point's lock:
// busybox timeout ends reload_config after it, so a hung reload (a ubus
// call procd never answers) holds up the next claim, and the revocations
// it carries, for this long at most, rather than until ubus's own
// 30-second call timeout. Ending reload_config early loses nothing: it
// sends its change events before it records what it has sent, so a cut
// reload sends them again at the next Sync.
const reloadBound = 20 * time.Second

// MaxFile bounds what Sync reads back from the access point, so a hostile
// one cannot fill the enforcer's memory.
const MaxFile = 1 << 20

// Pusher reaches one access point.
type Pusher struct {
	// Addr is the access point's admin address and port.
	Addr string
	// HostKey is the access point's SSH host key, pinned at setup over
	// the wired admin port. Any other key ends the connection before
	// anything is sent.
	HostKey ssh.PublicKey
	// Signer is the enforcer's own SSH key (ap.Layout.EnforcerKey is its
	// public half).
	Signer ssh.Signer
	// Dial opens the TCP connection on the wired admin port; slice l
	// binds it there. There is no default, so a pusher nobody bound
	// reaches nothing.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Timeout bounds one Sync; zero is 30 seconds.
	Timeout time.Duration

	// mu keeps two Syncs of this Pusher from overlapping; there is one
	// Pusher per access point (ENF-g-8). It cannot order a command a
	// timed-out Sync left running on the access point against the next
	// Sync's; the access point's lock and token do (claimCmd).
	mu sync.Mutex
}

// Result is what one Sync did.
type Result struct {
	// Drift is the paths whose content on the access point differed from
	// the config before the Sync (absent counts).
	Drift []string
	// Applied reports that at least one file was written and the
	// reload after it succeeded.
	Applied bool
}

// Sync makes the access point hold exactly files: it reads each back,
// writes those that differ, reloads, and reads them all back again. It
// reloads on every Sync, drift or not, and after a failed write too, so
// a Sync that failed after some writes (a reload that errored, a later
// write that failed, a connection that dropped) is finished by the next
// one: reload_config applies only configs that changed since
// its last run, so an in-sync reload is a no-op. Syncs of one Pusher run
// one at a time, and once a Sync has claimed the access point, no command
// an earlier Sync left running there writes or reloads (claimCmd).
func (p *Pusher) Sync(ctx context.Context, files []ap.File) (Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, f := range files {
		if !slices.Contains(ap.Paths, f.Path) {
			return Result{}, fmt.Errorf("%w: %q", ErrPath, f.Path)
		}
	}
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, err := p.connect(ctx)
	if err != nil {
		return Result{}, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()

	tok := token()
	if _, err := run(c, claimCmd(tok), nil); err != nil {
		return Result{}, fmt.Errorf("push: claim: %w", err)
	}
	var res Result
	for _, f := range files {
		same, err := holds(c, f)
		if err != nil {
			return res, err
		}
		if !same {
			res.Drift = append(res.Drift, f.Path)
		}
	}
	// A write that fails does not stop the others or the reload: the
	// files written are on the access point and would not read as drift
	// next time, so every file is tried and the reload runs, and the
	// errors are returned together. A refused write ends the Sync: every
	// later command of it would be refused too.
	var errs []error
	wrote := 0
	for _, f := range files {
		if slices.Contains(res.Drift, f.Path) {
			if _, err := run(c, writeCmd(f.Path, tok, f.Data), f.Data); err != nil {
				err = fmt.Errorf("push: write %s: %w", f.Path, superseded(err))
				if errors.Is(err, ErrSuperseded) {
					return res, errors.Join(append(errs, err)...)
				}
				errs = append(errs, err)
				continue
			}
			wrote++
		}
	}
	if _, err := run(c, applyCmd(tok), nil); err != nil {
		errs = append(errs, fmt.Errorf("push: reload: %w", superseded(err)))
	} else {
		res.Applied = wrote > 0
	}
	if len(errs) > 0 {
		return res, errors.Join(errs...)
	}
	for _, f := range files {
		same, err := holds(c, f)
		if err != nil {
			return res, err
		}
		if !same {
			return res, fmt.Errorf("%w: %s", ErrVerify, f.Path)
		}
	}
	return res, nil
}

// Watch runs Sync with cfg's files now and every interval until ctx ends,
// reporting each outcome, so drift on the access point is pushed back
// within one interval. cfg is read each time, so a new policy version or
// a revoked password reaches the access point at the next tick.
func (p *Pusher) Watch(ctx context.Context, every time.Duration, cfg func() ([]ap.File, error), report func(Result, error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		files, err := cfg()
		var res Result
		if err == nil {
			res, err = p.Sync(ctx, files)
		}
		report(res, err)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// superseded marks err as ErrSuperseded when the access point refused
// the command for a newer claim.
func superseded(err error) error {
	var exit *ssh.ExitError
	if errors.As(err, &exit) && exit.ExitStatus() == refusedExit {
		return fmt.Errorf("%w: %w", ErrSuperseded, err)
	}
	return err
}

func (p *Pusher) connect(ctx context.Context) (*ssh.Client, error) {
	if p.HostKey == nil || p.Signer == nil || p.Dial == nil {
		return nil, errors.New("push: no pinned host key, enforcer key or admin-port dialer")
	}
	conn, err := p.Dial(ctx, "tcp", p.Addr)
	if err != nil {
		return nil, fmt.Errorf("push: dial: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	cfg := &ssh.ClientConfig{
		User:              "root",
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(p.Signer)},
		HostKeyCallback:   ssh.FixedHostKey(p.HostKey),
		HostKeyAlgorithms: []string{p.HostKey.Type()},
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, p.Addr, cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("push: ssh: %w", err)
	}
	return ssh.NewClient(sc, chans, reqs), nil
}

// The commands. A path is always one of ap.Paths, which hold no
// character a shell reads specially; the temporary file sits on /etc's
// own filesystem, so mv replaces the file in one rename, and umask keeps
// the passwords readable by root only.
//
// A Sync that times out closes the connection without waiting for the
// command it was running, which can keep running on the access point
// (ENF-g-10, #4313). So each Sync first claims the access point: under the
// access point's lock (busybox flock on lockPath) it writes a fresh
// random token to tokenPath and removes every temporary file. A write
// reads stdin into a temporary file of its own path and token and checks
// its hash with no lock held, so a write whose stdin never ends holds
// nothing; only the move into place, and the reload, take the lock, and
// they run only while tokenPath still holds their own Sync's token. A
// command a timed-out Sync left behind therefore either moves its file
// before the next Sync's claim, which waits for the lock, or finds the
// newer token and does nothing but exit refusedExit: a late old write
// cannot put back an older config, such as a revoked password. Reads
// take no lock: mv
// replaces a file in one rename. The lock and token are on the access
// point's tmpfs, so a reboot, which ends every command, also clears them.
const (
	readPrefix = "cat "
	lockPath   = "/tmp/agentos-ap.lock"
	tokenPath  = "/tmp/agentos-ap.sync"
)

// token is a Sync's claim on the access point: 128 random bits in hex.
func token() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// locked runs cmd holding the access point's lock on file descriptor 9,
// which the shell keeps open, and so the lock held, until cmd ends.
func locked(cmd string) string {
	return "{ flock -x 9 && " + cmd + "; } 9>" + lockPath
}

// owns is true on the access point only while tok is the newest claim;
// otherwise its status is refusedExit, without ending the shell.
func owns(tok string) string {
	return "{ [ \"$(cat " + tokenPath + ")\" = " + tok + " ] || (exit " + fmt.Sprint(refusedExit) + "); }"
}

// tmpGlob matches every temporary file tmpPath names.
const tmpGlob = "/etc/agentos-ap-*.new"

// claimCmd makes tok the newest claim and removes the temporary files
// of earlier Syncs, which a reboot mid-write would otherwise leave on
// /etc. A write of an earlier Sync still running then fails its hash
// check or its move.
func claimCmd(tok string) string {
	return locked("echo " + tok + " > " + tokenPath + " && rm -f " + tmpGlob)
}

// applyCmd reloads while tok is the newest claim, for reloadBound at
// most. reload_config does not get the lock's descriptor, so nothing it
// starts can hold the lock, nor the session's output, so nothing it
// leaves running when the bound ends it holds the Sync's command open.
func applyCmd(tok string) string {
	return locked(owns(tok) + " && timeout " + fmt.Sprint(int(reloadBound/time.Second)) + " reload_config 9>&- </dev/null >/dev/null 2>&1")
}

// tmpPath is the temporary file for path in the Sync holding tok: one per
// path and Sync, so no two writes share one, and on /etc's own
// filesystem.
func tmpPath(path, tok string) string {
	return "/etc/agentos-ap" + strings.ReplaceAll(path, "/", "-") + "." + tok + ".new"
}

func readCmd(path string) string { return readPrefix + path }

// writeCmd stores data at path while tok is the newest claim: it reads
// stdin into the temporary file and, only if the file's SHA-256 is
// data's, takes the lock and moves it over path while tok is the newest
// claim, so a stdin cut short (a dropped connection, a deadline) leaves
// path alone. Reading and the hash take no lock, so a stdin that never
// ends holds up no other Sync. A failed check, a newer claim or a failed
// move removes the temporary file and keeps the failure's status, so a
// newer claim exits refusedExit. The hash is hex.
func writeCmd(path, tok string, data []byte) string {
	sum := sha256.Sum256(data)
	t := tmpPath(path, tok)
	return "umask 077 && cat > " + t + " && [ \"$(sha256sum " + t + " | cut -d' ' -f1)\" = " + hex.EncodeToString(sum[:]) +
		" ] && " + locked(owns(tok)+" && mv -f "+t+" "+path) + " || { s=$?; rm -f " + t + "; exit $s; }"
}

// holds reports whether the access point's file at f.Path is exactly
// f.Data; a missing file is not.
func holds(c *ssh.Client, f ap.File) (bool, error) {
	out, err := run(c, readCmd(f.Path), nil)
	var exit *ssh.ExitError
	if errors.As(err, &exit) {
		return false, nil // cat failed: absent or unreadable
	}
	if err != nil {
		return false, fmt.Errorf("push: read %s: %w", f.Path, err)
	}
	// out is cut at MaxFile+1 bytes, so a longer file reads as drift and
	// is rewritten.
	return len(out) <= MaxFile && bytes.Equal(out, f.Data), nil
}

// run runs one command with stdin, returning at most MaxFile+1 bytes of
// its output.
func run(c *ssh.Client, cmd string, stdin []byte) ([]byte, error) {
	s, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	s.Stdin = bytes.NewReader(stdin)
	out, err := s.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := s.Start(cmd); err != nil {
		return nil, err
	}
	b, rerr := io.ReadAll(io.LimitReader(out, MaxFile+1))
	if len(b) > MaxFile {
		return b, nil // cut off; Close ends the command rather than wait on it
	}
	if err := s.Wait(); err != nil {
		return nil, err
	}
	return b, rerr
}
