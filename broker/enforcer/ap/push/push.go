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
// three fixed strings over a path from ap.Paths; file contents go only on
// stdin, never into a command.
package push

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ghbmrk/agentos/broker/enforcer/ap"
)

var (
	ErrPath   = errors.New("push: not an access point path")
	ErrVerify = errors.New("push: access point does not hold what was written")
)

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
}

// Result is what one Sync did.
type Result struct {
	// Drift is the paths whose content on the access point differed from
	// the config before the Sync (absent counts).
	Drift []string
	// Applied reports that files were written and the access point told
	// to reload them.
	Applied bool
}

// Sync makes the access point hold exactly files: it reads each back,
// writes those that differ, reloads, and reads them all back again. A
// Sync that fails leaves the access point's files as written so far but
// not reloaded; the next Sync finds them as drift.
func (p *Pusher) Sync(ctx context.Context, files []ap.File) (Result, error) {
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
	if len(res.Drift) == 0 {
		return res, nil
	}
	for _, f := range files {
		if slices.Contains(res.Drift, f.Path) {
			if _, err := run(c, writeCmd(f.Path), f.Data); err != nil {
				return res, fmt.Errorf("push: write %s: %w", f.Path, err)
			}
		}
	}
	if _, err := run(c, applyCmd, nil); err != nil {
		return res, fmt.Errorf("push: reload: %w", err)
	}
	res.Applied = true
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

// The three commands. A path is always one of ap.Paths, which hold no
// character a shell reads specially; the temporary file sits on /etc's
// own filesystem, so mv replaces the file in one rename, and umask keeps
// the passwords readable by root only.
const (
	readPrefix = "cat "
	applyCmd   = "reload_config"
	tmpPath    = "/etc/agentos-ap.new"
)

func readCmd(path string) string { return readPrefix + path }
func writeCmd(path string) string {
	return "umask 077 && cat > " + tmpPath + " && mv -f " + tmpPath + " " + path
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
	return bytes.Equal(out, f.Data), nil
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
	if rerr == nil && len(b) > MaxFile {
		return nil, fmt.Errorf("push: %q output over %d bytes", cmd, MaxFile)
	}
	if err := s.Wait(); err != nil {
		return nil, err
	}
	return b, rerr
}
