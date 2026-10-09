// Package childproc is the only broker code that starts a process
// (P3-4b-3r-env-r8). It wraps os/exec behind an opaque handle and checks
// the child's environment immediately before every start, so no child
// inherits agentosd's environment whatever route the caller took to the
// start (#621 delta Security 6). The import gate (gate_test.go) keeps
// os/exec and the launcher selectors in os, syscall and unix out of every
// other package's dependency graph; the daemon's childEnvCheck is defence
// in depth on top.
//
// The handle hands out no *exec.Cmd, embeds none, and no exported field,
// result or accessor yields one or an os/exec value (TestTheHandleIsOpaque).
// A child's environment is exactly the pairs the caller passed to NewEnv;
// each key must be on allowedKeys, and no value may carry the process's own
// value of an AGENTOS_* or credential-named variable (deny by default:
// comparing against os.Environ would pass a filtered copy of it).
package childproc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// allowedKeys are the only variables a child may be given, each with the
// children that need it. A new key is a reviewed entry with its reason.
var allowedKeys = map[string]string{
	"PATH":    "every child: where its own helpers are; never the daemon's value by copy",
	"HOME":    "fuzz and probe children (loop7, probecmd): their scratch directory",
	"TMPDIR":  "fuzz and probe children (loop7, probecmd): their scratch directory",
	"GOCACHE": "Go fuzz and probe binaries (loop7, probecmd): off, so no cache outside scratch",
	"GOFLAGS": "Go fuzz and probe binaries (loop7, probecmd): empty, so no flags from outside",
	"LANG":    "the browser driver (browser): C.UTF-8, so page text decodes the same everywhere",
}

// deniedPrefix names agentosd's own configuration, the owner's number
// (AGENTOS_OWNER) among it: never a child's, by key or by value.
const deniedPrefix = "AGENTOS_"

// credentialWords mark a variable's name as holding a credential; its
// value, like an AGENTOS_* value, may not appear in a child's
// environment under any key.
var credentialWords = []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "API_KEY", "APIKEY", "PRIVATE_KEY", "COOKIE"}

// minContained is the shortest secret looked for inside a value; a
// shorter one must match a value whole, so "1" in some flag does not
// refuse every child. An absolute path (AGENTOS_RUNSC, a state directory)
// is configuration, not a secret, and is not looked for: a child's HOME
// may lie under one.
const minContained = 6

// ErrNoEnv is returned by a start whose Env was not built by NewEnv.
var ErrNoEnv = errors.New("childproc: no environment: build it with NewEnv")

// ErrWaitDelay is returned by Wait when the child exited but its I/O did
// not close within Options.WaitDelay.
var ErrWaitDelay = errors.New("childproc: I/O incomplete after the wait delay")

// Env is a child's whole environment. Only NewEnv builds one; the zero
// Env is refused at start.
type Env struct {
	pairs []string
	built bool
}

// NewEnv copies kv, "KEY=value" entries, as a child's whole environment.
// It is checked when a child starts, not here, so a refusal names the
// start.
func NewEnv(kv ...string) Env {
	return Env{pairs: append([]string{}, kv...), built: true}
}

// check refuses an environment that is not exactly an explicit,
// allowlisted set of pairs free of the process's own secrets.
func (e Env) check() error {
	if !e.built {
		return ErrNoEnv
	}
	secrets := ownSecrets()
	seen := map[string]bool{}
	for i, kv := range e.pairs {
		k, v, ok := strings.Cut(kv, "=")
		switch {
		case !ok || k == "":
			// The index only: an entry with no key may be a bare secret.
			return fmt.Errorf("childproc: environment entry %d has no KEY= part", i)
		case strings.ContainsRune(kv, 0):
			return fmt.Errorf("childproc: environment entry %s holds a NUL", k)
		case seen[k]:
			return fmt.Errorf("childproc: environment key %s given twice", k)
		case strings.HasPrefix(k, deniedPrefix):
			return fmt.Errorf("childproc: environment key %s is agentosd's own", k)
		case allowedKeys[k] == "":
			return fmt.Errorf("childproc: environment key %s is not allowlisted", k)
		}
		seen[k] = true
		for name, s := range secrets {
			if v == s || len(s) >= minContained && strings.Contains(v, s) {
				// The value is never printed: it is the secret.
				return fmt.Errorf("childproc: environment key %s carries the value of %s", k, name)
			}
		}
	}
	return nil
}

// ownSecrets are the process's non-empty AGENTOS_* and credential-named
// variables.
func ownSecrets() map[string]string {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if v == "" || strings.HasPrefix(v, "/") {
			continue
		}
		u := strings.ToUpper(k)
		if strings.HasPrefix(u, deniedPrefix) {
			out[k] = v
			continue
		}
		for _, w := range credentialWords {
			if strings.Contains(u, w) {
				out[k] = v
				break
			}
		}
	}
	return out
}

// Options are what a child gets besides its argv and environment.
type Options struct {
	Dir            string
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	SysProcAttr    *syscall.SysProcAttr
	ExtraFiles     []*os.File
	// WaitDelay bounds the wait for the child's I/O after it exits or
	// is killed (exec.Cmd.WaitDelay).
	WaitDelay time.Duration
	// KillGroup makes a cancelled context SIGKILL the child's whole
	// process group, not only the child; SysProcAttr must set Setpgid.
	KillGroup bool
	// OnCancel, if set, runs when the context ends, before the kill.
	OnCancel func()
}

// Cmd is a child process to start. It is opaque: its exec.Cmd never
// leaves this package.
type Cmd struct {
	c   *exec.Cmd
	env Env
}

// Command prepares name with args to run with env. A nil ctx panics, as
// exec.CommandContext does.
func Command(ctx context.Context, env Env, o Options, name string, args ...string) *Cmd {
	if ctx == nil {
		panic("childproc: nil Context")
	}
	c := exec.CommandContext(ctx, name, args...)
	// Never nil, so never the process's environment, even before Start
	// replaces it with the checked pairs.
	c.Env = []string{}
	c.Dir = o.Dir
	c.Stdin, c.Stdout, c.Stderr = o.Stdin, o.Stdout, o.Stderr
	c.SysProcAttr = o.SysProcAttr
	c.ExtraFiles = o.ExtraFiles
	c.WaitDelay = o.WaitDelay
	c.Cancel = func() error {
		if o.OnCancel != nil {
			o.OnCancel()
		}
		if o.KillGroup {
			return syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		}
		return c.Process.Kill()
	}
	return &Cmd{c: c, env: env}
}

// Start checks the environment and, only if it passes, starts the child
// with exactly it.
func (c *Cmd) Start() error {
	if err := c.env.check(); err != nil {
		return err
	}
	// A fresh copy, set immediately before the start: nothing else in
	// this package writes c.c.Env.
	c.c.Env = append([]string{}, c.env.pairs...)
	return scrub(c.c.Start())
}

// Wait waits for the started child to exit.
func (c *Cmd) Wait() error { return scrub(c.c.Wait()) }

// Run starts the child and waits for it.
func (c *Cmd) Run() error {
	if err := c.Start(); err != nil {
		return err
	}
	return c.Wait()
}

// Output runs the child and returns its standard output.
func (c *Cmd) Output() ([]byte, error) {
	if c.c.Stdout != nil {
		return nil, errors.New("childproc: Stdout already set")
	}
	var b bytes.Buffer
	c.c.Stdout = &b
	err := c.Run()
	return b.Bytes(), err
}

// CombinedOutput runs the child and returns its standard output and
// standard error together.
func (c *Cmd) CombinedOutput() ([]byte, error) {
	if c.c.Stdout != nil || c.c.Stderr != nil {
		return nil, errors.New("childproc: Stdout or Stderr already set")
	}
	// One writer for both: exec.Cmd then writes from one goroutine.
	var b bytes.Buffer
	c.c.Stdout, c.c.Stderr = &b, &b
	err := c.Run()
	return b.Bytes(), err
}

// StdinPipe returns a pipe to the child's standard input.
func (c *Cmd) StdinPipe() (io.WriteCloser, error) {
	// Checked here too: a refused start would leave the pipe open.
	if err := c.env.check(); err != nil {
		return nil, err
	}
	w, err := c.c.StdinPipe()
	if err != nil {
		return nil, scrub(err)
	}
	return writePipe{w}, nil
}

// StdoutPipe returns a pipe from the child's standard output.
func (c *Cmd) StdoutPipe() (io.ReadCloser, error) {
	// Checked here too: a refused start would leave the pipe open.
	if err := c.env.check(); err != nil {
		return nil, err
	}
	r, err := c.c.StdoutPipe()
	if err != nil {
		return nil, scrub(err)
	}
	return readPipe{r}, nil
}

// Pid is the started child's process ID, or 0 before a start.
func (c *Cmd) Pid() int {
	if c.c.Process == nil {
		return 0
	}
	return c.c.Process.Pid
}

// Signal sends sig to the started child.
func (c *Cmd) Signal(sig os.Signal) error {
	if c.c.Process == nil {
		return errors.New("childproc: not started")
	}
	return c.c.Process.Signal(sig)
}

// Kill kills the started child.
func (c *Cmd) Kill() error {
	if c.c.Process == nil {
		return errors.New("childproc: not started")
	}
	return c.c.Process.Kill()
}

// ExitError is a child that ran and exited non-zero or was killed.
type ExitError struct {
	msg  string
	code int
}

func (e *ExitError) Error() string { return e.msg }

// ExitCode is the child's exit status, or -1 if a signal killed it.
func (e *ExitError) ExitCode() int { return e.code }

// LookPath finds an executable as exec.LookPath does.
func LookPath(file string) (string, error) {
	p, err := exec.LookPath(file)
	return p, scrub(err)
}

// scrub replaces an os/exec error with one of this package's, so no
// os/exec value leaves it.
func scrub(err error) error {
	var ee *exec.ExitError
	var xe *exec.Error
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ee):
		return &ExitError{msg: ee.Error(), code: ee.ExitCode()}
	case errors.Is(err, exec.ErrWaitDelay):
		return ErrWaitDelay
	case errors.As(err, &xe):
		return fmt.Errorf("childproc: %s: %w", xe.Name, xe.Err)
	}
	return err
}

type writePipe struct{ w io.WriteCloser }

func (p writePipe) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p writePipe) Close() error                { return p.w.Close() }

type readPipe struct{ r io.ReadCloser }

func (p readPipe) Read(b []byte) (int, error) { return p.r.Read(b) }
func (p readPipe) Close() error               { return p.r.Close() }
