package provagent

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm"
)

// ErrSignInBusy is a sign-in asked for while the provider's last one runs.
var ErrSignInBusy = errors.New("provagent: a sign-in is already running")

// SignInTimes bound a sign-in. Link is how long the CLI has to print its
// link and code; Wall is how long the owner has to approve it (the code's
// own life); Poll is how often the worker is read. Zero is the default.
type SignInTimes struct{ Poll, Link, Wall time.Duration }

func (t SignInTimes) orDefault() SignInTimes {
	if t.Poll <= 0 {
		t.Poll = time.Second
	}
	if t.Link <= 0 {
		t.Link = time.Minute
	}
	if t.Wall <= 0 {
		t.Wall = 15 * time.Minute
	}
	return t
}

// The sign-in CLI's output and exit status, in the worker's workspace.
const (
	signInOut    = "/.agentos-signin"
	signInStatus = "/.agentos-signin-status"
)

// signInCode is egress's check on the code (PlanRoute.SignInLink).
var signInCode = regexp.MustCompile(`\A[A-Z0-9-]{4,16}\z`)

// ansi is a terminal escape sequence, stripped before the output is read.
var ansi = regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]")

// SignInCommand starts d's sign-in CLI in the background and returns: the
// worker's Exec runs one command at a time, and the CLI waits for the
// owner. Its stdout and stderr go to a file in the workspace, which the
// broker reads only for the link and code; its exit status goes to a second
// file. As in Command, env -i gives it exactly the declared environment.
func SignInCommand(d Declaration) vm.Command {
	argv := []string{
		"sh", "-c", `cd "$1" || exit 125; out=$2; st=$3; shift 3; ("$@" >"$out" 2>&1 </dev/null; echo $? >"$st") >/dev/null 2>&1 </dev/null & exit 0`,
		"sh", d.Cwd, d.Cwd + signInOut, d.Cwd + signInStatus, "env", "-i",
	}
	argv = append(argv, d.Env...)
	argv = append(argv, d.Wrap...)
	argv = append(argv, d.SignInArgv...)
	return vm.Command{Argv: argv, MaxOutput: outputKeep, As: vm.Private}
}

// SignInPrompt reads the link and code from what d's sign-in CLI printed:
// the first token that is one of d's links, then the first code-shaped
// token after it. The link returned is always d's own page, never the one
// printed (the forwarder's); ok is false when either is missing.
func (d Declaration) SignInPrompt(printed string) (link, code string, ok bool) {
	toks := strings.Fields(ansi.ReplaceAllString(printed, ""))
	for i, t := range toks {
		if !contains(d.SignInLinks, t) {
			continue
		}
		for _, c := range toks[i+1:] {
			if signInCode.MatchString(c) {
				return d.SignInPage, c, true
			}
		}
		return "", "", false
	}
	return "", "", false
}

// StartSignIn starts provider's device-code sign-in (ONB-3, #1264) in a
// fresh private provider worker whose route is a sign-in route, and returns
// the link and code for the owner's page. The worker then waits, past ctx
// but within r.Background, for the owner to approve the code: once the
// vault process reports that this worker's own sign-in stored the login
// (SignInStored), the provider is SignedIn, whatever the CLI's exit status.
// The worker is destroyed on every path. Nothing the CLI printed is logged
// or returned but the link and code.
func (r *Runner) StartSignIn(ctx context.Context, provider string, class admission.Class, memMB int64) (link, code string, err error) {
	d, ok := r.Decls[provider]
	if !ok || len(d.SignInArgv) == 0 || d.Custody != BrokerHeld || r.SignInFor == nil || r.SignInStored == nil {
		return "", "", refuse(Unqualified)
	}
	g := Gate{ImageVersion: r.ImageVersion(d.Image), Consent: r.Consent != nil && r.Consent(d.ID)}
	if err := g.Check(d); err != nil {
		return "", "", err
	}
	if !r.claimSignIn(d.ID) {
		return "", "", ErrSignInBusy
	}
	held := true
	defer func() {
		if held {
			r.releaseSignIn(d.ID)
		}
	}()

	id := r.NewID()
	r.SignInFor(id)
	spec := vm.Spec{Image: d.Image, Class: class, MemMB: memMB, Label: vm.Private, Argv: d.Idle}
	if _, err := r.Host.CreateProviderWorker(ctx, id, spec, nil); err != nil {
		r.logf("provagent: %s sign-in: create provider worker %s: %v", d.ID, id, err)
		r.Seeder.Close(id) // forgets the mark; no route was left open
		return "", "", refuse(Failed)
	}
	t := r.SignInTimes.orDefault()
	if res, err := r.Host.Exec(ctx, id, SignInCommand(d), t.Link); err != nil || res.ExitCode != 0 || res.TimedOut {
		// The result's exit status and timeout only: its output is the
		// worker's, never logged.
		if err == nil {
			err = fmt.Errorf("exit status %d, timed out %t", res.ExitCode, res.TimedOut)
		}
		r.logf("provagent: %s sign-in: start the CLI in %s: %v", d.ID, id, err)
		r.destroy(ctx, id)
		return "", "", refuse(Failed)
	}
	link, code, err = r.awaitPrompt(ctx, id, d, t)
	if err != nil {
		r.destroy(ctx, id)
		return "", "", err
	}
	held = false
	bg := r.Background
	if bg == nil {
		bg = context.WithoutCancel(ctx)
	}
	go r.awaitSignIn(bg, id, d, t)
	return link, code, nil
}

// CanSignIn reports whether StartSignIn would start provider's sign-in now,
// short of a sign-in already running: the route declares one and its gate
// is open. The setup page offers the sign-in only then (ONB-3).
func (r *Runner) CanSignIn(provider string) bool {
	d, ok := r.Decls[provider]
	if !ok || len(d.SignInArgv) == 0 || d.Custody != BrokerHeld || r.SignInFor == nil || r.SignInStored == nil || r.ImageVersion == nil {
		return false
	}
	return Gate{ImageVersion: r.ImageVersion(d.Image), Consent: r.Consent != nil && r.Consent(d.ID)}.Check(d) == nil
}

func (r *Runner) claimSignIn(provider string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.signing[provider] {
		return false
	}
	if r.signing == nil {
		r.signing = map[string]bool{}
	}
	r.signing[provider] = true
	return true
}

func (r *Runner) releaseSignIn(provider string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.signing, provider)
}

func (r *Runner) destroy(ctx context.Context, id string) {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := r.Host.Destroy(dctx, id); err != nil {
		r.logf("provagent: destroy provider worker %s: %v", id, err)
	}
}

// read returns a workspace file's text, "" when it cannot be read.
func (r *Runner) read(ctx context.Context, id, path string, wait time.Duration) string {
	res, err := r.Host.Exec(ctx, id, vm.Command{Argv: []string{"cat", path}, MaxOutput: outputKeep, As: vm.Private}, wait)
	if err != nil || res.ExitCode != 0 {
		return ""
	}
	return string(res.Stdout)
}

// awaitPrompt polls the CLI's output until it has printed its link and
// code, the CLI exits, or t.Link passes.
func (r *Runner) awaitPrompt(ctx context.Context, id string, d Declaration, t SignInTimes) (string, string, error) {
	deadline := time.Now().Add(t.Link)
	for {
		if link, code, ok := d.SignInPrompt(r.read(ctx, id, d.Cwd+signInOut, t.Link)); ok {
			return link, code, nil
		}
		if st := r.read(ctx, id, d.Cwd+signInStatus, t.Link); st != "" {
			r.logf("provagent: %s sign-in: the CLI exited without a code, %s", d.ID, exitStatus(st))
			return "", "", refuse(Failed)
		}
		if !time.Now().Before(deadline) {
			r.logf("provagent: %s sign-in: no link and code within %v", d.ID, t.Link)
			return "", "", refuse(TimedOut)
		}
		select {
		case <-ctx.Done():
			r.logf("provagent: %s sign-in: no link and code before it was stopped", d.ID)
			return "", "", refuse(TimedOut)
		case <-time.After(t.Poll):
		}
	}
}

// exitStatus is the status file's text as a log may carry it: the CLI can
// write that file too, so only a number is quoted.
func exitStatus(st string) string {
	if n, err := strconv.Atoi(strings.TrimSpace(st)); err == nil {
		return fmt.Sprintf("exit status %d", n)
	}
	return "a status that is not a number"
}

// awaitSignIn waits up to t.Wall, or until ctx ends, for the owner's
// sign-in. The vault process's record that this worker's sign-in stored
// the login is the only success signal (CRED-5): an earlier login, perhaps
// the refused one this sign-in replaces, is not, and neither is anything
// the worker writes, its exit status included. A CLI that cannot write its
// own auth file after the login was stored still signs the owner in. The
// CLI's exit ends the wait: its status is read before the last check, and
// the vault commits a login before the CLI sees it, so that check is
// final. Either way the worker is destroyed.
func (r *Runner) awaitSignIn(ctx context.Context, id string, d Declaration, t SignInTimes) {
	defer r.releaseSignIn(d.ID)
	defer r.destroy(ctx, id)
	deadline := time.Now().Add(t.Wall)
	for {
		exited := strings.TrimSpace(r.read(ctx, id, d.Cwd+signInStatus, t.Link)) != ""
		if r.SignedIn(d.ID, id) {
			return
		}
		switch {
		case exited:
			r.logf("provagent: %s sign-in ended without storing a login", d.ID)
			return
		case !time.Now().Before(deadline):
			r.logf("provagent: %s sign-in was not approved in time", d.ID)
			return
		}
		select {
		case <-ctx.Done():
			r.logf("provagent: %s sign-in stopped before it was approved", d.ID)
			return
		case <-time.After(t.Poll):
		}
	}
}
