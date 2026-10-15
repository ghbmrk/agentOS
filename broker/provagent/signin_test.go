package provagent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: ONB-3, CRED-5, CRED-7, CAP-11, A14

const (
	fwdLink  = "http://127.0.0.1:18432/codex/device"
	ownLink  = "https://auth.openai.com/codex/device"
	userCode = "ABCD-1234"
)

// printed is the device-auth prompt, colours and all, carrying a canary the
// broker must never log or return.
var printed = "\x1b[1mWelcome to Codex\x1b[0m " + canaryToken + "\n" +
	"1. Open this link in your browser and sign in to your account\n   \x1b[94m" + fwdLink + "\x1b[0m\n\n" +
	"2. Enter this one-time code \x1b[90m(expires in 15 minutes)\x1b[0m\n   \x1b[94m" + userCode + "\x1b[0m\n"

func signInDecl() Declaration {
	d := good()
	d.Q = qualified()
	d.SignInArgv = []string{"stubcli", "login", "--device-auth"}
	d.SignInLinks = []string{fwdLink, ownLink}
	d.SignInPage = ownLink
	return d
}

// signRig is a runner whose sign-in CLI prints prompt when started.
type signRig struct {
	h      *stub
	sd     *seeder
	r      *Runner
	mu     sync.Mutex
	marked []string // SignInFor's ids, in order
	logs   []string
	stored map[string]bool // worker: its own sign-in stored the login
	signed chan string
}

func newSignRig(prompt string) *signRig {
	g := &signRig{signed: make(chan string, 4), stored: map[string]bool{}}
	g.h = newStub(func(c vm.Command, s *stub) vm.ExecResult {
		if len(c.Argv) > 5 && c.Argv[0] == "sh" {
			s.write(c.Argv[5], prompt)
		}
		return vm.ExecResult{}
	})
	g.sd = &seeder{}
	g.r = &Runner{
		Host: g.h, Seeder: g.sd,
		Decls:        map[string]Declaration{"stub": signInDecl(), "plain": good()},
		ImageVersion: func(string) string { return "1.0.0" },
		SignInFor: func(id string) {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.marked = append(g.marked, id)
		},
		SignInStored: func(id string) bool {
			g.mu.Lock()
			defer g.mu.Unlock()
			return g.stored[id]
		},
		OnSignedIn: func(p string) { g.signed <- p },
		Logf: func(f string, a ...any) {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.logs = append(g.logs, fmt.Sprintf(f, a...))
		},
		SignInTimes: SignInTimes{Poll: time.Millisecond, Link: 200 * time.Millisecond, Wall: 2 * time.Second},
		NewID:       func() string { return "pw-sign" },
	}
	return g
}

func (g *signRig) start(t *testing.T) (string, string, error) {
	t.Helper()
	return g.r.StartSignIn(context.Background(), "stub", admission.Accepted, 512)
}

// gone waits for the sign-in's worker to be destroyed and its claim freed.
func (g *signRig) gone(t *testing.T) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		g.h.mu.Lock()
		n := len(g.h.live)
		g.h.mu.Unlock()
		g.r.mu.Lock()
		busy := g.r.signing["stub"]
		g.r.mu.Unlock()
		if n == 0 && !busy {
			return
		}
	}
	t.Fatal("the sign-in worker outlived its sign-in")
}

func (g *signRig) noCanary(t *testing.T) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, l := range g.logs {
		if strings.Contains(l, canaryToken) || strings.Contains(l, userCode) {
			t.Errorf("a log line carries the CLI's output: %q", l)
		}
	}
}

// The owner's sign-in: a private worker on a sign-in route, created with no
// seed, prints the provider's link and code; the page gets the provider's
// own link (never the forwarder's) and the code, and once the owner
// approves and the vault holds the login the provider is signed in and the
// worker is gone (ONB-3, CRED-5).
func TestONB3SignInShowsTheProvidersPageAndCode(t *testing.T) {
	g := newSignRig(printed)
	link, code, err := g.start(t)
	if err != nil || link != ownLink || code != userCode {
		t.Fatalf("sign-in: %q %q %v", link, code, err)
	}
	g.mu.Lock()
	marked := append([]string(nil), g.marked...)
	g.mu.Unlock()
	g.h.mu.Lock()
	created, spec, seed := g.h.created, g.h.specs[0], g.h.seeds[0]
	g.h.mu.Unlock()
	if len(marked) != 1 || len(created) != 1 || marked[0] != created[0] {
		t.Fatalf("route marked %v for workers %v", marked, created)
	}
	if spec.Label != vm.Private || spec.Image != "stub-image" || seed != nil {
		t.Errorf("sign-in worker %+v seeded %v", spec, seed)
	}
	if _, _, err := g.start(t); !errors.Is(err, ErrSignInBusy) {
		t.Errorf("a second sign-in while one runs: %v", err)
	}
	g.r.signIn("stub", true) // a refused login had stopped the route
	g.mu.Lock()
	g.stored["pw-sign"] = true
	g.mu.Unlock()
	g.h.write("/work"+signInStatus, "0\n")
	select {
	case p := <-g.signed:
		if p != "stub" {
			t.Errorf("signed in %q", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("an approved sign-in was not taken")
	}
	g.gone(t)
	if g.r.isStopped("stub") {
		t.Error("the sign-in did not lift the stopped route")
	}
	g.noCanary(t)
}

// A sign-in whose worker stored no login signs nothing in and leaves no
// worker, whatever the CLI's exit status says. The case the ONB-9 line
// exists for (security review 2): a refused login is still stored and has
// stopped the route, and a CLI that exits 0 without a code exchange (or
// anything in the worker writing 0) must not lift the stop and retry the
// refused login (CRED-5).
func TestONB3UnfinishedSignInSignsNothingIn(t *testing.T) {
	for name, finish := range map[string]func(g *signRig){
		"exit 0, no login": func(g *signRig) { g.h.write("/work"+signInStatus, "0\n") },
		"exit 0, an earlier refused login": func(g *signRig) {
			g.mu.Lock()
			g.stored["pw-old"] = true
			g.mu.Unlock()
			g.h.write("/work"+signInStatus, "0\n")
		},
		"exit 1, no login": func(g *signRig) { g.h.write("/work"+signInStatus, "1\n") },
		"never approved":   func(*signRig) {},
	} {
		t.Run(name, func(t *testing.T) {
			g := newSignRig(printed)
			var line int
			g.r.SignIn = func(string) { line++ }
			g.r.signIn("stub", true) // the stored login was refused
			g.r.SignInTimes.Wall = 50 * time.Millisecond
			if _, _, err := g.start(t); err != nil {
				t.Fatal(err)
			}
			finish(g)
			g.gone(t)
			select {
			case p := <-g.signed:
				t.Errorf("signed %q in", p)
			default:
			}
			g.r.mu.Lock()
			told := g.r.told["stub"]
			g.r.mu.Unlock()
			if !g.r.isStopped("stub") || !told || line != 1 {
				t.Errorf("the refused login's stop was lifted: stopped %v, told %v, line set %d times", g.r.isStopped("stub"), told, line)
			}
			g.noCanary(t)
		})
	}
}

// The reverse (security review 2): the vault stored this sign-in's login
// but the CLI could not write its own auth file (CODEX_HOME root-owned,
// K27) and exits non-zero. The owner did sign in, so the provider is
// signed in; a login stored before the CLI exits is taken at once.
func TestONB3StoredSignInCountsWhateverTheCLIExits(t *testing.T) {
	for name, status := range map[string]string{"exit 1": "1\n", "still running": ""} {
		t.Run(name, func(t *testing.T) {
			g := newSignRig(printed)
			g.r.signIn("stub", true)
			if _, _, err := g.start(t); err != nil {
				t.Fatal(err)
			}
			g.mu.Lock()
			g.stored["pw-sign"] = true
			g.mu.Unlock()
			if status != "" {
				g.h.write("/work"+signInStatus, status)
			}
			select {
			case p := <-g.signed:
				if p != "stub" {
					t.Errorf("signed %q in", p)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("a stored sign-in was not taken")
			}
			g.gone(t)
			if g.r.isStopped("stub") {
				t.Error("the stored sign-in did not lift the stop")
			}
			g.noCanary(t)
		})
	}
}

// L4: the wait for the owner ends with the runner's Background context
// (shutdown), signs nothing in, and destroys the worker.
func TestONB3SignInWaitEndsWithTheBackgroundContext(t *testing.T) {
	g := newSignRig(printed)
	bg, cancel := context.WithCancel(context.Background())
	g.r.Background = bg
	g.r.SignInTimes.Wall = time.Hour
	if _, _, err := g.start(t); err != nil {
		t.Fatal(err)
	}
	cancel()
	g.gone(t)
	select {
	case p := <-g.signed:
		t.Errorf("signed %q in", p)
	default:
	}
}

// Security review 3: a run refused by the old login while a sign-in lands
// must leave the line on whenever the route is stopped. SignedIn clears the
// line in the same lock hold that lifts the stop, so a refusal racing it
// either lands before (and is lifted with the line) or after (and sets the
// line again); it can never set the line just before SignedIn's clear.
// OnSignedIn here starts that refusal and gives it time to run, which the
// old order (clear after unlock) lost.
func TestONB9SignInLineMatchesTheStopUnderARacingRefusal(t *testing.T) {
	var line atomic.Bool
	r := &Runner{SignIn: func(string) { line.Store(true) }}
	var refused sync.WaitGroup
	r.OnSignedIn = func(string) {
		refused.Add(1)
		done := make(chan struct{})
		go func() {
			defer refused.Done()
			r.signIn("stub", true) // the old login's refusal
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Millisecond):
		}
		line.Store(false)
	}
	r.signIn("stub", true)
	r.SignedIn("stub")
	refused.Wait()
	r.mu.Lock()
	stopped, told := r.stopped["stub"], r.told["stub"]
	r.mu.Unlock()
	if !stopped || !told || !line.Load() {
		t.Fatalf("stopped %v, told %v, line %v: the owner is not told the route stopped", stopped, told, line.Load())
	}
}

// A sign-in the CLI cannot finish returns a closed reason and leaves no
// worker; one that may not start creates none.
func TestONB3SignInRefusals(t *testing.T) {
	t.Run("ungated", func(t *testing.T) {
		g := newSignRig(printed)
		g.r.ImageVersion = func(string) string { return "9.9.9" }
		if _, _, err := g.start(t); reasonOf(err) != Unqualified {
			t.Errorf("an image the record does not pin: %v", err)
		}
		if len(g.h.created) != 0 {
			t.Error("an ungated sign-in created a worker")
		}
	})
	t.Run("no sign-in declared", func(t *testing.T) {
		g := newSignRig(printed)
		g.r.Decls["plain"] = func() Declaration { d := good(); d.Q = qualified(); return d }()
		if _, _, err := g.r.StartSignIn(context.Background(), "plain", admission.Accepted, 512); reasonOf(err) != Unqualified {
			t.Errorf("%v", err)
		}
		if len(g.h.created) != 0 {
			t.Error("created a worker")
		}
	})
	t.Run("create fails", func(t *testing.T) {
		g := newSignRig(printed)
		g.h.createErr = errors.New("no room")
		if _, _, err := g.start(t); reasonOf(err) != Failed {
			t.Errorf("%v", err)
		}
		if len(g.sd.closed) != 1 || g.sd.closed[0] != "pw-sign" {
			t.Errorf("the marked route was not closed: %v", g.sd.closed)
		}
		g.gone(t)
	})
	for name, c := range map[string]struct {
		prompt, status string
		want           Reason
	}{
		"no code":              {fwdLink + "\n", "", TimedOut},
		"look-alike link":      {"https://auth.openai.com.evil.test/codex/device " + userCode, "", TimedOut},
		"exits without a code": {"error: " + canaryToken, "1\n", Failed},
	} {
		t.Run(name, func(t *testing.T) {
			g := newSignRig(c.prompt)
			if c.status != "" {
				g.h.write("/work"+signInStatus, c.status)
			}
			if _, _, err := g.start(t); reasonOf(err) != c.want {
				t.Errorf("%v, want %s", err, c.want)
			}
			g.gone(t)
			g.noCanary(t)
		})
	}
}

func TestONB3SignInPromptReadsOnlyTheDeclaredLink(t *testing.T) {
	d := signInDecl()
	for in, want := range map[string]string{
		printed:                              userCode,
		ownLink + " WXYZ-9876":               "WXYZ-9876",
		userCode + " " + fwdLink:             "", // a code before the link is not read
		fwdLink + " abcd-1234":               "", // out of shape
		fwdLink + "/x ABCD-1234":             "",
		"see " + fwdLink + "?x ABCD-1234":    "",
		fwdLink + " 15 minutes) " + userCode: userCode,
		// #1436 S2 (L2): userinfo, opaque and empty-host links are not
		// the declared link, so they are never read.
		"https://openai.com@evil.example/codex/device " + userCode:      "",
		"https://auth.openai.com@evil.example/codex/device " + userCode: "",
		"https://evil.example@auth.openai.com/codex/device " + userCode: "",
		"https:auth.openai.com/codex/device " + userCode:                "",
		"https:///codex/device " + userCode:                             "",
	} {
		link, code, ok := d.SignInPrompt(in)
		if code != want || ok != (want != "") || (ok && link != ownLink) {
			t.Errorf("%q: %q %q %v", in, link, code, ok)
		}
	}
}

// Codex's declaration reads the same links and codes egress's sign-in
// route accepts, and shows the page egress returns.
func TestONB3CodexSignInMatchesTheEgressCheck(t *testing.T) {
	d := Builtins()["codex"]
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	route := egress.Codex()
	for _, l := range append(append([]string(nil), d.SignInLinks...), "https://auth.openai.com.evil.test/codex/device", "http://127.0.0.1:18432/x",
		"https://openai.com@evil.example/codex/device", "https://evil.example@auth.openai.com/codex/device", "https:auth.openai.com/codex/device", "https:///codex/device") {
		for _, c := range []string{userCode, "abcd", "AB", "ABCD-EFGH-1234-56789"} {
			_, gotCode, ok := d.SignInPrompt(l + " " + c)
			link, eCode, err := route.SignInLink(l, c)
			if ok != (err == nil) || (ok && (link != d.SignInPage || gotCode != eCode)) {
				t.Errorf("%q %q: provagent %v %q, egress %q %q %v", l, c, ok, gotCode, link, eCode, err)
			}
		}
	}
}

func TestONB3SignInDeclarationIsChecked(t *testing.T) {
	for name, f := range map[string]func(d *Declaration){
		"worker-held":   func(d *Declaration) { d.Custody, d.Endpoints = WorkerHeld, nil },
		"no links":      func(d *Declaration) { d.SignInLinks = nil },
		"http page":     func(d *Declaration) { d.SignInPage = fwdLink },
		"page unlisted": func(d *Declaration) { d.SignInPage = "https://other.test/device" },
		"credential":    func(d *Declaration) { d.SignInArgv = append(d.SignInArgv, "sk-"+strings.Repeat("a", 20)) },
	} {
		d := signInDecl()
		f(&d)
		if d.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := signInDecl().Validate(); err != nil {
		t.Errorf("good sign-in refused: %v", err)
	}
}

// SignInCommand under a real /bin/sh: it returns at once while the CLI
// runs on, in the declared cwd with only the declared env; the CLI's
// output, stderr included, goes only to its file, and its exit status to
// the second file once it exits.
func TestONB3SignInCommandUnderARealShellRunsInTheBackground(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	envBin, err := exec.LookPath("env")
	if err != nil {
		t.Skip("no env")
	}
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	gate := filepath.Join(dir, "approve")
	cli := filepath.Join(dir, "fakecli")
	script := "#!/bin/sh\n" +
		"echo \"cwd=$(pwd) leak=${PROVAGENT_TEST_LEAK:-none} args=$*\"\n" +
		"echo \"" + fwdLink + " " + userCode + "\" >&2\n" +
		"while [ ! -e " + gate + " ]; do sleep 0.01; done\n" +
		"exit 3\n"
	if err := os.WriteFile(cli, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROVAGENT_TEST_LEAK", "broker-env")
	d := signInDecl()
	d.Cwd, d.ResultPath = work, filepath.Join(work, ".result")
	d.Env = []string{"PATH=" + filepath.Dir(envBin) + ":/usr/bin:/bin"}
	d.Wrap = nil
	d.SignInArgv = []string{cli, "login", "--device-auth"}
	c := SignInCommand(d)
	cmd := exec.Command(c.Argv[0], c.Argv[1:]...)
	cmd.Dir = dir
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("start: %v (%s)", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the start waited for the CLI")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Errorf("the start printed %q %q", stdout.String(), stderr.String())
	}
	read := func(p string) string { b, _ := os.ReadFile(p); return string(b) }
	var out string
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if out = read(work + signInOut); strings.Contains(out, userCode) {
			break
		}
	}
	if _, code, ok := d.SignInPrompt(out); !ok || code != userCode {
		t.Fatalf("output %q", out)
	}
	if !strings.Contains(out, "cwd="+work+" leak=none args=login --device-auth") {
		t.Errorf("output %q", out)
	}
	if read(work+signInStatus) != "" {
		t.Fatal("a status before the CLI exited")
	}
	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var st string
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if st = read(work + signInStatus); st != "" {
			break
		}
	}
	if strings.TrimSpace(st) != "3" {
		t.Errorf("status %q", st)
	}
}
