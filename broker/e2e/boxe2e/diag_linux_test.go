package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/e2e/boxe2e/codexstub"
	"github.com/ghbmrk/agentos/broker/modemlink"
)

// REQ: HW-10, ONB-3. The console is a public CI log, so a diag quotes
// whole journal lines only from the units ASSUMPTIONS E8 names: the page,
// its claim move and the modem bridge. agentosd and the vault process hold
// what E8 never prints (G1-e2e-later #1740 item 2), so claimDiag and
// modemDiag give only their unit states, and journalTail refuses them.
func TestDiagsQuoteNoAgentosdOrVaultJournal(t *testing.T) {
	var calls [][]string
	defer func(o func(string, ...string) string) { output = o }(output)
	output = func(name string, args ...string) string {
		calls = append(calls, append([]string{name}, args...))
		if name == "journalctl" {
			return "a journal line\n"
		}
		return "active\nrunning\n"
	}
	journalUnits := func() (units []string) {
		for _, c := range calls {
			if c[0] != "journalctl" {
				continue
			}
			for i, a := range c {
				if a == "-u" && i+1 < len(c) {
					units = append(units, c[i+1])
				}
			}
		}
		return units
	}
	shown := func() (units []string) {
		for _, c := range calls {
			if c[0] == "systemctl" {
				for _, a := range c[1:] {
					if strings.HasSuffix(a, ".service") {
						units = append(units, a)
					}
				}
			}
		}
		return units
	}
	for _, tc := range []struct {
		name    string
		diag    func() string
		journal []string
		states  []string
	}{
		{"claim", func() string { return claimDiag("ABCD-EFGH") },
			[]string{"agentos-localui-claim.service", "agentos-localui.service"},
			[]string{"agentosd.service", "agentos-egress.service"}},
		{"modem", modemDiag, []string{"agentos-modem.service"}, []string{"agentosd.service"}},
	} {
		calls = nil
		got := tc.diag()
		if u := journalUnits(); !slices.Equal(u, tc.journal) {
			t.Errorf("%s diag quotes the journals of %v, want %v", tc.name, u, tc.journal)
		}
		for _, s := range tc.states {
			if !slices.Contains(shown(), s) {
				t.Errorf("%s diag does not give %s's unit state (shows %v)", tc.name, s, shown())
			}
		}
		if !strings.Contains(got, "a journal line") {
			t.Errorf("%s diag drops the quotable lines: %q", tc.name, got)
		}
	}
	for _, u := range []string{"agentosd.service", "agentos-egress.service", "agentos-egress-setup.service"} {
		calls = nil
		got := journalTail(20, "agentos-localui.service", u)
		if len(calls) != 0 || strings.Contains(got, "a journal line") {
			t.Errorf("journalTail read %s's journal: calls %v, got %q", u, calls, got)
		}
	}
}

// journalCanary is a journal line no filtered reader keeps: the stand-in
// for a line that holds a secret E8 never prints.
const journalCanary = "journal-canary-0f3a: a line no filtered reader keeps"

// filteredJournal is a box journal that holds a line each filtered reader
// keeps, each next to the canary; the hook line also carries the canary
// before localui's hook text.
var filteredJournal = strings.Join([]string{
	journalCanary,
	journalCanary + " " + hostHookLog + "localui: synthetic hook error",
	journalCanary,
	"agentosd: agent machine guest-1: no socket",
	journalCanary,
	"agentosd: worker tools: not offered",
	journalCanary,
	"agentosd: setup: StartSignIn refused at step 6",
	journalCanary,
	"agentosd: provagent: worker exited 1",
	journalCanary,
	modemlink.MissedLog + " kind=request via owner.(*Channel).sendRequest",
	journalCanary,
}, "\n") + "\n"

// stubJournal makes output answer journalctl with filteredJournal and
// returns the units each journalctl call read.
func stubJournal(t *testing.T) *[][]string {
	t.Helper()
	var units [][]string
	old := output
	t.Cleanup(func() { output = old })
	output = func(name string, args ...string) string {
		if name != "journalctl" {
			return ""
		}
		var u []string
		for i, a := range args {
			if a == "-u" && i+1 < len(args) {
				u = append(u, args[i+1])
			}
		}
		units = append(units, u)
		return filteredJournal
	}
	return &units
}

// REQ: HW-10, ONB-3. Every journal read that reaches the console is
// filtered as ASSUMPTIONS E8 states (#4544 items 1 and 3): driven against
// a journal where each kept line sits next to a canary line, host quotes
// only localui's hook text, agentDiag only agentosd's agent-machine and
// worker-tools lines, and workerDiag only its setup and provagent lines;
// phoneControl's lost-send notes are pinned the same way in
// TestPhoneControlAgainstTheOwnerChannel. Each reads only its own unit,
// through output. It catches a reader that regresses to quoting its
// unit's whole journal.
func TestFilteredJournalReadersQuoteOnlyTheirLines(t *testing.T) {
	t.Run("host", func(t *testing.T) {
		units := stubJournal(t)
		const page = `<h2>5. This PC</h2><p class="err">Could not save.</p>`
		box := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method + " " + r.URL.Path {
			case "POST /setup/host":
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
			case "GET /setup":
				w.Write([]byte(page))
			default:
				http.NotFound(w, r)
			}
		})
		clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
		d := &driver{now: clk.now, sleep: clk.sleep, phone: &http.Client{Transport: handlerRT{box},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
		err := d.host()
		want := fmt.Sprintf("after %s: %s: %slocalui: synthetic hook error", time.Minute, where([]byte(page)), hostHookLog)
		if err == nil || err.Error() != want {
			t.Fatalf("host error\n %v\nwant\n %s", err, want)
		}
		if !slices.EqualFunc(*units, [][]string{{"agentos-localui.service"}}, slices.Equal) {
			t.Errorf("host read the journals of %v, want localui's once", *units)
		}
	})
	for _, c := range []struct {
		name string
		diag func() string
		keep []string
	}{
		{"agentDiag", func() string { return agentDiag(nil) },
			[]string{"agent machine guest-1: no socket", "worker tools: not offered"}},
		{"workerDiag", func() string {
			d := &driver{runscLog: func() string { return "" }}
			return d.workerDiag("sign-in output", "")
		}, []string{"setup: StartSignIn refused at step 6", "provagent: worker exited 1"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			units := stubJournal(t)
			got := c.diag()
			if strings.Contains(got, "journal-canary") {
				t.Errorf("%s quotes a line it does not keep: %q", c.name, got)
			}
			for _, k := range c.keep {
				if !strings.Contains(got, k) {
					t.Errorf("%s drops its line %q: %q", c.name, k, got)
				}
			}
			for _, other := range []string{"synthetic hook error", "kind=request", "agent machine", "provagent"} {
				if !slices.ContainsFunc(c.keep, func(k string) bool { return strings.Contains(k, other) }) && strings.Contains(got, other) {
					t.Errorf("%s quotes another reader's line %q: %q", c.name, other, got)
				}
			}
			if !slices.EqualFunc(*units, [][]string{{"agentosd.service"}}, slices.Equal) {
				t.Errorf("%s read the journals of %v, want agentosd's once", c.name, *units)
			}
		})
	}
}

type answer func(*http.Request) (*http.Response, error)

func (f answer) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// fixedAnswer is a box that answers the request at with status and a page
// whose step heading and error line are known, and passes every other
// request to next.
type fixedAnswer struct {
	at     string
	status int
	next   http.Handler
}

const (
	answerPage = `<h2>4. Store your recovery key</h2><p class="err">Tick the box to say it is stored.</p>`
	answerAt   = `at "4. Store your recovery key" saying "Tick the box to say it is stored."`
)

func (f fixedAnswer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method+" "+r.URL.RequestURI() == f.at || f.next == nil {
		w.WriteHeader(f.status)
		w.Write([]byte(answerPage))
		return
	}
	f.next.ServeHTTP(w, r)
}

// REQ: ONB-3. Every request the driver makes through answerErr (codes,
// the card's sheet, page and confirm, recovery, host, the AI sign-in and
// /status) says where setup stood when setup answers it wrongly: the
// page's step heading and its error line, never a bare status
// (G1-e2e-later #1740 item 1, G1-e2e-tidy #1715 item 3, #4517 item 1); a
// request with no answer names its error.
func TestFailedRequestsSayWhereSetupStood(t *testing.T) {
	disp, auth, _ := realCard(t)
	for _, c := range []struct {
		req  string
		at   string // the request the box answers wrongly
		st   int
		next http.Handler
		box  *fakeBox // the sign-in box, whose stub the driver uses
		step func(*driver) error
	}{
		{"POST /setup/codes", "POST /setup/codes", 200, nil, nil, (*driver).codes},
		{"GET card sheet", "GET /setup/card?save=1", 500, disp, nil, (*driver).card},
		{"GET card page", "GET /setup/card", 500, disp, nil, (*driver).card},
		{"POST card confirm", "POST /setup/card", 200, disp, nil, (*driver).card},
		{"POST /setup/recovery", "POST /setup/recovery", 200, nil, nil, (*driver).recovery},
		{"POST /setup/host", "POST /setup/host", 200, nil, nil, (*driver).host},
		{"POST /setup/ai-device", "POST /setup/ai-device", 200, nil, signInBox(), (*driver).planSignIn},
		{"GET /status", "GET /status", 500, nil, signInBox(), (*driver).planSignIn},
	} {
		box := c.box
		if box == nil {
			box = &fakeBox{stub: codexstub.New()}
		} else {
			c.next = box
		}
		d := fakeDriver(box)
		d.phone.Transport = handlerRT{fixedAnswer{c.at, c.st, c.next}}
		d.seed = []byte("synthetic-seed-canary")
		usePublished(t, auth)
		err := c.step(d)
		if want := fmt.Sprintf("%s %d %s", c.req, c.st, answerAt); err == nil || err.Error() != want {
			t.Errorf("%s error\n %v\nwant\n %s", c.req, err, want)
		}
	}
	if got := answerErr("GET /status", 0, nil, errors.New("connection refused")).Error(); got != "GET /status 0: connection refused" {
		t.Fatalf("transport error line %q", got)
	}
}

// signInBox is fakeBox at step 6 offering the codex sign-in.
func signInBox() *fakeBox {
	return &fakeBox{stub: codexstub.New(), offer: true, host: "auth.openai.com"}
}

// realCard is a real Owner Card display under the box's page paths, the
// authority it prints, and a copy of the card it generated (the display
// wipes its own once confirmed).
func realCard(t *testing.T) (http.Handler, []byte, card.Card) {
	t.Helper()
	auth := cardAuthority(t)
	var made card.Card
	d, err := card.NewDisplay(card.DisplayConfig{Authority: auth, Provision: func(*card.Card) error { return nil },
		Generate: func(r io.Reader) (*card.Card, error) {
			c, err := card.Generate(r)
			if c != nil {
				made = *c
			}
			return c, err
		}})
	if err != nil {
		t.Fatal(err)
	}
	return d.Handler(func(*http.Request) bool { return true }, "/setup"), auth, made
}

// usePublished points the card step's published certificate at auth.
func usePublished(t *testing.T, auth []byte) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "authority.der")
	if err := os.WriteFile(p, auth, 0o600); err != nil {
		t.Fatal(err)
	}
	old := publishedAuthority
	publishedAuthority = p
	t.Cleanup(func() { publishedAuthority = old })
}

// realAnswer passes the request at to next, then answers it with next's
// page under status; wrong, if set, changes the request first.
type realAnswer struct {
	at     string
	status int
	wrong  func(*http.Request)
	next   http.Handler
	got    *int // the status next answered
}

func (f realAnswer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method+" "+r.URL.RequestURI() != f.at {
		f.next.ServeHTTP(w, r)
		return
	}
	if f.wrong != nil {
		f.wrong(r)
	}
	rr := httptest.NewRecorder()
	f.next.ServeHTTP(rr, r)
	*f.got = rr.Code
	w.WriteHeader(f.status)
	w.Write(rr.Body.Bytes())
}

// REQ: ONB-3, HW-10. A failed card request's line is read off the card's
// own pages, which hold every printed card secret: the saved sheet, the
// display page and the wrong-answer page of a real display each give
// their step heading only, with no passphrase word, and no group or whole
// value of the recovery key, setup code or reset secret (#4517 item 4,
// #4544 item 4). It catches a card heading or error line that gains a
// secret.
func TestCardAnswerErrQuotesNoCardSecret(t *testing.T) {
	disp, auth, made := realCard(t)
	get := func(target string) []byte {
		w := httptest.NewRecorder()
		disp.ServeHTTP(w, httptest.NewRequest("GET", target, nil))
		return w.Body.Bytes()
	}
	sheet := string(get("/setup/card?save=1"))
	pass, rec, err := sheetSecrets([]byte(sheet))
	if err != nil {
		t.Fatal(err)
	}
	if pass != made.VaultPassphrase || rec != made.RecoveryKey {
		t.Fatal("the sheet's passphrase or recovery key is not the generated card's")
	}
	// The secrets are the generated card's printed values: the setup code
	// and reset secret (the card's SetupSecret) are on the sheet too.
	whole := []string{made.RecoveryKey, made.SetupCode, made.SetupSecret}
	for _, v := range whole {
		if v == "" {
			t.Fatal("the generated card has an empty printed value")
		}
		if !strings.Contains(sheet, v) {
			t.Fatalf("the sheet does not print the card value %q", v)
		}
	}
	// A secret is a whole passphrase word, in any case, or a full group of
	// the recovery key, setup code or reset secret as printed. A short
	// last group (two symbols of the reset secret) is caught as part of
	// the whole value only, since a two-letter token can be ordinary text.
	secret := map[string]bool{}
	for _, w := range strings.Fields(pass) {
		secret[strings.ToLower(w)] = true
	}
	for _, v := range whole {
		for _, g := range strings.FieldsFunc(v, func(r rune) bool { return !strings.ContainsRune(card.Alphabet, r) }) {
			if len(g) >= 4 {
				secret[g] = true
			}
		}
	}
	for _, c := range []struct {
		req, at string
		status  int
		wrong   func(*http.Request)
		real    int // the status the display answers
	}{
		{"GET card sheet", "GET /setup/card?save=1", 500, nil, 200},
		{"GET card page", "GET /setup/card", 500, nil, 200},
		{"POST card confirm", "POST /setup/card", http.StatusUnprocessableEntity, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(url.Values{"word": {"wrong"}, "group": {"ZZZZ"}}.Encode()))
		}, http.StatusUnprocessableEntity},
	} {
		var got int
		d := fakeDriver(&fakeBox{stub: codexstub.New()})
		d.phone.Transport = handlerRT{realAnswer{c.at, c.status, c.wrong, disp, &got}}
		usePublished(t, auth)
		err := d.card()
		if got != c.real {
			t.Fatalf("%s: the display answered %d, want its %d page", c.req, got, c.real)
		}
		prefix := fmt.Sprintf("%s %d at ", c.req, c.status)
		if err == nil || !strings.HasPrefix(err.Error(), prefix) {
			t.Fatalf("%s: %v", c.req, err)
		}
		// Only what the page gave is checked: the request's own name has
		// words a passphrase may hold (confirm, sheet).
		page := strings.TrimPrefix(err.Error(), prefix)
		for _, v := range whole {
			if strings.Contains(page, v) || strings.Contains(card.Normalize(page), card.Normalize(v)) {
				t.Errorf("%s line %q carries the card value %q", c.req, err, v)
			}
		}
		for _, w := range strings.FieldsFunc(page, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
			if secret[strings.ToLower(w)] || secret[w] {
				t.Errorf("%s line %q carries the card's %q", c.req, err, w)
			}
		}
	}
}

// journalReaders are the only functions that may read a journal, and the
// functions that may call each: readJournal alone runs journalctl, and
// journal is agentosd's whole journal, so only callers that keep lines of
// one shape take it. ASSUMPTIONS E8 names each.
var journalReaders = map[string][]string{
	"readJournal": {"journalTail", "host", "agentDiag", "journal"},
	"journal":     {"workerDiag", "phoneControl"},
}

// runners are the package's ways to run a system tool. Each takes the
// tool's name first; run and output pass their own name and args
// parameters on to command.
var runners = map[string]bool{"command": true, "run": true, "output": true}

// spawners start a process other than through a runner, keyed by import
// path and name, so an alias or dot import of the package is the same
// use; command alone calls childproc.Command.
var spawners = map[string]bool{
	"github.com/ghbmrk/agentos/broker/childproc.Command": true,
	"os.StartProcess": true,
}

// sysAllowed are the only functions of syscall and x/sys/unix the driver
// may use, those it uses today: either package can start a process
// (Exec, ForkExec, a raw execve), and a list of what they add would go
// stale, so every other function of theirs is refused.
var sysAllowed = map[string]bool{
	"golang.org/x/sys/unix.Close": true, "golang.org/x/sys/unix.Setns": true,
	"golang.org/x/sys/unix.IoctlSetPointerInt": true, "golang.org/x/sys/unix.IoctlGetUint32": true,
}

// osAllowed are the only functions of os the driver may use anywhere:
// none opens a file or makes a link, and none changes the process's
// environment. Opening and linking go through the file gate.
var osAllowed = map[string]bool{
	"os.Exit": true, "os.Lstat": true, "os.MkdirAll": true, "os.Remove": true, "os.RemoveAll": true,
	"os.Chmod": true, "os.Chown": true, "os.OpenRoot": true, "os.NewFile": true,
	"(*os.Root).Lstat": true, "(*os.Root).Close": true,
}

// gates are the driver's file gate (nofollow_linux.go): every open and
// every new link goes through them, and only they use gateOnly, so a
// journal file is refused by its content and a write outside writeDirs
// by its resolved path, however the path is spelled (#4609).
var (
	gates    = []string{"openRaw", "inDir", "fdPath", "checkFD", "rootOpen", "symlink"}
	gateOnly = map[string]bool{
		"golang.org/x/sys/unix.Open": true, "golang.org/x/sys/unix.Openat": true, "golang.org/x/sys/unix.Fstat": true,
		"golang.org/x/sys/unix.Pread": true, "golang.org/x/sys/unix.Symlinkat": true,
		"os.Readlink": true, "(*os.Root).OpenFile": true,
	}
)

// toolNames are the tools ASSUMPTIONS E8 allows, and the keys tools must
// have, each an absolute path on the image's read-only /usr.
var toolNames = []string{"ip", "systemctl", "journalctl"}

// barred are imports no file of the driver takes: os/exec and
// net/http/cgi start a process outside command, and unsafe, plugin and
// cgo reach code the source test cannot read.
var barred = map[string]bool{"os/exec": true, "net/http/cgi": true, "unsafe": true, "plugin": true, "C": true}

// procReach are the packages that start a process the caller names, and
// procImports the only direct imports of the driver whose own imports
// reach one, those it takes today: modem/at runs only arecord and aplay,
// and modem/atsim reaches childproc only through modem/at. Any other import that reaches
// childproc or os/exec, such as machprobe or probecmd, could run sh -c
// outside command, so it is refused (#4594 item 1).
var (
	procReach   = map[string]bool{"github.com/ghbmrk/agentos/broker/childproc": true, "os/exec": true}
	procImports = map[string]bool{
		"github.com/ghbmrk/agentos/broker/childproc":   true,
		"github.com/ghbmrk/agentos/broker/modem/at":    true,
		"github.com/ghbmrk/agentos/broker/modem/atsim": true,
	}
)

// commandCall says why command's childproc.Command call n runs other than
// tools[name] with args, under childEnv and empty options, or "". params
// are command's own; spawn takes the childEnv and tools idents it allows.
func commandCall(info *types.Info, n *ast.CallExpr, envObj, toolsObj types.Object, params []types.Object, spawn map[*ast.Ident]bool) string {
	is := func(e ast.Expr, o types.Object) bool {
		id, ok := e.(*ast.Ident)
		if ok && o != nil && info.Uses[id] == o {
			spawn[id] = true
			return true
		}
		return false
	}
	if len(n.Args) != 5 || len(params) != 2 || !n.Ellipsis.IsValid() {
		return "other than as childproc.Command(ctx, childEnv, childproc.Options{}, tools[name], args...)"
	}
	if !is(n.Args[1], envObj) {
		return "with an environment other than childEnv"
	}
	if cl, ok := n.Args[2].(*ast.CompositeLit); !ok || len(cl.Elts) > 0 {
		return "with options other than childproc.Options{}"
	}
	ix, ok := n.Args[3].(*ast.IndexExpr)
	if !ok || !is(ix.X, toolsObj) || !is(ix.Index, params[0]) {
		return "with a program other than tools[name]"
	}
	if !is(n.Args[4], params[1]) {
		return "with arguments other than its own args"
	}
	return ""
}

// basicString is a string literal's value, or "" for any other
// expression.
func basicString(e ast.Expr) string {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	v, _ := strconv.Unquote(lit.Value)
	return v
}

// funcPath is the package path and name of the package-level function a
// call calls, or "".
func funcPath(info *types.Info, call *ast.CallExpr) string {
	var id *ast.Ident
	switch fn := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		id = fn
	case *ast.SelectorExpr:
		id = fn.Sel
	}
	if f, ok := info.Uses[id].(*types.Func); ok && f.Pkg() != nil && f.Signature().Recv() == nil {
		return f.Pkg().Path() + "." + f.Name()
	}
	return ""
}

// REQ: HW-10, ONB-3. The console is a public CI log, so no diag runs
// journalctl but through the readers ASSUMPTIONS E8 names (#4517 item 3):
// journalctl is named only in readJournal, and each reader is called
// only by the functions E8 names for it. command runs only tools[name],
// an absolute path on the read-only /usr; only the file gate opens a file
// or makes a link, and of os the driver uses only osAllowed; no import but
// procImports reaches childproc or os/exec; and run and output pass their
// own parameters on unchanged (#4594, #4609). Data flow and other
// packages' own opens are E8's review items. A tool runs only through a
// direct call of command, run or output, and only the tools E8 allows,
// under constant names and arguments: ip link, addr or netns add, and
// systemctl show, restart or daemon-reload; journalctl only in
// readJournal (#4544 item 2, #4571). The test type-checks the driver, so
// it matches runners, readers and spawners by what they are, not by
// spelling: a runner taken as a value, an aliased or dot-imported
// spawner, and a wrapper tool such as sh or env each fail it, and so does
// systemctl status, which prints the unit's journal.
func TestJournalIsReadOnlyByNamedReaders(t *testing.T) {
	for _, tags := range [][]string{nil, {"agentos_e2e"}} {
		fset, files, imp := driverSources(t, tags)
		for _, p := range sourceProblems(fset, files, imp) {
			t.Errorf("tags %v: %s", tags, p)
		}
	}
	e8 := assumptionRow(t, "E8")
	for reader, callers := range journalReaders {
		for _, n := range append([]string{reader}, callers...) {
			if !strings.Contains(e8, "`"+n+"`") {
				t.Errorf("ASSUMPTIONS E8 does not name the journal reader `%s`", n)
			}
		}
	}
	for _, tool := range []string{"`ip`", "`systemctl`", "`journalctl`", "`show`", "`restart`", "`daemon-reload`"} {
		if !strings.Contains(e8, tool) {
			t.Errorf("ASSUMPTIONS E8 does not name the allowed tool word %s", tool)
		}
	}
}

// REQ: HW-10, ONB-3. Each shape that #4547's reviews and #4571 name, and
// the ones #4544 closed, added to the driver as one more file, fails the
// source test with its own reason; the driver as it stands has none.
func TestSourceTestRefusesEachBypass(t *testing.T) {
	fset, files, imp := driverSources(t, nil)
	const cp = `"github.com/ghbmrk/agentos/broker/childproc"`
	for _, c := range []struct{ name, src, want string }{
		{"runner as a value", `func zz() { f := output; f("systemctl", "status", "agentosd.service") }`, "uses output other than as a direct call"},
		{"runner in a package var", `var zz = run`, "uses run other than as a direct call"},
		{"aliased spawner", `import cp ` + cp + "\n" + `func zz() { cp.Command(nil, childEnv, cp.Options{}, "systemctl", "status") }`, "starts a process through github.com/ghbmrk/agentos/broker/childproc.Command"},
		{"dot-imported spawner", `import . ` + cp + "\n" + `func zz() { Command(nil, childEnv, Options{}, "id") }`, "starts a process through github.com/ghbmrk/agentos/broker/childproc.Command"},
		{"aliased syscall", `import sc "syscall"` + "\n" + `func zz() { sc.Exec("/bin/sh", nil, nil) }`, "uses syscall.Exec, which the driver does not need"},
		{"spawner as a value", `import "os"` + "\n" + `var zz = os.StartProcess`, "starts a process through os.StartProcess"},
		{"os/exec alias", `import x "os/exec"` + "\n" + `var zz = x.Command`, "imports os/exec"},
		{"unsafe", `import _ "unsafe"`, "imports unsafe"},
		{"sh wrapper", `func zz() { output("sh", "-c", "systemctl status agentosd.service") }`, `runs "sh", which ASSUMPTIONS E8 does not allow`},
		{"env wrapper", `func zz() { output("env", "systemctl", "status", "agentosd.service") }`, `runs "env", which ASSUMPTIONS E8 does not allow`},
		{"absolute path", `func zz() { output("/usr/bin/systemctl", "show") }`, `runs "/usr/bin/systemctl"`},
		{"systemctl status", `func zz() { output("systemctl", "status", "-n", "50", "agentosd.service") }`, "runs systemctl status"},
		{"computed verb", `func zz() { output("systemctl", "sta"+"tus", "agentosd.service") }`, "runs systemctl status"},
		{"verb after an option", `func zz() { output("systemctl", "-p", "x", "status") }`, "runs systemctl -p"},
		{"variable systemctl argument", `func zz(v string) { output("systemctl", "show", v) }`, "runs systemctl with an argument that is not a constant"},
		{"spread systemctl arguments", `func zz() { a := []string{"status"}; run("systemctl", a...) }`, "runs systemctl with an argument that is not a constant"},
		{"variable tool name", `func zz(n string) { run(n, "status") }`, "with a tool name that is not a constant"},
		{"computed journalctl", `func zz() { output("journal"+"ctl", "-u", "agentosd.service") }`, "names journalctl"},
		{"journalctl constant", `const zz = "journalctl"`, "names journalctl"},
		{"ip netns exec", `func zz() { run("ip", "netns", "exec", netns, "sh") }`, "runs ip netns exec"},
		{"ip batch", `func zz() { run("ip", "-b", "/tmp/x") }`, "runs ip -b"},
		{"method named readJournal", `type zt struct{}` + "\n" + `func (zt) readJournal() string { return output("journalctl", "-u", "agentosd.service") }` + "\n" + `func zz() string { return zt{}.readJournal() }`, "(zt).readJournal names journalctl"},
		{"method named output", `type zt struct{}` + "\n" + `func (zt) output(name string, args ...string) string { out, _ := command(name, args...).Output(); return string(out) }` + "\n" + `func zz() string { return zt{}.output("sh", "-c", "systemctl status agentosd.service") }`, "(zt).output calls command with a tool name that is not a constant"},
		{"method named output, called", `type zt struct{}` + "\n" + `func (zt) output(name string, args ...string) string { return "" }` + "\n" + `func zz() string { return zt{}.output("sh") }`, "zz uses (zt).output, which is not the driver's own output"},
		{"method named command", `import cp ` + cp + "\n" + `type zt struct{}` + "\n" + `func (zt) command() *cp.Cmd { return cp.Command(nil, childEnv, cp.Options{}, "sh", "-c", "systemctl status agentosd.service") }`, "(zt).command starts a process through github.com/ghbmrk/agentos/broker/childproc.Command"},
		{"journal through an interface", `type jr interface{ journal() string }` + "\n" + `func zz(j jr) string { return j.journal() }`, "zz uses (jr).journal, which is not the driver's own journal"},
		{"command's own params from a closure", `func zz(name string, args ...string) { command(name, args...) }`, "zz calls command with a tool name that is not a constant"},
		{"AllThreadsSyscall", `import "syscall"` + "\n" + `func zz() { syscall.AllThreadsSyscall(syscall.SYS_EXECVE, 0, 0, 0) }`, "uses syscall.AllThreadsSyscall, which the driver does not need"},
		{"AllThreadsSyscall6", `import "syscall"` + "\n" + `func zz() { syscall.AllThreadsSyscall6(syscall.SYS_EXECVE, 0, 0, 0, 0, 0, 0) }`, "uses syscall.AllThreadsSyscall6, which the driver does not need"},
		{"unix SyscallNoError", `import "golang.org/x/sys/unix"` + "\n" + `func zz() { unix.SyscallNoError(unix.SYS_EXECVE, 0, 0, 0) }`, "uses golang.org/x/sys/unix.SyscallNoError, which the driver does not need"},
		{"unix RawSyscallNoError", `import "golang.org/x/sys/unix"` + "\n" + `func zz() { unix.RawSyscallNoError(unix.SYS_EXECVE, 0, 0, 0) }`, "uses golang.org/x/sys/unix.RawSyscallNoError, which the driver does not need"},
		{"syscall Exec", `import sc "syscall"` + "\n" + `func zz() { sc.ForkExec("/bin/sh", nil, nil) }`, "uses syscall.ForkExec, which the driver does not need"},
		{"net/http/cgi", `import "net/http/cgi"` + "\n" + `var zz = cgi.Handler{Path: "/bin/sh"}`, "imports net/http/cgi"},
		{"readJournal from an unnamed caller", `func zz() string { return readJournal(0, "agentosd.service") }`, "zz reads through readJournal"},
		{"journal as a value", `func zz(d *driver) { f := d.journal; _ = f }`, "uses journal other than as a direct call"},
		{"machprobe's child", `import "github.com/ghbmrk/agentos/broker/machprobe"` + "\n" + `var zz = machprobe.Options{Child: []string{"sh", "-c", "systemctl status agentosd.service"}}`, "imports github.com/ghbmrk/agentos/broker/machprobe, which reaches github.com/ghbmrk/agentos/broker/childproc"},
		{"probecmd's command", `import "github.com/ghbmrk/agentos/broker/probecmd"` + "\n" + `var zz = probecmd.CommandProbe{Cmd: []string{"sh"}}`, "imports github.com/ghbmrk/agentos/broker/probecmd, which reaches github.com/ghbmrk/agentos/broker/childproc"},
		{"journal file read", `import "os"` + "\n" + `func zz() { os.ReadFile("/var/log/journal/x/system.journal") }`, "zz uses os.ReadFile, which the driver does not need (osAllowed)"},
		{"file opened", `import "os"` + "\n" + `func zz() { os.Open("/var/l" + "og/journal") }`, "zz uses os.Open, which the driver does not need"},
		{"file opened for writing", `import "os"` + "\n" + `func zz() { os.OpenFile("/etc/ld.so.preload", os.O_WRONLY, 0) }`, "zz uses os.OpenFile, which the driver does not need"},
		{"program planted", `import "os"` + "\n" + `func zz() { os.WriteFile("/run/zz/ip", nil, 0o755); run("ip", "link") }`, "zz uses os.WriteFile, which the driver does not need"},
		{"link made", `import "os"` + "\n" + `func zz() { os.Symlink("/run/agentos-e2e/zz", "/etc/systemd/system/zz.service") }`, "zz uses os.Symlink, which the driver does not need"},
		{"file moved", `import "os"` + "\n" + `func zz() { os.Rename("/run/agentos-e2e/zz", "/etc/ld.so.preload") }`, "zz uses os.Rename, which the driver does not need"},
		{"hard link", `import "os"` + "\n" + `func zz() { os.Link("/var/log/journal/x/system.journal", "/run/agentos-e2e/j") }`, "zz uses os.Link, which the driver does not need"},
		{"directory filesystem", `import "os"` + "\n" + `var zz = os.DirFS("/var/log")`, "zz uses os.DirFS, which the driver does not need"},
		{"PATH changed", `import "os"` + "\n" + `func zz() { os.Setenv("PATH", "/run/zz") }`, "zz uses os.Setenv, which the driver does not need"},
		{"working directory changed", `import "os"` + "\n" + `func zz() { os.Chdir("/var/log") }`, "zz uses os.Chdir, which the driver does not need"},
		{"open as a value", `import "os"` + "\n" + `var zz = os.ReadFile`, "zz uses os.ReadFile, which the driver does not need"},
		{"unix open outside the gate", `import "golang.org/x/sys/unix"` + "\n" + `func zz() { unix.Open("/var/log/journal", unix.O_RDONLY, 0) }`, "zz uses golang.org/x/sys/unix.Open, which only the file gate uses"},
		{"unix openat outside the gate", `import "golang.org/x/sys/unix"` + "\n" + `func zz(d int) { unix.Openat(d, "x", unix.O_RDONLY, 0) }`, "zz uses golang.org/x/sys/unix.Openat, which only the file gate uses"},
		{"root read", `import "os"` + "\n" + `func zz(r *os.Root) { r.ReadFile("system.journal") }`, "zz uses (*os.Root).ReadFile, which the driver does not need"},
		{"root open outside the gate", `import "os"` + "\n" + `func zz(r *os.Root) { r.OpenFile("system.journal", os.O_RDONLY, 0) }`, "zz uses (*os.Root).OpenFile, which only the file gate uses"},
		{"readlink outside the gate", `import "os"` + "\n" + `func zz() { os.Readlink("/proc/self/fd/3") }`, "zz uses os.Readlink, which only the file gate uses"},
		{"syscall open", `import "syscall"` + "\n" + `func zz() { syscall.Open("/var/log/journal", 0, 0) }`, "zz uses syscall.Open, which the driver does not need (sysAllowed)"},
		{"tools passed elsewhere", `var zz = tools`, "zz uses tools other than in command's childproc.Command call"},
		{"tools changed", `func zz() { tools["ip"] = "/run/zz/ip" }`, "zz uses tools other than in command's childproc.Command call"},
		{"childEnv passed elsewhere", `import cp ` + cp + "\n" + `var zz = []cp.Env{childEnv}`, "zz uses childEnv other than in command's childproc.Command call"},
		{"bodiless function", `func zz(p *byte) int`, "zz has no body"},
		{"import reaching childproc through another", `import _ "github.com/ghbmrk/agentos/broker/vision/supervise"`, "imports github.com/ghbmrk/agentos/broker/vision/supervise, which reaches"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, err := parser.ParseFile(fset, "zz_bypass.go", "package main\n"+c.src+"\n", 0)
			if err != nil {
				t.Fatal(err)
			}
			got := sourceProblems(fset, append(slices.Clone(files), f), imp)
			if !slices.ContainsFunc(got, func(p string) bool { return strings.Contains(p, c.want) }) {
				t.Errorf("source test does not refuse it with %q; it says %q", c.want, got)
			}
		})
	}
}

// TestSourceTestPinsTheRunnersPassThrough edits run, output, command and
// childEnv in place: each edit makes command run a tool the caller did
// not name or find it on another PATH, and the source test refuses it
// with its own reason (#4594 item 3, #4609).
func TestSourceTestPinsTheRunnersPassThrough(t *testing.T) {
	fset, files, imp := driverSources(t, nil)
	const outputCall, runCall = "out, _ := command(name, args...).Output()", "out, err := command(name, args...).CombinedOutput()"
	const commandCall = "return childproc.Command(context.Background(), childEnv, childproc.Options{}, tools[name], args...)"
	const toolsDecl = `var tools = map[string]string{"ip": "/usr/bin/ip", "systemctl": "/usr/bin/systemctl", "journalctl": "/usr/bin/journalctl"}`
	for _, c := range []struct{ name, old, new, want string }{
		{"output passes another variable", outputCall, `x := "sh"; out, _ := command(x, args...).Output()`, "output calls command with a tool name that is not a constant"},
		{"output passes its args alone", outputCall, `out, _ := command("systemctl", args...).Output()`, "output calls command and runs systemctl with an argument that is not a constant"},
		{"output reassigns name", outputCall, `name = "sh"; ` + outputCall, "output uses its parameter name other than to pass it to command or quote it"},
		{"output's closure reassigns name", outputCall, `func() { name = "sh" }(); ` + outputCall, "output uses its parameter name other than"},
		{"run writes an argument", runCall, `args[0] = "status"; ` + runCall, "run uses its parameter args other than"},
		{"run copies over its args", runCall, `copy(args, []string{"status"}); ` + runCall, "run uses its parameter args other than"},
		{"run passes a pointer to name", runCall, `p := &name; *p = "sh"; ` + runCall, "run uses its parameter name other than"},
		{"run hands its args to a closure", runCall, `func(_ string, a []string) { a[0] = "status" }(name, args); ` + runCall, "run uses its parameter args other than"},
		{"output hands its params to a named function", outputCall, `_ = fmt.Sprint(name, args); ` + outputCall, "output uses its parameter name other than"},
		{"childEnv built from the process's PATH", `var childEnv = childproc.NewEnv("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")`, `var childEnv = childproc.NewEnv("PATH=" + os.Getenv("PATH"))`, "childEnv is not childproc.NewEnv of string literals"},
		{"a tool outside /usr", toolsDecl, strings.Replace(toolsDecl, `"/usr/bin/ip"`, `"/run/agentos-e2e/ip"`, 1), "tools is not a map literal"},
		{"a tool path not clean", toolsDecl, strings.Replace(toolsDecl, `"/usr/bin/ip"`, `"/usr/../run/agentos-e2e/ip"`, 1), "tools is not a map literal"},
		{"a tool more", toolsDecl, strings.Replace(toolsDecl, `"ip": `, `"sh": "/usr/bin/sh", "ip": `, 1), "tools is not a map literal"},
		{"command runs its name", commandCall, strings.Replace(commandCall, "tools[name]", "name", 1), "command starts a process with a program other than tools[name]"},
		{"command runs a constant", commandCall, strings.Replace(commandCall, "tools[name]", `"/usr/bin/sh"`, 1), "command starts a process with a program other than tools[name]"},
		{"command indexes another key", commandCall, strings.Replace(commandCall, "tools[name]", `tools["ip"]`, 1), "command starts a process with a program other than tools[name]"},
		{"command reassigns name", commandCall, `name = "journalctl"; ` + commandCall, "command uses its parameter name other than in its childproc.Command call"},
		{"command with another environment", commandCall, strings.Replace(commandCall, "childEnv", `childproc.NewEnv("PATH=/run/zz")`, 1), "command starts a process with an environment other than childEnv"},
		{"command with a local environment", commandCall, "var e childproc.Env; " + strings.Replace(commandCall, "childEnv", "e", 1), "command starts a process with an environment other than childEnv"},
		{"command with options", commandCall, strings.Replace(commandCall, "childproc.Options{}", `childproc.Options{Dir: "/run/zz"}`, 1), "command starts a process with options other than childproc.Options{}"},
		{"command with other arguments", commandCall, strings.Replace(commandCall, "args...", `[]string{"status"}...`, 1), "command starts a process with arguments other than its own args"},
	} {
		t.Run(c.name, func(t *testing.T) {
			edited := slices.Clone(files)
			n := 0
			for i, f := range files {
				name := fset.Position(f.Pos()).Filename
				src, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(src), c.old) {
					continue
				}
				n++
				if edited[i], err = parser.ParseFile(fset, name, strings.Replace(string(src), c.old, c.new, 1), 0); err != nil {
					t.Fatal(err)
				}
			}
			if n != 1 {
				t.Fatalf("%d driver files hold %q; the case is stale", n, c.old)
			}
			got := sourceProblems(fset, edited, imp)
			if !slices.ContainsFunc(got, func(p string) bool { return strings.Contains(p, c.want) }) {
				t.Errorf("source test does not refuse it with %q; it says %q", c.want, got)
			}
		})
	}
}

var (
	sourceOnce sync.Once
	sourceFset *token.FileSet
	sourceImp  types.Importer
)

// driverSources is the driver's non-test files that a Linux build with
// tags compiles, parsed, and an importer that type-checks their imports
// from source, shared by every caller so each package is read once.
func driverSources(t *testing.T, tags []string) (*token.FileSet, []*ast.File, types.Importer) {
	t.Helper()
	sourceOnce.Do(func() {
		sourceFset = token.NewFileSet()
		sourceImp = importer.ForCompiler(sourceFset, "source", nil)
	})
	ctx := build.Default
	ctx.GOOS, ctx.BuildTags = "linux", tags
	bp, err := ctx.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for kind, fs := range map[string][]string{"cgo": bp.CgoFiles, "assembly": bp.SFiles, "syso": bp.SysoFiles, "C": bp.CFiles} {
		if len(fs) > 0 {
			t.Errorf("the driver has %s files %v, which the source test cannot read", kind, fs)
		}
	}
	var files []*ast.File
	for _, n := range bp.GoFiles {
		f, err := parser.ParseFile(sourceFset, n, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	return sourceFset, files, sourceImp
}

// sourceProblems type-checks the driver's files and names each way they
// run a tool, start a process or read a journal outside what
// ASSUMPTIONS E8 allows. Runners, readers and their callers are the
// objects the test's names stand for, a package function or a *driver
// method, never whatever else is spelled the same. A driver that does
// not type-check, or lacks one of those objects, is itself a problem, so
// the test fails closed.
func sourceProblems(fset *token.FileSet, files []*ast.File, imp types.Importer) []string {
	var bad []string
	add := func(at token.Pos, format string, a ...any) {
		bad = append(bad, fset.Position(at).String()+": "+fmt.Sprintf(format, a...))
	}
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}}
	pkg, err := (&types.Config{Importer: imp}).Check("main", fset, files, info)
	if err != nil {
		return []string{"the driver does not type-check: " + err.Error()}
	}
	var drv types.Type
	if tn, ok := pkg.Scope().Lookup("driver").(*types.TypeName); ok {
		drv = types.NewPointer(tn.Type())
	}
	var missing []string
	object := func(n string) types.Object {
		if o := pkg.Scope().Lookup(n); o != nil {
			return o
		}
		if drv != nil {
			if o, _, _ := types.LookupFieldOrMethod(drv, true, pkg, n); o != nil {
				if _, ok := o.(*types.Func); ok {
					return o
				}
			}
		}
		missing = append(missing, n)
		return nil
	}
	guarded := map[string]bool{} // the names of runners and readers
	runner := map[types.Object]string{}
	for n := range runners {
		runner[object(n)], guarded[n] = n, true
	}
	reader := map[types.Object]string{}
	callers := map[string][]types.Object{}
	for r, cs := range journalReaders {
		reader[object(r)], guarded[r] = r, true
		for _, c := range cs {
			callers[r] = append(callers[r], object(c))
		}
	}
	if len(missing) > 0 {
		return []string{fmt.Sprintf("the driver has no function or *driver method %v that the test names", missing)}
	}
	// childEnv must be childproc.NewEnv of one PATH= string literal, the
	// only PATH= in the driver; its directories' last components are the
	// ones no other constant may hold.
	// childEnv is childproc.NewEnv of string literals, and tools a map
	// literal from each of toolNames to a clean absolute path on /usr;
	// each is used only in command's one childproc.Command call.
	envObj, _ := pkg.Scope().Lookup("childEnv").(*types.Var)
	toolsObj, _ := pkg.Scope().Lookup("tools").(*types.Var)
	envOK, toolsOK := false, false
	for _, f := range files {
		for _, u := range units(info, f) {
			sp, ok := u.node.(*ast.ValueSpec)
			if !ok || u.obj == nil || len(sp.Values) != 1 {
				continue
			}
			switch u.obj {
			case envObj:
				call, ok := sp.Values[0].(*ast.CallExpr)
				envOK = ok && funcPath(info, call) == "github.com/ghbmrk/agentos/broker/childproc.NewEnv" && !call.Ellipsis.IsValid() &&
					!slices.ContainsFunc(call.Args, func(a ast.Expr) bool { lit, ok := a.(*ast.BasicLit); return !ok || lit.Kind != token.STRING })
			case toolsObj:
				lit, ok := sp.Values[0].(*ast.CompositeLit)
				if _, isMap := info.Types[sp.Values[0]].Type.Underlying().(*types.Map); !ok || !isMap {
					break
				}
				keys := []string{}
				toolsOK = true
				for _, e := range lit.Elts {
					kv, _ := e.(*ast.KeyValueExpr)
					var k, v string
					if kv != nil {
						k, v = basicString(kv.Key), basicString(kv.Value)
					}
					if k == "" || !strings.HasPrefix(v, "/usr/") || filepath.Clean(v) != v {
						toolsOK = false
						break
					}
					keys = append(keys, k)
				}
				slices.Sort(keys)
				toolsOK = toolsOK && slices.Equal(keys, slices.Sorted(slices.Values(toolNames)))
			}
		}
	}
	if !envOK {
		return []string{"childEnv is not childproc.NewEnv of string literals"}
	}
	if !toolsOK {
		return []string{fmt.Sprintf("tools is not a map literal from each of %v to a clean absolute path under /usr/", toolNames)}
	}
	gate := map[types.Object]bool{}
	for _, n := range gates {
		gate[object(n)] = true
	}
	if len(missing) > 0 {
		return []string{fmt.Sprintf("the driver has no file gate function %v that the test names", missing)}
	}
	imported := map[string]*types.Package{}
	for _, p := range pkg.Imports() {
		imported[p.Path()] = p
	}
	childCommand := "github.com/ghbmrk/agentos/broker/childproc.Command"
	uses := map[string][]types.Object{} // reader -> the declarations that use it
	named := false                      // readJournal names journalctl
	for _, f := range files {
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if barred[p] {
				add(im.Pos(), "imports %s", p)
			} else if via := reach(imported[p], map[*types.Package]bool{}); via != "" && !procImports[p] {
				add(im.Pos(), "imports %s, which reaches %s and is not in procImports", p, via)
			}
		}
		for _, u := range units(info, f) {
			in, label := u.obj, objLabel(u.obj)
			var params []types.Object // a runner's own parameters
			if runner[in] != "" && u.fn != nil {
				for _, fld := range u.fn.Params.List {
					for _, n := range fld.Names {
						params = append(params, info.Defs[n])
					}
				}
			}
			var own []types.Object // run's and output's, which they pass on
			if r := runner[in]; r == "run" || r == "output" {
				own = params
			}
			passed := ownUses(info, runner, own, u.node)
			called := map[*ast.Ident]bool{} // the idents that are a call's function
			spawn := map[*ast.Ident]bool{}  // childEnv and tools in command's call
			ast.Inspect(u.node, func(n ast.Node) bool {
				if e, ok := n.(ast.Expr); ok {
					if v := info.Types[e].Value; v != nil && v.Kind() == constant.String && strings.Contains(constant.StringVal(v), "journalctl") {
						if reader[in] != "readJournal" && in != toolsObj {
							add(e.Pos(), "%s names journalctl, which only readJournal runs", label)
						}
						named = named || reader[in] == "readJournal"
					}
				}
				switch n := n.(type) {
				case *ast.FuncDecl:
					if n.Body == nil {
						add(n.Pos(), "%s has no body, so its code is not Go the test reads", label)
					}
				case *ast.CallExpr:
					if funcPath(info, n) == childCommand && runner[in] == "command" {
						if why := commandCall(info, n, envObj, toolsObj, params, spawn); why != "" {
							add(n.Pos(), "command starts a process %s", why)
						}
					}
					switch fn := n.Fun.(type) {
					case *ast.Ident:
						called[fn] = true
						if name, ok := runner[info.Uses[fn]]; ok {
							if why := runnerCall(info, reader[in] == "readJournal", own, name, n); why != "" {
								add(n.Pos(), "%s calls %s %s", label, name, why)
							}
						}
					case *ast.SelectorExpr:
						called[fn.Sel] = true
					}
				case *ast.Ident:
					obj := info.Uses[n]
					if obj == nil {
						break
					}
					if runner[in] == "command" && slices.Contains(params, obj) && !spawn[n] {
						add(n.Pos(), "command uses its parameter %s other than in its childproc.Command call", n.Name)
					}
					if (obj == envObj || obj == toolsObj) && !spawn[n] {
						add(n.Pos(), "%s uses %s other than in command's childproc.Command call", label, n.Name)
					}
					if slices.Contains(own, obj) && !passed[n] {
						add(n.Pos(), "%s uses its parameter %s other than to pass it to command or quote it", label, n.Name)
					}
					if name, ok := runner[obj]; ok && !called[n] {
						add(n.Pos(), "%s uses %s other than as a direct call", label, name)
					}
					if name, ok := reader[obj]; ok {
						if !called[n] {
							add(n.Pos(), "%s uses %s other than as a direct call", label, name)
						}
						uses[name] = append(uses[name], in)
					}
					fn, isFunc := obj.(*types.Func)
					if !isFunc {
						break
					}
					if guarded[fn.Name()] && runner[obj] == "" && reader[obj] == "" {
						add(n.Pos(), "%s uses %s, which is not the driver's own %s", label, objLabel(obj), fn.Name())
					}
					if fn.Pkg() == nil {
						break
					}
					sp, recv := fn.Pkg().Path()+"."+fn.Name(), ""
					if r := fn.Signature().Recv(); r != nil {
						recv = types.TypeString(r.Type(), func(p *types.Package) string { return p.Path() })
						sp = "(" + recv + ")." + fn.Name()
					}
					switch p := fn.Pkg().Path(); {
					case gateOnly[sp]:
						if !gate[in] {
							add(n.Pos(), "%s uses %s, which only the file gate uses (gates)", label, sp)
						}
					case spawners[sp]:
						if sp != childCommand || runner[in] != "command" {
							add(n.Pos(), "%s starts a process through %s, not command", label, sp)
						}
					case p == "os" && (recv == "" || recv == "*os.Root") && !osAllowed[sp]:
						add(n.Pos(), "%s uses %s, which the driver does not need (osAllowed)", label, sp)
					case recv != "":
					case (p == "syscall" || p == "golang.org/x/sys/unix") && !sysAllowed[sp]:
						add(n.Pos(), "%s uses %s, which the driver does not need (sysAllowed)", label, sp)
					}
				}
				return true
			})
		}
	}
	if !named {
		bad = append(bad, "readJournal does not name journalctl: the test reads the wrong files")
	}
	for r, cs := range callers {
		for _, in := range uses[r] {
			if in == nil || !slices.Contains(cs, in) {
				bad = append(bad, fmt.Sprintf("%s reads through %s, which ASSUMPTIONS E8 does not name it for (callers %v)", objLabel(in), r, journalReaders[r]))
			}
		}
	}
	return bad
}

// reach is the first package of procReach that p is or imports, directly
// or not, or "".
func reach(p *types.Package, seen map[*types.Package]bool) string {
	if p == nil || seen[p] {
		return ""
	}
	seen[p] = true
	if procReach[p.Path()] {
		return p.Path()
	}
	for _, q := range p.Imports() {
		if via := reach(q, seen); via != "" {
			return via
		}
	}
	return ""
}

// ownUses are the uses of run's or output's own parameters own that the
// source test allows: passed on whole to command, or quoted by
// fmt.Errorf or strings.Join, which neither change them. Any other use,
// an assignment, an index write, a closure or a call that could change
// args in place, is refused, so the tool command runs is the one the
// caller named (#4594 item 3).
func ownUses(info *types.Info, runner map[types.Object]string, own []types.Object, node ast.Node) map[*ast.Ident]bool {
	ok := map[*ast.Ident]bool{}
	if len(own) == 0 {
		return ok
	}
	ast.Inspect(node, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		var callee types.Object
		if fn, isId := call.Fun.(*ast.Ident); isId {
			callee = info.Uses[fn]
		}
		quote := slices.Contains([]string{"fmt.Errorf", "strings.Join"}, funcPath(info, call))
		for i, a := range call.Args {
			id, isId := a.(*ast.Ident)
			if !isId || !slices.Contains(own, info.Uses[id]) {
				continue
			}
			if quote || runner[callee] == "command" && i < len(own) && info.Uses[id] == own[i] {
				ok[id] = true
			}
		}
		return true
	})
	return ok
}

// unit is one declaration the source test reads: its object (nil for a
// declaration of several names or none), its syntax, and, for a function
// or a variable holding a function literal, that function's type.
type unit struct {
	obj  types.Object
	node ast.Node
	fn   *ast.FuncType
}

// units are a file's declarations: each function and method, and each
// spec of a const, var or type declaration on its own.
func units(info *types.Info, f *ast.File) []unit {
	var us []unit
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			us = append(us, unit{info.Defs[d.Name], d, d.Type})
		case *ast.GenDecl:
			for _, sp := range d.Specs {
				u := unit{node: sp}
				switch sp := sp.(type) {
				case *ast.ValueSpec:
					if len(sp.Names) == 1 {
						u.obj = info.Defs[sp.Names[0]]
						if len(sp.Values) == 1 {
							if lit, ok := sp.Values[0].(*ast.FuncLit); ok {
								u.fn = lit.Type
							}
						}
					}
				case *ast.TypeSpec:
					u.obj = info.Defs[sp.Name]
				}
				us = append(us, u)
			}
		}
	}
	return us
}

// objLabel names a declaration for a problem line: a function's name, a
// method's with its receiver type, or "(package level)" for none.
func objLabel(o types.Object) string {
	if o == nil {
		return "(package level)"
	}
	if fn, ok := o.(*types.Func); ok {
		if r := fn.Signature().Recv(); r != nil {
			return "(" + types.TypeString(r.Type(), func(*types.Package) string { return "" }) + ")." + fn.Name()
		}
	}
	return o.Name()
}

// runnerCall says why a call of the runner name runs a tool ASSUMPTIONS
// E8 does not allow, or "". own are the enclosing run's or output's own
// parameters, which it may pass on to command; every other call names
// its tool by a constant, and ip and systemctl take only constant
// arguments: ip link, addr or netns add, after an optional -n and
// namespace, and systemctl show, restart or daemon-reload as its first
// argument. journalctl runs only in readJournal (inReadJournal), with the
// arguments readJournal builds.
func runnerCall(info *types.Info, inReadJournal bool, own []types.Object, name string, call *ast.CallExpr) string {
	if len(call.Args) == 0 {
		return "with no tool name"
	}
	param := func(e ast.Expr, i int) bool {
		id, ok := e.(*ast.Ident)
		return ok && i < len(own) && own[i] != nil && info.Uses[id] == own[i]
	}
	if name == "command" && len(own) == 2 && len(call.Args) == 2 && call.Ellipsis.IsValid() &&
		param(call.Args[0], 0) && param(call.Args[1], 1) {
		return ""
	}
	vals, allConst := constStrings(info, call.Args)
	if vals[0] == nil {
		return "with a tool name that is not a constant"
	}
	tool, args := *vals[0], vals[1:]
	switch tool {
	case "journalctl":
		if !inReadJournal {
			return "with journalctl outside readJournal"
		}
		return ""
	case "ip", "systemctl":
	default:
		return fmt.Sprintf("and runs %q, which ASSUMPTIONS E8 does not allow", tool)
	}
	if !allConst || call.Ellipsis.IsValid() {
		return "and runs " + tool + " with an argument that is not a constant"
	}
	a := make([]string, len(args))
	for i, v := range args {
		a[i] = *v
	}
	if tool == "systemctl" {
		if len(a) == 0 || !slices.Contains([]string{"show", "restart", "daemon-reload"}, a[0]) {
			return "and runs systemctl " + strings.Join(a, " ") + ", not show, restart or daemon-reload"
		}
		return ""
	}
	obj := a
	if len(obj) >= 2 && obj[0] == "-n" {
		obj = obj[2:]
	}
	if len(obj) == 0 || !(obj[0] == "link" || obj[0] == "addr" || len(obj) >= 2 && obj[0] == "netns" && obj[1] == "add") {
		return "and runs ip " + strings.Join(a, " ") + ", not link, addr or netns add"
	}
	return ""
}

// constStrings is each argument's constant string value, nil where it
// has none, and whether every argument has one.
func constStrings(info *types.Info, args []ast.Expr) ([]*string, bool) {
	vals := make([]*string, len(args))
	all := true
	for i, a := range args {
		if v := info.Types[a].Value; v != nil && v.Kind() == constant.String {
			s := constant.StringVal(v)
			vals[i] = &s
		} else {
			all = false
		}
	}
	return vals, all
}

// assumptionRow is ASSUMPTIONS.md's row whose first cell is id.
func assumptionRow(t *testing.T, id string) string {
	t.Helper()
	b, err := os.ReadFile("ASSUMPTIONS.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "| "+id+" |") {
			return l
		}
	}
	t.Fatalf("ASSUMPTIONS.md has no %s row", id)
	return ""
}
