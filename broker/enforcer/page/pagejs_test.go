package page

// REQ: NET-4, NET-2, HW-10

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/enrol"
	"github.com/ghbmrk/agentos/broker/enforcer/page/internal/csrf"
)

// enrolScreens draws the enrolment screen as the book moves through first
// boot, a passkey in force, a recovery waiting and a factory reset, with
// the book driven directly, so a test of the screens runs only the page's
// screen code (mutgate targets every line a changed test runs, #4908).
type enrolScreens struct {
	t    *testing.T
	book *enrol.Book
	s    *Server
	now  time.Time
}

func newEnrolScreens(t *testing.T) *enrolScreens {
	t.Helper()
	bs := &bookStore{}
	if err := enrol.Provision(bs, caseCode, nil); err != nil {
		t.Fatal(err)
	}
	g := &enrolScreens{t: t, now: time.UnixMilli(1_800_000_000_000)}
	now := func() time.Time { return g.now }
	b, err := enrol.Open(enrol.Config{Name: rp, Store: bs, Network: &fakeNetwork{}, Alerts: &nopAlerts{}, Now: now, Log: func(string) {}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.OpenPolicy(&memStore{}); err != nil {
		t.Fatal(err)
	}
	g.book = b
	g.s = &Server{cfg: Config{Name: rp, Enrol: b, Zone: zone, Now: now}}
	var ok bool
	if g.s.tokens, ok = csrf.New(now); !ok {
		t.Fatal("csrf")
	}
	if g.s.tmpl, err = template.New("").Funcs(funcs).Funcs(template.FuncMap{"when": g.s.when}).ParseFS(files, "templates/*.html"); err != nil {
		t.Fatal(err)
	}
	return g
}

// enrol enrols a new passkey with code, and returns the recovery code.
func (g *enrolScreens) enrol(code string) string {
	g.t.Helper()
	a := newAuthenticator(g.t)
	id, msg, err := g.book.Begin(code, a.Public())
	if err != nil {
		g.t.Fatal(err)
	}
	res, err := g.book.Finish(id, a.signMsg(msg))
	if err != nil {
		g.t.Fatal(err)
	}
	return res.Recovery
}

// screen is the enrolment screen as it stands, saved under dir as name.
func (g *enrolScreens) screen(dir, name string) (string, string) {
	g.t.Helper()
	w := httptest.NewRecorder()
	g.s.enrolScreen(w, httptest.NewRequest(http.MethodGet, "https://"+rp+"/enrol", nil))
	if w.Code != http.StatusOK {
		g.t.Fatalf("%s screen: %d", name, w.Code)
	}
	p := filepath.Join(dir, name+".html")
	if err := os.WriteFile(p, w.Body.Bytes(), 0o600); err != nil {
		g.t.Fatal(err)
	}
	return p, w.Body.String()
}

// TestPageScript (NET-4, HW-10; #4929 R-P1, R-P2): the page's script, run
// in Node against the enrolment screens (first boot, after a factory
// reset, a passkey in force), shows the owner what each answer means: the
// recovery code once, the card with the words that fit the state, and a
// form left ready after a failure; on home, a step that cannot be undone
// (revoking the core's key, #4751) asks before the tap. An id the script reads that a screen
// lacks fails it, as it throws in a browser. Catches the script's mutants
// that Go tests cannot see. CI has Node, so there a missing node fails
// rather than skips.
func TestPageScript(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI")
		}
		t.Skip("no node")
	}
	g := newEnrolScreens(t)
	dir := t.TempDir()
	factory, page := g.screen(dir, "factory")
	for _, id := range []string{`id="net-new"`, `id="net-kept"`, `id="net-once"`, `id="rejoin"`, `id="recovery-box"`} {
		if !strings.Contains(page, id) {
			t.Errorf("enrolment screen lacks %s", id)
		}
	}
	g.enrol(caseCode)
	enrolled, _ := g.screen(dir, "enrolled")
	if err := g.book.FactoryReset(caseCode); err != nil {
		t.Fatal(err)
	}
	reset, _ := g.screen(dir, "reset")
	sg, _, _ := stateRig(t) // home with an alert to clear and the core's key to revoke
	home := filepath.Join(dir, "home.html")
	if err := os.WriteFile(home, []byte(sg.homeHTML()), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, "testdata/pagejs.js", "static/page.js", factory, reset, enrolled, home).CombinedOutput()
	if err != nil {
		t.Fatalf("page.js: %v\n%s", err, out)
	}
}

// TestResetTextNamesTheResetScreen (NET-2; #4929 R-UX1): the factory
// reset's text tells a reset cut short by a line it quotes, so the reset
// screen shows that line and no screen with a passkey in force does, nor
// one with a recovery waiting, nor the home page. Catches a text that
// tells an owner who enrolled since the reset to reset again.
func TestResetTextNamesTheResetScreen(t *testing.T) {
	const resetLine = "This enforcer was factory reset."
	w, err := alert.Words(alert.FactoryReset, "")
	if err != nil || !strings.Contains(w, `"`+resetLine+`"`) {
		t.Fatalf("the reset text does not quote %q: %q %v", resetLine, w, err)
	}
	home, err := files.ReadFile("templates/home.html")
	if err != nil || strings.Contains(string(home), resetLine) {
		t.Fatalf("the home page shows %q: %v", resetLine, err)
	}
	g := newEnrolScreens(t)
	dir := t.TempDir()
	if _, s := g.screen(dir, "factory"); strings.Contains(s, resetLine) {
		t.Error("the first-boot screen shows the reset line")
	}
	code := g.enrol(caseCode)
	if _, s := g.screen(dir, "enrolled"); strings.Contains(s, resetLine) {
		t.Error("the screen with a passkey in force shows the reset line")
	}
	g.enrol(code)
	due, ok := g.book.Recovery()
	if _, s := g.screen(dir, "waiting"); !ok || strings.Contains(s, resetLine) || !strings.Contains(s, "A new passkey is already waiting") ||
		!strings.Contains(s, clock(due.UnixMilli(), zone)) {
		t.Errorf("the screen with a recovery waiting (%v): %s", ok, s)
	}
	if err := g.book.FactoryReset(caseCode); err != nil {
		t.Fatal(err)
	}
	if _, s := g.screen(dir, "reset"); !strings.Contains(s, resetLine) {
		t.Errorf("the reset screen lacks %q", resetLine)
	}
	g.enrol(caseCode)
	if _, s := g.screen(dir, "re-enrolled"); strings.Contains(s, resetLine) {
		t.Error("the screen after enrolling since the reset shows the reset line")
	}
}
