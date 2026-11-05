package page

// REQ: NET-4, NET-2, HW-10

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestPageScript (NET-4, HW-10; #4929 R-P1): the page's script, run in
// Node against the enrolment screens this server renders (first boot,
// after a factory reset, a passkey in force), shows the owner what each
// answer means: the recovery code once, the card with the words that fit
// the state, and a form left ready after a failure. An id the script reads
// that a screen lacks fails it, as it throws in a browser. Catches the
// script's mutants that Go tests cannot see. CI has Node, so there a
// missing node fails rather than skips.
func TestPageScript(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI")
		}
		t.Skip("no node")
	}
	g := newEnrolRig(t)
	dir := t.TempDir()
	screen := func(name string) string {
		t.Helper()
		w := g.do(http.MethodGet, "/enrol", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s screen: %d", name, w.Code)
		}
		p := filepath.Join(dir, name+".html")
		if err := os.WriteFile(p, w.Body.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	factory := screen("factory")
	if code, out := g.enrolAs(newAuthenticator(t), caseCode); code != http.StatusOK {
		t.Fatalf("enrol: %d %v", code, out)
	}
	g.build()
	enrolled := screen("enrolled")
	if w := g.do(http.MethodPost, "/enrol/reset", map[string]string{"code": caseCode}); w.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", w.Code, w.Body)
	}
	g.build()
	reset := screen("reset")
	out, err := exec.Command(node, "testdata/pagejs.js", "static/page.js", factory, reset, enrolled).CombinedOutput()
	if err != nil {
		t.Fatalf("page.js: %v\n%s", err, out)
	}
}
