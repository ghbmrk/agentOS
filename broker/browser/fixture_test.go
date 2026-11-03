package browser

// REQ: CRED-4, CRED-10

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// fixture starts the S5 driver behind a gate on S5's local fixture site and
// its "evil" twin. Needs python3 with Playwright and Chromium's headless
// shell; skipped where absent (the broker CI job), and run by
// `go test ./browser` where they are.
func fixture(t *testing.T, scrub Scrubber) (g *Gate, site, evil string) {
	t.Helper()
	s5, _ := filepath.Abs("../../spikes/S5-browser-actions")
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	// The S5 driver needs AI-mode snapshots (aria_snapshot(mode="ai"), Playwright
	// 1.63 in S5's measurement); older installs skip rather than fail.
	if exec.Command(py, "-c", `import inspect
from playwright.sync_api import Locator
assert "mode" in inspect.signature(Locator.aria_snapshot).parameters`).Run() != nil {
		t.Skip("Playwright with AI-mode snapshots not installed")
	}
	chrome := os.Getenv("S5_CHROME")
	if chrome == "" {
		m, _ := filepath.Glob("/opt/pw-browsers/chromium_headless_shell-*/chrome-linux/headless_shell")
		if len(m) == 0 {
			t.Skip("Chromium headless shell not installed")
		}
		chrome = m[0]
	}

	// Serve the fixture site and its "evil" twin.
	srv := exec.Command(py, "-c", `import sys, server
s, e = server.serve_pair()
print(s.server_port, e.server_port, flush=True)
sys.stdin.read()`)
	srv.Dir = filepath.Join(s5, "fixture")
	stdin, _ := srv.StdinPipe()
	stdout, _ := srv.StdoutPipe()
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); srv.Wait() })
	ports := strings.Fields(mustLine(t, stdout))
	site = "http://127.0.0.1:" + ports[0]
	evil = "http://localhost:" + ports[1]

	g, err = Start(context.Background(), Config{
		Driver:    wrapDriver(t, []string{py, filepath.Join(s5, "executor.py")}, []string{"S5_CHROME=" + chrome}),
		Origins:   []string{site},
		Workspace: filepath.Join(t.TempDir(), "ws"),
		Scrub:     scrub,
		Timeout:   60 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	return g, site, evil
}

// The S5 driver behind the gate, against S5's local fixture site.
func TestFixtureThroughTheGate(t *testing.T) {
	const canaryURLToken = "s5CanaryUrlTokenR2d2C3po4BB8Kx9" // planted by the fixture
	const canaryShown = "sk-ant-s5canaryDisplayedKey0123456789abcdef"
	g, site, evil := fixture(t, fakeScrubber{canaryShown})
	var transcript []string
	do := func(req string) Result {
		r, _, _ := g.do(context.Background(), []byte(req), nil)
		b, _ := json.Marshal(r)
		transcript = append(transcript, string(b))
		return r
	}

	if r := do(`{"v":0,"verb":"navigate","url":"` + site + `/app.html"}`); !r.OK {
		t.Fatalf("navigate: %+v", r)
	}
	snap := do(`{"v":0,"verb":"snapshot"}`)
	if !snap.OK || !strings.Contains(snap.Snapshot, "Search") {
		t.Fatalf("snapshot: %+v", snap)
	}
	// Drive one widget by ref through the gate.
	ref := regexp.MustCompile(`textbox "Search"[^\n]*\[ref=((?:f\d+)?e\d+)\]`).FindStringSubmatch(snap.Snapshot)
	if ref == nil {
		t.Fatalf("no search box in snapshot")
	}
	if r := do(`{"v":0,"verb":"type","ref":"` + ref[1] + `","text":"kettle","submit":true}`); !r.OK {
		t.Fatalf("type: %+v", r)
	}
	if r := do(`{"v":0,"verb":"snapshot"}`); !strings.Contains(r.Snapshot, "echo:kettle [submitted]") {
		t.Fatalf("typed text not seen: %.400s", r.Snapshot)
	}
	// Off-origin navigation is refused at the gate.
	if r := do(`{"v":0,"verb":"navigate","url":"` + evil + `/stolen"}`); r.OK || r.Error != "off_origin" {
		t.Fatalf("off-origin navigate: %+v", r)
	}
	// The page shows a key without a reveal step: the screenshot is withheld.
	if r := do(`{"v":0,"verb":"screenshot"}`); r.OK || r.Error != "withheld" {
		t.Fatalf("screenshot: %+v", r)
	}
	// Refusals from the protocol itself.
	if r := do(`{"v":0,"verb":"evaluate","script":"document.cookie"}`); r.Error != "protocol" {
		t.Fatalf("evaluate: %+v", r)
	}

	all := strings.Join(transcript, "\n")
	for _, c := range []string{canaryURLToken, canaryShown} {
		if strings.Contains(all, c) {
			t.Errorf("canary %q reached the agent", c)
		}
	}
}

// K16, against real Playwright: within one document an unchanged element
// keeps its ref when the driver snapshots again (as it does inside a
// screenshot), and a new document, even at the same URL, resolves no ref of
// the old one, so the driver refuses what the gate cannot see changed.
func TestFixtureRefsFollowTheDriversDocument(t *testing.T) {
	g, site, _ := fixture(t, fakeScrubber{})
	do := func(req string) Result {
		r, _, _ := g.do(context.Background(), []byte(req), nil)
		return r
	}
	email := regexp.MustCompile(`textbox "Email"[^\n]*\[ref=((?:f\d+)?e\d+)\]`)
	refOf := func(what string) string {
		t.Helper()
		snap := do(`{"v":0,"verb":"snapshot"}`)
		m := email.FindStringSubmatch(snap.Snapshot)
		if !snap.OK || m == nil {
			t.Fatalf("%s: no email field in %+v", what, snap)
		}
		return m[1]
	}
	login := `{"v":0,"verb":"navigate","url":"` + site + `/login.html"}`
	if r := do(login); !r.OK {
		t.Fatalf("navigate: %+v", r)
	}
	ref := refOf("first look")
	if r := do(`{"v":0,"verb":"screenshot"}`); !r.OK {
		t.Fatalf("screenshot: %+v", r)
	}
	if again := refOf("after the screenshot"); again != ref {
		t.Fatalf("the email field's ref moved from %s to %s within one document", ref, again)
	}
	if r := do(`{"v":0,"verb":"type","ref":"` + ref + `","text":"a"}`); !r.OK {
		t.Fatalf("type on the same document: %+v", r)
	}
	// The same URL loaded again is a new document: the gate keeps its refs
	// (the URL did not change) and the driver refuses the old one.
	if r := do(login); !r.OK {
		t.Fatalf("navigate again: %+v", r)
	}
	if r := do(`{"v":0,"verb":"type","ref":"` + ref + `","text":"a"}`); r.OK || r.Error != "protocol" || !strings.Contains(r.Detail, "stale") {
		t.Fatalf("type with a ref from the earlier document: %+v", r)
	}
	// Another page without a snapshot: the gate refuses the old page's
	// ref itself, and nothing reaches the driver.
	first := ref
	ref = refOf("second document")
	t.Logf("email field ref: %s in the first document, %s in the second", first, ref)
	if r := do(`{"v":0,"verb":"navigate","url":"` + site + `/hop-check"}`); !r.OK {
		t.Fatalf("navigate: %+v", r)
	}
	if r := do(`{"v":0,"verb":"click","ref":"` + ref + `"}`); r.Error != "unknown_ref" {
		t.Fatalf("click with a ref from another page: %+v", r)
	}
}

func mustLine(t *testing.T, r interface{ Read([]byte) (int, error) }) string {
	t.Helper()
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return line
}
