package browser

// REQ: CRED-4, CRED-10

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/vault"
)

// The test binary doubles as a scripted driver: with BROWSER_FAKE_DRIVER set it
// answers each request line with the reply scripted for its verb and logs what
// it received, so tests can see what crossed the gate.
func TestMain(m *testing.M) {
	if os.Getenv("BROWSER_FAKE_DRIVER") == "1" {
		fakeDriver()
		return
	}
	os.Exit(m.Run())
}

func fakeDriver() {
	log, _ := os.OpenFile(os.Getenv("BROWSER_FAKE_LOG"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	fmt.Fprintf(log, "ENV %s\n", strings.Join(os.Environ(), "\x00"))
	fmt.Fprintf(log, "ARGS %s\n", strings.Join(os.Args[1:], " "))
	var replies map[string]json.RawMessage
	_ = json.Unmarshal([]byte(os.Getenv("BROWSER_FAKE_REPLIES")), &replies)
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := sc.Text()
		fmt.Fprintf(log, "REQ %s\n", line)
		var req struct{ Verb string }
		_ = json.Unmarshal([]byte(line), &req)
		if req.Verb == "screenshot" || req.Verb == "download" {
			// The file the driver says it wrote.
			body := os.Getenv("BROWSER_FAKE_FILE")
			_ = os.WriteFile(filepath.Join(os.Getenv("BROWSER_FAKE_WS"), "out.bin"), []byte(body), 0o600)
		}
		r, ok := replies[req.Verb]
		if !ok {
			r = json.RawMessage(`{"ok":true}`)
		}
		if string(r) == `"hang"` {
			time.Sleep(time.Hour)
		}
		if string(r) == `"big"` {
			big, _ := json.Marshal(map[string]any{"ok": true, "url": "https://shop.example.test/",
				"snapshot": strings.Repeat("- text: kettle\n", MaxSnapshot/10)})
			r = big
		}
		if string(r) == `"exit"` {
			os.Exit(3)
		}
		os.Stdout.Write(append(r, '\n'))
	}
}

type harness struct {
	g   *Gate
	log string
	ws  string
}

func newHarness(t *testing.T, replies map[string]any, file string, timeout time.Duration) *harness {
	t.Helper()
	dir := t.TempDir()
	ws := filepath.Join(dir, "ws")
	log := filepath.Join(dir, "driver.log")
	raw, _ := json.Marshal(replies)
	t.Setenv("AGENTOS_PARENT_CANARY", "parentEnvCanaryZq81")
	exe, _ := os.Executable()
	g, err := Start(context.Background(), Config{
		Driver:    []string{exe, "-test.run=^$"},
		Origins:   []string{"https://shop.example.test"},
		Workspace: ws,
		Scrub:     vault.NewRedactor([][]byte{[]byte("vaultCanarySessionV4lt"), []byte("pw-canary-short")}),
		Timeout:   timeout,
		Env: []string{"BROWSER_FAKE_DRIVER=1", "BROWSER_FAKE_LOG=" + log,
			"BROWSER_FAKE_REPLIES=" + string(raw), "BROWSER_FAKE_WS=" + ws,
			"BROWSER_FAKE_FILE=" + file},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	return &harness{g: g, log: log, ws: ws}
}

func (h *harness) do(t *testing.T, raw string) Result {
	t.Helper()
	return h.g.Do(context.Background(), []byte(raw))
}

func (h *harness) received(t *testing.T) []string {
	t.Helper()
	b, _ := os.ReadFile(h.log)
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "REQ ") {
			out = append(out, strings.TrimPrefix(l, "REQ "))
		}
	}
	return out
}

func TestRefusedRequestsNeverReachTheDriver(t *testing.T) {
	h := newHarness(t, nil, "", 0)
	for _, raw := range []string{
		`{"v":0,"verb":"evaluate","script":"document.cookie"}`,
		`{"v":0,"verb":"cookies"}`,
		`{"v":0,"verb":"navigate","url":"javascript:alert(1)"}`,
		`{"v":0,"verb":"navigate","url":"https://evil.test/"}`, // off the declared origins
		`{"v":0,"verb":"snapshot","verb":"evaluate"}`,
	} {
		r := h.do(t, raw)
		if r.OK || (r.Error != "protocol" && r.Error != "off_origin") {
			t.Errorf("%s: got %+v", raw, r)
		}
	}
	h.do(t, `{"v":0,"verb":"snapshot"}`) // flush: the driver answers this one
	if got := h.received(t); len(got) != 1 {
		t.Fatalf("driver received %d requests, want only the snapshot: %v", len(got), got)
	}
}

func TestGateForwardsOnlyTheCanonicalRequest(t *testing.T) {
	h := newHarness(t, nil, "", 0)
	h.do(t, `{"text":"kettle","verb":"type","v":0,"ref":"e3"}`)
	got := h.received(t)
	if len(got) != 1 || got[0] != `{"v":0,"verb":"type","ref":"e3","text":"kettle","submit":false}` {
		t.Fatalf("driver received %v", got)
	}
}

// The driver starts with a fixed environment, not the broker's.
func TestDriverDoesNotInheritTheBrokerEnvironment(t *testing.T) {
	h := newHarness(t, nil, "", 0)
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	b, _ := os.ReadFile(h.log)
	if strings.Contains(string(b), "parentEnvCanaryZq81") {
		t.Fatal("broker environment reached the driver")
	}
	if !strings.Contains(string(b), "--origins https://shop.example.test --workspace ") {
		t.Fatalf("driver not told its origins and workspace: %s", b)
	}
}

func TestOutputIsScrubbedOfVaultValuesAndDetectedTokens(t *testing.T) {
	h := newHarness(t, map[string]any{"snapshot": map[string]any{
		"ok": true, "url": "https://shop.example.test/cb#access_token=abc123",
		"title":               "Hello vaultCanarySessionV4lt",
		"snapshot":            "- text: key " + canaryAPI + " and pw-canary-short",
		"detail":              "x",
		"refused_navigations": []string{"https://evil.test/?session=vaultCanarySessionV4lt"},
		"redactions":          1,
	}}, "", 0)
	r := h.do(t, `{"v":0,"verb":"snapshot"}`)
	out, _ := json.Marshal(r)
	for _, c := range []string{"vaultCanarySessionV4lt", "pw-canary-short", canaryAPI, "abc123"} {
		if strings.Contains(string(out), c) {
			t.Errorf("canary %q reached the agent: %s", c, out)
		}
	}
	if r.Redactions < 5 {
		t.Errorf("redactions = %d, want the driver's 1 plus the gate's own", r.Redactions)
	}
}

// Fields the protocol does not define are dropped, so a driver cannot widen
// the output (e.g. a "cookies" field).
func TestUnknownOutputFieldsAreDropped(t *testing.T) {
	h := newHarness(t, map[string]any{"snapshot": map[string]any{
		"ok": true, "url": "https://shop.example.test/", "cookies": "sid=leakedCookieValue",
	}}, "", 0)
	out, _ := json.Marshal(h.do(t, `{"v":0,"verb":"snapshot"}`))
	if strings.Contains(string(out), "leakedCookieValue") || strings.Contains(string(out), "cookies") {
		t.Fatalf("unknown field passed: %s", out)
	}
}

// CRED-10: a page off the declared origins means confinement failed; the gate
// fails closed and stops the executor rather than report from that page.
func TestOffOriginPageStopsTheExecutor(t *testing.T) {
	h := newHarness(t, map[string]any{"click": map[string]any{
		"ok": true, "url": "https://evil.test/landing", "snapshot": "evil page",
	}}, "", 0)
	r := h.do(t, `{"v":0,"verb":"click","ref":"e1"}`)
	if r.OK || r.Error != "confinement" || r.Snapshot != "" {
		t.Fatalf("got %+v", r)
	}
	if r := h.do(t, `{"v":0,"verb":"snapshot"}`); r.OK || r.Error != "stopped" {
		t.Fatalf("executor still running after a confinement failure: %+v", r)
	}
}

// CRED-10: screenshots of pages with a match are withheld. The gate checks the
// page with its own filter (including the vault's exact values) before it lets a
// screenshot through.
func TestScreenshotWithheldWhenThePageShowsASecret(t *testing.T) {
	h := newHarness(t, map[string]any{
		"snapshot":   map[string]any{"ok": true, "url": "https://shop.example.test/", "snapshot": "your session vaultCanarySessionV4lt"},
		"screenshot": map[string]any{"ok": true, "path": "out.bin", "bytes": 3},
	}, "png", 0)
	r := h.do(t, `{"v":0,"verb":"screenshot"}`)
	if r.OK || r.Error != "withheld" || r.Path != "" {
		t.Fatalf("got %+v", r)
	}
	for _, req := range h.received(t) {
		if strings.Contains(req, "screenshot") {
			t.Fatal("the screenshot was taken despite the match")
		}
	}
}

func TestScreenshotPassesOnACleanPage(t *testing.T) {
	h := newHarness(t, map[string]any{
		"snapshot":   map[string]any{"ok": true, "url": "https://shop.example.test/", "snapshot": "a kettle"},
		"screenshot": map[string]any{"ok": true, "path": "out.bin", "bytes": 3},
	}, "png", 0)
	if r := h.do(t, `{"v":0,"verb":"screenshot"}`); !r.OK || r.Path != "out.bin" {
		t.Fatalf("got %+v", r)
	}
}

// A downloaded file that carries a vault value or a detected token is removed
// from the workspace and withheld.
func TestDownloadWithASecretIsWithheldAndRemoved(t *testing.T) {
	h := newHarness(t, map[string]any{
		"download": map[string]any{"ok": true, "url": "https://shop.example.test/", "path": "out.bin", "bytes": 10},
	}, "report: vaultCanarySessionV4lt", 0)
	r := h.do(t, `{"v":0,"verb":"download","ref":"e2"}`)
	if r.OK || r.Error != "withheld" {
		t.Fatalf("got %+v", r)
	}
	if _, err := os.Stat(filepath.Join(h.ws, "out.bin")); !os.IsNotExist(err) {
		t.Fatal("withheld file left in the workspace")
	}
}

func TestOutputPathMustBeAFlatWorkspaceName(t *testing.T) {
	for _, p := range []string{"../escape", "/etc/passwd", "a/b", ".hidden", "missing.bin"} {
		h := newHarness(t, map[string]any{
			"download": map[string]any{"ok": true, "url": "https://shop.example.test/", "path": p},
		}, "clean", 0)
		if r := h.do(t, `{"v":0,"verb":"download","ref":"e2"}`); r.OK || r.Path != "" {
			t.Errorf("path %q passed: %+v", p, r)
		}
	}
}

func TestHungDriverTimesOutAndStops(t *testing.T) {
	h := newHarness(t, map[string]any{"snapshot": "hang"}, "", 300*time.Millisecond)
	start := time.Now()
	if r := h.do(t, `{"v":0,"verb":"snapshot"}`); r.OK || r.Error != "timeout" {
		t.Fatalf("got %+v", r)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout not enforced")
	}
	if r := h.do(t, `{"v":0,"verb":"click","ref":"e1"}`); r.Error != "stopped" {
		t.Fatalf("got %+v", r)
	}
}

func TestDriverExitIsReportedNotHidden(t *testing.T) {
	h := newHarness(t, map[string]any{"snapshot": "exit"}, "", 0)
	if r := h.do(t, `{"v":0,"verb":"snapshot"}`); r.OK || r.Error != "stopped" {
		t.Fatalf("got %+v", r)
	}
}

func TestOversizedSnapshotIsCapped(t *testing.T) {
	h := newHarness(t, map[string]any{"snapshot": "big"}, "", 0)
	r := h.do(t, `{"v":0,"verb":"snapshot"}`)
	if !r.OK || !r.Truncated || len(r.Snapshot) > MaxSnapshot+64 {
		t.Fatalf("ok=%v truncated=%v len=%d", r.OK, r.Truncated, len(r.Snapshot))
	}
}
