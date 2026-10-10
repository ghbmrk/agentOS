package browser

// REQ: CRED-4, CRED-10

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
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
	ws := os.Getenv("BROWSER_FAKE_WS")
	seen := map[string]int{}
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := sc.Text()
		fmt.Fprintf(log, "REQ %s\n", line)
		var req struct{ Verb string }
		_ = json.Unmarshal([]byte(line), &req)
		if req.Verb == "screenshot" || req.Verb == "download" || os.Getenv("BROWSER_FAKE_ANYFILE") == "1" {
			// The file the driver says it wrote, or a link to a file outside
			// the workspace.
			name := os.Getenv("BROWSER_FAKE_NAME")
			if name == "" {
				name = "out.bin"
			}
			body := []byte(os.Getenv("BROWSER_FAKE_FILE"))
			dst := filepath.Join(ws, name)
			switch os.Getenv("BROWSER_FAKE_LINK") {
			case "sym", "hard":
				outside := filepath.Join(filepath.Dir(ws), "outside.txt")
				_ = os.WriteFile(outside, body, 0o600)
				_ = os.Remove(dst)
				if os.Getenv("BROWSER_FAKE_LINK") == "sym" {
					_ = os.Symlink(outside, dst)
				} else {
					_ = os.Link(outside, dst)
				}
			default:
				_ = os.WriteFile(dst, body, 0o600)
			}
		}
		r, ok := replies[req.Verb]
		if !ok {
			// The real driver (S5 executor.py) puts the page URL on every reply.
			r = json.RawMessage(`{"ok":true,"url":"https://shop.example.test/"}`)
		}
		if len(r) > 0 && r[0] == '[' {
			// A list scripts successive replies to the same verb.
			var seq []json.RawMessage
			_ = json.Unmarshal(r, &seq)
			i := seen[req.Verb]
			if i >= len(seq) {
				i = len(seq) - 1
			}
			r = seq[i]
		}
		seen[req.Verb]++
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

func newHarness(t *testing.T, replies map[string]any, file string, timeout time.Duration, env ...string) *harness {
	t.Helper()
	dir := t.TempDir()
	ws := filepath.Join(dir, "ws")
	log := filepath.Join(dir, "driver.log")
	raw, _ := json.Marshal(replies)
	t.Setenv("AGENTOS_PARENT_CANARY", "parentEnvCanaryZq81")
	exe, _ := os.Executable()
	g, err := Start(context.Background(), Config{
		Driver: wrapDriver(t, []string{exe, "-test.run=^$"}, append([]string{"BROWSER_FAKE_DRIVER=1", "BROWSER_FAKE_LOG=" + log,
			"BROWSER_FAKE_REPLIES=" + string(raw), "BROWSER_FAKE_WS=" + ws,
			"BROWSER_FAKE_FILE=" + file}, env...)),
		Origins:   []string{"https://shop.example.test"},
		Workspace: ws,
		Scrub:     vault.NewRedactor([][]byte{[]byte("vaultCanarySessionV4lt"), []byte("pw-canary-short")}),
		Timeout:   timeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	return &harness{g: g, log: log, ws: ws}
}

// wrapDriver returns a driver argv that sets env, NAME=value pairs, and
// runs argv: the fakes' settings are test-only keys, so they travel in
// the driver, not in Config.Env, which childproc's allowlist holds to the
// keys a real driver needs (P3-4b-3r-env-r8b).
func wrapDriver(t *testing.T, argv, env []string) []string {
	t.Helper()
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	sh := "#!/bin/sh\n"
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		sh += "export " + k + "=" + q(v) + "\n"
	}
	sh += "exec"
	for _, a := range argv {
		sh += " " + q(a)
	}
	w := filepath.Join(t.TempDir(), "driver")
	if err := os.WriteFile(w, []byte(sh+" \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return []string{w}
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

// REQ: CRED-1
//
// P3-4b-3r-env-r8b: the driver starts through childproc with exactly
// PATH, HOME (its workspace) and LANG, plus Config.Env, which is empty
// here: the fake's own settings come from its wrapper.
func TestDriverGetsExactlyItsEnvironment(t *testing.T) {
	t.Setenv("AGENTOS_OWNER", "+15550100999") // synthetic
	h := newHarness(t, nil, "", 0)
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	b, _ := os.ReadFile(h.log)
	line, _, _ := strings.Cut(string(b), "\n")
	env, ok := strings.CutPrefix(line, "ENV ")
	if !ok {
		t.Fatalf("no ENV line: %q", line)
	}
	var got []string
	for _, kv := range strings.Split(env, "\x00") {
		// The wrapper's shell sets PWD and the fake's settings itself.
		if !strings.HasPrefix(kv, "PWD=") && !strings.HasPrefix(kv, "BROWSER_FAKE_") {
			got = append(got, kv)
		}
	}
	sort.Strings(got)
	if want := []string{"HOME=" + h.ws, "LANG=C.UTF-8", "PATH=/usr/local/bin:/usr/bin:/bin"}; !slices.Equal(got, want) {
		t.Fatalf("driver env %q, want %q", got, want)
	}
}

// REQ: CRED-1
//
// A Config.Env key not on childproc's allowlist refuses the configuration:
// the driver never starts.
func TestAConfiguredKeyNotAllowlistedIsRefused(t *testing.T) {
	ran := filepath.Join(t.TempDir(), "ran")
	_, err := Start(context.Background(), Config{
		Driver:    []string{"/bin/sh", "-c", "touch " + ran},
		Origins:   []string{"https://shop.example.test"},
		Workspace: filepath.Join(t.TempDir(), "ws"),
		Env:       []string{"LD_PRELOAD=/x.so"},
	})
	if err == nil || !strings.Contains(err.Error(), "LD_PRELOAD is not allowlisted") {
		t.Fatalf("start: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("the driver ran")
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
		"screenshot": map[string]any{"ok": true, "url": "https://shop.example.test/", "path": "out.bin", "bytes": 3},
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
		"screenshot": map[string]any{"ok": true, "url": "https://shop.example.test/", "path": "out.bin", "bytes": 3},
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
	// L3 #3: a link to a file outside the workspace is not an output file.
	for _, link := range []string{"sym", "hard"} {
		for _, verb := range []string{"download", "screenshot"} {
			h := newHarness(t, map[string]any{
				verb: map[string]any{"ok": true, "url": "https://shop.example.test/", "path": "out.bin"},
			}, "clean", 0, "BROWSER_FAKE_LINK="+link)
			if r := h.do(t, `{"v":0,"verb":"`+verb+`"`+map[string]string{"download": `,"ref":"e2"`}[verb]+`}`); r.OK || r.Path != "" {
				t.Errorf("%s link from %s passed: %+v", link, verb, r)
			}
		}
	}
}

// CRED-10 / G4 (L3 #2): the real driver's action replies carry no snapshot, so
// the page URL is required on every ok reply; without it the gate cannot check
// confinement and stops the executor.
func TestOKReplyWithoutAURLStopsTheExecutor(t *testing.T) {
	for _, verb := range []string{"navigate", "click", "type", "select", "snapshot", "download"} {
		h := newHarness(t, map[string]any{verb: map[string]any{"ok": true}}, "clean", 0)
		req := map[string]string{
			"navigate": `{"v":0,"verb":"navigate","url":"https://shop.example.test/"}`,
			"click":    `{"v":0,"verb":"click","ref":"e1"}`,
			"type":     `{"v":0,"verb":"type","ref":"e1","text":"x"}`,
			"select":   `{"v":0,"verb":"select","ref":"e1","option":"a"}`,
			"snapshot": `{"v":0,"verb":"snapshot"}`,
			"download": `{"v":0,"verb":"download","ref":"e1"}`,
		}[verb]
		if r := h.do(t, req); r.OK || r.Error != "confinement" {
			t.Errorf("%s: got %+v", verb, r)
		}
		if r := h.do(t, `{"v":0,"verb":"snapshot"}`); r.Error != "stopped" {
			t.Errorf("%s: executor still running: %+v", verb, r)
		}
	}
}

// An error reply may omit the URL (the driver may not know it), but a URL it
// does carry is still checked.
func TestErrorReplyWithoutAURLIsRelayed(t *testing.T) {
	h := newHarness(t, map[string]any{"click": map[string]any{"ok": false, "error": "TimeoutError"}}, "", 0)
	if r := h.do(t, `{"v":0,"verb":"click","ref":"e1"}`); r.OK || r.Error != "TimeoutError" {
		t.Fatalf("got %+v", r)
	}
	if r := h.do(t, `{"v":0,"verb":"snapshot"}`); !r.OK {
		t.Fatalf("executor stopped after a plain error: %+v", r)
	}
}

// CRED-10 / G6 (L3 #3): only screenshot and download name an output file.
func TestPathOnOtherVerbsIsRefused(t *testing.T) {
	for _, verb := range []string{"click", "snapshot"} {
		h := newHarness(t, map[string]any{
			verb: map[string]any{"ok": true, "url": "https://shop.example.test/", "path": "out.bin"},
		}, "clean", 0, "BROWSER_FAKE_ANYFILE=1")
		req := map[string]string{"click": `{"v":0,"verb":"click","ref":"e1"}`, "snapshot": `{"v":0,"verb":"snapshot"}`}[verb]
		if r := h.do(t, req); r.OK || r.Path != "" {
			t.Errorf("%s with a path passed: %+v", verb, r)
		}
	}
}

// CRED-10 / G3 (L3 #3): a site names its downloads, so the output file name is
// filtered like any other string; a match withholds and removes the file.
func TestOutputPathCarryingASecretIsWithheld(t *testing.T) {
	for _, name := range []string{"report-vaultCanarySessionV4lt.txt", canaryGitHub + ".csv"} {
		h := newHarness(t, map[string]any{
			"download": map[string]any{"ok": true, "url": "https://shop.example.test/", "path": name},
		}, "clean", 0, "BROWSER_FAKE_NAME="+name)
		r := h.do(t, `{"v":0,"verb":"download","ref":"e2"}`)
		out, _ := json.Marshal(r)
		if r.OK || r.Error != "withheld" || strings.Contains(string(out), name) {
			t.Errorf("%s: got %s", name, out)
		}
		if _, err := os.Lstat(filepath.Join(h.ws, name)); !os.IsNotExist(err) {
			t.Errorf("%s: withheld file left in the workspace", name)
		}
	}
}

// CRED-10 / G5 (L3 #3): screenshot bytes are scanned like downloads, and the
// page is checked again after the shot, so a secret drawn in between is caught.
func TestScreenshotBytesAreScanned(t *testing.T) {
	h := newHarness(t, map[string]any{
		"snapshot":   map[string]any{"ok": true, "url": "https://shop.example.test/", "snapshot": "a kettle"},
		"screenshot": map[string]any{"ok": true, "url": "https://shop.example.test/", "path": "out.bin"},
	}, "PNG...tEXt vaultCanarySessionV4lt", 0)
	if r := h.do(t, `{"v":0,"verb":"screenshot"}`); r.OK || r.Error != "withheld" || r.Path != "" {
		t.Fatalf("got %+v", r)
	}
	if _, err := os.Stat(filepath.Join(h.ws, "out.bin")); !os.IsNotExist(err) {
		t.Fatal("withheld screenshot left in the workspace")
	}
}

func TestScreenshotWithheldWhenThePageChangesDuringTheShot(t *testing.T) {
	h := newHarness(t, map[string]any{
		"snapshot": []any{
			map[string]any{"ok": true, "url": "https://shop.example.test/", "snapshot": "a kettle"},
			map[string]any{"ok": true, "url": "https://shop.example.test/", "snapshot": "key " + canaryGitHub},
		},
		"screenshot": map[string]any{"ok": true, "url": "https://shop.example.test/", "path": "out.bin"},
	}, "png", 0)
	if r := h.do(t, `{"v":0,"verb":"screenshot"}`); r.OK || r.Error != "withheld" || r.Path != "" {
		t.Fatalf("got %+v", r)
	}
	if _, err := os.Stat(filepath.Join(h.ws, "out.bin")); !os.IsNotExist(err) {
		t.Fatal("withheld screenshot left in the workspace")
	}
	if got := h.received(t); len(got) != 3 {
		t.Fatalf("want snapshot, screenshot, snapshot; driver received %v", got)
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
