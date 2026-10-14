package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// The console lines ci_boot.sh greps: a step that passes, an expected
// failure with its issue, a step that unexpectedly passes, and the steps
// after a failure, which are blocked rather than run.
func TestReportLinesAndBlocking(t *testing.T) {
	var out bytes.Buffer
	r := newReport(&out, map[string]expectedFailure{"b": {12, "status 500"}, "d": {34, "x"}})
	ran := map[string]bool{}
	step := func(name string, err error) {
		r.step(name, func() error { ran[name] = true; return err })
	}
	step("a", nil)
	step("d", nil)
	step("b", errors.New("status 500\nsecond line"))
	step("c", nil)
	r.done()
	want := []string{
		"agentos-e2e: PASS a",
		"agentos-e2e: XPASS d expected to fail (#34) but passed",
		"agentos-e2e: XFAIL(#12) b status 500 second line",
		"agentos-e2e: BLOCKED c after b",
		"agentos-e2e: DONE pass=1 fail=0 xfail=1 xpass=1 blocked=1",
	}
	if got := strings.Split(strings.TrimSpace(out.String()), "\n"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got:\n%s\nwant:\n%s", out.String(), strings.Join(want, "\n"))
	}
	if ran["c"] {
		t.Fatal("a step after a failure ran")
	}
	if !r.failed() {
		t.Fatal("an XPASS must fail the run")
	}
}

func TestReportUnexpectedFailureFailsTheRun(t *testing.T) {
	var out bytes.Buffer
	r := newReport(&out, nil)
	r.step("a", func() error { return errors.New("no") })
	r.step("b", func() error { return nil })
	r.done()
	if !strings.Contains(out.String(), "agentos-e2e: FAIL a no\n") || !strings.Contains(out.String(), "BLOCKED b after a") || !r.failed() {
		t.Fatalf("%s", out.String())
	}
	out.Reset()
	r = newReport(&out, map[string]expectedFailure{"a": {1, "no"}})
	r.step("a", func() error { return errors.New("no") })
	r.done()
	if r.failed() {
		t.Fatalf("an expected failure failed the run: %s", out.String())
	}
}

// REQ: HW-10. A listed step is XFAIL only when its error carries the
// expected text; any other error from it is FAIL and fails the run.
func TestReportExpectedFailureMatchesItsText(t *testing.T) {
	list := map[string]expectedFailure{"host": {1221, `at "6. This PC"`}}
	var out bytes.Buffer
	r := newReport(&out, list)
	r.step("host", func() error { return errors.New(`after 1m0s: at "6. This PC"`) })
	if !strings.Contains(out.String(), `XFAIL(#1221) host after 1m0s: at "6. This PC"`) || r.failed() {
		t.Fatalf("expected text not XFAIL: %s", out.String())
	}
	for _, msg := range []string{"POST /setup/host 500 <nil>", `after 1m0s: at "7. Done"`, "connection refused"} {
		out.Reset()
		r = newReport(&out, list)
		r.step("host", func() error { return errors.New(msg) })
		r.step("next", func() error { return nil })
		r.done()
		if !strings.Contains(out.String(), "agentos-e2e: FAIL host "+msg+"\n") || strings.Contains(out.String(), "XFAIL") ||
			!strings.Contains(out.String(), "fail=1 xfail=0") || !r.failed() {
			t.Fatalf("%q was hidden: %s", msg, out.String())
		}
	}
}

// A failed step's diagnostics quote service logs: any secret the driver
// holds is cut out of them, and each log line is kept short.
func TestRedactLog(t *testing.T) {
	got := redactLog("start\nclaim ABCD-EFGH typed\n"+strings.Repeat("x", 300), 3, "ABCD-EFGH", "")
	if strings.Contains(got, "ABCD-EFGH") {
		t.Fatalf("secret left in %q", got)
	}
	if !strings.Contains(got, "start | claim [redacted] typed | ") {
		t.Fatalf("lines not joined: %q", got)
	}
	if len(got) > 3*(logLineMax+3) {
		t.Fatalf("long line kept: %d bytes", len(got))
	}
	if got := redactLog("a\nb\nc\nd", 2); got != "c | d" {
		t.Fatalf("last lines: %q", got)
	}
}
