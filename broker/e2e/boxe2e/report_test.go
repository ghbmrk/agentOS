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
// expected text; any other error from it is FAIL and fails the run. This
// runs the production table, so a weaker text (empty, "at") is caught.
func TestReportExpectedFailureMatchesItsText(t *testing.T) {
	hostErr := `at "6. This PC": ` + hostHookLog + "localui: not served by agentosd yet"
	cases := []struct {
		step, msg string
		xfail     bool
	}{
		{"guest-task", notDriven + " needs a stub", true},
		{"phone-control", notDriven + " needs a text", true},
		// host is no longer listed (#1221 serves it): the old not-served
		// error, and every other way to be stuck at "6. This PC", is FAIL.
		{"host", `after 1m0s: ` + hostErr, false},
		{"host", `after 1m0s: at "6. This PC"`, false},
		{"host", `after 1m0s: at "6. This PC" saying Could not save. Try again.`, false},
		{"host", `after 1m0s: at "6. This PC" saying Finish the earlier steps first.`, false},
		{"host", `after 1m0s: at "6. This PC": ` + hostHookLog + "localui: agentosd: 500", false},
		{"host", "POST /setup/host 500 <nil>", false},
		{"host", `after 1m0s: at "7. Done"`, false},
		{"host", "", false},
		{"guest-task", "connection refused", false},
		{"phone-control", "connection refused", false},
	}
	for _, c := range cases {
		var out bytes.Buffer
		r := newReport(&out, xfail)
		r.step(c.step, func() error { return errors.New(c.msg) })
		r.step("next", func() error { return nil })
		r.done()
		got := out.String()
		if c.xfail && (!strings.Contains(got, "XFAIL(") || strings.Contains(got, "FAIL "+c.step) || r.failed()) {
			t.Fatalf("%s %q not XFAIL: %s", c.step, c.msg, got)
		}
		if !c.xfail && (strings.Contains(got, "XFAIL") || !strings.Contains(got, "agentos-e2e: FAIL "+c.step+" ") ||
			!strings.Contains(got, "fail=1 xfail=0") || !r.failed()) {
			t.Fatalf("%s %q was hidden: %s", c.step, c.msg, got)
		}
	}
}

// Every production want is a specific text; an empty or one-word want
// would match any error.
func TestXfailWantsAreSpecific(t *testing.T) {
	for name, ef := range xfail {
		if len(ef.want) < 10 || ef.issue == 0 {
			t.Errorf("%s: want %q issue %d is too loose", name, ef.want, ef.issue)
		}
	}
	if xfail["guest-task"].want != notDriven || xfail["phone-control"].want != notDriven || notDriven != "not driven yet:" {
		t.Fatal("not-driven wants changed")
	}
}

// hostCause quotes localui's journaled hook error and nothing else.
func TestHostCause(t *testing.T) {
	j := "boot\n2026/10/14 23:00:01 localui: " + hostHookLog + "localui: not served by agentosd yet\nlater line\n"
	if got := hostCause(j); got != hostHookLog+"localui: not served by agentosd yet" {
		t.Fatalf("cause %q", got)
	}
	if got := hostCause("a\nb\n"); got != "" {
		t.Fatalf("cause %q from a journal without one", got)
	}
	if got := hostCause(j + "x " + hostHookLog + "second\n"); got != hostHookLog+"second" {
		t.Fatalf("last cause %q", got)
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
