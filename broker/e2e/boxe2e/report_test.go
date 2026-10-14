package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// REQ: ONB-3

// The console lines ci_boot.sh greps: a step that passes, an expected
// failure with its issue, a step that unexpectedly passes, and the steps
// after a failure, which are blocked rather than run.
func TestReportLinesAndBlocking(t *testing.T) {
	var out bytes.Buffer
	r := newReport(&out, map[string]int{"b": 12, "d": 34})
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
	r = newReport(&out, map[string]int{"a": 1})
	r.step("a", func() error { return errors.New("no") })
	r.done()
	if r.failed() {
		t.Fatalf("an expected failure failed the run: %s", out.String())
	}
}
