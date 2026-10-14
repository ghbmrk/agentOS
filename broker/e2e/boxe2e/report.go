package main

import (
	"fmt"
	"io"
	"strings"
)

// report writes one console line per step, in the form ci_boot.sh reads:
// PASS, FAIL, XFAIL(#issue) for a failure the expected-failure list names,
// XPASS for a listed step that passed (the list is stale), and BLOCKED for
// the steps after the first failure, which do not run.
type report struct {
	w       io.Writer
	xfail   map[string]int
	blocker string
	n       map[string]int
}

func newReport(w io.Writer, xfail map[string]int) *report {
	return &report{w: w, xfail: xfail, n: map[string]int{}}
}

func (r *report) line(kind, rest string) {
	r.n[kind]++
	fmt.Fprintf(r.w, "agentos-e2e: %s\n", rest)
}

func (r *report) step(name string, run func() error) {
	if r.blocker != "" {
		r.line("blocked", "BLOCKED "+name+" after "+r.blocker)
		return
	}
	err := run()
	issue, expected := r.xfail[name]
	switch {
	case err == nil && expected:
		r.line("xpass", fmt.Sprintf("XPASS %s expected to fail (#%d) but passed", name, issue))
	case err == nil:
		r.line("pass", "PASS "+name)
	case expected:
		r.blocker = name
		r.line("xfail", fmt.Sprintf("XFAIL(#%d) %s %s", issue, name, oneLine(err.Error())))
	default:
		r.blocker = name
		r.line("fail", "FAIL "+name+" "+oneLine(err.Error()))
	}
}

func (r *report) done() {
	fmt.Fprintf(r.w, "agentos-e2e: DONE pass=%d fail=%d xfail=%d xpass=%d blocked=%d\n",
		r.n["pass"], r.n["fail"], r.n["xfail"], r.n["xpass"], r.n["blocked"])
}

// failed reports whether ci_boot.sh should fail: an unexpected failure, or
// an expected failure that no longer happens.
func (r *report) failed() bool { return r.n["fail"] > 0 || r.n["xpass"] > 0 }

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
