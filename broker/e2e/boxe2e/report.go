package main

import (
	"fmt"
	"io"
	"strings"
)

// report writes one console line per step, in the form ci_boot.sh reads:
// PASS, FAIL, XFAIL(#issue) for a failure whose error carries the text the
// expected-failure list gives for that step (any other error from a listed
// step is FAIL), XPASS for a listed step that passed (the list is stale), and BLOCKED for
// the steps after the first failure, which do not run.
type report struct {
	w       io.Writer
	xfail   map[string]expectedFailure
	blocker string
	n       map[string]int
}

// expectedFailure is a known failure: its work-item issue and the text its
// error must carry, so a different failure of the same step is not hidden.
type expectedFailure struct {
	issue int
	want  string
}

func newReport(w io.Writer, xfail map[string]expectedFailure) *report {
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
	ef, listed := r.xfail[name]
	expected := listed && err != nil && strings.Contains(err.Error(), ef.want)
	switch {
	case err == nil && listed:
		r.line("xpass", fmt.Sprintf("XPASS %s expected to fail (#%d) but passed", name, ef.issue))
	case err == nil:
		r.line("pass", "PASS "+name)
	case expected:
		r.blocker = name
		r.line("xfail", fmt.Sprintf("XFAIL(#%d) %s %s", ef.issue, name, oneLine(err.Error())))
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

// logLineMax bounds each service log line a diagnostic quotes.
const logLineMax = 160

// redactLog keeps a log's last n lines, each cut to logLineMax bytes with
// every non-empty secret replaced, joined on one line for the console.
func redactLog(log string, n int, secrets ...string) string {
	for _, s := range secrets {
		if s != "" {
			log = strings.ReplaceAll(log, s, "[redacted]")
		}
	}
	lines := strings.Split(strings.TrimSpace(log), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for i, l := range lines {
		if l = oneLine(l); len(l) > logLineMax {
			l = l[:logLineMax]
		}
		lines[i] = l
	}
	return strings.Join(lines, " | ")
}
