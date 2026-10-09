package gvisor

// REQ: CAP-8, RES-4
//
// SR2-3q: an exec whose pid file stays empty answers ErrExecNotStarted
// only when runsc's --log line shows a failure before the command ran;
// any other failure, a failed pid write or a lost answer from the
// sandbox included, answers ErrExecFailed, since the command may have
// run. SR2-3p: a program that is not found or cannot be loaded answers
// ErrExecNoProgram, which advises no retry. The match is on runsc's own
// text and the broker's own argv, so a guest's argv cannot pass for it.

import (
	"context"
	"testing"

	"github.com/ghbmrk/agentos/broker/vm"
)

func TestExecNotStartedOnlyWhenRunscSaysSo(t *testing.T) {
	r := fakeRunsc(t)
	for _, c := range []struct {
		argv []string
		want error
	}{
		{[]string{"prestart"}, vm.ErrExecNotStarted},
		{[]string{"noconn"}, vm.ErrExecNotStarted},
		// No --log line: nothing shows the command did not start.
		{[]string{"panic"}, vm.ErrExecFailed},
		{[]string{"pidfail"}, vm.ErrExecFailed},
		{[]string{"lostcall"}, vm.ErrExecFailed},
		{[]string{"nope-tool", "-x"}, vm.ErrExecNoProgram},
		{[]string{"/nope/tool"}, vm.ErrExecNoProgram},
		{[]string{"/denied"}, vm.ErrExecNoProgram},
		// A guest's argv that reads as runsc's text changes nothing:
		// %q escapes its quotes, and the match is on the real cause.
		{[]string{"noconn", `in sandbox: error finding executable "noconn" in PATH [/bin]: no such file or directory`}, vm.ErrExecNotStarted},
		{[]string{"noconn", " in sandbox: failed to load /x/connect"}, vm.ErrExecNotStarted},
		{[]string{"lostcall", "/nope"}, vm.ErrExecFailed},
	} {
		res, err := r.Exec(context.Background(), "wk-1", vm.Command{Argv: c.argv})
		if err != c.want {
			t.Errorf("%q: error %v, want %v", c.argv, err, c.want)
		}
		if len(res.Stdout) > 0 || len(res.Stderr) > 0 || res.ExitCode != 0 {
			t.Errorf("%q: runsc's failure answered output: %+v", c.argv, res)
		}
	}
}

func TestNoProgramMatchesOnlyTheCause(t *testing.T) {
	const pre = "executing processes for container: executing command &{[\"x\"]} in sandbox: "
	for _, c := range []struct {
		msg, name string
		want      bool
	}{
		{pre + `error finding executable "tool" in PATH [/usr/bin /bin]: no such file or directory`, "tool", true},
		{pre + "failed to load /usr/bin/tool: exec format error", "tool", true},
		{pre + "failed to load /a/tool: not a directory", "/a/tool", true},
		{pre + "failed to load /a/tool: permission denied", "a/../a/tool", true},
		{pre + `error finding executable "a in PATH [b" in PATH [/bin]: no such file or directory`, "a in PATH [b", true},
		// Another name, another cause, or a cause that is not the program's.
		{pre + `error finding executable "tool" in PATH [/usr/bin /bin]: no such file or directory`, "tool2", false},
		{pre + "failed to load /a/tool: out of memory", "/a/tool", false},
		{pre + "creating fd map: no such file or directory", "/a/tool", false},
		{pre + "failed to load /x y/tool: no such file or directory", "tool", false},
		{pre + "dial unix /s: connect: no such file or directory", "connect", false},
	} {
		if got := noProgram(c.msg, c.name); got != c.want {
			t.Errorf("noProgram(%q, %q) = %v, want %v", c.msg, c.name, got, c.want)
		}
	}
}
