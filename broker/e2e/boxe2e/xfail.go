package main

import "strings"

// xfail names the steps known not to pass yet, each with its work-item
// issue and the error text it must fail with. A listed step that fails any
// other way is FAIL, and one that passes fails the run (XPASS), so the list
// shrinks as the issues close. host left the list when #1221 served the
// "this PC" step; if its hook fails, localui journals the error
// (hostHookLog) and the driver's host step quotes it (hostCause), since the
// page itself cannot tell the causes apart: every hook error reads "Could
// not save" and setup stays at "6. This PC" whatever went wrong.
var xfail = map[string]expectedFailure{
	"guest-task":    {1701, notDriven},
	"phone-control": {1714, notDriven},
}

// notDriven starts the error of a step the driver does not run yet.
const notDriven = "not driven yet:"

// hostHookLog is what localui's setup page journals before the hook error
// when saving "this PC" fails (broker/localui/setup.go).
const hostHookLog = "setup host hook: "

// hostCause returns the last localui journal line that reports a failed
// TrustHost hook, from its text onward, or "" when there is none.
func hostCause(journal string) string {
	cause := ""
	for _, l := range strings.Split(journal, "\n") {
		if i := strings.Index(l, hostHookLog); i >= 0 {
			cause = strings.TrimSpace(l[i:])
		}
	}
	return cause
}
