package main

import (
	"io"
	"os"
	"testing"
)

// REQ: HW-8

func capture(t *testing.T, args ...string) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	code := run(args)
	os.Stdout = old
	w.Close()
	b, _ := io.ReadAll(r)
	return string(b), code
}

// The udev helper always answers, and anything it cannot classify is
// "unknown". As any uid but root it reads nothing (security H6).
func TestClassifyAlwaysAnswers(t *testing.T) {
	defer func(f func() int) { geteuid = f }(geteuid)
	for _, uid := range []int{0, 1000} {
		geteuid = func() int { return uid }
		for _, name := range []string{"../../etc", "no-such-disk", "loop0"} {
			out, code := capture(t, "classify", name)
			if code != 0 || out != "AGENTOS_DISK=unknown\n" {
				t.Errorf("uid %d, %s: %q, %d", uid, name, out, code)
			}
		}
	}
	geteuid = func() int { return 1000 }
	if out, code := capture(t, "list"); code != 1 || out != "" {
		t.Errorf("non-root list: %q, %d", out, code)
	}
	if _, code := capture(t, "format", "sda"); code != 2 {
		t.Errorf("unknown command exit %d", code)
	}
}
