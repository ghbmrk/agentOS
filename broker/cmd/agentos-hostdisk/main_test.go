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

// The udev helper always answers, and anything it cannot classify is not
// the drive, so the rule hides it.
func TestClassifyAlwaysAnswers(t *testing.T) {
	for _, name := range []string{"../../etc", "no-such-disk", "loop0"} {
		out, code := capture(t, "classify", name)
		if code != 0 || out != "AGENTOS_DRIVE=0\n" {
			t.Errorf("%s: %q, %d", name, out, code)
		}
	}
	if _, code := capture(t, "format", "sda"); code != 2 {
		t.Errorf("unknown command exit %d", code)
	}
}
