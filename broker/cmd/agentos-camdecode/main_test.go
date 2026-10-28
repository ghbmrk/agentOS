package main

// REQ: NET-2

import (
	"bytes"
	"strings"
	"testing"
)

// TestRunExitsWithOneWord: a refusal is an exit code and one word on
// stderr, nothing from the input.
func TestRunExitsWithOneWord(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-video", "8x6"}, strings.NewReader(""), &out, &errOut); code != 2 || errOut.String() != "usage\n" {
		t.Errorf("bad argv: exit %d, stderr %q", code, errOut.String())
	}
	errOut.Reset()
	in := strings.NewReader("\x03\x00\x00\x00\x01MARKER")
	if code := run([]string{"-video", "8x6", "-thermal", "4x3"}, in, &out, &errOut); code != 10 || errOut.String() != "stream\n" || out.Len() != 0 {
		t.Errorf("bad frame: exit %d, stderr %q, out %d bytes", code, errOut.String(), out.Len())
	}
	errOut.Reset()
	if code := run([]string{"-video", "8x6", "-thermal", "4x3"}, strings.NewReader(""), &out, &errOut); code != 0 || errOut.Len() != 0 {
		t.Errorf("empty input: exit %d, stderr %q", code, errOut.String())
	}
}
