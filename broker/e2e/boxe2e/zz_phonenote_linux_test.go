package main

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
)

// REQ: CH-1. The NOTE a passing phone-control prints is one ci_boot.sh's
// console check takes: the step's name, then lower-case words only, so a
// pass that names its commands still reads as no step (#1883 item 4).
func TestPhoneControlPassNoteReadsAsANote(t *testing.T) {
	boot, err := os.ReadFile("../../../image/ci_boot.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`r ~ /(\^NOTE [^/]*)/ \{ next \}`).FindSubmatch(boot)
	if m == nil {
		t.Fatal("ci_boot.sh has no NOTE check")
	}
	var out bytes.Buffer
	r := newReport(&out, nil)
	r.step("phone-control", func() error { r.note(passNote); return nil })
	line := strings.SplitN(out.String(), "\n", 2)[0]
	if !regexp.MustCompile(string(m[1])).MatchString(strings.TrimPrefix(line, "agentos-e2e: ")) {
		t.Fatalf("%q does not match ci_boot.sh's %s", line, m[1])
	}
}
