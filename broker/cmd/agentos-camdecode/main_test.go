package main

// REQ: NET-2

import (
	"bytes"
	"os"
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

// TestImageBuildsDecoderAlone: image/camdecode.sh, the image's one tagged
// build (TestImageBuildShipsTheUntaggedBuild keeps image/build.sh
// untagged), builds this program alone with exactly the libavcodec tags,
// never agentos_e2e, and sets no GOFLAGS; image/build.sh runs it.
func TestImageBuildsDecoderAlone(t *testing.T) {
	b, err := os.ReadFile("../../../image/camdecode.sh")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, bad := range []string{"GOFLAGS", "agentos_e2e"} {
		if strings.Contains(src, bad) {
			t.Fatalf("image/camdecode.sh mentions %s", bad)
		}
	}
	const line = "go build -tags libavcodec,netgo,osusergo -trimpath"
	if strings.Count(src, "-tags") != 1 || strings.Count(src, "go build") != 1 || !strings.Contains(src, line) ||
		!strings.Contains(src, "-o \"$ROOT/agentos-camdecode\" ./cmd/agentos-camdecode)") {
		t.Fatal("image/camdecode.sh no longer builds agentos-camdecode alone with the line this test pins")
	}
	bs, err := os.ReadFile("../../../image/build.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(bs), `sh "$HERE/camdecode.sh" `) {
		t.Fatal("image/build.sh no longer builds the decoder with image/camdecode.sh")
	}
}
