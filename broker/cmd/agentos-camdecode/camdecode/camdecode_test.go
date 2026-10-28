package camdecode

// REQ: NET-2

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// TestParseArgs: the shapes come only from the argv the clerk builds
// from the node's bundle, in one exact form; Args is its inverse.
func TestParseArgs(t *testing.T) {
	c := Config{Video: fuzzVideo, Thermal: fuzzThermal}
	got, err := ParseArgs(Args(c))
	if err != nil || got != c {
		t.Fatalf("ParseArgs(Args) = %+v, %v", got, err)
	}
	if got, err := ParseArgs([]string{"-video", "8x6", "-thermal", "0x0"}); err != nil || got.Thermal != (camwire.Shape{}) {
		t.Errorf("no thermal core: %+v, %v", got, err)
	}
	for _, bad := range [][]string{
		nil, {"-video", "8x6"}, {"-thermal", "4x3", "-video", "8x6"},
		{"-video", "0x6", "-thermal", "4x3"}, {"-video", "4097x6", "-thermal", "4x3"},
		{"-video", "08x6", "-thermal", "4x3"}, {"-video", "+8x6", "-thermal", "4x3"},
		{"-video", "8x6", "-thermal", "4x0"}, {"-video", "8x6", "-thermal", "1024x1024"},
		{"-video", "8x6", "-thermal", "4x3", "x"}, {"-video", "8*6", "-thermal", "4x3"},
	} {
		if _, err := ParseArgs(bad); !errors.Is(err, ErrUsage) {
			t.Errorf("ParseArgs(%q) = %v", bad, err)
		}
	}
}

// TestRunThermal: each thermal frame comes out as one output frame of the
// declared shape, its counter and samples kept; a clean end is no error.
func TestRunThermal(t *testing.T) {
	in := append(thermalFrame(4, 3, 7), thermalFrame(4, 3, 8)...)
	var out bytes.Buffer
	if err := Run(bytes.NewReader(in), &out, Config{Video: fuzzVideo, Thermal: fuzzThermal}); err != nil {
		t.Fatal(err)
	}
	size := HeaderLen + Len(KindThermal, fuzzThermal)
	want := append(AppendHeader(nil, KindThermal, fuzzThermal, 7), make([]byte, size-HeaderLen)...)
	want = append(want, AppendHeader(nil, KindThermal, fuzzThermal, 8)...)
	want = append(want, make([]byte, size-HeaderLen)...)
	if !bytes.Equal(out.Bytes(), want) {
		t.Errorf("out %x", out.Bytes())
	}
}

// TestRunRefuses: a thermal frame of another shape, a truncated frame or
// a video slice with no parameter sets (in either build, HasH264 or not)
// ends the run with its error and exit code.
func TestRunRefuses(t *testing.T) {
	good := thermalFrame(4, 3, 1)
	for _, c := range []struct {
		in   []byte
		want error
		code int
	}{
		{thermalFrame(3, 4, 1), ErrStream, 10},
		{good[:len(good)-1], ErrStream, 10},
		{[]byte{byte(camwire.TypeVideo), 0, 0, 0, 5, 0, 0, 0, 1, 0x65}, ErrVideo, 11},
	} {
		err := Run(bytes.NewReader(c.in), &bytes.Buffer{}, Config{Video: fuzzVideo, Thermal: fuzzThermal})
		if err != c.want || ExitCode(err) != c.code {
			t.Errorf("Run = %v (exit %d), want %v (exit %d)", err, ExitCode(err), c.want, c.code)
		}
	}
	if ExitCode(nil) != 0 || ExitCode(ErrUsage) != 2 || ExitCode(ErrWrite) != 12 {
		t.Error("exit codes")
	}
}
