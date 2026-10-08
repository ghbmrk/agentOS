package gvisor

// REQ: RES-4, CAP-8
//
// SR2-3m: a Go runtime panic in runsc after the guest started writes its
// trace to stderr with no --log line. When runsc exits 2 and stderr holds
// a goroutine header after a "panic: " or "fatal error: " line, Exec
// treats it as runsc's failure: an error, no output, and the trace only
// in the broker's exec log.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/vm"
)

func TestRunscPanicAfterStartAnswersNoOutput(t *testing.T) {
	r := fakeRunsc(t)
	for _, mode := range []string{"latepanic", "fullpanic"} {
		res, err := r.Exec(context.Background(), "wk-1", vm.Command{Argv: []string{mode}, MaxOutput: 4096})
		if err == nil {
			t.Fatalf("%s: runsc's panic read as a result: %+v", mode, res)
		}
		if strings.Contains(err.Error(), "canary") {
			t.Fatalf("%s: error carries runsc's text: %v", mode, err)
		}
		if len(res.Stdout) > 0 || len(res.Stderr) > 0 || res.ExitCode != 0 {
			t.Fatalf("%s: runsc's panic answered output: %+v", mode, res)
		}
	}
	b, err := os.ReadFile(filepath.Join(r.StateDir, "exec.log"))
	if err != nil {
		t.Fatal(err)
	}
	// The trace is logged even when the guest's stderr filled the cap.
	for _, want := range []string{"panic: open " + runscCanary, "fatal error: " + runscCanary} {
		if !strings.Contains(string(b), want) {
			t.Errorf("exec log lacks %q:\n%s", want, b)
		}
	}
}

func TestGuestExitTwoWithoutPanicIsAResult(t *testing.T) {
	r := fakeRunsc(t)
	res, err := r.Exec(context.Background(), "wk-1", vm.Command{Argv: []string{"exit2"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 2 || string(res.Stdout) != "guest out\n" {
		t.Fatalf("guest's own exit 2: %+v", res)
	}
}

func TestPanicTrailer(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"panic: x\n\ngoroutine 1 [running]:\n", true},
		{"abcpanic: x\n\ngoroutine 12 gp=0xc000002380 m=0 mp=0x1f2e3c0 [running]:\n", true},
		{"fatal error: x\ngoroutine 3 gp=0xc0 m=nil [select]:\n", true},
		{"goroutine 1 [running]:\npanic: x\n", false},
		{"panic: x\ngoroutine one [running]:\n", false},
		{"panic: x\n", false},
		{"guest err\n", false},
	} {
		// Every split into two writes, so a marker across writes is found.
		for i := 0; i <= len(c.in); i++ {
			var w panicWatch
			w.Write([]byte(c.in[:i]))
			w.Write([]byte(c.in[i:]))
			if got := w.found(); got != c.want {
				t.Fatalf("%q split at %d: found %v, want %v", c.in, i, got, c.want)
			}
		}
	}
	// A long trace: the header far past the marker, in many writes.
	var w panicWatch
	w.Write([]byte("panic: x\n"))
	for i := 0; i < 1000; i++ {
		w.Write([]byte("runtime.gopark(...)\n\t/usr/lib/go/src/runtime/proc.go:424 +0xce\n"))
	}
	w.Write([]byte("goroutine 7 [chan receive]:\n"))
	if !w.found() || !strings.HasPrefix(string(w.trailer()), "panic: x\n") || len(w.trailer()) > runscMsgMax {
		t.Fatalf("long trace: found %v, trailer %d bytes", w.found(), len(w.trailer()))
	}
}
