package gvisor

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// REQ: RES-4
//
// Security review 2, finding 3 (SR2-3): a guest printing without end
// fills no more than its console allowance: the broker reads the console
// and keeps the newest output, the current log and one old one, within
// vm.ConsoleMaxBytes.

func TestConsoleKeepsTheNewestOutputWithinItsCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "console.log")
	const limit = 64 << 10 // per file
	must(t, os.WriteFile(path, bytes.Repeat([]byte("o"), limit-10), 0o600))
	r, w := io.Pipe()
	done := make(chan struct{})
	go func() { keepConsole(r, path, limit); close(done) }()
	line := bytes.Repeat([]byte("x"), 1000)
	for i := 0; i < 500; i++ { // ~8 limits' worth
		if _, err := w.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	w.Write([]byte("the end\n"))
	w.Close()
	<-done
	cur, err := os.ReadFile(path)
	must(t, err)
	old, err := os.ReadFile(path + ".1")
	must(t, err)
	if len(cur) > limit || len(old) > limit {
		t.Fatalf("logs %d and %d bytes, cap %d each", len(cur), len(old), limit)
	}
	if !bytes.HasSuffix(cur, []byte("the end\n")) {
		t.Fatal("newest output not kept")
	}
	if len(old) != limit {
		t.Fatalf("rotated log is %d bytes, want it filled to %d", len(old), limit)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
