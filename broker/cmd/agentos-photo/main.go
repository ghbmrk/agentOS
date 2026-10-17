// Command agentos-photo re-encodes one owner photo (CH-23). It reads the
// file on stdin and writes a frame on stdout (package photo/decoder);
// a refused file exits non-zero with one word on stderr: type, size,
// pixels or decode. It touches nothing but stdin, stdout and stderr: the
// broker runs it only as a one-shot runsc container with no network and
// a read-only root holding this binary alone (vm/gvisor RunOnce, ARC-5).
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/ghbmrk/agentos/broker/photo/decoder"
)

// softMemory is the Go heap's soft limit, below the container's cap
// (photo.MemBytes), so the collector works harder before the cap kills
// the process.
const softMemory = 448 << 20

func main() {
	debug.SetMemoryLimit(softMemory)
	os.Exit(run(os.Stdin, os.Stdout, os.Stderr))
}

func run(in io.Reader, out, errOut io.Writer) int {
	w := bufio.NewWriterSize(out, 1<<20)
	err := decoder.Run(bufio.NewReader(in), w)
	if err == nil {
		err = w.Flush()
	}
	if err == nil {
		return 0
	}
	var r decoder.Refusal
	if errors.As(err, &r) {
		fmt.Fprintln(errOut, r)
		return r.ExitCode()
	}
	fmt.Fprintln(errOut, "decode")
	return decoder.RefuseDecode.ExitCode()
}
