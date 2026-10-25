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
// the process; heicSoftMemory is the same below a HEIC run's cap
// (photo.HEICMemBytes).
const (
	softMemory     = 448 << 20
	heicSoftMemory = 832 << 20
)

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<12)
	debug.SetMemoryLimit(softLimit(in))
	os.Exit(run(in, os.Stdout, os.Stderr))
}

// softLimit picks the soft limit from the file's first bytes, the ones
// that hold a HEIC's ftyp box. A HEIC whose ftyp box is longer than
// they are keeps softMemory: the collector then works harder, still
// under the larger cap.
func softLimit(in *bufio.Reader) int64 {
	head, _ := in.Peek(in.Size())
	if decoder.IsHEIC(head) {
		return heicSoftMemory
	}
	return softMemory
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
