// Command agentos-camdecode decodes one camera's stream (CAM-clerk part
// b, #3514; SPEC NET-2 Cameras). It reads camwire frames on stdin and
// writes raw frames on stdout (package camdecode); a refusal exits
// non-zero with one word on stderr. It touches nothing but stdin, stdout
// and stderr: the camera clerk runs it only in a long-running runsc
// container per streaming camera, with no network and a read-only root
// holding this binary alone (vm/gvisor StartStream).
package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/ghbmrk/agentos/broker/cmd/agentos-camdecode/camdecode"
)

// softMemory is the Go heap's soft limit, below the container's cap
// (camera.DefaultDecodeMem), so the collector works harder before the
// cap kills the process.
const softMemory = 448 << 20

func main() {
	debug.SetMemoryLimit(softMemory)
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, in io.Reader, out, errOut io.Writer) int {
	c, err := camdecode.ParseArgs(args)
	if err == nil {
		err = camdecode.Run(in, out, c)
	}
	if err != nil {
		fmt.Fprintln(errOut, err)
	}
	return camdecode.ExitCode(err)
}
