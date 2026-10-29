// Command agentos-vision is the camera vision service (VIS-core). It
// answers the protocol in broker/vision on the listener agentosd passes it
// as fd 3: detections from a closed vocabulary for each frame, and sound
// labels for each clip. On fd 4, its control socket, it answers only the
// enrolment and lend calls of the side that holds the template slots
// (vision/faces): it holds the enrolled templates in memory only, compares
// each face it sees with them, and sends a name, never an encoding. It creates and names no socket, and agentosd links
// none of it (ARC-2): agentosd starts it through vision/supervise, as its
// own user, in the inference cgroup leaf, with no network, and drops its
// output, so nothing it writes reaches agentosd's log (DEV-7).
//
// It runs on CPU (RES-3). Built with -tags vision_onnx it detects with the
// pinned ONNX Runtime and YOLOX-Tiny from -models, and finds warm bodies in
// thermal frames (VIS-A27 to A29); the default build links no runtime and
// answers every call Unavailable (VIS-A1).
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	var cfg Config
	flag.IntVar(&cfg.Concurrent, "concurrent", 2, "requests held or in flight")
	flag.DurationVar(&cfg.CallTimeout, "call-timeout", 10*time.Second, "bound on one runtime call")
	flag.Float64Var(&cfg.Match, "match", DefaultMatch, "least cosine similarity that names an enrolled face")
	models := flag.String("models", DefaultModels, "directory of the pinned runtime library and models")
	threads := flag.Int("threads", 2, "runtime threads per call")
	flag.Parse()
	if flag.NArg() != 0 || *threads < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentos-vision [-concurrent N] [-call-timeout D] [-match F] [-models DIR] [-threads N] (listeners on fd 3 and 4)")
		os.Exit(2)
	}
	ln, ctl := listener(3), listener(4)
	s := newService(cfg, newRuntime(*models, *threads), os.Stderr)
	s.ready() // load at start, so hello answers at once
	errc := make(chan error, 2)
	go func() { errc <- s.Serve(ln) }()
	go func() { errc <- s.ServeControl(ctl) }()
	fmt.Fprintf(os.Stderr, "vision: listener failed: %v\n", <-errc)
	os.Exit(1)
}

// DefaultModels is where the image puts the runtime library and models.
const DefaultModels = "/usr/lib/agentos/vision"

// listener is the listener on fd, or the end of the process.
func listener(fd uintptr) net.Listener {
	f := os.NewFile(fd, "listener")
	if f == nil {
		fmt.Fprintf(os.Stderr, "vision: no listener on fd %d\n", fd)
		os.Exit(1)
	}
	ln, err := net.FileListener(f)
	f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "vision: fd %d is not a listener\n", fd)
		os.Exit(1)
	}
	return ln
}
