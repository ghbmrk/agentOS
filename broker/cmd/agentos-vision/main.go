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
// It runs on CPU (RES-3); this build links no runtime and answers every
// call Unavailable (ASSUMPTIONS VIS-A1).
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
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: agentos-vision [-concurrent N] [-call-timeout D] [-match F] (listeners on fd 3 and 4)")
		os.Exit(2)
	}
	ln, ctl := listener(3), listener(4)
	s := newService(cfg, newRuntime(), os.Stderr)
	s.ready() // load at start, so hello answers at once
	errc := make(chan error, 2)
	go func() { errc <- s.Serve(ln) }()
	go func() { errc <- s.ServeControl(ctl) }()
	fmt.Fprintf(os.Stderr, "vision: listener failed: %v\n", <-errc)
	os.Exit(1)
}

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
