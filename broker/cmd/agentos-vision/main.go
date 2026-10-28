// Command agentos-vision is the camera vision service (VIS-core). It
// answers the protocol in broker/vision on the listener agentosd passes it
// as fd 3: detections from a closed vocabulary for each frame, and sound
// labels for each clip. It creates and names no socket, and agentosd links
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
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: agentos-vision [-concurrent N] [-call-timeout D] (listener on fd 3)")
		os.Exit(2)
	}
	f := os.NewFile(3, "listener")
	if f == nil {
		fmt.Fprintln(os.Stderr, "vision: no listener on fd 3")
		os.Exit(1)
	}
	ln, err := net.FileListener(f)
	f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "vision: fd 3 is not a listener")
		os.Exit(1)
	}
	s := newService(cfg, newRuntime(), os.Stderr)
	s.ready() // load at start, so hello answers at once
	err = s.Serve(ln)
	fmt.Fprintf(os.Stderr, "vision: listener failed: %v\n", err)
	os.Exit(1)
}
