// Command agentos-infer is the local inference service (INFER-SVC). It
// answers the protocol in broker/infer on the listener agentosd passes it as
// fd 3, embedding text with the model file named by -model, which must hash
// to -model-sha256. It creates and names no socket, and agentosd links none
// of it (ARC-2): agentosd starts it through infer/supervise, as its own
// user, in the inference cgroup leaf, with no network (INF-1, INF-6).
//
// Its log goes to agentosd's and carries causes, counts, sizes and
// durations only, never request text or vectors (INF-8).
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	var cfg Config
	var runtime string
	flag.StringVar(&cfg.Model, "model", "", "model file")
	flag.StringVar(&cfg.Pin, "model-sha256", "", "the model file's SHA-256, lower-case hex")
	flag.StringVar(&cfg.Name, "model-name", "", "the model's name in hello replies (default: the file's base name)")
	flag.StringVar(&runtime, "runtime", "", "the model runtime's executable")
	flag.IntVar(&cfg.Concurrent, "concurrent", 2, "runtime calls in flight")
	flag.DurationVar(&cfg.CallTimeout, "call-timeout", 30*time.Second, "bound on one runtime call")
	flag.Parse()
	if cfg.Model == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: agentos-infer -model FILE -model-sha256 HEX -runtime PATH (listener on fd 3)")
		os.Exit(2)
	}
	if cfg.Name == "" {
		cfg.Name = strings.TrimSuffix(filepath.Base(cfg.Model), filepath.Ext(cfg.Model))
	}
	f := os.NewFile(3, "listener")
	if f == nil {
		fmt.Fprintln(os.Stderr, "infer: no listener on fd 3")
		os.Exit(1)
	}
	ln, err := net.FileListener(f)
	f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "infer: fd 3 is not a listener")
		os.Exit(1)
	}
	s := newService(cfg, newRuntime(runtime), os.Stderr)
	s.ready() // load at start, so hello answers at once
	err = s.Serve(ln)
	fmt.Fprintf(os.Stderr, "infer: listener failed: %v\n", err)
	os.Exit(1)
}
