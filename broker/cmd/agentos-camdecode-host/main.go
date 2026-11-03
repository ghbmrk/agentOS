// Command agentos-camdecode-host is one camera decoder session's process
// (CAM-decoder-uid, #4134; CLK-1, NET-2, RES-2). agentos-camdecode.socket
// starts it, in a fresh agentos-camdecode@.service under a dynamic user of
// its own, for each connection the camera clerk opens; the connection is
// its standard input:
//
//	agentos-camdecode-host -runsc /usr/lib/agentos/runsc -runsc-root /tmp/runsc \
//	    -decode-root /usr/lib/agentos/images/camdecode
//
// It moves into its leaf of its unit's delegated group and runs the
// session (decodehost.Serve) in a gVisor sandbox started rootless, as its
// own user, beside the leaf. A sandbox escape therefore lands as this
// unit's user, which owns no file of the clerk's, cannot reach its socket
// or its state, and is no other session's.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ghbmrk/agentos/broker/clerk/camera"
	"github.com/ghbmrk/agentos/broker/clerk/camera/decodehost"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:], os.Stderr, os.Stdin, "/proc/self/cgroup"); err != nil {
		log.Fatal(err)
	}
}

type config struct{ runsc, runscRoot, decodeRoot string }

func parse(args []string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("agentos-camdecode-host", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c config
	fs.StringVar(&c.runsc, "runsc", "", "the gVisor runtime the decoder's sandbox runs under")
	fs.StringVar(&c.runscRoot, "runsc-root", "", "runsc's state directory, in this unit's own /tmp")
	fs.StringVar(&c.decodeRoot, "decode-root", "", "the decoder sandbox's read-only root, holding /agentos-camdecode")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	switch {
	case fs.NArg() != 0:
		return c, fmt.Errorf("unexpected arguments: %q", fs.Args())
	case !filepath.IsAbs(c.runsc) || !filepath.IsAbs(c.runscRoot) || !filepath.IsAbs(c.decodeRoot):
		return c, errors.New("-runsc, -runsc-root and -decode-root are required, as absolute paths")
	}
	return c, nil
}

// run serves the one session on connFile, the unit's connection. procSelf
// names the file the process's cgroup is read from.
func run(args []string, stderr io.Writer, connFile *os.File, procSelf string) error {
	c, err := parse(args, stderr)
	if err != nil {
		return err
	}
	cg, err := decodehost.OwnCgroup(procSelf)
	if err != nil {
		return err
	}
	if err := decodehost.Leave(cg); err != nil {
		return err
	}
	conn, err := net.FileConn(connFile)
	if err != nil {
		return fmt.Errorf("the session's connection: %w", err)
	}
	defer conn.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return decodehost.Serve(ctx, conn, decodehost.Config{Start: decodehost.GVisor(runtime(c)), Root: c.decodeRoot,
		Cgroup: cg, MemBytes: camera.DefaultDecodeMem})
}

// runtime is the session's runsc: rootless, since the unit's user is not
// root, in a user namespace runsc makes for itself.
func runtime(c config) *gvisor.Runtime {
	return &gvisor.Runtime{Bin: c.runsc, StateDir: c.runscRoot, Platform: "systrap", Rootless: true}
}
