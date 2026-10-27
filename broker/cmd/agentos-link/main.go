// Command agentos-link is the core's end of the edge link (EDGE-link-core
// c2, HW-15, HW-16, HW-17): one TCP port, on the link interface only, where
// the edge box connects over TLS 1.3 (edgelink). It runs in one of two
// modes.
//
// Before the store (the Owner Card confirm has not run), as root:
//
//	agentos-link -iface link0 -port 7443 -capture /run/agentos-link-capture/first-edge \
//	    -store /var/lib/agentos-store/store -uid 984 -gid 984
//
// takes the first valid hello as the first edge's key and writes it, as
// root with mode 0600, where enrollment reads it (agentos-enroll
// -first-edge); later hellos are ignored. A child under -uid reads the
// edge's bytes; the root parent checks the 128 bytes again and writes them.
//
// Served, under the link's own uid, after the kernel runs:
//
//	agentos-link -iface link0 -port 7443 \
//	    -kernel-sock /run/agentos-kernel/link.sock -kernel-uid 980 \
//	    -consumer-sock /run/agentos-link/items.sock -consumer-uid 985
//
// asks the kernel about the edge's key on every connection: the live key's
// frames go to the consumer with their kind's label; any other key sends
// one hello, which is reported to the kernel as a candidate for the owner
// page step. The link key never leaves the kernel: TLS signs through the
// kernel's linksign.
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
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ghbmrk/agentos/broker/sockets"
)

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:], os.Stderr); err != nil {
		log.Fatal(err)
	}
}

type config struct {
	iface string
	port  int

	capture, store string // pre-store mode
	uid, gid       int    // the child's ids, in pre-store mode
	child          bool   // this process is the pre-store child

	kernelSock, consumerSock string // served mode
	kernelUID, consumerUID   int
}

func parse(args []string) (config, error) {
	var c config
	fs := flag.NewFlagSet("agentos-link", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.iface, "iface", "", "the link interface, the only one the port listens on")
	fs.IntVar(&c.port, "port", 0, "the link's TCP port")
	fs.StringVar(&c.capture, "capture", "", "pre-store mode: the first edge's capture file, which enrollment reads")
	fs.StringVar(&c.store, "store", "", "pre-store mode: the sealed store, whose existence ends the capture window")
	fs.IntVar(&c.uid, "uid", 0, "pre-store mode: the uid the hello reader runs under")
	fs.IntVar(&c.gid, "gid", 0, "pre-store mode: the gid the hello reader runs under")
	fs.BoolVar(&c.child, "hello-child", false, "internal: the pre-store hello reader, on descriptor 3")
	fs.StringVar(&c.kernelSock, "kernel-sock", "", "served mode: the kernel's link socket")
	fs.IntVar(&c.kernelUID, "kernel-uid", 0, "served mode: the kernel's uid, its only peer")
	fs.StringVar(&c.consumerSock, "consumer-sock", "", "served mode: the socket the edge's items are served on")
	fs.IntVar(&c.consumerUID, "consumer-uid", 0, "served mode: the consumer's uid, the socket's only peer")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() > 0 {
		return c, fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	if c.child {
		return c, nil
	}
	if !ifaceName(c.iface) || c.port <= 0 || c.port > 65535 {
		return c, errors.New("-iface and -port name the link interface and its port")
	}
	pre, served := c.capture != "", c.kernelSock != ""
	switch {
	case pre == served:
		return c, errors.New("give -capture (before the store) or -kernel-sock (served), not both or neither")
	case pre && (!abs(c.capture) || !abs(c.store) || c.uid <= 0 || c.gid <= 0):
		return c, errors.New("before the store, -capture and -store are absolute and -uid and -gid name the hello reader")
	case served && (!abs(c.kernelSock) || !abs(c.consumerSock) || c.kernelUID <= 0 || c.consumerUID <= 0):
		return c, errors.New("served, -kernel-sock and -consumer-sock are absolute and -kernel-uid and -consumer-uid name their peers")
	}
	return c, nil
}

func abs(p string) bool { return strings.HasPrefix(p, "/") }

// ifaceName is a Linux interface name: 1 to 15 bytes, no slash, space or
// control byte.
func ifaceName(s string) bool {
	if len(s) == 0 || len(s) > 15 {
		return false
	}
	for _, c := range []byte(s) {
		if c <= ' ' || c == '/' || c == ':' || c >= 0x7f {
			return false
		}
	}
	return true
}

func run(args []string, stderr io.Writer) error {
	c, err := parse(args)
	if err != nil {
		return fmt.Errorf("agentos-link: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	switch {
	case c.child:
		ln, err := net.FileListener(os.NewFile(3, "link"))
		if err != nil {
			return fmt.Errorf("agentos-link: the hello reader's listener: %w", err)
		}
		return helloChild(ln, os.Stdout, stderr)
	case c.capture != "":
		return runCapture(ctx, c, stderr)
	}
	return runServed(ctx, c, stderr)
}

// runCapture is the pre-store parent: it binds the link port as root,
// starts the hello reader under c.uid with the listener, and writes the one
// capture it hands back.
func runCapture(ctx context.Context, c config, stderr io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("agentos-link: before the store I run as root, so enrollment takes the capture")
	}
	if err := writeable(c); err != nil {
		fmt.Fprintf(stderr, "%v; I capture nothing\n", err)
		return nil
	}
	ln, err := listenLink(c.iface, c.port)
	if err != nil {
		return err
	}
	defer ln.Close()
	f, err := ln.(*net.TCPListener).File()
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, self, "-hello-child")
	cmd.Env = []string{}
	cmd.ExtraFiles = []*os.File{f}
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(c.uid), Gid: uint32(c.gid), Groups: []uint32{}},
		Pdeathsig:  syscall.SIGKILL,
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	f.Close()
	ln.Close()
	err = takeCapture(out, c.capture, c.store)
	cmd.Process.Kill()
	cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if errors.Is(err, errStoreExists) || errors.Is(err, errTaken) {
		fmt.Fprintf(stderr, "%v; this hello is ignored\n", err)
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(stderr, "agentos-link: the first edge's key is captured for the Owner Card confirm")
	return nil
}

// writeable is nil while a capture can still be written.
func writeable(c config) error {
	if _, err := os.Lstat(c.store); !errors.Is(err, os.ErrNotExist) {
		return errStoreExists
	}
	if _, err := os.Lstat(c.capture); !errors.Is(err, os.ErrNotExist) {
		return errTaken
	}
	return nil
}

// runServed is the served mode, under the link's own uid.
func runServed(ctx context.Context, c config, stderr io.Writer) error {
	if os.Geteuid() == 0 {
		return errors.New("agentos-link: served, I never run as root")
	}
	s, err := newServer(kernelConn{c.kernelSock, c.kernelUID}, stderr)
	if err != nil {
		return err
	}
	ln, err := listenLink(c.iface, c.port)
	if err != nil {
		return err
	}
	defer ln.Close()
	cl, err := sockets.ListenPeers(c.consumerSock, c.consumerUID)
	if err != nil {
		return err
	}
	defer cl.Close()
	errs := make(chan error, 2)
	go func() { errs <- s.serve(ln) }()
	go func() { errs <- s.serveConsumer(cl) }()
	select {
	case <-ctx.Done():
		return nil
	case err := <-errs:
		return err
	}
}
