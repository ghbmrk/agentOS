// Command imapconn is the mail clerk's IMAP connection process (#2937 gap
// 2): it serves one session on descriptor 3, the control connection the
// clerk's socket hands it, and exits when the clerk closes it. Its launch,
// one fresh process per session under its own uid with no network and no
// file of the clerk's, is the clerk main's (#2995).
package main

import (
	"fmt"
	"net"
	"os"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapconn"
)

func main() {
	// Before any session's bytes arrive: a concurrent session's process,
	// under the same user, cannot read or write this one's memory.
	if err := imapconn.Undumpable(); err != nil {
		fmt.Fprintln(os.Stderr, "imapconn: cannot mark the process undumpable")
		os.Exit(2)
	}
	f := os.NewFile(3, "control")
	c, err := net.FileConn(f)
	f.Close()
	u, ok := c.(*net.UnixConn)
	if err != nil || !ok {
		fmt.Fprintln(os.Stderr, "imapconn: descriptor 3 is not a Unix socket")
		os.Exit(2)
	}
	if err := imapconn.Serve(u); err != nil {
		fmt.Fprintln(os.Stderr, "imapconn: the session failed")
		os.Exit(1)
	}
}
