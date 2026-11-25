//go:build linux

package kernelsock

// REQ: LOG-4

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// KEY-9-named-utf8 (#6322): a label that is not valid UTF-8 is refused as
// kernel.ErrLabel before any call is made. JSON would carry its bad bytes
// as U+FFFD, and the kernel could then match a label the owner did not
// type. The socket listens, so a client that sent the label would connect.
func TestNamedRefusesInvalidUTF8AndSendsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	dialed := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
			dialed <- struct{}{}
		}
	}()
	o := Owner{Socket: path, UID: os.Getuid(), As: os.Getuid()}
	for _, label := range []string{"Alice\xffSmith", "\xc3", "Al\xedce"} {
		found, unread, err := o.Named(context.Background(), label)
		if !errors.Is(err, kernel.ErrLabel) || found != nil || unread != nil {
			t.Fatalf("Named(%q) = %v %v %v, want kernel.ErrLabel and nothing", label, found, unread, err)
		}
	}
	select {
	case <-dialed:
		t.Fatal("an invalid label reached the socket")
	case <-time.After(100 * time.Millisecond):
	}
}
