package sockets

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestListenPeersKeepsThePeerRule: ListenPeers and PeerUID are the peer rule
// of sockets/peers (#6039), so callers outside the kernel keep their names.
func TestListenPeersKeepsThePeerRule(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.sock")
	if _, err := ListenPeers(p); err == nil {
		t.Fatal("ListenPeers with no uid opened a socket")
	}
	ln, err := ListenPeers(p, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan int, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- -1
			return
		}
		defer c.Close()
		uid, ok := PeerUID(c)
		if !ok {
			uid = -1
		}
		got <- uid
	}()
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if uid := <-got; uid != os.Getuid() {
		t.Fatalf("the admitted peer's uid = %d, want %d", uid, os.Getuid())
	}
}
