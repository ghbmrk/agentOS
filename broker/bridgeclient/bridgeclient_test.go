package bridgeclient

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// REQ: CH-1

// L3 on #170 (A16): an answer longer than MaxAnswer is refused, not read
// without bound.
func TestAnAnswerIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.Read(make([]byte, 4096))
				c.Write([]byte(`{"ok":true,"result":"` + strings.Repeat("a", 2*MaxAnswer) + `"}` + "\n"))
			}()
		}
	}()
	var out string
	if err := (Client{Path: path}).Call(context.Background(), "state", struct{}{}, &out); err == nil {
		t.Fatalf("an answer of %d bytes was read", len(out))
	}
}
