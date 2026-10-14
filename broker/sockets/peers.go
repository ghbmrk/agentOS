package sockets

import (
	"errors"
	"net"
	"os"
)

// ListenPeers opens a unix socket at path that admits only the peer uids
// given; every other connection is closed unread. A stale socket file is
// replaced. It serves listeners outside Server that speak HTTP (the key
// holders and the CH-4 checker, SIM-split) under the same peer rule.
func ListenPeers(path string, uids ...int) (net.Listener, error) {
	if len(uids) == 0 {
		return nil, errors.New("sockets: a socket needs at least one peer uid")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(true)
	// The uid check, not the mode, admits the peer; the run directory
	// keeps the path unlistable.
	if err := os.Chmod(path, 0o666); err != nil {
		ln.Close()
		return nil, err
	}
	allow := map[int]bool{}
	for _, u := range uids {
		allow[u] = true
	}
	return peerListener{ln, allow}, nil
}

type peerListener struct {
	net.Listener
	allow map[int]bool
}

func (l peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if uid, ok := PeerUID(c); ok && l.allow[uid] {
			return c, nil
		}
		c.Close()
	}
}
