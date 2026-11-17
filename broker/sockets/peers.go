package sockets

import (
	"net"

	"github.com/ghbmrk/agentos/broker/sockets/peers"
)

// ListenPeers opens a unix socket at path that admits only the peer uids
// given (peers.ListenUnix), for listeners outside Server that speak HTTP under
// the same peer rule.
func ListenPeers(path string, uids ...int) (net.Listener, error) {
	return peers.ListenUnix(path, uids...)
}

// PeerUID returns the uid of the process on the other end of a Unix
// connection (SO_PEERCRED, peers.UID).
func PeerUID(c net.Conn) (int, bool) { return peers.UID(c) }
