package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/ghbmrk/agentos/broker/edgelink"
)

// The consumer socket (decision 7): one local socket, admitting one
// configured uid, that carries the live edge's items out as JSON lines and
// takes the core's outbound fetch and device frames in the same way. Which
// component consumes it is not this row's (brief, Unowned gaps).
type wireItem struct {
	Kind   edgelink.Kind  `json:"kind"`
	Origin string         `json:"origin"`
	Body   []byte         `json:"body"`
	Label  edgelink.Label `json:"label,omitempty"` // set by the link on items out, ignored on frames in
}

// maxOutLine bounds one outbound line: a 64 KiB body in base64 and a
// 1024-byte origin, with room for the JSON around them.
const maxOutLine = 128 << 10

// serveConsumer serves the consumer on each connection ln accepts, one at a
// time: while one is connected, the next waits in the backlog.
func (s *server) serveConsumer(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		s.consume(conn)
	}
}

// consume writes items to conn and sends the frames it reads, until either
// side of conn fails.
func (s *server) consume(conn net.Conn) {
	defer conn.Close()
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		sc := bufio.NewScanner(conn)
		sc.Buffer(make([]byte, 4096), maxOutLine)
		for sc.Scan() {
			var w wireItem
			if json.Unmarshal(sc.Bytes(), &w) != nil {
				fmt.Fprintln(s.log, "agentos-link: the consumer sent a line that is not a frame")
				continue
			}
			if err := s.send(edgelink.Frame{Kind: w.Kind, Origin: w.Origin, Body: w.Body}); err != nil {
				fmt.Fprintf(s.log, "agentos-link: an outbound frame was not sent: %v\n", err)
			}
		}
	}()
	enc := json.NewEncoder(conn)
	for {
		select {
		case it := <-s.items:
			if enc.Encode(wireItem{it.Kind, it.Origin, it.Body, it.Label}) != nil {
				fmt.Fprintln(s.log, "agentos-link: an item was lost with the consumer's connection")
				return
			}
		case <-gone:
			return
		}
	}
}
