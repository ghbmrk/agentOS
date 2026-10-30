package radio

import (
	"io"
	"sync"
)

// Handler carries out one request inside a stack's process. Server has
// already held it to the stack's declaration.
type Handler func(Request) (data []byte, code Code)

// Server is a stack's end of its command interface, run inside the
// confined process.
type Server struct {
	stack Stack
	conn  io.ReadWriteCloser
	wmu   sync.Mutex
}

// NewServer serves stack s on conn.
func NewServer(s Stack, conn io.ReadWriteCloser) *Server {
	return &Server{stack: s, conn: conn}
}

// Serve answers requests until conn ends or a frame does not decode. A
// request the stack does not declare is refused here as well as in Host,
// so a stack adapter cannot widen the interface by handling more.
func (s *Server) Serve(h Handler) error {
	defer s.conn.Close()
	for {
		var r Request
		if err := read(s.conn, &r); err != nil {
			return err
		}
		if r.ID == 0 || !name(r.Device) {
			return ErrMalformed
		}
		u := Up{ID: r.ID, Device: r.Device, Code: CodeRefused}
		if r.Check(s.stack) == nil {
			u.Data, u.Code = h(r)
			if len(u.Data) > MaxData || u.Code < CodeOK || u.Code > CodeUnreachable {
				u.Data, u.Code = nil, CodeFailed
			}
		}
		if err := s.send(u); err != nil {
			return err
		}
	}
}

// Notify sends a notification from a subscribed characteristic.
func (s *Server) Notify(device, char string, data []byte) error {
	u := Up{Device: device, Char: char, Data: data}
	if err := u.check(); err != nil {
		return err
	}
	return s.send(u)
}

func (s *Server) send(u Up) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return write(s.conn, u)
}
