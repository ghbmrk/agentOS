package localsrv

import (
	"context"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// heldOps is the held-text op, served only with Config.Held: a signed-in
// page reads what was kept for it, and reading removes nothing (CH-8,
// CH-19, #993).
func (s *Server) heldOps() map[string]sockets.Handler {
	return map[string]sockets.Handler{localapi.OpHeld: s.authed(s.held)}
}

func (s *Server) held(context.Context) (any, error) {
	return s.cfg.Held(), nil
}
