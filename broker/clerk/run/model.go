package run

import (
	"encoding/json"
	"errors"
	"net"

	"github.com/ghbmrk/agentos/broker/clerk/model"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// The model clerk's process (#2572, MIG-4-run slice 3). Its provider holds a
// credential, so it runs under its own uid, apart from the kernel's process
// (CLK-1, option A). It meters through the kernel's meter socket (Meter as
// its model.Ledger) and serves one call, a model call for a plan, on its own
// socket to the one uid that runs the planner. The key, the task and every
// cap come from the plan in the log, never from the caller (model.Clerk).

type modelArgs struct {
	Plan   string `json:"plan"`
	Route  string `json:"route"`
	Prompt string `json:"prompt"`
	MaxOut int64  `json:"max_out"`
}

// ListenModel opens the model clerk's socket, admitting only the planner's
// uid.
func ListenModel(path string, plannerUID int) (net.Listener, error) {
	return sockets.ListenPeers(path, plannerUID)
}

// ServeModel answers model calls to c on ln until ln closes, each on its own
// connection; c serializes them. clock is the model clerk process's, which
// only orders the clerk's own owed log writes: the kernel dates every one.
func ServeModel(ln net.Listener, c *model.Clerk, clock func() int64) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go serveOne(conn, func(op string, raw json.RawMessage) (json.RawMessage, error) {
			var a modelArgs
			if op != "call" || json.Unmarshal(raw, &a) != nil {
				return nil, errors.New("run: the model socket has one call, call")
			}
			reply, err := c.Call(clock(), a.Plan, a.Route, a.Prompt, a.MaxOut)
			if err != nil {
				return nil, err
			}
			return json.Marshal(reply)
		})
	}
}

// Model is the model clerk over its socket, for the planner's process. A
// refusal arrives as the *key.Refusal the kernel gave; a lost answer is
// ErrLost, and the call's spend, if any, is metered all the same.
type Model struct{ Conn }

func (m Model) Call(plan, route, prompt string, maxOut int64) (reply string, err error) {
	err = m.call("call", modelArgs{plan, route, prompt, maxOut}, &reply)
	return
}
