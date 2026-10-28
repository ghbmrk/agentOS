package run

import (
	"encoding/json"
	"errors"
	"net"

	"github.com/ghbmrk/agentos/broker/clerk/model"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// The model clerk's process (#2572, MIG-4-run slice 3). Its provider holds a
// credential, so it runs under its own uid, apart from the kernel's process
// (CLK-1, option A). It meters through the kernel's meter socket (Meter as
// its model.Ledger) and serves two calls on its own socket to the one uid
// that runs the planner: call, a prompt on a route the clerk's Provider
// serves, and send, a declared operation's JSON body on an API-key route
// (MIG-4-exit m1). The key, the task and every cap come from the plan in the
// log and the route's declaration, never from the caller (model.Clerk).

type modelArgs struct {
	Plan   string `json:"plan"`
	Route  string `json:"route"`
	Prompt string `json:"prompt"`
	MaxOut int64  `json:"max_out"`
}

// sendArgs is an API-key route's call: the operation, its JSON body, and
// whether every value in it is public (PLN-3); a call that does not say so
// is private.
type sendArgs struct {
	Plan   string          `json:"plan"`
	Route  string          `json:"route"`
	Op     string          `json:"op"`
	Body   json.RawMessage `json:"body"`
	Public bool            `json:"public,omitempty"`
}

// ModelHost is what the model socket serves: the clerk, its API-key routes
// (nil: none) and the clerk process's clock, which only orders the clerk's
// own owed log writes, since the kernel dates every one.
type ModelHost struct {
	Clerk *model.Clerk
	APIs  *model.APIs
	Clock func() int64
}

// ListenModel opens the model clerk's socket, admitting only the planner's
// uid.
func ListenModel(path string, plannerUID int) (net.Listener, error) {
	return sockets.ListenPeers(path, plannerUID)
}

// ServeModel answers model calls to h on ln until ln closes, each on its own
// connection.
func ServeModel(ln net.Listener, h ModelHost) error {
	return proc.ServeConns(ln, proc.MaxConns, func(conn net.Conn) {
		proc.ServeOne(conn, func(op string, raw json.RawMessage) (json.RawMessage, error) {
			switch op {
			case "call":
				var a modelArgs
				if h.Clerk.Provider == nil || json.Unmarshal(raw, &a) != nil {
					return nil, errModelOp
				}
				reply, err := h.Clerk.Call(h.Clock(), a.Plan, a.Route, a.Prompt, a.MaxOut)
				if err != nil {
					return nil, modelError(err)
				}
				return json.Marshal(reply)
			case "send":
				var a sendArgs
				if h.APIs == nil || json.Unmarshal(raw, &a) != nil {
					return nil, errModelOp
				}
				reply, err := h.APIs.Call(h.Clerk, h.Clock(), a.Plan, a.Route, a.Op, a.Body, a.Public)
				if err != nil {
					return nil, modelError(err)
				}
				return reply, nil
			}
			return nil, errModelOp
		})
	})
}

var errModelOp = errors.New("run: the model socket has two calls, call and send")

// ErrModelCall is what the planner sees of a model call that failed other
// than by a refusal.
var ErrModelCall = errors.New("run: the model call failed; any spend it made is metered")

// modelError is what may leave the clerk's process of a failed call: a
// refusal, with its code, an API route's typed detail, or ErrModelCall. A
// provider's own error can carry its URL, a header or a key, so its text
// stays here (CLK-1).
func modelError(err error) error {
	var rf *key.Refusal
	if errors.As(err, &rf) && rf != nil {
		return rf
	}
	var ae *model.APIError
	if errors.As(err, &ae) && ae != nil {
		return ae
	}
	return ErrModelCall
}

// Model is the model clerk over its socket, for the planner's process. A
// refusal arrives as the *key.Refusal the kernel gave, any other failure as
// ErrModelCall, and a lost answer as ErrLost; the call's spend, if any, is
// metered all the same.
type Model struct{ proc.Conn }

func (m Model) Call(plan, route, prompt string, maxOut int64) (reply string, err error) {
	err = m.Conn.Call("call", modelArgs{plan, route, prompt, maxOut}, &reply)
	return
}

// Send makes one call of a declared operation on an API-key route, with its
// JSON body, and returns the provider's answer with the key stripped. public
// says every value in body is public (PLN-3).
func (m Model) Send(plan, route, op string, body []byte, public bool) (reply json.RawMessage, err error) {
	err = m.Conn.Call("send", sendArgs{plan, route, op, body, public}, &reply)
	return
}
