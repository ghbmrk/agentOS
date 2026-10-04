package guest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// MCP over streamable HTTP, the subset a tool server needs: one JSON-RPC
// request per POST, answered with one JSON response (no SSE stream, no
// server-initiated messages, no sessions). This is the shape the S4 spike
// qualified with OpenClaw 2026.9.8. It is a few dozen lines of stdlib
// rather than an SDK because the broker takes no third-party code on its
// own process (DEP-1) and the server side of this subset is small.

const maxMCPBody = 1 << 20

var protocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Tool names avoid the bare word "intent": OpenClaw has a built-in tool of
// that name (S4 finding 4).
var tools = []map[string]any{
	{
		"name": "effect_request",
		"description": "Ask the broker for an effect outside this machine (send, post, buy, change an account...). " +
			"The broker journals it, checks grants and approvals, and runs it at most once per request_id. " +
			"Reuse the same request_id to retry; a new request_id is a new effect. Returns the request's state.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"request_id": map[string]any{"type": "string", "description": "Your idempotency key: letters, digits, '.', '_', '-'; at most 64."},
				"account":    map[string]any{"type": "string", "description": "The connected account the effect lands on."},
				"action":     map[string]any{"type": "string", "description": "What to do, e.g. message.send."},
				"params":     map[string]any{"type": "object"},
				"recipients": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			},
			"required": []string{"request_id", "account", "action"},
		},
	},
	{
		"name":        "effect_status",
		"description": "Report the state of an earlier effect_request by its request_id.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"request_id": map[string]any{"type": "string"}},
			"required":   []string{"request_id"},
		},
	},
}

var requestIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func (p *Plane) mcp(machine string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "this server sends no stream; POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxMCPBody+1))
	if err != nil || len(body) > maxMCPBody {
		http.Error(w, "body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	var req rpcRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
		writeRPC(w, nil, nil, &rpcError{-32600, "invalid request (batches are not supported)"})
		return
	}
	if len(req.ID) == 0 || string(req.ID) == "null" {
		w.WriteHeader(http.StatusAccepted) // a notification: nothing to answer
		return
	}
	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(req.Params, &params)
		v := protocolVersions[0]
		for _, s := range protocolVersions {
			if s == params.ProtocolVersion {
				v = s
			}
		}
		writeRPC(w, req.ID, map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]string{"name": "agentos-broker", "version": "p1"},
		}, nil)
	case "ping":
		writeRPC(w, req.ID, map[string]any{}, nil)
	case "tools/list":
		writeRPC(w, req.ID, map[string]any{"tools": tools}, nil)
	case "tools/call":
		var call struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &call); err != nil {
			writeRPC(w, req.ID, nil, &rpcError{-32602, "bad params"})
			return
		}
		res, err := p.callTool(r.Context(), machine, call.Name, call.Arguments)
		p.step(machine)
		if err != nil {
			writeRPC(w, req.ID, toolResult(err.Error(), true), nil)
			return
		}
		b, _ := json.Marshal(res)
		writeRPC(w, req.ID, toolResult(string(b), false), nil)
	default:
		writeRPC(w, req.ID, nil, &rpcError{-32601, "method not found"})
	}
}

func toolResult(text string, isErr bool) map[string]any {
	return map[string]any{"content": []map[string]string{{"type": "text", "text": text}}, "isError": isErr}
}

func writeRPC(w http.ResponseWriter, id json.RawMessage, result any, e *rpcError) {
	if id == nil {
		id = json.RawMessage("null")
	}
	out := map[string]any{"jsonrpc": "2.0", "id": id}
	if e != nil {
		out["error"] = e
	} else {
		out["result"] = result
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// effectState is what a guest learns about its request. It carries the
// broker's own fields only, never executor evidence.
type effectState struct {
	RequestID string `json:"request_id"`
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
}

type effectArgs struct {
	RequestID  string         `json:"request_id"`
	Account    string         `json:"account"`
	Action     string         `json:"action"`
	Params     map[string]any `json:"params"`
	Recipients []string       `json:"recipients"`
}

// callTool runs one broker tool for machine. Intent IDs and origins are
// the machine's fork lineage: forks share their source's memory, so a
// request a fork repeats from its source's history is the same intent and
// runs at most once (OP-1), while no machine outside the lineage can read
// or collide with it. The origin therefore names the lineage, not the fork.
func (p *Plane) callTool(ctx context.Context, machine, name string, raw json.RawMessage) (effectState, error) {
	lineage, err := p.cfg.Machines.Lineage(machine)
	if err != nil {
		return effectState{}, errors.New("broker: unknown machine")
	}
	switch name {
	case "effect_request":
		var a effectArgs
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&a); err != nil {
			return effectState{}, errors.New("arguments must be an object")
		}
		if !requestIDRE.MatchString(a.RequestID) || a.Account == "" || a.Action == "" {
			return effectState{}, errors.New("request_id (letters, digits, . _ -; at most 64), account, and action are required")
		}
		exec, ok := p.cfg.Route(a.Account)
		if !ok {
			return effectState{RequestID: a.RequestID, State: "refused", Reason: "no adapter is connected for account " + clip(a.Account, 64)}, nil
		}
		id := lineage + "/" + a.RequestID
		st, err := p.cfg.Effects.Submit(journal.Intent{
			ID: id, Origin: "guest:" + lineage, Account: a.Account, Action: a.Action,
			Params: a.Params, Recipients: a.Recipients, Executor: exec,
			Machine: machine, Label: p.label(machine),
		})
		if err != nil {
			if errors.Is(err, journal.ErrConflict) {
				return effectState{}, fmt.Errorf("request_id %s was already used with different arguments", a.RequestID)
			}
			return effectState{}, fmt.Errorf("broker refused the request: %v", err)
		}
		if st.State == journal.Pending {
			s2, err := p.cfg.Effects.Authorize(ctx, id)
			if s2.Intent.ID == "" {
				return effectState{}, fmt.Errorf("broker could not decide: %v", err)
			}
			st = s2
		}
		var held error
		if st.State == journal.Authorized || st.State == journal.NotApplied {
			// The effect runs to an outcome even if the guest hangs up.
			dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
			defer cancel()
			s2, err := p.cfg.Effects.Dispatch(dctx, id)
			if s2.Intent.ID != "" {
				st = s2
			}
			held = err
		}
		out := state(a.RequestID, st)
		if held != nil && out.Reason == "" {
			out.Reason = "held: " + held.Error()
		}
		return out, nil
	case "effect_status":
		var a struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(raw, &a); err != nil || !requestIDRE.MatchString(a.RequestID) {
			return effectState{}, errors.New("request_id is required")
		}
		st, err := p.cfg.Effects.Get(lineage + "/" + a.RequestID)
		if err != nil {
			return effectState{}, fmt.Errorf("no request %s", a.RequestID)
		}
		return state(a.RequestID, st), nil
	}
	return effectState{}, fmt.Errorf("no tool %q", clip(name, 64))
}

// label is the machine's data label for the journal, failing closed.
func (p *Plane) label(machine string) string {
	if p.cfg.Label != nil {
		if l := p.cfg.Label(machine); l == "public" || l == "private" {
			return l
		}
	}
	return "private"
}

func state(reqID string, st journal.Status) effectState {
	return effectState{RequestID: reqID, State: string(st.State), Reason: st.Permission.Reason}
}
