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
	"strings"
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

// nameRE is an account or action name: lowercase ASCII only, so no
// spacing, invisible, look-alike, or case variant can pass for another
// name in the checks below, in routing, or in the journal.
var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func (p *Plane) mcp(m *machine, w http.ResponseWriter, r *http.Request) {
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
		res, submitted, err := p.callTool(r.Context(), m, call.Name, call.Arguments)
		if submitted {
			p.step(m) // REV-1: after every effect request the journal took
		}
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

// Bounds on one effect request's guest-chosen fields.
const (
	maxParamsBytes = 16 << 10
	maxRecipients  = 50
	maxRecipient   = 320
)

// callTool runs one broker tool for machine m, and reports whether an
// effect request reached the journal. Intent IDs and origins are the
// machine's fork lineage: forks share their source's memory, so a request
// a fork repeats from its source's history is the same intent and runs at
// most once (OP-1), while no machine outside the lineage can read or
// collide with it. The origin therefore names the lineage, not the fork.
// Errors the guest sees are fixed strings; broker detail goes to Logf.
func (p *Plane) callTool(ctx context.Context, m *machine, name string, raw json.RawMessage) (effectState, bool, error) {
	lineage, err := p.cfg.Machines.Lineage(m.id)
	if err != nil {
		return effectState{}, false, errors.New("broker: unknown machine")
	}
	switch name {
	case "effect_request":
		var a effectArgs
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&a); err != nil {
			return effectState{}, false, errors.New("arguments must be an object")
		}
		if !requestIDRE.MatchString(a.RequestID) || a.Account == "" || a.Action == "" {
			return effectState{}, false, errors.New("request_id (letters, digits, . _ -; at most 64), account, and action are required")
		}
		if !nameRE.MatchString(a.Account) || !nameRE.MatchString(a.Action) {
			return effectState{}, false, errors.New("account and action must be lowercase names (a-z, 0-9, . _ -; at most 64)")
		}
		if params, _ := json.Marshal(a.Params); len(params) > maxParamsBytes {
			return effectState{}, false, fmt.Errorf("params are larger than %d bytes", maxParamsBytes)
		}
		if len(a.Recipients) > maxRecipients {
			return effectState{}, false, fmt.Errorf("more than %d recipients", maxRecipients)
		}
		for _, r := range a.Recipients {
			if len(r) > maxRecipient {
				return effectState{}, false, fmt.Errorf("a recipient is longer than %d bytes", maxRecipient)
			}
		}
		// Broker-state intents (budgets, grants, the broker's own
		// settings) come from the owner and the broker, never a guest:
		// some of them narrow and so pass STOP (OP-5, ARC-7).
		if a.Account == journal.BrokerAccount || strings.HasPrefix(a.Action, "meta.") {
			return effectState{RequestID: a.RequestID, State: "refused", Reason: "broker-state changes are the owner's; a guest cannot request them"}, false, nil
		}
		if !m.rate.take(p.cfg.SubmitBurst, p.cfg.SubmitEvery) {
			return effectState{}, false, errors.New("too many effect requests from this machine; wait and retry with the same request_id")
		}
		exec, ok := p.cfg.Route(a.Account)
		if !ok {
			return effectState{RequestID: a.RequestID, State: "refused", Reason: "no adapter is connected for account " + clip(a.Account, 64)}, false, nil
		}
		id := lineage + "/" + a.RequestID
		st, err := p.cfg.Effects.Submit(journal.Intent{
			ID: id, Origin: "guest:" + lineage, Account: a.Account, Action: a.Action,
			Params: a.Params, Recipients: a.Recipients, Executor: exec,
		})
		if err != nil {
			if errors.Is(err, journal.ErrConflict) {
				return effectState{}, false, fmt.Errorf("request_id %s was already used with different arguments", a.RequestID)
			}
			p.cfg.Logf("guest %s: submit %s: %v", m.id, id, err)
			return effectState{}, false, errors.New("broker refused the request")
		}
		if st.State == journal.Pending {
			s2, err := p.cfg.Effects.Authorize(ctx, id)
			if s2.Intent.ID == "" {
				p.cfg.Logf("guest %s: authorize %s: %v", m.id, id, err)
				return effectState{}, true, errors.New("broker could not decide; retry with the same request_id")
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
			p.cfg.Logf("guest %s: dispatch %s: %v", m.id, id, held)
			out.Reason = "held by the broker; ask again later with effect_status"
		}
		return out, true, nil
	case "effect_status":
		var a struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(raw, &a); err != nil || !requestIDRE.MatchString(a.RequestID) {
			return effectState{}, false, errors.New("request_id is required")
		}
		st, err := p.cfg.Effects.Get(lineage + "/" + a.RequestID)
		if err != nil {
			return effectState{}, false, fmt.Errorf("no request %s", a.RequestID)
		}
		return state(a.RequestID, st), false, nil
	}
	return effectState{}, false, fmt.Errorf("no tool %q", clip(name, 64))
}

func state(reqID string, st journal.Status) effectState {
	return effectState{RequestID: reqID, State: string(st.State), Reason: st.Permission.Reason}
}
