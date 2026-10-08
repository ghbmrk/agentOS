package guest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/guesterr"
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
		list := tools
		if p.cfg.Tools != nil {
			list = append([]map[string]any(nil), tools...)
			for _, t := range p.cfg.Tools.List() {
				// The effect tools' names are the broker's own.
				if n := t["name"]; n != "effect_request" && n != "effect_status" {
					list = append(list, t)
				}
			}
		}
		writeRPC(w, req.ID, map[string]any{"tools": list}, nil)
	case "tools/call":
		var call struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &call); err != nil {
			writeRPC(w, req.ID, nil, &rpcError{-32602, "bad params"})
			return
		}
		if call.Name != "effect_request" && call.Name != "effect_status" && p.cfg.Tools != nil {
			lineage, err := p.cfg.Machines.Lineage(m.id)
			if err != nil {
				writeRPC(w, req.ID, m.result("broker: unknown machine", true), nil)
				return
			}
			text, handled, err := p.cfg.Tools.Call(r.Context(), m.id, lineage, call.Name, call.Arguments)
			if handled {
				if err != nil {
					writeRPC(w, req.ID, m.result(guesterr.Filter(m.id, call.Name, err).Error(), true), nil)
				} else {
					writeRPC(w, req.ID, m.result(text, false), nil)
				}
				return
			}
		}
		res, submitted, err := p.callTool(r.Context(), m, call.Name, call.Arguments)
		if submitted {
			p.step(m) // REV-1: after every effect request the journal took
		}
		if err != nil {
			writeRPC(w, req.ID, m.result(guesterr.Filter(m.id, call.Name, err).Error(), true), nil)
			return
		}
		b, _ := json.Marshal(res)
		writeRPC(w, req.ID, m.result(string(b), false), nil)
	default:
		writeRPC(w, req.ID, nil, &rpcError{-32601, "method not found"})
	}
}

// result is a tool result for machine m, carrying after it any untold
// note about a failed step snapshot as its own content item, so a JSON
// result stays whole (SR2-3s).
func (m *machine) result(text string, isErr bool) map[string]any {
	res := toolResult(text, isErr)
	if n := m.takeNote(); n != "" {
		res["content"] = append(res["content"].([]map[string]string), map[string]string{"type": "text", "text": n})
	}
	return res
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
	lineage := p.lineageOf(m)
	if lineage == "" {
		return effectState{}, false, guesterr.New("broker: unknown machine")
	}
	switch name {
	case "effect_request":
		var a effectArgs
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&a); err != nil {
			return effectState{}, false, guesterr.New("arguments must be an object")
		}
		if !requestIDRE.MatchString(a.RequestID) || a.Account == "" || a.Action == "" {
			return effectState{}, false, guesterr.New("request_id (letters, digits, . _ -; at most 64), account, and action are required")
		}
		if !nameRE.MatchString(a.Account) || !nameRE.MatchString(a.Action) {
			return effectState{}, false, guesterr.New("account and action must be lowercase names (a-z, 0-9, . _ -; at most 64)")
		}
		if params, _ := json.Marshal(a.Params); len(params) > maxParamsBytes {
			return effectState{}, false, guesterr.Newf("params are larger than %d bytes", guesterr.Num(maxParamsBytes))
		}
		if len(a.Recipients) > maxRecipients {
			return effectState{}, false, guesterr.Newf("more than %d recipients", guesterr.Num(maxRecipients))
		}
		for _, r := range a.Recipients {
			if len(r) > maxRecipient {
				return effectState{}, false, guesterr.Newf("a recipient is longer than %d bytes", guesterr.Num(maxRecipient))
			}
		}
		// Broker-state intents (budgets, grants, the broker's own
		// settings) come from the owner and the broker, never a guest:
		// some of them narrow and so pass STOP (OP-5, ARC-7).
		if a.Account == journal.BrokerAccount || strings.HasPrefix(a.Action, "meta.") {
			return effectState{RequestID: a.RequestID, State: "refused", Reason: "broker-state changes are the owner's; a guest cannot request them"}, false, nil
		}
		if !m.rate.take(p.cfg.SubmitBurst, p.cfg.SubmitEvery) {
			return effectState{}, false, guesterr.New("too many effect requests from this machine; wait and retry with the same request_id")
		}
		exec, ok := p.cfg.Route(a.Account)
		if !ok {
			return effectState{RequestID: a.RequestID, State: "refused", Reason: "no adapter is connected for that account"}, false, nil
		}
		label := p.label(m.id)
		id, readOnly, prior, seen := p.intentID(lineage, a.RequestID, label)
		// The goal is fixed by the first submission (G14): a repeat keeps
		// the goal its request was journaled with, even if the lineage
		// has moved on to another owner message since.
		goal := prior.Intent.GoalID
		if !seen {
			goal = p.goal(lineage)
		}
		in := journal.Intent{
			ID: id, GoalID: goal, Origin: "guest:" + lineage, Account: a.Account, Action: a.Action,
			Params: a.Params, Recipients: a.Recipients, Executor: exec,
			Machine: m.id, Label: label,
		}
		st, err := p.cfg.Effects.Submit(in)
		if errors.Is(err, journal.ErrConflict) && !seen {
			// A concurrent first submission of the same request may have
			// won with another goal; the request is still the same one.
			if prior, gerr := p.cfg.Effects.Get(id); gerr == nil && prior.Intent.GoalID != goal {
				in.GoalID = prior.Intent.GoalID
				st, err = p.cfg.Effects.Submit(in)
			}
		}
		if err != nil {
			if errors.Is(err, journal.ErrConflict) {
				return effectState{}, false, guesterr.Newf("request_id %s was already used with different arguments", guesterr.Guest(a.RequestID))
			}
			p.cfg.Logf("guest %s: submit %s: %v", m.id, id, err)
			return effectState{}, false, guesterr.New("broker refused the request")
		}
		if readOnly {
			// A private machine repeating a request its lineage made while
			// public sees it but does not drive it, so nothing a private
			// machine does changes what a public one can observe (REV-5).
			return state(a.RequestID, st), false, nil
		}
		if st.State == journal.Pending {
			s2, err := p.cfg.Effects.Authorize(ctx, id)
			if s2.Intent.ID == "" {
				p.cfg.Logf("guest %s: authorize %s: %v", m.id, id, err)
				return effectState{}, true, guesterr.New("broker could not decide; retry with the same request_id")
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
			return effectState{}, false, guesterr.New("request_id is required")
		}
		var st journal.Status
		err := journal.ErrNotFound
		if p.label(m.id) == "private" {
			st, err = p.cfg.Effects.Get(privateID(lineage, a.RequestID))
		}
		if err != nil {
			st, err = p.cfg.Effects.Get(lineage + "/" + a.RequestID)
		}
		if err != nil {
			return effectState{}, false, guesterr.Newf("no request %s", guesterr.Guest(a.RequestID))
		}
		return state(a.RequestID, st), false, nil
	}
	return effectState{}, false, guesterr.Newf("no tool %q", guesterr.Guest(clip(name, 64)))
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

// intentID partitions a lineage's requests by data label (REV-5). Public
// machines use <lineage>/<request_id>; private ones <lineage>/private/<request_id>
// (request IDs hold no '/', so the two never collide). A public machine
// never sees, collides with, or learns anything from a private machine's
// request. A private machine repeating a request its lineage made while
// public gets that intent, read-only (OP-1: it runs at most once).
//
// When the request was journaled before, prior is its status and seen is
// true.
func (p *Plane) intentID(lineage, reqID, label string) (id string, readOnly bool, prior journal.Status, seen bool) {
	pub := lineage + "/" + reqID
	if label != "private" {
		st, err := p.cfg.Effects.Get(pub)
		return pub, false, st, err == nil
	}
	priv := privateID(lineage, reqID)
	if st, err := p.cfg.Effects.Get(priv); err == nil {
		return priv, false, st, true
	}
	if st, err := p.cfg.Effects.Get(pub); err == nil {
		return pub, true, st, true
	}
	return priv, false, journal.Status{}, false
}

func privateID(lineage, reqID string) string { return lineage + "/private/" + reqID }

func state(reqID string, st journal.Status) effectState {
	return effectState{RequestID: reqID, State: string(st.State), Reason: st.Permission.Reason}
}
