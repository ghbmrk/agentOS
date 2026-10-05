package skill

import (
	"context"
	"encoding/json"

	"github.com/ghbmrk/agentos/broker/skill/format"
)

// Effects asks the broker for one effect and reports its state. In the
// guest it is the broker's effect_request tool (MCPEffects).
type Effects interface {
	Request(ctx context.Context, e Effect) (State, error)
}

// Effect is one effect request, as effect_request takes it.
type Effect struct {
	RequestID  string         `json:"request_id"`
	Account    string         `json:"account"`
	Action     string         `json:"action"`
	Params     map[string]any `json:"params,omitempty"`
	Recipients []string       `json:"recipients,omitempty"`
}

// State is what the broker says about a request (effect_request's answer).
type State struct {
	RequestID string `json:"request_id"`
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
}

// Succeeded is the one state that lets a skill go on.
const Succeeded = "succeeded"

// Request IDs live in skill/format, so the broker's measurement can parse
// them without linking this bridge (ARC-2).
const RequestPrefix = format.RequestPrefix

// RequestID is step i's (0-based) request ID in run runID (format.RequestID).
func RequestID(skillID, runID string, i int) string { return format.RequestID(skillID, runID, i) }

// ParseRequestID splits a skill step's request ID (format.ParseRequestID).
func ParseRequestID(reqID string) (skillID, runID string, step int, ok bool) {
	return format.ParseRequestID(reqID)
}

// Result is a run's outcome, written for the model that called it.
type Result struct {
	Skill  string `json:"skill"`
	RunID  string `json:"run_id"`
	Status string `json:"status"` // "done" or "stopped"
	Done   []Done `json:"done,omitempty"`
	// Stopped says where and why an assumption failed; Remaining lists the
	// steps not yet run, with their bound values, for the model to finish.
	Stopped   *Stopped `json:"stopped,omitempty"`
	Remaining []Effect `json:"remaining,omitempty"`
}

// Done is one step that succeeded.
type Done struct {
	Step      int    `json:"step"`
	RequestID string `json:"request_id"`
}

// Stopped is the failed assumption.
type Stopped struct {
	Step      int    `json:"step"` // 0: before any effect (an input)
	RequestID string `json:"request_id,omitempty"`
	State     string `json:"state,omitempty"`
	Why       string `json:"why"`
}

// Run runs skill s with args. It checks every input first; then requests
// each step in order and goes on only while a step succeeds. Anything else
// (an input of the wrong type, a step waiting for the owner, denied, held,
// or failed) stops the run: the model takes over from there. A run never
// retries, skips, or reorders a step.
func Run(ctx context.Context, s *Skill, runID string, args map[string]json.RawMessage, fx Effects) Result {
	res := Result{Skill: s.ID, RunID: runID, Status: "stopped"}
	if !format.ValidRunID(runID) {
		res.Stopped = &Stopped{Why: "run_id must be 1 to 32 letters, digits, or _"}
		return res
	}
	vals, err := s.Bind(args)
	if err != nil {
		res.Stopped = &Stopped{Why: err.Error()}
		return res
	}
	effects := make([]Effect, len(s.Steps))
	for i := range s.Steps {
		params, recips, err := s.Fill(i, vals)
		if err != nil {
			res.Stopped = &Stopped{Step: i + 1, Why: err.Error()}
			return res
		}
		effects[i] = Effect{RequestID: RequestID(s.ID, runID, i), Account: s.Steps[i].Account,
			Action: s.Steps[i].Action, Params: params, Recipients: recips}
	}
	for i, e := range effects {
		st, err := fx.Request(ctx, e)
		if err != nil {
			res.Stopped = &Stopped{Step: i + 1, RequestID: e.RequestID, Why: "the broker did not take the request: " + err.Error()}
			res.Remaining = effects[i:]
			return res
		}
		if st.State != Succeeded {
			res.Stopped = &Stopped{Step: i + 1, RequestID: e.RequestID, State: st.State, Why: why(st)}
			res.Remaining = effects[i+1:]
			if st.State == "refused" {
				res.Remaining = effects[i:] // never journaled
			}
			return res
		}
		res.Done = append(res.Done, Done{Step: i + 1, RequestID: e.RequestID})
	}
	res.Status = "done"
	return res
}

func why(st State) string {
	switch st.State {
	case "pending", "authorized", "in_flight":
		return "this step is not finished (it may be waiting for the owner); check it with effect_status before going on"
	case "denied":
		return "this step was denied"
	case "refused":
		return "the broker refused this step"
	}
	return "this step did not succeed"
}
