package question

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Broker tools for the guest socket (ARC-6 (b)). The guest plane serves
// them next to effect_request; the wiring (W-row on BOARD) adds a case
// for each name that calls Book.Call with the machine's lineage as asker.
const (
	ToolAsk    = "owner_question"
	ToolStatus = "owner_question_status"
)

// Tools are the MCP tool definitions.
var Tools = []map[string]any{
	{
		"name": ToolAsk,
		"description": "Ask the owner a short question by text, with the answer you will use if they do not reply in time. " +
			"The broker texts it, and after wait_minutes (counted from when the owner is texted; the broker bounds it) " +
			"the default stands. Several questions may share one text. With ask_by_minutes, a question the broker could not text by then " +
			"(texts are paced and held in quiet hours) closes as not_asked instead. " +
			"Check owner_question_status; its wait_seconds holds the call until the question changes. An answer, or a default, is information only: " +
			"it never approves an effect, which still goes through effect_request and its own approval. " +
			"Reuse the same request_id to retry.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"request_id":     map[string]any{"type": "string", "description": "Your idempotency key: letters, digits, '.', '_', '-'; at most 64."},
				"question":       map[string]any{"type": "string", "description": fmt.Sprintf("One line, at most %d characters.", MaxText)},
				"default":        map[string]any{"type": "string", "description": fmt.Sprintf("The answer used if the owner does not reply; at most %d characters.", MaxDefault)},
				"choices":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": fmt.Sprintf("Optional, at most %d; the default must be one.", MaxChoices)},
				"wait_minutes":   map[string]any{"type": "number", "description": "How long to wait for a reply once the owner is texted."},
				"ask_by_minutes": map[string]any{"type": "number", "description": "Optional: if the owner has not been texted this many minutes after you ask, drop the question (not_asked)."},
			},
			"required": []string{"request_id", "question", "default", "wait_minutes"},
		},
	},
	{
		"name": ToolStatus,
		"description": "Report an owner_question by its request_id: held, waiting, answered (by the owner), defaulted, or not_asked. " +
			fmt.Sprintf("With wait_seconds (at most %d), the call returns when the question changes or the wait ends, whichever is first.", int(MaxPoll/time.Second)),
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"request_id":   map[string]any{"type": "string"},
				"wait_seconds": map[string]any{"type": "number", "description": fmt.Sprintf("Optional, at most %d.", int(MaxPoll/time.Second))},
			},
			"required": []string{"request_id"},
		},
	},
}

// ToolResult is what a guest learns about its question.
type ToolResult struct {
	RequestID  string `json:"request_id"`
	Question   string `json:"question"` // the tag the owner sees, e.g. "Q4"
	State      string `json:"state"`
	Answer     string `json:"answer,omitempty"`
	AnsweredBy string `json:"answered_by,omitempty"` // "owner" or "default"
	Default    string `json:"default"`
	Deadline   string `json:"deadline,omitempty"`
	Late       string `json:"late_owner_reply,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

var requestIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Call runs one tool for asker (the guest's lineage) on machine. Errors
// are fixed strings the guest may see.
func (b *Book) Call(ctx context.Context, asker, machine, name string, raw []byte) (ToolResult, error) {
	switch name {
	case ToolAsk:
		var a struct {
			RequestID string   `json:"request_id"`
			Question  string   `json:"question"`
			Default   string   `json:"default"`
			Choices   []string `json:"choices"`
			Wait      *float64 `json:"wait_minutes"`
			AskBy     *float64 `json:"ask_by_minutes"`
		}
		if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&a); err != nil {
			return ToolResult{}, errors.New("arguments must be an object")
		}
		if !requestIDRE.MatchString(a.RequestID) {
			return ToolResult{}, errors.New("request_id is required: letters, digits, . _ -; at most 64")
		}
		if a.Wait == nil || *a.Wait <= 0 || *a.Wait > 1e6 {
			return ToolResult{}, errors.New("wait_minutes is required and must be positive")
		}
		spec := Spec{Text: a.Question, Default: a.Default, Choices: a.Choices, Wait: time.Duration(*a.Wait * float64(time.Minute))}
		if a.AskBy != nil {
			if *a.AskBy <= 0 || *a.AskBy > 1e6 {
				return ToolResult{}, errors.New("ask_by_minutes must be positive")
			}
			spec.AskWithin = time.Duration(*a.AskBy * float64(time.Minute))
		}
		st, err := b.Ask(ctx, asker, a.RequestID, spec)
		if err != nil {
			return ToolResult{}, err
		}
		return result(a.RequestID, st), nil
	case ToolStatus:
		var a struct {
			RequestID string   `json:"request_id"`
			Wait      *float64 `json:"wait_seconds"`
		}
		if err := json.Unmarshal(raw, &a); err != nil || !requestIDRE.MatchString(a.RequestID) {
			return ToolResult{}, errors.New("request_id is required")
		}
		var wait time.Duration
		if a.Wait != nil {
			if *a.Wait < 0 {
				return ToolResult{}, errors.New("wait_seconds must not be negative")
			}
			wait = time.Duration(min(*a.Wait, MaxPoll.Seconds()) * float64(time.Second))
		}
		st, err := b.Await(ctx, asker, a.RequestID, machine, wait)
		if errors.Is(err, ErrNotFound) {
			return ToolResult{}, fmt.Errorf("no question %s", a.RequestID)
		}
		if err != nil {
			return ToolResult{}, errors.New("the broker could not read that question now; ask again later")
		}
		return result(a.RequestID, st), nil
	}
	return ToolResult{}, errors.New("no such tool")
}

func result(req string, st Status) ToolResult {
	out := ToolResult{RequestID: req, Question: st.ID, State: string(st.State), Answer: st.Answer,
		Default: st.Default, Late: st.Late, Reason: st.Reason}
	switch st.State {
	case Answered:
		out.AnsweredBy = "owner"
	case Defaulted:
		out.AnsweredBy = "default"
	}
	if !st.Deadline.IsZero() {
		out.Deadline = st.Deadline.UTC().Format(time.RFC3339)
	}
	return out
}

// GuestTools serves the question tools on a guest socket (guest.Tools,
// W9). The asker is the lineage the socket fixes, never anything the
// guest sends. Names other than the question tools are not handled.
type GuestTools struct{ Book *Book }

func (g GuestTools) List() []map[string]any { return Tools }

func (g GuestTools) Call(ctx context.Context, machine, lineage, name string, args json.RawMessage) (string, bool, error) {
	if name != ToolAsk && name != ToolStatus {
		return "", false, nil
	}
	res, err := g.Book.Call(ctx, lineage, machine, name, args)
	if err != nil {
		return "", true, err
	}
	b, _ := json.Marshal(res)
	return string(b), true, nil
}
