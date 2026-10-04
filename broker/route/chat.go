package route

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// chatRequest is the part of an OpenAI chat-completions body (the guest
// interface, ARC-6 (a)) the router understands. The router decodes the
// guest's body into it and each provider encodes its own request from it,
// so a field not listed here never reaches any provider.
type chatRequest struct {
	Model               string          `json:"model"`
	Messages            []chatMessage   `json:"messages"`
	MaxTokens           *int            `json:"max_tokens,omitempty"`
	MaxCompletionTokens *int            `json:"max_completion_tokens,omitempty"`
	Temperature         *float64        `json:"temperature,omitempty"`
	TopP                *float64        `json:"top_p,omitempty"`
	Stop                json.RawMessage `json:"stop,omitempty"`
	Stream              bool            `json:"stream,omitempty"`
	StreamOptions       *streamOptions  `json:"stream_options,omitempty"`
	Tools               []chatTool      `json:"tools,omitempty"`
	ToolChoice          json.RawMessage `json:"tool_choice,omitempty"`
	ParallelToolCalls   *bool           `json:"parallel_tool_calls,omitempty"`
	ResponseFormat      json.RawMessage `json:"response_format,omitempty"`
	N                   *int            `json:"n,omitempty"`
	Seed                *int64          `json:"seed,omitempty"`
	PresencePenalty     *float64        `json:"presence_penalty,omitempty"`
	FrequencyPenalty    *float64        `json:"frequency_penalty,omitempty"`
}

type streamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

type chatMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content,omitempty"`
	Name       string          `json:"name,omitempty"`
	ToolCalls  []toolCall      `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
}

type toolCall struct {
	Index    *int         `json:"index,omitempty"`
	ID       string       `json:"id,omitempty"`
	Type     string       `json:"type,omitempty"`
	Function functionCall `json:"function"`
}

type functionCall struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments"`
}

type chatTool struct {
	Type     string      `json:"type"`
	Function functionDef `json:"function"`
}

type functionDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// contentPart is one element of an array-form message content.
type contentPart struct {
	Type     string    `json:"type"`
	Text     string    `json:"text,omitempty"`
	ImageURL *imageURL `json:"image_url,omitempty"`
}

type imageURL struct {
	URL    string `json:"url"`
	Detail string `json:"detail,omitempty"`
}

// parseChat decodes exactly one JSON object; trailing data is refused, so
// the router and every provider read the same request.
func parseChat(body []byte) (*chatRequest, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	var req chatRequest
	if err := dec.Decode(&req); err != nil {
		return nil, fmt.Errorf("body is not a chat completions request: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON body")
	}
	if req.Model == "" {
		return nil, errors.New("model is required")
	}
	if len(req.Messages) == 0 {
		return nil, errors.New("messages are required")
	}
	for _, t := range req.Tools {
		if t.Type != "function" || t.Function.Name == "" {
			return nil, errors.New("only function tools are accepted")
		}
	}
	return &req, nil
}

// parts returns a message's content as parts: a string is one text part,
// null or absent is none.
func parts(raw json.RawMessage) ([]contentPart, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		return []contentPart{{Type: "text", Text: s}}, nil
	}
	var ps []contentPart
	if err := json.Unmarshal(raw, &ps); err != nil {
		return nil, errors.New("content must be a string or a list of parts")
	}
	return ps, nil
}

// stops returns the stop field as a list.
func stops(raw json.RawMessage) ([]string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	if raw[0] == '"' {
		var s string
		err := json.Unmarshal(raw, &s)
		return []string{s}, err
	}
	var ss []string
	err := json.Unmarshal(raw, &ss)
	return ss, err
}

// apiError is the OpenAI error body, which is what a chat-completions
// guest expects to parse.
func apiError(message, typ, code string) []byte {
	b, _ := json.Marshal(map[string]any{"error": map[string]any{
		"message": message, "type": typ, "code": code,
	}})
	return b
}
