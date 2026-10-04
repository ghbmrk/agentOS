package route

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// anthropic translates the guest's chat-completions interface to the
// Messages API and back, so a guest qualified on one interface (ARC-6 (a))
// can be served by either provider.
type anthropic struct{ adapter string }

// Anthropic is the provider for egress.Anthropic's relay (adapter
// "anthropic").
func Anthropic() Provider { return anthropic{adapter: "anthropic"} }

// AnthropicVersion is the Messages API version the translation targets.
const AnthropicVersion = "2023-06-01"

// DefaultMaxTokens is sent when the guest names no limit: the Messages API
// requires one.
const DefaultMaxTokens = 4096

func (a anthropic) Name() string { return a.adapter }
func (anthropic) Path() string   { return "/v1/messages" }
func (anthropic) Headers() map[string]string {
	return map[string]string{"Anthropic-Version": AnthropicVersion}
}

type aRequest struct {
	Model         string       `json:"model"`
	System        string       `json:"system,omitempty"`
	Messages      []aMessage   `json:"messages"`
	MaxTokens     int          `json:"max_tokens"`
	Temperature   *float64     `json:"temperature,omitempty"`
	TopP          *float64     `json:"top_p,omitempty"`
	StopSequences []string     `json:"stop_sequences,omitempty"`
	Stream        bool         `json:"stream,omitempty"`
	Tools         []aTool      `json:"tools,omitempty"`
	ToolChoice    *aToolChoice `json:"tool_choice,omitempty"`
}

type aMessage struct {
	Role    string   `json:"role"`
	Content []aBlock `json:"content"`
}

type aBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	Source    *aSource        `json:"source,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   []aBlock        `json:"content,omitempty"`
}

type aSource struct {
	Type      string `json:"type"`
	MediaType string `json:"media_type,omitempty"`
	Data      string `json:"data,omitempty"`
	URL       string `json:"url,omitempty"`
}

type aTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type aToolChoice struct {
	Type                   string `json:"type"`
	Name                   string `json:"name,omitempty"`
	DisableParallelToolUse bool   `json:"disable_parallel_tool_use,omitempty"`
}

// Request translates a chat-completions request. Features the Messages API
// cannot honor (several choices, a structured response format) make the
// route unable to cover the call, so the router tries the next one.
func (anthropic) Request(req *chatRequest, model string) ([]byte, error) {
	if req.N != nil && *req.N != 1 {
		return nil, unsupported("n other than 1")
	}
	if len(req.ResponseFormat) > 0 && !bytes.Equal(bytes.TrimSpace(req.ResponseFormat), []byte("null")) {
		var rf struct{ Type string }
		if json.Unmarshal(req.ResponseFormat, &rf) != nil || rf.Type != "text" {
			return nil, unsupported("response_format other than text")
		}
	}
	out := aRequest{Model: model, Temperature: req.Temperature, TopP: req.TopP, Stream: req.Stream, MaxTokens: DefaultMaxTokens}
	switch {
	case req.MaxCompletionTokens != nil:
		out.MaxTokens = *req.MaxCompletionTokens
	case req.MaxTokens != nil:
		out.MaxTokens = *req.MaxTokens
	}
	var err error
	if out.StopSequences, err = stops(req.Stop); err != nil {
		return nil, badRequest("stop must be a string or a list of strings")
	}
	var system []string
	for _, m := range req.Messages {
		ps, err := parts(m.Content)
		if err != nil {
			return nil, badRequest(err.Error())
		}
		switch m.Role {
		case "system", "developer":
			for _, p := range ps {
				if p.Type != "text" {
					return nil, badRequest("system content must be text")
				}
				system = append(system, p.Text)
			}
		case "user":
			var blocks []aBlock
			for _, p := range ps {
				b, err := userBlock(p)
				if err != nil {
					return nil, err
				}
				if b != nil {
					blocks = append(blocks, *b)
				}
			}
			out.Messages = appendTurn(out.Messages, "user", blocks)
		case "assistant":
			var blocks []aBlock
			for _, p := range ps {
				if p.Type != "text" {
					return nil, badRequest("assistant content must be text")
				}
				if p.Text != "" {
					blocks = append(blocks, aBlock{Type: "text", Text: p.Text})
				}
			}
			for _, tc := range m.ToolCalls {
				input := json.RawMessage(strings.TrimSpace(tc.Function.Arguments))
				if len(input) == 0 {
					input = json.RawMessage("{}")
				}
				var obj map[string]any
				if json.Unmarshal(input, &obj) != nil || obj == nil {
					return nil, unsupported("tool call arguments that are not a JSON object")
				}
				blocks = append(blocks, aBlock{Type: "tool_use", ID: tc.ID, Name: tc.Function.Name, Input: input})
			}
			out.Messages = appendTurn(out.Messages, "assistant", blocks)
		case "tool":
			var inner []aBlock
			for _, p := range ps {
				if p.Type != "text" {
					return nil, badRequest("tool content must be text")
				}
				if p.Text != "" {
					inner = append(inner, aBlock{Type: "text", Text: p.Text})
				}
			}
			out.Messages = appendTurn(out.Messages, "user", []aBlock{{Type: "tool_result", ToolUseID: m.ToolCallID, Content: inner}})
		default:
			return nil, badRequest("unknown message role " + m.Role)
		}
	}
	out.System = strings.Join(system, "\n\n")
	if len(out.Messages) == 0 {
		return nil, badRequest("no user or assistant messages")
	}
	for _, t := range req.Tools {
		schema := t.Function.Parameters
		if len(bytes.TrimSpace(schema)) == 0 {
			schema = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		out.Tools = append(out.Tools, aTool{Name: t.Function.Name, Description: t.Function.Description, InputSchema: schema})
	}
	if out.ToolChoice, err = toolChoice(req.ToolChoice); err != nil {
		return nil, err
	}
	if req.ParallelToolCalls != nil && !*req.ParallelToolCalls && len(out.Tools) > 0 {
		if out.ToolChoice == nil {
			out.ToolChoice = &aToolChoice{Type: "auto"}
		}
		if out.ToolChoice.Type != "none" {
			out.ToolChoice.DisableParallelToolUse = true
		}
	}
	return json.Marshal(out)
}

// appendTurn merges consecutive same-role turns, as tool results following
// a user message would otherwise produce.
func appendTurn(ms []aMessage, role string, blocks []aBlock) []aMessage {
	if len(blocks) == 0 {
		return ms
	}
	if n := len(ms); n > 0 && ms[n-1].Role == role {
		ms[n-1].Content = append(ms[n-1].Content, blocks...)
		return ms
	}
	return append(ms, aMessage{Role: role, Content: blocks})
}

func userBlock(p contentPart) (*aBlock, error) {
	switch p.Type {
	case "text":
		if p.Text == "" {
			return nil, nil
		}
		return &aBlock{Type: "text", Text: p.Text}, nil
	case "image_url":
		if p.ImageURL == nil || p.ImageURL.URL == "" {
			return nil, badRequest("image_url part without a url")
		}
		u := p.ImageURL.URL
		if rest, ok := strings.CutPrefix(u, "data:"); ok {
			meta, data, ok := strings.Cut(rest, ",")
			mt, isB64 := strings.CutSuffix(meta, ";base64")
			if !ok || !isB64 || mt == "" {
				return nil, badRequest("image data URL must be base64")
			}
			return &aBlock{Type: "image", Source: &aSource{Type: "base64", MediaType: mt, Data: data}}, nil
		}
		// A remote source: the egress body rule admits it only for a
		// public machine (REV-5).
		return &aBlock{Type: "image", Source: &aSource{Type: "url", URL: u}}, nil
	default:
		return nil, unsupported("content part type " + p.Type)
	}
}

func toolChoice(raw json.RawMessage) (*aToolChoice, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		switch s {
		case "auto":
			return &aToolChoice{Type: "auto"}, nil
		case "none":
			return &aToolChoice{Type: "none"}, nil
		case "required":
			return &aToolChoice{Type: "any"}, nil
		}
		return nil, badRequest("tool_choice " + s)
	}
	var o struct {
		Type     string `json:"type"`
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if json.Unmarshal(raw, &o) != nil || o.Type != "function" || o.Function.Name == "" {
		return nil, badRequest("tool_choice must name a function")
	}
	return &aToolChoice{Type: "tool", Name: o.Function.Name}, nil
}

type aResponse struct {
	ID         string `json:"id"`
	StopReason string `json:"stop_reason"`
	Content    []struct {
		Type  string          `json:"type"`
		Text  string          `json:"text"`
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"content"`
	Usage aUsage `json:"usage"`
}

type aUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

func (u aUsage) openAI() map[string]int {
	return map[string]int{
		"prompt_tokens": u.InputTokens, "completion_tokens": u.OutputTokens,
		"total_tokens": u.InputTokens + u.OutputTokens,
	}
}

func finishReason(stop string) string {
	switch stop {
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	case "refusal":
		return "content_filter"
	}
	return "stop"
}

// Response translates a Messages response to a chat completion. The model
// the guest sees is the class it asked for.
func (anthropic) Response(body []byte, class string) ([]byte, error) {
	var r aResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("provider response is not a message: %v", err)
	}
	var text strings.Builder
	var calls []toolCall
	for _, c := range r.Content {
		switch c.Type {
		case "text":
			text.WriteString(c.Text)
		case "tool_use":
			calls = append(calls, toolCall{ID: c.ID, Type: "function", Function: functionCall{Name: c.Name, Arguments: string(c.Input)}})
		}
	}
	msg := map[string]any{"role": "assistant", "content": text.String()}
	if text.Len() == 0 && len(calls) > 0 {
		msg["content"] = nil
	}
	if len(calls) > 0 {
		msg["tool_calls"] = calls
	}
	return json.Marshal(map[string]any{
		"id": "chatcmpl-" + r.ID, "object": "chat.completion", "created": time.Now().Unix(), "model": class,
		"choices": []any{map[string]any{"index": 0, "message": msg, "finish_reason": finishReason(r.StopReason)}},
		"usage":   r.Usage.openAI(),
	})
}

// errorTypes maps Messages API error types to the OpenAI types a guest's
// client library branches on.
var errorTypes = map[string]string{
	"invalid_request_error": "invalid_request_error",
	"authentication_error":  "authentication_error",
	"permission_error":      "permission_error",
	"not_found_error":       "not_found_error",
	"request_too_large":     "invalid_request_error",
	"rate_limit_error":      "rate_limit_error",
	"api_error":             "server_error",
	"overloaded_error":      "server_error",
}

func (anthropic) Error(status int, body []byte) []byte {
	var e struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil || e.Error.Type == "" {
		return apiError(fmt.Sprintf("provider error (HTTP %d)", status), "server_error", "")
	}
	typ := errorTypes[e.Error.Type]
	if typ == "" {
		typ = "server_error"
	}
	return apiError(e.Error.Message, typ, e.Error.Type)
}

type aEvent struct {
	Type    string `json:"type"`
	Index   int    `json:"index"`
	Message *struct {
		ID    string `json:"id"`
		Usage aUsage `json:"usage"`
	} `json:"message"`
	ContentBlock *struct {
		Type string `json:"type"`
		ID   string `json:"id"`
		Name string `json:"name"`
		Text string `json:"text"`
	} `json:"content_block"`
	Delta *struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		PartialJSON string `json:"partial_json"`
		StopReason  string `json:"stop_reason"`
	} `json:"delta"`
	Usage *aUsage `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// Stream translates Messages server-sent events into chat-completion
// chunks, ending with data: [DONE] as OpenAI clients expect.
func (anthropic) Stream(dst io.Writer, flush func(), src io.Reader, class string, includeUsage bool) error {
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	var (
		id      = "chatcmpl-stream"
		created = time.Now().Unix()
		usage   aUsage
		tools   = map[int]int{} // Messages block index -> chat tool call index
	)
	send := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(dst, "data: %s\n\n", b); err != nil {
			return err
		}
		flush()
		return nil
	}
	chunk := func(delta map[string]any, finish any) error {
		return send(map[string]any{
			"id": id, "object": "chat.completion.chunk", "created": created, "model": class,
			"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}},
		})
	}
	for sc.Scan() {
		data, ok := strings.CutPrefix(sc.Text(), "data:")
		if !ok {
			continue
		}
		var ev aEvent
		if err := json.Unmarshal([]byte(strings.TrimSpace(data)), &ev); err != nil {
			return fmt.Errorf("provider stream: %v", err)
		}
		var err error
		switch ev.Type {
		case "message_start":
			if ev.Message != nil {
				id = "chatcmpl-" + ev.Message.ID
				usage.InputTokens = ev.Message.Usage.InputTokens
			}
			err = chunk(map[string]any{"role": "assistant", "content": ""}, nil)
		case "content_block_start":
			if b := ev.ContentBlock; b != nil {
				switch {
				case b.Type == "tool_use":
					i := len(tools)
					tools[ev.Index] = i
					err = chunk(map[string]any{"tool_calls": []any{map[string]any{
						"index": i, "id": b.ID, "type": "function",
						"function": map[string]any{"name": b.Name, "arguments": ""},
					}}}, nil)
				case b.Type == "text" && b.Text != "":
					err = chunk(map[string]any{"content": b.Text}, nil)
				}
			}
		case "content_block_delta":
			if d := ev.Delta; d != nil {
				switch d.Type {
				case "text_delta":
					err = chunk(map[string]any{"content": d.Text}, nil)
				case "input_json_delta":
					if i, ok := tools[ev.Index]; ok {
						err = chunk(map[string]any{"tool_calls": []any{map[string]any{
							"index": i, "function": map[string]any{"arguments": d.PartialJSON},
						}}}, nil)
					}
				}
			}
		case "message_delta":
			if ev.Usage != nil {
				usage.OutputTokens = ev.Usage.OutputTokens
			}
			if ev.Delta != nil && ev.Delta.StopReason != "" {
				err = chunk(map[string]any{}, finishReason(ev.Delta.StopReason))
			}
		case "message_stop":
			if includeUsage {
				if err := send(map[string]any{
					"id": id, "object": "chat.completion.chunk", "created": created, "model": class,
					"choices": []any{}, "usage": usage.openAI(),
				}); err != nil {
					return err
				}
			}
			_, err := io.WriteString(dst, "data: [DONE]\n\n")
			flush()
			return err
		case "error":
			msg, typ := "provider stream error", "server_error"
			if ev.Error != nil {
				msg = ev.Error.Message
				if t := errorTypes[ev.Error.Type]; t != "" {
					typ = t
				}
			}
			fmt.Fprintf(dst, "data: %s\n\n", apiError(msg, typ, ""))
			flush()
			return errors.New("provider stream ended with an error event")
		}
		if err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return io.ErrUnexpectedEOF
}
