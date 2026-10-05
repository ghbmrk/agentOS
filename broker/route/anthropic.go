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
	System        []aBlock     `json:"system,omitempty"`
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
	Cache     *cacheControl   `json:"cache_control,omitempty"`
}

// cacheControl marks a prompt-cache breakpoint: the prefix up to and
// including the marked block is cached, and later calls that resend it
// are billed at the cache-read rate (about a tenth of input).
type cacheControl struct {
	Type string `json:"type"`
}

var ephemeral = &cacheControl{Type: "ephemeral"}

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
	Cache       *cacheControl   `json:"cache_control,omitempty"`
}

type aToolChoice struct {
	Type                   string `json:"type"`
	Name                   string `json:"name,omitempty"`
	DisableParallelToolUse bool   `json:"disable_parallel_tool_use,omitempty"`
}

// Request translates a chat-completions request. A valid request the
// Messages API cannot express (several choices, a structured response
// format, the legacy function role, non-text system content) makes the
// route unable to cover the call, so the router tries the next one.
//
// Agent loops resend a growing prefix (tools, system prompt, history) on
// every call, so Request marks prompt-cache breakpoints: after the tools,
// after the system prompt, and on the last two messages (four, the API's
// limit). A prefix below the model's minimum cacheable length is simply
// not cached.
func (anthropic) Request(req *chatRequest, model string) ([]byte, error) {
	if req.N != nil && *req.N != 1 {
		return nil, unsupported("n other than 1")
	}
	if rf := req.ResponseFormat; rf != nil && rf.Type != "text" {
		return nil, unsupported("response_format " + rf.Type)
	}
	out := aRequest{Model: model, Temperature: req.Temperature, TopP: req.TopP, Stream: req.Stream, MaxTokens: DefaultMaxTokens}
	if t := out.Temperature; t != nil && *t > 1 {
		// Chat completions allows up to 2, the Messages API up to 1.
		one := 1.0
		out.Temperature = &one
	}
	switch {
	case req.MaxCompletionTokens != nil:
		out.MaxTokens = *req.MaxCompletionTokens
	case req.MaxTokens != nil:
		out.MaxTokens = *req.MaxTokens
	}
	out.StopSequences = req.Stop
	for _, m := range req.Messages {
		ps := m.Content.parts()
		switch m.Role {
		case "system", "developer":
			for _, p := range ps {
				if p.Type != "text" {
					return nil, unsupported("non-text system content")
				}
				if p.Text != "" {
					out.System = append(out.System, aBlock{Type: "text", Text: p.Text})
				}
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
					return nil, unsupported("non-text assistant content")
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
					return nil, unsupported("non-text tool content")
				}
				if p.Text != "" {
					inner = append(inner, aBlock{Type: "text", Text: p.Text})
				}
			}
			out.Messages = appendTurn(out.Messages, "user", []aBlock{{Type: "tool_result", ToolUseID: m.ToolCallID, Content: inner}})
		default:
			return nil, unsupported("message role " + m.Role)
		}
	}
	if len(out.Messages) == 0 {
		return nil, unsupported("a conversation with no user or assistant messages")
	}
	for _, t := range req.Tools {
		schema := t.Function.Parameters
		if len(bytes.TrimSpace(schema)) == 0 {
			schema = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		out.Tools = append(out.Tools, aTool{Name: t.Function.Name, Description: t.Function.Description, InputSchema: schema})
	}
	if tc := req.ToolChoice; tc != nil {
		switch {
		case tc.Function != "":
			out.ToolChoice = &aToolChoice{Type: "tool", Name: tc.Function}
		case tc.Mode == "required":
			out.ToolChoice = &aToolChoice{Type: "any"}
		default:
			out.ToolChoice = &aToolChoice{Type: tc.Mode}
		}
	}
	if req.ParallelToolCalls != nil && !*req.ParallelToolCalls && len(out.Tools) > 0 {
		if out.ToolChoice == nil {
			out.ToolChoice = &aToolChoice{Type: "auto"}
		}
		if out.ToolChoice.Type != "none" {
			out.ToolChoice.DisableParallelToolUse = true
		}
	}
	if n := len(out.Tools); n > 0 {
		out.Tools[n-1].Cache = ephemeral
	}
	if n := len(out.System); n > 0 {
		out.System[n-1].Cache = ephemeral
	}
	for i := len(out.Messages) - 1; i >= 0 && i >= len(out.Messages)-2; i-- {
		c := out.Messages[i].Content
		c[len(c)-1].Cache = ephemeral
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
			return nil, unsupported("image_url part without a url")
		}
		u := p.ImageURL.URL
		if rest, ok := strings.CutPrefix(u, "data:"); ok {
			meta, data, ok := strings.Cut(rest, ",")
			mt, isB64 := strings.CutSuffix(meta, ";base64")
			if !ok || !isB64 || mt == "" {
				return nil, unsupported("image data URL that is not base64")
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
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
}

func (u aUsage) usage() Usage {
	return Usage{Input: u.InputTokens, Output: u.OutputTokens, CacheRead: u.CacheReadInputTokens, CacheWrite: u.CacheCreationInputTokens}
}

// merge takes the nonzero counts of a later usage report (message_delta
// carries cumulative counts, sometimes only the output).
func (u *aUsage) merge(o aUsage) {
	for _, f := range []struct {
		dst *int64
		src int64
	}{
		{&u.InputTokens, o.InputTokens}, {&u.OutputTokens, o.OutputTokens},
		{&u.CacheReadInputTokens, o.CacheReadInputTokens}, {&u.CacheCreationInputTokens, o.CacheCreationInputTokens},
	} {
		if f.src != 0 {
			*f.dst = f.src
		}
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
func (anthropic) Response(body []byte, class string) ([]byte, Usage, error) {
	var r aResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, Usage{}, fmt.Errorf("provider response is not a message: %v", err)
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
	u := r.Usage.usage()
	out, err := json.Marshal(map[string]any{
		"id": "chatcmpl-" + r.ID, "object": "chat.completion", "created": time.Now().Unix(), "model": class,
		"choices": []any{map[string]any{"index": 0, "message": msg, "finish_reason": finishReason(r.StopReason)}},
		"usage":   u.openAI(),
	})
	return out, u, err
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
// chunks, ending with data: [DONE] as OpenAI clients expect. Usage is read
// from message_start and message_delta whether or not the guest asked for
// it. An error event before the message starts writes nothing, so the
// router can still fail over.
func (anthropic) Stream(dst io.Writer, flush func(), src io.Reader, class string, includeUsage bool) (Usage, error) {
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	var (
		id      = "chatcmpl-stream"
		created = time.Now().Unix()
		usage   aUsage
		started bool
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
			return usage.usage(), fmt.Errorf("provider stream: %v", err)
		}
		var err error
		switch ev.Type {
		case "message_start":
			started = true
			if ev.Message != nil {
				id = "chatcmpl-" + ev.Message.ID
				usage.merge(ev.Message.Usage)
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
				usage.merge(*ev.Usage)
			}
			if ev.Delta != nil && ev.Delta.StopReason != "" {
				err = chunk(map[string]any{}, finishReason(ev.Delta.StopReason))
			}
		case "message_stop":
			if includeUsage {
				if err := send(map[string]any{
					"id": id, "object": "chat.completion.chunk", "created": created, "model": class,
					"choices": []any{}, "usage": usage.usage().openAI(),
				}); err != nil {
					return usage.usage(), err
				}
			}
			_, err := io.WriteString(dst, "data: [DONE]\n\n")
			flush()
			return usage.usage(), err
		case "error":
			msg, typ := "provider stream error", "server_error"
			if ev.Error != nil {
				msg = ev.Error.Message
				if t := errorTypes[ev.Error.Type]; t != "" {
					typ = t
				}
			}
			if !started {
				return usage.usage(), errNotStarted
			}
			fmt.Fprintf(dst, "data: %s\n\n", apiError(msg, typ, ""))
			flush()
			return usage.usage(), errors.New("provider stream ended with an error event")
		}
		if err != nil {
			return usage.usage(), err
		}
	}
	if err := sc.Err(); err != nil {
		return usage.usage(), err
	}
	return usage.usage(), io.ErrUnexpectedEOF
}
