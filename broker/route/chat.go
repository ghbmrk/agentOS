package route

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/ghbmrk/agentos/broker/meter"
)

// chatRequest is the part of an OpenAI chat-completions body (the guest
// interface, ARC-6 (a)) the router accepts. The router decodes the guest's
// body into it and each provider encodes its own request from it. Every
// field, nested ones included, is typed: a key or part type not listed
// here never reaches a provider. The one exception is a function's
// parameters, which is the guest's own JSON schema.
type chatRequest struct {
	Model               string          `json:"model"`
	Messages            []chatMessage   `json:"messages"`
	MaxTokens           *int            `json:"max_tokens,omitempty"`
	MaxCompletionTokens *int            `json:"max_completion_tokens,omitempty"`
	Temperature         *float64        `json:"temperature,omitempty"`
	TopP                *float64        `json:"top_p,omitempty"`
	Stop                stopList        `json:"stop,omitempty"`
	Stream              bool            `json:"stream,omitempty"`
	StreamOptions       *streamOptions  `json:"stream_options,omitempty"`
	Tools               []chatTool      `json:"tools,omitempty"`
	ToolChoice          *toolChoice     `json:"tool_choice,omitempty"`
	ParallelToolCalls   *bool           `json:"parallel_tool_calls,omitempty"`
	ResponseFormat      *responseFormat `json:"response_format,omitempty"`
	N                   *int            `json:"n,omitempty"`
	Seed                *int64          `json:"seed,omitempty"`
	PresencePenalty     *float64        `json:"presence_penalty,omitempty"`
	FrequencyPenalty    *float64        `json:"frequency_penalty,omitempty"`
}

type streamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

type chatMessage struct {
	Role       string     `json:"role"`
	Content    *content   `json:"content,omitempty"`
	Name       string     `json:"name,omitempty"`
	ToolCalls  []toolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// roles the router accepts. "function" is the legacy tool-result role.
var roles = map[string]bool{"system": true, "developer": true, "user": true, "assistant": true, "tool": true, "function": true}

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
	Strict      *bool           `json:"strict,omitempty"`
}

// content is a message's content: a string, or a list of text and
// image_url parts. It encodes in the form it was given.
type content struct {
	Text  *string
	Parts []contentPart
}

type contentPart struct {
	Type     string    `json:"type"`
	Text     string    `json:"text,omitempty"`
	ImageURL *imageURL `json:"image_url,omitempty"`
}

type imageURL struct {
	URL    string `json:"url"`
	Detail string `json:"detail,omitempty"`
}

func (c *content) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		c.Text = &s
		return nil
	}
	if err := json.Unmarshal(b, &c.Parts); err != nil {
		return errors.New("content must be a string or a list of parts")
	}
	for _, p := range c.Parts {
		switch {
		case p.Type == "text":
		case p.Type == "image_url" && p.ImageURL != nil && p.ImageURL.URL != "":
		default:
			return fmt.Errorf("content part %q is not accepted (text and image_url only)", p.Type)
		}
	}
	return nil
}

func (c content) MarshalJSON() ([]byte, error) {
	if c.Text != nil {
		return json.Marshal(*c.Text)
	}
	if c.Parts == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(c.Parts)
}

// parts returns content as parts: a string is one text part.
func (c *content) parts() []contentPart {
	switch {
	case c == nil:
		return nil
	case c.Text != nil:
		return []contentPart{{Type: "text", Text: *c.Text}}
	}
	return c.Parts
}

// stopList is the stop field: a string or a list of strings. It always
// encodes as a list.
type stopList []string

func (s *stopList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var one string
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*s = stopList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return errors.New("stop must be a string or a list of strings")
	}
	*s = many
	return nil
}

// toolChoice is auto, none, required, or one named function.
type toolChoice struct {
	Mode     string // auto, none, required; empty when Function is set
	Function string
}

func (t *toolChoice) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		switch s {
		case "auto", "none", "required":
			t.Mode = s
			return nil
		}
		return fmt.Errorf("tool_choice %q is not accepted", s)
	}
	var o struct {
		Type     string `json:"type"`
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if json.Unmarshal(b, &o) != nil || o.Type != "function" || o.Function.Name == "" {
		return errors.New("tool_choice must be auto, none, required, or a named function")
	}
	t.Function = o.Function.Name
	return nil
}

func (t toolChoice) MarshalJSON() ([]byte, error) {
	if t.Function != "" {
		return json.Marshal(map[string]any{"type": "function", "function": map[string]string{"name": t.Function}})
	}
	return json.Marshal(t.Mode)
}

// responseFormat is text, json_object, or json_schema.
type responseFormat struct {
	Type       string      `json:"type"`
	JSONSchema *jsonSchema `json:"json_schema,omitempty"`
}

type jsonSchema struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Schema      json.RawMessage `json:"schema,omitempty"`
	Strict      *bool           `json:"strict,omitempty"`
}

// chatKeys are chatRequest's top-level keys.
var chatKeys = func() []string {
	t := reflect.TypeFor[chatRequest]()
	keys := make([]string, t.NumField())
	for i := range keys {
		keys[i], _, _ = strings.Cut(t.Field(i).Tag.Get("json"), ",")
	}
	return keys
}()

// parseChat decodes exactly one JSON object; trailing data is refused, so
// the router and every provider read the same request. Its top-level keys
// pass meter.Object first: the decoder below matches them to fields
// case-insensitively, last match winning, so a repeated key, or one
// differing from another or from a field only in case, would let it read
// a value (n, an output limit) other than the one the meter checked.
func parseChat(body []byte) (*chatRequest, error) {
	if _, err := meter.Object(body, chatKeys...); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	var req chatRequest
	if err := dec.Decode(&req); err != nil {
		return nil, fmt.Errorf("body is not an accepted chat completions request: %v", err)
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
	for _, m := range req.Messages {
		if !roles[m.Role] {
			return nil, fmt.Errorf("message role %q is not accepted", m.Role)
		}
	}
	for _, t := range req.Tools {
		if t.Type != "function" || t.Function.Name == "" {
			return nil, errors.New("only function tools are accepted")
		}
	}
	if rf := req.ResponseFormat; rf != nil {
		switch {
		case rf.Type == "text" || rf.Type == "json_object":
			rf.JSONSchema = nil
		case rf.Type == "json_schema" && rf.JSONSchema != nil && rf.JSONSchema.Name != "":
		default:
			return nil, errors.New("response_format must be text, json_object, or json_schema")
		}
	}
	return &req, nil
}

// apiError is the OpenAI error body, which is what a chat-completions
// guest expects to parse.
func apiError(message, typ, code string) []byte {
	b, _ := json.Marshal(map[string]any{"error": map[string]any{
		"message": message, "type": typ, "code": code,
	}})
	return b
}

// isAPIError reports whether b is a JSON object carrying an error object.
func isAPIError(b []byte) bool {
	var e struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	return json.Unmarshal(b, &e) == nil && e.Error != nil
}

// Usage is what one call cost. Input excludes cached tokens: CacheRead
// and CacheWrite count them separately, since providers bill them at
// their own weights. Reported says the provider gave the counts; Complete
// says the response finished normally. When usage is not reported, or
// the stream was cut off, the meter falls back to OutputChars, the
// characters of content and tool arguments the provider produced as the
// router saw them (also the floor for a cut-off stream).
type Usage struct {
	Input       int64 `json:"input"`
	Output      int64 `json:"output"`
	CacheRead   int64 `json:"cache_read,omitempty"`
	CacheWrite  int64 `json:"cache_write,omitempty"`
	Reported    bool  `json:"reported"`
	Complete    bool  `json:"complete"`
	OutputChars int64 `json:"output_chars"`
}

// Total is every token the call was billed for.
func (u Usage) Total() int64 { return u.Input + u.Output + u.CacheRead + u.CacheWrite }

// openAI renders u as a chat-completions usage object: prompt tokens
// include cached ones, and cache reads appear as cached_tokens.
func (u Usage) openAI() map[string]any {
	prompt := u.Input + u.CacheRead + u.CacheWrite
	return map[string]any{
		"prompt_tokens": prompt, "completion_tokens": u.Output, "total_tokens": prompt + u.Output,
		"prompt_tokens_details": map[string]int64{"cached_tokens": u.CacheRead},
	}
}

// oaUsage is a chat-completions usage object as OpenAI reports it.
type oaUsage struct {
	PromptTokens        int64  `json:"prompt_tokens"`
	CompletionTokens    *int64 `json:"completion_tokens"` // nil: not reported
	PromptTokensDetails struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
}

// usage is reported only with an output count (see aUsage.usage).
func (o oaUsage) usage() Usage {
	u := Usage{Input: o.PromptTokens - o.PromptTokensDetails.CachedTokens, CacheRead: o.PromptTokensDetails.CachedTokens, Reported: o.CompletionTokens != nil}
	if o.CompletionTokens != nil {
		u.Output = *o.CompletionTokens
	}
	return u
}
