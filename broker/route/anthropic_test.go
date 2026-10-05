package route

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// REQ: CAP-9, ADP-3
//
// Translation between the guest interface (chat completions) and the
// Anthropic Messages API, checked against fixtures in the documented
// shapes (testdata/README.md).

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func jsonEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("got is not JSON: %v\n%s", err, got)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestAnthropicRequestTranslation(t *testing.T) {
	req, err := parseChat(fixture(t, "chat_request.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Anthropic().Request(req, "claude-fixture")
	if err != nil {
		t.Fatal(err)
	}
	// The golden body carries the four prompt-cache breakpoints: last tool,
	// end of the system prompt, and the last two messages.
	jsonEqual(t, got, fixture(t, "anthropic_request.golden.json"))
	for _, dropped := range []string{"guest-supplied-field", `"metadata"`, `"user":`} {
		if bytes.Contains(got, []byte(dropped)) {
			t.Fatalf("undeclared field %s reached the provider body", dropped)
		}
	}
}

func TestAnthropicRequestDefaultsAndChoices(t *testing.T) {
	req, _ := parseChat([]byte(`{"model":"c","messages":[{"role":"user","content":"hi"}],
		"tools":[{"type":"function","function":{"name":"f"}}],
		"tool_choice":{"type":"function","function":{"name":"f"}}}`))
	b, err := Anthropic().Request(req, "m")
	if err != nil {
		t.Fatal(err)
	}
	var a aRequest
	json.Unmarshal(b, &a)
	if a.MaxTokens != DefaultMaxTokens {
		t.Fatalf("max_tokens %d", a.MaxTokens)
	}
	if a.ToolChoice == nil || a.ToolChoice.Type != "tool" || a.ToolChoice.Name != "f" {
		t.Fatalf("tool_choice %+v", a.ToolChoice)
	}
	if string(a.Tools[0].InputSchema) != `{"type":"object","properties":{}}` {
		t.Fatalf("schema %s", a.Tools[0].InputSchema)
	}
}

// ADP-3: valid chat-completions requests the Messages API cannot express
// are unsupported (the router tries the next route), not refused.
func TestAnthropicCannotExpress(t *testing.T) {
	for _, body := range []string{
		`{"model":"c","n":2,"messages":[{"role":"user","content":"hi"}]}`,
		`{"model":"c","response_format":{"type":"json_schema","json_schema":{"name":"x","schema":{}}},"messages":[{"role":"user","content":"hi"}]}`,
		`{"model":"c","response_format":{"type":"json_object"},"messages":[{"role":"user","content":"hi"}]}`,
		`{"model":"c","messages":[{"role":"function","name":"f","content":"42"}]}`,
		`{"model":"c","messages":[{"role":"system","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AA=="}}]},{"role":"user","content":"hi"}]}`,
		`{"model":"c","messages":[{"role":"assistant","tool_calls":[{"id":"x","type":"function","function":{"name":"f","arguments":"[1]"}}]}]}`,
		`{"model":"c","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png,AA"}}]}]}`,
		`{"model":"c","messages":[{"role":"system","content":"only a system prompt"}]}`,
	} {
		req, err := parseChat([]byte(body))
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		_, err = Anthropic().Request(req, "m")
		var u errUnsupported
		if !asUnsupported(err, &u) {
			t.Fatalf("%s: want unsupported, got %v", body, err)
		}
	}
}

// Temperatures above the Messages API's maximum of 1 are clamped to 1.
func TestAnthropicClampsTemperature(t *testing.T) {
	req, _ := parseChat([]byte(`{"model":"c","temperature":1.5,"messages":[{"role":"user","content":"hi"}]}`))
	b, err := Anthropic().Request(req, "m")
	if err != nil {
		t.Fatal(err)
	}
	var a aRequest
	json.Unmarshal(b, &a)
	if a.Temperature == nil || *a.Temperature != 1 {
		t.Fatalf("temperature %v", a.Temperature)
	}
}

func asUnsupported(err error, u *errUnsupported) bool {
	e, ok := err.(errUnsupported)
	if ok {
		*u = e
	}
	return ok
}

func TestAnthropicResponseTranslation(t *testing.T) {
	out, u, err := Anthropic().Response(fixture(t, "anthropic_message.json"), "default")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		ID      string
		Object  string
		Model   string
		Choices []struct {
			Message struct {
				Role      string
				Content   string
				ToolCalls []toolCall `json:"tool_calls"`
			}
			FinishReason string `json:"finish_reason"`
		}
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
			Details          struct {
				CachedTokens int `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
		}
	}
	if err := json.Unmarshal(out, &c); err != nil {
		t.Fatal(err)
	}
	if c.Object != "chat.completion" || c.Model != "default" || c.ID != "chatcmpl-msg_01SyntheticFixture0001" {
		t.Fatalf("envelope %+v", c)
	}
	ch := c.Choices[0]
	if ch.FinishReason != "tool_calls" || ch.Message.Content != "Checking the weather." {
		t.Fatalf("choice %+v", ch)
	}
	tc := ch.Message.ToolCalls[0]
	if tc.ID != "toolu_01SyntheticFixture01" || tc.Type != "function" || tc.Function.Name != "get_weather" {
		t.Fatalf("tool call %+v", tc)
	}
	jsonEqual(t, []byte(tc.Function.Arguments), []byte(`{"city":"Paris","unit":"c"}`))
	// Prompt tokens include cached ones; cache reads show as cached_tokens.
	if c.Usage.PromptTokens != 412+3000+200 || c.Usage.CompletionTokens != 57 || c.Usage.TotalTokens != 3669 ||
		c.Usage.Details.CachedTokens != 3000 {
		t.Fatalf("usage %+v", c.Usage)
	}
	if u != (Usage{Input: 412, Output: 57, CacheRead: 3000, CacheWrite: 200}) {
		t.Fatalf("reported usage %+v", u)
	}
}

func TestAnthropicErrorTranslation(t *testing.T) {
	var e struct {
		Error struct{ Type, Code, Message string }
	}
	json.Unmarshal(Anthropic().Error(429, fixture(t, "anthropic_rate_limit.json")), &e)
	if e.Error.Type != "rate_limit_error" || !strings.Contains(e.Error.Message, "rate limit") {
		t.Fatalf("%+v", e)
	}
	json.Unmarshal(Anthropic().Error(502, []byte("egress denied: x")), &e)
	if e.Error.Type != "server_error" {
		t.Fatalf("%+v", e)
	}
}

// chunks parses an OpenAI-style event stream and reassembles it.
type assembled struct {
	text    string
	role    string
	args    map[int]string
	names   map[int]string
	ids     map[int]string
	finish  string
	usage   map[string]any
	done    bool
	nChunks int
}

func reassemble(t *testing.T, stream []byte) assembled {
	t.Helper()
	a := assembled{args: map[int]string{}, names: map[int]string{}, ids: map[int]string{}}
	sc := bufio.NewScanner(bytes.NewReader(stream))
	for sc.Scan() {
		data, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		if data == "[DONE]" {
			a.done = true
			continue
		}
		var c struct {
			Object  string
			Choices []struct {
				Delta struct {
					Role      string
					Content   string
					ToolCalls []toolCall `json:"tool_calls"`
				}
				FinishReason *string `json:"finish_reason"`
			}
			Usage map[string]any
		}
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			t.Fatalf("chunk %q: %v", data, err)
		}
		if c.Object != "chat.completion.chunk" {
			t.Fatalf("object %q", c.Object)
		}
		a.nChunks++
		if c.Usage != nil {
			a.usage = c.Usage
		}
		for _, ch := range c.Choices {
			if ch.Delta.Role != "" {
				a.role = ch.Delta.Role
			}
			a.text += ch.Delta.Content
			for _, tc := range ch.Delta.ToolCalls {
				i := *tc.Index
				a.args[i] += tc.Function.Arguments
				if tc.Function.Name != "" {
					a.names[i] = tc.Function.Name
				}
				if tc.ID != "" {
					a.ids[i] = tc.ID
				}
			}
			if ch.FinishReason != nil {
				a.finish = *ch.FinishReason
			}
		}
	}
	return a
}

func TestAnthropicStreamTranslation(t *testing.T) {
	var out bytes.Buffer
	flushes := 0
	u, err := Anthropic().Stream(&out, func() { flushes++ }, bytes.NewReader(fixture(t, "anthropic_stream.sse")), "default", true)
	if err != nil {
		t.Fatal(err)
	}
	if u != (Usage{Input: 25, Output: 32, CacheRead: 1800}) {
		t.Fatalf("reported usage %+v", u)
	}
	a := reassemble(t, out.Bytes())
	if !a.done || a.role != "assistant" || a.text != "Hello, world" || a.finish != "tool_calls" {
		t.Fatalf("%+v", a)
	}
	if a.names[0] != "get_weather" || a.ids[0] != "toolu_01SyntheticStream01" {
		t.Fatalf("tool call %+v", a)
	}
	jsonEqual(t, []byte(a.args[0]), []byte(`{"city":"Paris"}`))
	if a.usage["prompt_tokens"] != float64(25+1800) || a.usage["completion_tokens"] != float64(32) {
		t.Fatalf("usage %v", a.usage)
	}
	if flushes < a.nChunks {
		t.Fatalf("each chunk must be flushed: %d flushes, %d chunks", flushes, a.nChunks)
	}
}

func TestAnthropicStreamTruncatedOrError(t *testing.T) {
	full := fixture(t, "anthropic_stream.sse")
	cut := full[:bytes.Index(full, []byte("event: message_delta"))]
	var out bytes.Buffer
	if _, err := Anthropic().Stream(&out, func() {}, bytes.NewReader(cut), "default", false); err == nil {
		t.Fatal("a stream without message_stop must report an error")
	}
	if strings.Contains(out.String(), "[DONE]") {
		t.Fatal("a truncated stream must not claim completion")
	}

	// An error before the message starts writes nothing: the router can
	// still fail over.
	out.Reset()
	errEvent := "event: error\ndata: " + strings.TrimSpace(string(fixture(t, "anthropic_overloaded.json"))) + "\n\n"
	if _, err := Anthropic().Stream(&out, func() {}, strings.NewReader(errEvent), "default", false); err != errNotStarted || out.Len() != 0 {
		t.Fatalf("early error: %v, wrote %q", err, out.String())
	}

	// An error after it started ends the guest's stream with an error chunk.
	out.Reset()
	started := string(full[:bytes.Index(full, []byte("event: content_block_start"))]) + errEvent
	if _, err := Anthropic().Stream(&out, func() {}, strings.NewReader(started), "default", false); err == nil {
		t.Fatal("error event must end the stream with an error")
	}
	if !strings.Contains(out.String(), `"server_error"`) || strings.Contains(out.String(), "[DONE]") {
		t.Fatalf("guest must see an error chunk: %s", out.String())
	}
}

// R4: nested fields are typed allow-lists. Unknown part types, tool_choice
// forms, response formats, and roles are refused; extra keys inside
// accepted objects are dropped.
func TestTypedAllowLists(t *testing.T) {
	for _, body := range []string{
		`{"model":"c","messages":[{"role":"user","content":[{"type":"file","file":{"file_id":"file-canary"}}]}]}`,
		`{"model":"c","messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"AA","format":"wav"}}]}]}`,
		`{"model":"c","messages":[{"role":"user","content":"x"}],"tool_choice":{"type":"custom","custom":{"name":"f"}}}`,
		`{"model":"c","messages":[{"role":"user","content":"x"}],"tool_choice":{"type":"allowed_tools","allowed_tools":{"mode":"auto","tools":[]}}}`,
		`{"model":"c","messages":[{"role":"user","content":"x"}],"response_format":{"type":"json_schema"}}`,
		`{"model":"c","messages":[{"role":"user","content":"x"}],"response_format":{"type":"grammar"}}`,
		`{"model":"c","messages":[{"role":"critic","content":"x"}]}`,
	} {
		if _, err := parseChat([]byte(body)); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	req, err := parseChat([]byte(`{"model":"c","messages":[{"role":"user","extra_smuggle":1,"content":[{"type":"text","text":"hi","extra_smuggle":2},
		{"type":"image_url","image_url":{"url":"data:image/png;base64,AA==","extra_smuggle":3}}]}],
		"tool_choice":"auto","response_format":{"type":"json_object","extra_smuggle":4},"stop":"END"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := OpenAI().Request(req, "gpt")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("extra_smuggle")) {
		t.Fatalf("extra keys reached the provider: %s", b)
	}
	var sent map[string]any
	json.Unmarshal(b, &sent)
	if sent["tool_choice"] != "auto" || sent["stop"].([]any)[0] != "END" || sent["response_format"].(map[string]any)["type"] != "json_object" {
		t.Fatalf("re-encoded %s", b)
	}
}
