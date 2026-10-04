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

func TestAnthropicCannotExpress(t *testing.T) {
	for _, body := range []string{
		`{"model":"c","n":2,"messages":[{"role":"user","content":"hi"}]}`,
		`{"model":"c","response_format":{"type":"json_schema","json_schema":{}},"messages":[{"role":"user","content":"hi"}]}`,
		`{"model":"c","messages":[{"role":"user","content":[{"type":"input_audio"}]}]}`,
		`{"model":"c","messages":[{"role":"assistant","tool_calls":[{"id":"x","type":"function","function":{"name":"f","arguments":"[1]"}}]}]}`,
	} {
		req, err := parseChat([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		_, err = Anthropic().Request(req, "m")
		var u errUnsupported
		if !asUnsupported(err, &u) {
			t.Fatalf("%s: want unsupported, got %v", body, err)
		}
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
	out, err := Anthropic().Response(fixture(t, "anthropic_message.json"), "default")
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
		Usage map[string]int
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
	if c.Usage["prompt_tokens"] != 412 || c.Usage["completion_tokens"] != 57 || c.Usage["total_tokens"] != 469 {
		t.Fatalf("usage %v", c.Usage)
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
	usage   map[string]int
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
			Usage map[string]int
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
	err := Anthropic().Stream(&out, func() { flushes++ }, bytes.NewReader(fixture(t, "anthropic_stream.sse")), "default", true)
	if err != nil {
		t.Fatal(err)
	}
	a := reassemble(t, out.Bytes())
	if !a.done || a.role != "assistant" || a.text != "Hello, world" || a.finish != "tool_calls" {
		t.Fatalf("%+v", a)
	}
	if a.names[0] != "get_weather" || a.ids[0] != "toolu_01SyntheticStream01" {
		t.Fatalf("tool call %+v", a)
	}
	jsonEqual(t, []byte(a.args[0]), []byte(`{"city":"Paris"}`))
	if a.usage["prompt_tokens"] != 25 || a.usage["completion_tokens"] != 32 {
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
	if err := Anthropic().Stream(&out, func() {}, bytes.NewReader(cut), "default", false); err == nil {
		t.Fatal("a stream without message_stop must report an error")
	}
	if strings.Contains(out.String(), "[DONE]") {
		t.Fatal("a truncated stream must not claim completion")
	}
	out.Reset()
	errStream := "event: error\ndata: " + strings.TrimSpace(string(fixture(t, "anthropic_overloaded.json"))) + "\n\n"
	if err := Anthropic().Stream(&out, func() {}, strings.NewReader(errStream), "default", false); err == nil {
		t.Fatal("error event must end the stream with an error")
	}
	if !strings.Contains(out.String(), `"server_error"`) || strings.Contains(out.String(), "[DONE]") {
		t.Fatalf("guest must see an error chunk: %s", out.String())
	}
}
