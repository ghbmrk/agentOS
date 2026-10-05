package route

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// openAI speaks the guest's own interface, so it re-encodes the parsed
// request with the route's model and passes responses through, reading
// the usage they report.
type openAI struct{ adapter string }

// OpenAI is the provider for egress.OpenAI's relay (adapter "openai").
func OpenAI() Provider { return openAI{adapter: "openai"} }

func (o openAI) Name() string                  { return o.adapter }
func (openAI) Path() string                    { return "/v1/chat/completions" }
func (openAI) Headers() map[string]string      { return nil }
func (openAI) Error(_ int, body []byte) []byte { return body }

// Request always asks for usage on streams, so the router can report it;
// Stream drops the usage chunk again if the guest did not ask for it.
func (openAI) Request(req *chatRequest, model string) ([]byte, error) {
	out := *req
	out.Model = model
	if out.Stream {
		out.StreamOptions = &streamOptions{IncludeUsage: true}
	}
	return json.Marshal(out)
}

func (openAI) Response(body []byte, _ string) ([]byte, Usage, error) {
	var r struct {
		Usage   *oaUsage `json:"usage"`
		Choices []struct {
			Message oaDelta `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, Usage{}, fmt.Errorf("provider response is not a completion: %v", err)
	}
	var u Usage
	if r.Usage != nil {
		u = r.Usage.usage()
	}
	for _, c := range r.Choices {
		u.OutputChars += c.Message.chars()
	}
	u.Complete = true
	return body, u, nil
}

// oaDelta is the generated part of a message or stream delta.
type oaDelta struct {
	Content   string     `json:"content"`
	ToolCalls []toolCall `json:"tool_calls"`
}

func (d oaDelta) chars() int64 {
	n := int64(len(d.Content))
	for _, tc := range d.ToolCalls {
		n += int64(len(tc.Function.Arguments))
	}
	return n
}

// Stream passes events through as sent, except the usage-only chunk when
// the guest did not ask for one.
func (openAI) Stream(dst io.Writer, flush func(), src io.Reader, _ string, includeUsage bool) (Usage, error) {
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	var u Usage
	for sc.Scan() {
		data, ok := strings.CutPrefix(sc.Text(), "data:")
		if !ok {
			continue
		}
		data = strings.TrimSpace(data)
		if data == "[DONE]" {
			u.Complete = true
			_, err := io.WriteString(dst, "data: [DONE]\n\n")
			flush()
			return u, err
		}
		var c struct {
			Usage   *oaUsage `json:"usage"`
			Choices []struct {
				Delta oaDelta `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			return u, fmt.Errorf("provider stream: %v", err)
		}
		for _, ch := range c.Choices {
			u.OutputChars += ch.Delta.chars()
		}
		if c.Usage != nil {
			chars := u.OutputChars
			u = c.Usage.usage()
			u.OutputChars = chars
			if len(c.Choices) == 0 && !includeUsage {
				continue
			}
		}
		if _, err := fmt.Fprintf(dst, "data: %s\n\n", data); err != nil {
			return u, err
		}
		flush()
	}
	if err := sc.Err(); err != nil {
		return u, err
	}
	return u, io.ErrUnexpectedEOF
}
