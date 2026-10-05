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
		Usage *oaUsage `json:"usage"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, Usage{}, fmt.Errorf("provider response is not a completion: %v", err)
	}
	var u Usage
	if r.Usage != nil {
		u = r.Usage.usage()
	}
	return body, u, nil
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
			_, err := io.WriteString(dst, "data: [DONE]\n\n")
			flush()
			return u, err
		}
		var c struct {
			Usage   *oaUsage          `json:"usage"`
			Choices []json.RawMessage `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			return u, fmt.Errorf("provider stream: %v", err)
		}
		if c.Usage != nil {
			u = c.Usage.usage()
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
