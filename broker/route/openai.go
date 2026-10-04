package route

import (
	"encoding/json"
	"io"
)

// openAI speaks the guest's own interface, so it re-encodes the parsed
// request with the route's model and passes responses through unchanged.
type openAI struct{ adapter string }

// OpenAI is the provider for egress.OpenAI's relay (adapter "openai").
func OpenAI() Provider { return openAI{adapter: "openai"} }

func (o openAI) Name() string                  { return o.adapter }
func (openAI) Path() string                    { return "/v1/chat/completions" }
func (openAI) Headers() map[string]string      { return nil }
func (openAI) Error(_ int, body []byte) []byte { return body }

func (openAI) Request(req *chatRequest, model string) ([]byte, error) {
	out := *req
	out.Model = model
	return json.Marshal(out)
}

func (openAI) Response(body []byte, _ string) ([]byte, error) { return body, nil }

func (openAI) Stream(dst io.Writer, flush func(), src io.Reader, _ string, _ bool) error {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
			flush()
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
