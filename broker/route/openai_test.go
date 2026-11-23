package route

import (
	"bytes"
	"strings"
	"testing"
)

// REQ: CAP-9
//
// The OpenAI adapter passes streams through as sent; an error chunk before
// anything was written must leave the stream unstarted so the router can
// fail over (ROUTE-openai-early-error).

func TestOpenAIStreamEarlyErrorNotStarted(t *testing.T) {
	errChunk := "data: " + strings.TrimSpace(string(fixture(t, "openai_insufficient_quota.json"))) + "\n\n"

	// An error before any output writes nothing.
	var out bytes.Buffer
	if _, err := OpenAI().Stream(&out, func() {}, strings.NewReader(errChunk), "default", false); err != errNotStarted || out.Len() != 0 {
		t.Fatalf("early error: %v, wrote %q", err, out.String())
	}

	// An error after output started ends the stream with an error; the
	// guest sees a generic error chunk, never the provider's wording
	// (ROUTE-openai-early-error L1, #1460).
	out.Reset()
	full := fixture(t, "openai_stream.sse")
	first := string(full[:bytes.Index(full, []byte("\n\n"))+2])
	if _, err := OpenAI().Stream(&out, func() {}, strings.NewReader(first+errChunk), "default", false); err == nil || err == errNotStarted {
		t.Fatalf("late error: %v", err)
	}
	if strings.Contains(out.String(), "insufficient_quota") || strings.Contains(out.String(), "[DONE]") ||
		!strings.Contains(out.String(), string(apiError("provider stream error", "server_error", ""))) {
		t.Fatalf("guest must see only a generic error chunk: %s", out.String())
	}
}
