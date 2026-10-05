package egress

import (
	"net/http"
	"testing"
)

// REQ: ADP-10

// The proxy marks its own denials, and a provider cannot forge the mark.
func TestDenialsAreMarkedAndProviderCannotForgeMark(t *testing.T) {
	r := newRig(t, nil)
	w := r.do(t, "m1", chat("/openai/v1/models"))
	if w.Code != http.StatusForbidden || w.Header().Get(DeniedHeader) != "1" {
		t.Fatalf("denial %d, mark %q", w.Code, w.Header().Get(DeniedHeader))
	}
	r.provider.reply = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(DeniedHeader, "1")
		w.WriteHeader(http.StatusTooManyRequests)
	}
	w = r.do(t, "m1", chat("/openai/v1/chat/completions"))
	if w.Code != http.StatusTooManyRequests || w.Header().Get(DeniedHeader) != "" {
		t.Fatalf("provider 429 %d, mark %q", w.Code, w.Header().Get(DeniedHeader))
	}
}
