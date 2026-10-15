package localui

import (
	"context"
	"errors"
	"html"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: ONB-3, CRED-5, CRED-1

// U-2 (#1265): each way the vault can refuse a key shows its own text, so
// the owner is told the provider said no only when it did. Nothing is
// stored and the key is never shown back.
func TestTheAIKeyErrorsNameTheirCause(t *testing.T) {
	r := newRig(t)
	r.runSetupToAI()
	seen := map[string]bool{}
	for _, c := range []struct {
		err  error
		want string
	}{
		{ErrKeyRefused, "The provider did not accept that key."},
		{ErrKeyUnchecked, "could not reach the provider to check that key"},
		{ErrKeysLimited, "Too many keys"},
		{ErrKeyNotTaken, "Paste the API key"},
		{ErrSetupClosed, "Setup is already done."},
		{ErrCodesUnavailable, cannotFinish},
		{errors.New("vault: " + apiCanary), "Could not save the key."},
	} {
		r.hooks.mu.Lock()
		r.hooks.keyErr = c.err
		r.hooks.mu.Unlock()
		w := r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}, "private": {"1"}})
		got := html.UnescapeString(r.setupErr())
		if !strings.Contains(got, c.want) {
			t.Fatalf("%v: page says %q, want %q", c.err, got, c.want)
		}
		if c.err != ErrKeyRefused && strings.Contains(got, "did not accept") {
			t.Fatalf("%v: blamed the provider: %q", c.err, got)
		}
		if seen[got] {
			t.Fatalf("%v: text %q is shared with another cause", c.err, got)
		}
		seen[got] = true
		if strings.Contains(w.Body.String(), apiCanary) || strings.Contains(r.get("/setup"), apiCanary) {
			t.Fatalf("%v: the page showed the key back", c.err)
		}
		if len(r.hooks.keys) != 0 || r.hooks.finished != "" {
			t.Fatalf("%v: stored or finished", c.err)
		}
	}
}

// ownerAnswers is agentosd answering every call with one refusal, and
// recording how long the page would wait.
type ownerAnswers struct {
	code string
	wait *time.Duration
}

func (o ownerAnswers) Call(ctx context.Context, _ string, _, _ any) error {
	if d, ok := ctx.Deadline(); ok {
		*o.wait = time.Until(d)
	}
	if o.code == "" {
		return nil
	}
	return Refused(o.code)
}

// ConnectAPIKey names agentosd's fixed refusals as the page's errors, and
// waits APIKeyTimeout, longer than agentosd waits for the vault process's
// key check (Security L8.4).
func TestConnectAPIKeyNamesAgentosdsAnswer(t *testing.T) {
	var wait time.Duration
	for code, want := range map[string]error{
		localapi.ErrKeyRefused:        ErrKeyRefused,
		localapi.ErrKeyUnchecked:      ErrKeyUnchecked,
		localapi.ErrLimited:           ErrKeysLimited,
		localapi.ErrBadArgs:           ErrKeyNotTaken,
		localapi.ErrSetupClosed:       ErrSetupClosed,
		localapi.ErrEnrollUnavailable: ErrCodesUnavailable,
	} {
		err := AgentosdSetup{Owner: ownerAnswers{code, &wait}}.ConnectAPIKey("openai", apiCanary)
		if !errors.Is(err, want) || !refused(err, code) {
			t.Fatalf("%s: %v, want %v", code, err, want)
		}
		if strings.Contains(err.Error(), apiCanary) {
			t.Fatalf("%s: the error carries the key", code)
		}
	}
	if err := (AgentosdSetup{Owner: ownerAnswers{localapi.ErrFailed, &wait}}).ConnectAPIKey("openai", apiCanary); !refused(err, localapi.ErrFailed) || errors.Is(err, ErrKeyRefused) {
		t.Fatalf("failed: %v", err)
	}
	if err := (AgentosdSetup{Owner: ownerAnswers{"", &wait}}).ConnectAPIKey("openai", apiCanary); err != nil {
		t.Fatal(err)
	}
	if wait <= callTimeout || wait > localapi.APIKeyTimeout {
		t.Fatalf("the page waits %v for a key check", wait)
	}
}
