package sipline_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem/sipline"
	"github.com/ghbmrk/agentos/broker/smsapi"
)

// REQ: ADP-12, CH-1

// httpTexts stands in for the vault process's sms.sock (smsapi.Client).
type httpTexts struct {
	mu    sync.Mutex
	sent  []string
	inbox []smsapi.Inbound
	polls int
	fail  error
}

func (h *httpTexts) Send(ctx context.Context, to, text string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fail != nil {
		return h.fail
	}
	h.sent = append(h.sent, to+": "+text)
	return nil
}

func (h *httpTexts) Poll(ctx context.Context) ([]smsapi.Inbound, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.polls++
	in := h.inbox
	h.inbox = nil
	return in, nil
}

func (h *httpTexts) receive(in ...smsapi.Inbound) {
	h.mu.Lock()
	h.inbox = append(h.inbox, in...)
	h.mu.Unlock()
}

// Potency PL1 on #102 (P2-3c part 5b): with a texting account the line's
// texts go over the provider's HTTP API through the vault process, never
// as SIP MESSAGE; calls stay on SIP.
func TestWithATextingAccountTextsGoOverHTTP(t *testing.T) {
	defer sipline.SetPollEvery(10 * time.Millisecond)()
	p := provider(t)
	s := vault(p)
	h := &httpTexts{}
	cfg := config(p, s)
	cfg.Texts = h
	l := open(t, p, cfg)
	if err := l.Send("+1 (555) 000-0777", "Table for 2 at 7?"); err != nil {
		t.Fatal(err)
	}
	if len(h.sent) != 1 || h.sent[0] != "+15550000777: Table for 2 at 7?" {
		t.Fatalf("sent %q", h.sent)
	}
	select {
	case m := <-p.Texts():
		t.Fatalf("a SIP MESSAGE went out too: %+v", m)
	case <-time.After(30 * time.Millisecond):
	}
	if s.methods()["MESSAGE"] != 0 {
		t.Fatal("a MESSAGE was signed")
	}
	for _, to := range []string{"15550000777", "1555@evil.example", "+1555+0000777", ""} {
		if err := l.Send(to, "x"); !errors.Is(err, sipline.ErrNumber) {
			t.Errorf("Send to %q: %v", to, err)
		}
	}
	h.mu.Lock()
	h.fail = smsapi.ErrLimited
	h.mu.Unlock()
	if err := l.Send(shopNum, "x"); !errors.Is(err, smsapi.ErrLimited) || !strings.Contains(sipline.OwnerText(err), "sent as many texts as it may") {
		t.Fatalf("limited: %v", err)
	}
}

// Texts the vault process fetched reach the inbox as data, a sender name
// labelled as one, exactly as texts by SIP MESSAGE do.
func TestPolledTextsReachTheInbox(t *testing.T) {
	defer sipline.SetPollEvery(10 * time.Millisecond)()
	p := provider(t)
	h := &httpTexts{}
	cfg := config(p, vault(p))
	cfg.Texts = h
	l := open(t, p, cfg)
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	h.receive(smsapi.Inbound{ID: "SM1", From: shopNum, Text: "STOP", At: at}, smsapi.Inbound{ID: "SM2", From: "ShopCo", Named: true, Text: "Your table is ready", At: at})
	m := <-l.Inbox()
	if m.From != shopNum || m.Text != "STOP" || m.Alphanumeric || m.To != sipNum || !m.At.Equal(at) {
		t.Fatalf("%+v", m)
	}
	m = <-l.Inbox()
	if !m.Alphanumeric || m.From != "alpha:ShopCo" {
		t.Fatalf("%+v", m)
	}
	l.Close()
	h.mu.Lock()
	n := h.polls
	h.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.polls > n+1 {
		t.Fatalf("still polling after Close: %d then %d", n, h.polls)
	}
}

// Each texting refusal has its owner wording, without internals.
func TestTextingErrorsHaveOwnerWording(t *testing.T) {
	for err, want := range map[error]string{
		smsapi.ErrLocked:      "while I am locked. Unlock me on my Wi-Fi page",
		smsapi.ErrNoAccount:   "texting account isn't set up. Set it up on my Wi-Fi page",
		smsapi.ErrRecipient:   "doesn't text or call that number",
		smsapi.ErrLimited:     "sent as many texts as it may",
		smsapi.ErrTooLong:     "too long",
		smsapi.ErrRefused:     "provider didn't accept",
		smsapi.ErrUnreachable: "couldn't reach its provider",
	} {
		got := sipline.OwnerText(err)
		if !strings.Contains(got, want) || strings.ContainsAny(got, "0123456789") || strings.Contains(got, "smsapi") {
			t.Errorf("%v: %q", err, got)
		}
	}
}

// UX nit on #159: a full inbox drops polled texts rather than queueing
// without bound, and says how many in the log, never their text.
func TestAFullInboxLogsHowManyTextsItDropped(t *testing.T) {
	defer sipline.SetPollEvery(10 * time.Millisecond)()
	p := provider(t)
	h := &httpTexts{}
	cfg := config(p, vault(p))
	cfg.Texts = h
	var mu sync.Mutex
	var logs bytes.Buffer
	cfg.Log = slog.New(slog.NewTextHandler(lockedWriter{&mu, &logs}, nil))
	open(t, p, cfg)
	var in []smsapi.Inbound
	for i := 0; i < 70; i++ {
		in = append(in, smsapi.Inbound{ID: "SM", From: shopNum, Text: "secret-text", At: time.Now()})
	}
	h.receive(in...)
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		l := logs.String()
		mu.Unlock()
		if strings.Contains(l, "count=6") {
			if strings.Contains(l, "secret-text") {
				t.Fatalf("log carries the text: %s", l)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no drop count in the log: %q", l)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
