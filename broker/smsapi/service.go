package smsapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Store is the vault process's side of the HTTP account.
type Store interface {
	// SMSAccount returns the account and its token, or ErrLocked or
	// ErrNoAccount.
	SMSAccount() (Settings, string, error)
	// AllowText applies the recipient rules (CheckRecipient) and spends
	// the second line's shared budget (Budget.Take).
	AllowText(to string) error
	// Mark and SetMark keep the poll's high-water mark across restarts;
	// before the first poll, Mark is the time setup ran.
	Mark() (Mark, error)
	SetMark(Mark) error
}

// MinPollGap is the shortest time between two polls the vault process
// answers.
const MinPollGap = 10 * time.Second

// Service sends and fetches texts for the modem bridge.
type Service struct {
	Store Store
	// HTTP is the provider client; nil is NewHTTPClient().
	HTTP *http.Client
	Now  func() time.Time
	// Polled, if set, hears each poll's outcome at the provider: nil, or
	// ErrRefused, ErrLimited or ErrUnreachable. Polls that never reach
	// the provider (locked, no account, too soon) are not reported.
	Polled func(error)
	// Missed, if set, is called when a poll read MaxPages with more to
	// read, so older texts were passed over (security F1 on #159).
	Missed func()

	mu       sync.Mutex
	lastPoll time.Time
	client   *http.Client
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) upstream() (upstream, error) {
	set, token, err := s.Store.SMSAccount()
	if err != nil {
		return upstream{}, err
	}
	s.mu.Lock()
	if s.client == nil {
		s.client = s.HTTP
		if s.client == nil {
			s.client = NewHTTPClient()
		}
	}
	hc := s.client
	s.mu.Unlock()
	return upstream{s: set, token: token, hc: hc}, nil
}

// Send sends text to to from the line's own number. A locked vault fails
// it; nothing is queued for after the unlock (security C5).
func (s *Service) Send(ctx context.Context, to, text string) error {
	if err := CheckText(text); err != nil {
		return err
	}
	u, err := s.upstream()
	if err != nil {
		return err
	}
	if err := s.Store.AllowText(to); err != nil {
		return err
	}
	return u.send(ctx, to, text)
}

// Poll returns the texts the provider received for the line since the
// last poll, oldest first, each once.
func (s *Service) Poll(ctx context.Context) ([]Inbound, error) {
	u, err := s.upstream()
	if err != nil {
		return nil, err
	}
	now := s.now()
	s.mu.Lock()
	if !s.lastPoll.IsZero() && now.Sub(s.lastPoll) < MinPollGap {
		s.mu.Unlock()
		return nil, ErrTooSoon
	}
	s.lastPoll = now
	s.mu.Unlock()
	m, err := s.Store.Mark()
	if err != nil {
		return nil, ErrUnreachable
	}
	msgs, missed, err := u.list(ctx, m.Since)
	if s.Polled != nil {
		s.Polled(err)
	}
	if err != nil {
		return nil, err
	}
	out, next := fresh(msgs, m, u.s.Number)
	if err := s.Store.SetMark(next); err != nil {
		return nil, ErrUnreachable // delivered nothing, so nothing twice
	}
	if missed && s.Missed != nil {
		s.Missed()
	}
	return out, nil
}

// codes are the fixed refusals on the socket, both ways.
var codes = map[string]error{
	"locked": ErrLocked, "no_account": ErrNoAccount, "recipient": ErrRecipient, "too_long": ErrTooLong,
	"limited": ErrLimited, "refused": ErrRefused, "unreachable": ErrUnreachable, "too_soon": ErrTooSoon,
}

func codeOf(err error) string {
	for c, e := range codes {
		if errors.Is(err, e) {
			return c
		}
	}
	return "unreachable"
}

const maxRequest = 4 << 10

// Handler serves sms.sock: POST /send {to, text} and POST /poll. Replies
// carry a fixed code, never the provider's text or the account.
func Handler(s *Service) http.Handler {
	mux := http.NewServeMux()
	fail := func(w http.ResponseWriter, err error) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": codeOf(err)})
	}
	read := func(w http.ResponseWriter, r *http.Request, v any) bool {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return false
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, maxRequest)).Decode(v); err != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return false
		}
		return true
	}
	mux.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			To   string `json:"to"`
			Text string `json:"text"`
		}
		if !read(w, r, &req) {
			return
		}
		if err := s.Send(r.Context(), req.To, req.Text); err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		var req struct{}
		if !read(w, r, &req) {
			return
		}
		in, err := s.Poll(r.Context())
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string][]Inbound{"texts": in})
	})
	return mux
}

// Client is the modem bridge's side of sms.sock.
type Client struct{ c *http.Client }

// NewClient returns a client for the socket at path.
func NewClient(path string) *Client {
	return &Client{c: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}}
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	to := url.URL{Scheme: "http", Host: "agentos-egress", Path: path} // over the Unix socket
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, to.String(), bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.c.Do(req)
	if err != nil {
		return ErrUnreachable
	}
	defer resp.Body.Close()
	lr := io.LimitReader(resp.Body, 1<<20)
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusOK:
		if json.NewDecoder(lr).Decode(out) != nil {
			return ErrUnreachable
		}
		return nil
	}
	var e struct {
		Error string `json:"error"`
	}
	if json.NewDecoder(lr).Decode(&e) == nil {
		if err, ok := codes[e.Error]; ok {
			return err
		}
	}
	return ErrUnreachable
}

// Send asks the vault process to send text to to.
func (c *Client) Send(ctx context.Context, to, text string) error {
	return c.post(ctx, "/send", map[string]string{"to": to, "text": text}, nil)
}

// Poll asks for the texts received since the last poll.
func (c *Client) Poll(ctx context.Context) ([]Inbound, error) {
	var out struct {
		Texts []Inbound `json:"texts"`
	}
	err := c.post(ctx, "/poll", struct{}{}, &out)
	return out.Texts, err
}
