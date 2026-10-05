package smsapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// MaxResponse bounds a provider's reply; a longer one is refused unread
// (security on the #142 design read).
const MaxResponse = 64 << 10

// PageSize is how many messages one poll asks for.
const PageSize = 50

// NewHTTPClient is the vault process's client for the provider: TLS 1.2
// or later against the system's roots (no RootCAs override), no proxy, no
// redirects followed, and bounded time.
func NewHTTPClient() *http.Client {
	return newHTTPClient(&tls.Config{MinVersion: tls.VersionTLS12}, (&net.Dialer{Timeout: 10 * time.Second}).DialContext)
}

// newHTTPClient is NewHTTPClient with the TLS settings and dialer given;
// only tests pass anything but the system's (a test provider's roots).
func newHTTPClient(tc *tls.Config, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         dial,
			TLSClientConfig:     tc,
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// upstream is the provider's API as the vault process calls it. Its
// errors are the package's fixed values only: never the URL, which holds
// the account, nor the provider's own text (security C4).
type upstream struct {
	s     Settings
	token string
	hc    *http.Client
}

func (u upstream) do(ctx context.Context, method, query string, form url.Values) ([]byte, error) {
	to := url.URL{Scheme: "https", Host: u.s.Host(), Path: u.s.MessagesPath(), RawQuery: query}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, to.String(), body)
	if err != nil {
		return nil, ErrUnreachable
	}
	req.SetBasicAuth(u.s.Account, u.token)
	req.Header.Set("Accept", "application/json")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := u.hc.Do(req)
	if err != nil {
		return nil, ErrUnreachable
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	switch {
	case err != nil, len(raw) > MaxResponse:
		return nil, ErrUnreachable
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, ErrLimited
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return raw, nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return nil, ErrRefused
	}
	return nil, ErrUnreachable // 3xx (never followed) and 5xx
}

// send posts one text from the line's own number.
func (u upstream) send(ctx context.Context, to, text string) error {
	_, err := u.do(ctx, http.MethodPost, "", url.Values{"To": {to}, "From": {u.s.Number}, "Body": {text}})
	return err
}

// apiMessage is the part of a provider's message resource the line reads.
type apiMessage struct {
	SID         string `json:"sid"`
	From        string `json:"from"`
	To          string `json:"to"`
	Body        string `json:"body"`
	Direction   string `json:"direction"`
	DateSent    string `json:"date_sent"`
	DateCreated string `json:"date_created"`
}

// list fetches the newest page of messages to the line sent on or after
// since's day (UTC).
func (u upstream) list(ctx context.Context, since time.Time) ([]apiMessage, error) {
	q := url.Values{"To": {u.s.Number}, "DateSent>": {since.UTC().Format("2006-01-02")}, "PageSize": {"50"}}
	// "DateSent>" with a date is the API's on-or-after filter.
	raw, err := u.do(ctx, http.MethodGet, q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	var page struct {
		Messages []apiMessage `json:"messages"`
	}
	if json.Unmarshal(raw, &page) != nil {
		return nil, ErrUnreachable
	}
	if len(page.Messages) > PageSize {
		page.Messages = page.Messages[:PageSize]
	}
	return page.Messages, nil
}

// Mark is the poll's high-water mark: the newest delivered message's time
// and the IDs delivered at that time, so nothing is delivered twice
// (security C3).
type Mark struct {
	Since time.Time `json:"since"`
	IDs   []string  `json:"ids,omitempty"`
}

// fresh returns the inbound texts in msgs past m, oldest first, and the
// mark after them. Messages that fail a check are passed over (and
// marked), never delivered.
func fresh(msgs []apiMessage, m Mark, own string) ([]Inbound, Mark) {
	type cand struct {
		in Inbound
		ok bool
	}
	seen := map[string]bool{}
	for _, id := range m.IDs {
		seen[id] = true
	}
	var cs []cand
	// The API lists newest first; walking it backwards keeps arrival
	// order among texts stamped the same second.
	for i := len(msgs) - 1; i >= 0; i-- {
		a := msgs[i]
		at, err := time.Parse(time.RFC1123Z, a.DateSent)
		if a.DateSent == "" || err != nil {
			at, err = time.Parse(time.RFC1123Z, a.DateCreated)
		}
		if err != nil || a.SID == "" || len(a.SID) > 64 || !printableASCII(a.SID) {
			continue
		}
		at = at.UTC()
		if at.Before(m.Since) || at.Equal(m.Since) && seen[a.SID] {
			continue
		}
		c := cand{in: Inbound{ID: a.SID, At: at}}
		from, named, okFrom := checkSender(a.From)
		c.ok = okFrom && a.Direction == "inbound" && a.To == own && a.Body != "" &&
			utf8.ValidString(a.Body) && len(a.Body) <= MaxText
		c.in.From, c.in.Named, c.in.Text = from, named, a.Body
		cs = append(cs, c)
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].in.At.Before(cs[j].in.At) })
	next := Mark{Since: m.Since, IDs: append([]string(nil), m.IDs...)}
	var out []Inbound
	for _, c := range cs {
		if c.in.At.After(next.Since) {
			next = Mark{Since: c.in.At}
		}
		if c.in.At.Equal(next.Since) {
			next.IDs = append(next.IDs, c.in.ID)
		}
		if c.ok {
			out = append(out, c.in)
		}
	}
	return out, next
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
