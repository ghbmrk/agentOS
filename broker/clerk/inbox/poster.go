package inbox

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// The reasons a Poster refuses before sending (#2601). Each means no byte of
// the request left the box.
const (
	nBadURL  NotDone = "bad-unsubscribe-url" // not a plain https name on port 443
	nEgress  NotDone = "egress-refused"      // the address policy refused every way to it
	nNotSent NotDone = "post-not-sent"       // no connection to the endpoint was made
)

// postTimeout bounds one POST, dial to response headers.
const postTimeout = 30 * time.Second

// postURLMax is the longest unsubscribe URL a Poster sends to.
const postURLMax = 2048

// postReadMax is how much of a response body a Poster reads before closing.
const postReadMax = 4 << 10

// hostName is a DNS name: LDH labels of 1 to 63, at least two of them.
var hostName = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Poster sends the clerk's RFC 8058 one-click unsubscribe POST, the one
// request the mail clerk makes off the mail servers (#2601). Only a public
// HTTPS endpoint is reached: the URL is parsed with net/url and must be
// https, on port 443, to a DNS name, with no userinfo, fragment, whitespace,
// control or non-ASCII character; the name is resolved and every answer is
// checked by the address policy (DEV-2), which then connects to a checked
// literal address, so the address connected is the address checked; no proxy
// is used and no redirect is followed.
type Poster struct {
	client *http.Client
}

// NewPoster is a Poster whose dials go through guard. base, when set, is
// the TLS configuration to start from (tests give their own roots); nil is
// the system roots.
func NewPoster(guard *netguard.Policy, base *tls.Config) *Poster {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if base != nil {
		tc = base.Clone()
		if tc.MinVersion < tls.VersionTLS12 {
			tc.MinVersion = tls.VersionTLS12
		}
	}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            guard.DialContext,
		TLSClientConfig:        tc,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  postTimeout,
		MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives:      true,
		// HTTP/1.1 only: one request on one connection.
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	return &Poster{client: &http.Client{
		Transport: tr,
		Timeout:   postTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

// postURL is raw parsed as an unsubscribe endpoint, or ok false.
func postURL(raw string) (*url.URL, bool) {
	if len(raw) > postURLMax || !strings.HasPrefix(strings.ToLower(raw), "https://") {
		return nil, false
	}
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c <= ' ' || c >= 0x7f || c == '\\' {
			return nil, false
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" ||
		strings.Contains(raw, "#") || (u.Port() != "" && u.Port() != "443") {
		return nil, false
	}
	h := u.Hostname()
	if _, err := netip.ParseAddr(h); err == nil || !hostName.MatchString(strings.ToLower(h)) {
		return nil, false
	}
	// The host VRB-2 aligned with the signing domain is the host posted to.
	if strings.ToLower(h) != urlHost(raw) {
		return nil, false
	}
	return u, true
}

// Post sends p. A NotDone error means nothing was sent; any other error
// means the request may have reached the endpoint and was not confirmed,
// so it is never sent again (a one-click POST is not idempotent).
func (ps *Poster) Post(ctx context.Context, p Post) error {
	u, ok := postURL(p.URL)
	if !ok || p.Method != http.MethodPost {
		return nBadURL
	}
	ctx, cancel := context.WithTimeout(ctx, postTimeout)
	defer cancel()
	connected := false
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { connected = true }})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(p.Body))
	if err != nil {
		return nBadURL
	}
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	res, err := ps.client.Do(req)
	if err != nil {
		switch {
		case errors.Is(err, netguard.ErrDenied):
			return nEgress
		case !connected:
			return nNotSent
		}
		return errUnconfirmed
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, postReadMax))
	// A redirect is not followed, so its endpoint has not confirmed.
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return errUnconfirmed
	}
	return nil
}
