// Package sipsign is the vault side of ADP-12's second line as a SIP
// account (sipline SL2, P2-3c): the account password, the digest answers
// made with it, and the socket protocol between the vault process
// (agentos-egress, serving sign.sock) and the modem bridge that runs the
// line. The password never leaves the vault process (CRED-1): the line
// sends a challenge and gets back an Authorization value.
//
// It links no SIP or SRTP stack, so the vault process can import it while
// those modules stay in the modem bridge's binary only (ARC-2).
package sipsign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/icholy/digest"
)

// Challenge is one digest challenge (RFC 3261 22.4) for one request.
type Challenge struct {
	// Header is the WWW-Authenticate or Proxy-Authenticate value.
	Header string `json:"header"`
	// Method and URI are the challenged request's method and Request-URI.
	Method string `json:"method"`
	URI    string `json:"uri"`
}

// Errors from Account, Settings, the handler and the client.
var (
	ErrRealm     = errors.New("sipsign: challenge is for another realm")
	ErrMethod    = errors.New("sipsign: not a method the second line signs")
	ErrChallenge = errors.New("sipsign: unsupported digest challenge")
	ErrSettings  = errors.New("sipsign: account settings refused")
	ErrLocked    = errors.New("sipsign: the vault is locked")
	ErrNoAccount = errors.New("sipsign: no calling account is set up")
	ErrRefused   = errors.New("sipsign: the vault process refused to sign")
	ErrDown      = errors.New("sipsign: the vault process did not answer")
)

// signable are the requests the line sends: registering, texts, calls and
// ending them.
var signable = map[string]bool{"REGISTER": true, "MESSAGE": true, "INVITE": true, "BYE": true, "CANCEL": true}

// Account is the vault side of the account: the only holder of its
// password. It answers challenges only for the realm recorded at setup and
// only for the requests the line sends, so a process that can ask it to
// sign cannot use it for another service that shares the password.
type Account struct {
	Username, Password string
	// Realm is the provider's digest realm, recorded from the first
	// registration over verified TLS (sipline SL3). Empty refuses
	// everything.
	Realm string
}

// String names the account without its password, so a stray log line
// cannot carry it.
func (a Account) String() string { return "sipsign.Account{" + a.Username + " @ " + a.Realm + "}" }

// GoString is String for %#v.
func (a Account) GoString() string { return a.String() }

// Sign answers c with the Authorization value. Only qop=auth challenges are
// answered: an RFC 2069 challenge (no qop) carries no client nonce.
func (a Account) Sign(_ context.Context, c Challenge) (string, error) {
	ch, err := digest.ParseChallenge(c.Header)
	if err != nil {
		return "", ErrChallenge
	}
	ch.Algorithm = strings.ToUpper(ch.Algorithm)
	if a.Realm == "" || ch.Realm != a.Realm {
		return "", ErrRealm
	}
	if !signable[c.Method] {
		return "", ErrMethod
	}
	if !digest.CanDigest(ch) || !ch.SupportsQOP("auth") {
		return "", ErrChallenge
	}
	cred, err := digest.Digest(ch, digest.Options{Method: c.Method, URI: c.URI, Username: a.Username, Password: a.Password})
	if err != nil {
		return "", ErrChallenge
	}
	return cred.String(), nil
}

// Settings are the account's settings other than its password, entered at
// setup and handed to the line. None of them is secret, but each reaches a
// SIP URI or a TLS dial, so Check keeps them to plain values.
type Settings struct {
	// Server is the provider's SIP-over-TLS host and port (registrar and
	// outbound proxy).
	Server string `json:"server"`
	// Domain is the account's SIP domain.
	Domain string `json:"domain"`
	// User is the account's user part (also its digest username).
	User string `json:"user"`
	// Number is the account's phone number, E.164 with its +.
	Number string `json:"number"`
	// NoPlus dials numbers without the leading + (sipline SL6).
	NoPlus bool `json:"no_plus,omitempty"`
}

// AOR is the account's address of record, which the second line's role is
// bound to (secondline Roles.SecondAccount, sipline SL10).
func (s Settings) AOR() string { return "sip:" + s.User + "@" + strings.ToLower(s.Domain) }

// Check refuses settings that could steer the line anywhere but one TLS
// server and one account: a server that is not host:port, a domain that is
// not a host name, a user part with URI syntax, or a number that is not
// E.164.
func (s Settings) Check() error {
	host, port, err := net.SplitHostPort(s.Server)
	if err != nil || !hostName(host) {
		return ErrSettings
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return ErrSettings
	}
	if !hostName(s.Domain) || !userPart(s.User) || !e164(s.Number) {
		return ErrSettings
	}
	return nil
}

// hostName is a DNS name or an IP address literal.
func hostName(h string) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	if h == "" || len(h) > 253 {
		return false
	}
	for _, r := range h {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

// userPart allows RFC 3261's unreserved characters and +, never the
// separators that would end the user part (@, ;, ?, :) or escapes.
func userPart(u string) bool {
	if u == "" || len(u) > 64 {
		return false
	}
	for _, r := range u {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.~+", r)) {
			return false
		}
	}
	return true
}

// e164 is + and 3 to 15 digits.
func e164(n string) bool {
	d, ok := strings.CutPrefix(n, "+")
	if !ok || len(d) < 3 || len(d) > 15 {
		return false
	}
	for _, r := range d {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Store is the vault process's account, as the socket serves it.
type Store interface {
	// Account returns the settings and the account, or ErrLocked or
	// ErrNoAccount.
	Account() (Settings, Account, error)
	// LearnRealm records realm when none is recorded yet and setup's
	// window for the first registration is open, and returns the account
	// with it; otherwise it refuses.
	LearnRealm(realm string) (Account, error)
}

// maxRequest bounds a request on the socket.
const maxRequest = 8 << 10

// Handler serves the sign socket: GET /account returns the Settings, POST
// /sign a SignResponse for a Challenge. A challenge while no realm is
// recorded teaches the realm only if it is a REGISTER's and could be
// answered (sipline SL3). Refusals carry fixed text, never the reason a
// challenge failed.
func Handler(st Store) http.Handler {
	mux := http.NewServeMux()
	fail := func(w http.ResponseWriter, err error) {
		switch {
		case errors.Is(err, ErrLocked):
			http.Error(w, "vault locked", http.StatusServiceUnavailable)
		case errors.Is(err, ErrNoAccount):
			http.Error(w, "no account", http.StatusNotFound)
		default:
			http.Error(w, "refused", http.StatusForbidden)
		}
	}
	reply := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		s, _, err := st.Account()
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, s)
	})
	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var c Challenge
		if err := json.NewDecoder(io.LimitReader(r.Body, maxRequest)).Decode(&c); err != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}
		_, acct, err := st.Account()
		if err != nil {
			fail(w, err)
			return
		}
		var auth string
		if acct.Realm == "" {
			auth, err = learn(st, acct, c)
		} else {
			auth, err = acct.Sign(r.Context(), c)
		}
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, SignResponse{Authorization: auth})
	})
	return mux
}

// learn answers the first registration's challenge and records its realm,
// in that order, so a challenge the account cannot answer records nothing.
func learn(st Store, acct Account, c Challenge) (string, error) {
	if c.Method != "REGISTER" {
		return "", ErrRealm
	}
	ch, err := digest.ParseChallenge(c.Header)
	if err != nil || ch.Realm == "" {
		return "", ErrChallenge
	}
	acct.Realm = ch.Realm
	auth, err := acct.Sign(context.Background(), c)
	if err != nil {
		return "", err
	}
	if _, err := st.LearnRealm(ch.Realm); err != nil {
		return "", err
	}
	return auth, nil
}

// SignResponse is the vault process's answer to a challenge.
type SignResponse struct {
	Authorization string `json:"authorization"`
}

// Client is the line's side of the sign socket; it implements
// sipline.Signer.
type Client struct{ c *http.Client }

// NewClient returns a Client for the sign socket at path.
func NewClient(path string) *Client {
	return &Client{c: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
		},
		Proxy: nil,
	}}}
}

// over the Unix socket
func endpoint(p string) string {
	return (&url.URL{Scheme: "http", Host: "agentos-egress", Path: p}).String()
}

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.c.Do(req)
	if err != nil {
		return ErrDown
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusServiceUnavailable:
		return ErrLocked
	case http.StatusNotFound:
		return ErrNoAccount
	case http.StatusForbidden:
		return ErrRefused
	default:
		return ErrDown
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRequest)).Decode(out); err != nil {
		return ErrDown
	}
	return nil
}

// Settings returns the account's settings.
func (c *Client) Settings(ctx context.Context) (Settings, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint("/account"), nil)
	if err != nil {
		return Settings{}, err
	}
	var s Settings
	return s, c.do(req, &s)
}

// Sign asks the vault process to answer ch.
func (c *Client) Sign(ctx context.Context, ch Challenge) (string, error) {
	body, _ := json.Marshal(ch)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint("/sign"), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	var r SignResponse
	if err := c.do(req, &r); err != nil {
		return "", err
	}
	return r.Authorization, nil
}

// Vault entries for the account (agentos-egress). The password is an entry
// of its own so the vault's redactor matches it verbatim (CRED-7).
const (
	SettingsName = "second-line-sip"
	PasswordName = "second-line-sip-password"
	KindSettings = "sip_account"
	KindPassword = "sip_password"
)
