package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"unicode"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/sipsign"
	"github.com/ghbmrk/agentos/broker/smsapi"
	"github.com/ghbmrk/agentos/broker/vault"
)

// The second line's HTTP account (ADP-12, potency PL1 on #102; P2-3c part
// 5, egress K16): texts over the provider's API for providers whose SIP
// accounts carry no MESSAGE. The local UI sets it up on the unlock socket;
// the modem bridge sends and polls on sms.sock, which admits only its uid.
// The API token never leaves this process (CRED-1).

// SMSSocket is the modem bridge's texting socket.
const SMSSocket = "sms.sock"

// Setup refusals: one fixed reason per field, never the value entered.
var (
	errSMSProvider  = uerr(http.StatusBadRequest, "Choose Twilio or SignalWire.")
	errSMSSpace     = uerr(http.StatusBadRequest, "Enter the SignalWire space name: the first part of your-space.signalwire.com. Twilio has none.")
	errSMSAccount   = uerr(http.StatusBadRequest, "Copy the account ID exactly from your provider: for Twilio the Account SID (AC and 32 characters), for SignalWire the Project ID.")
	errSMSNumber    = uerr(http.StatusBadRequest, "Enter the number with its country code, like +44 7700 900123.")
	errSMSOtherKind = uerr(http.StatusBadRequest, "The box already holds a different credential under this name. Remove the texting account first, then set it up again.")
	errWeakSMSToken = uerr(http.StatusBadRequest, "Paste the auth token from your provider's console, 12 to 256 characters.")
)

// Owner notices when the account changes, as for the SIP account.
const (
	noteSMSReplaced = "The second line's texting account was replaced on the box's Wi-Fi page."
	noteSMSRemoved  = "The second line's texting account was removed on the box's Wi-Fi page."
	// noteSMSMissed: a poll read smsapi.MaxPages with more to read, so
	// older texts were passed over (security F1 on #159).
	noteSMSMissed = "Some texts to your second line may have been missed."
)

func smsFieldErr(err error) error {
	switch err {
	case smsapi.ErrProvider:
		return errSMSProvider
	case smsapi.ErrSpace:
		return errSMSSpace
	case smsapi.ErrAccount:
		return errSMSAccount
	case smsapi.ErrNumber:
		return errSMSNumber
	}
	return errInternal
}

// smsRecord is the settings entry and when setup ran (Unix seconds), from
// which the first poll starts, so the provider's older history is never
// handed to the agent.
type smsRecord struct {
	smsapi.Settings
	SetAt int64 `json:"set_at"`
}

// smsStatus is what the local page reads; never the token.
type smsStatus struct {
	Set      bool            `json:"set"`
	Settings smsapi.Settings `json:"settings"`
}

func smsToken(p string) bool {
	if len(p) < vault.MinValueLen || len(p) > 256 {
		return false
	}
	for _, r := range p {
		if !unicode.IsPrint(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// smsMarkPath is the poll's high-water mark, beside the unlock state: IDs
// and times only, nothing secret.
func (c *custody) smsMarkPath() string {
	return filepath.Join(filepath.Dir(c.statePath), "sms-mark.json")
}

// setSMS stores the account while the vault is open; the token is an
// entry of its own (CRED-7) and goes first.
func (c *custody) setSMS(s smsapi.Settings, token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return errLocked
	}
	s = s.Normalize()
	if err := s.Check(); err != nil {
		return smsFieldErr(err)
	}
	if hasOtherKind(c.v, smsapi.SettingsName, smsapi.KindSettings) || hasOtherKind(c.v, smsapi.TokenName, smsapi.KindToken) {
		return errSMSOtherKind
	}
	if !smsToken(token) {
		return errWeakSMSToken
	}
	replacing := hasKind(c.v, smsapi.SettingsName, smsapi.KindSettings)
	rec, err := json.Marshal(smsRecord{Settings: s, SetAt: c.now().Unix()})
	if err != nil {
		return errInternal
	}
	if err := os.Remove(c.smsMarkPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errInternal
	}
	if err := c.v.Put(smsapi.TokenName, smsapi.KindToken, []byte(token)); err != nil {
		return c.putErr(err)
	}
	if err := c.v.Put(smsapi.SettingsName, smsapi.KindSettings, rec); err != nil {
		return c.putErr(err)
	}
	c.smsFailSince, c.smsFail = time.Time{}, modelroute.TextsOK
	if replacing {
		c.notify(noteSMSReplaced)
	}
	return nil
}

func (c *custody) removeSMS() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return errLocked
	}
	removed := false
	for _, n := range []struct{ name, kind string }{{smsapi.SettingsName, smsapi.KindSettings}, {smsapi.TokenName, smsapi.KindToken}} {
		if !hasKind(c.v, n.name, n.kind) {
			continue
		}
		if err := c.v.Delete(n.name); err != nil {
			return c.putErr(err)
		}
		removed = true
	}
	c.smsFailSince, c.smsFail = time.Time{}, modelroute.TextsOK
	if removed {
		c.notify(noteSMSRemoved)
	}
	return nil
}

// smsAccount reads the account. Caller holds mu.
func (c *custody) smsAccount() (smsRecord, string, error) {
	if c.ph != open {
		return smsRecord{}, "", smsapi.ErrLocked
	}
	if !hasKind(c.v, smsapi.SettingsName, smsapi.KindSettings) || !hasKind(c.v, smsapi.TokenName, smsapi.KindToken) {
		return smsRecord{}, "", smsapi.ErrNoAccount
	}
	raw, ok1 := c.v.Secret(smsapi.SettingsName)
	tok, ok2 := c.v.Secret(smsapi.TokenName)
	var rec smsRecord
	if !ok1 || !ok2 || json.Unmarshal([]byte(raw.Reveal()), &rec) != nil {
		return smsRecord{}, "", smsapi.ErrNoAccount
	}
	return rec, tok.Reveal(), nil
}

func (c *custody) smsStatus() (smsStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, _, err := c.smsAccount()
	switch {
	case errors.Is(err, smsapi.ErrLocked):
		return smsStatus{}, errLocked
	case err != nil:
		return smsStatus{}, nil
	}
	return smsStatus{Set: true, Settings: rec.Settings}, nil
}

// smsPolled hears each poll's outcome at the provider (smsapi
// Service.Polled): a refusal reads as a sign-in failure, anything else
// as the provider not answering; a good poll clears it.
func (c *custody) smsPolled(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case err == nil:
		c.smsFailSince, c.smsFail = time.Time{}, modelroute.TextsOK
		return
	case c.smsFailSince.IsZero():
		c.smsFailSince = c.now()
	}
	c.smsFail = modelroute.TextsUnreached
	if errors.Is(err, smsapi.ErrRefused) {
		c.smsFail = modelroute.TextsSignIn
	}
}

// textsState is what agentosd learns about the texting account on the
// verify socket: how its polls fail once they have failed for
// modelroute.TextsQuiet, else nothing (UX-159-1).
func (c *custody) textsState() (modelroute.TextsState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, _, err := c.smsAccount(); errors.Is(err, smsapi.ErrLocked) {
		return modelroute.TextsOK, errLocked
	} else if err != nil {
		return modelroute.TextsOK, nil
	}
	if c.smsFailSince.IsZero() || c.now().Sub(c.smsFailSince) < modelroute.TextsQuiet {
		return modelroute.TextsOK, nil
	}
	return c.smsFail, nil
}

// lineNumbers are the second line's own numbers, which it never texts.
// Caller holds mu.
func (c *custody) lineNumbers() []string {
	var out []string
	if rec, _, err := c.sipAccount(); err == nil {
		out = append(out, rec.Number)
	}
	if rec, _, err := c.smsAccount(); err == nil {
		out = append(out, rec.Number)
	}
	return out
}

// allowSend applies the second line's recipient rules and spends its
// shared budget (security C1, Q2 on the #142 design read). Caller holds
// mu.
func (c *custody) allowSend(to string, spend bool) error {
	if err := smsapi.CheckRecipient(to, c.owner, ""); err != nil {
		return err
	}
	for _, n := range c.lineNumbers() {
		if to == n {
			return smsapi.ErrRecipient
		}
	}
	if !spend {
		return nil
	}
	return c.budget.Take(to, c.now())
}

// smsStore is the custody as sms.sock serves it (smsapi.Store).
type smsStore struct{ c *custody }

func (s smsStore) SMSAccount() (smsapi.Settings, string, error) {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	rec, tok, err := s.c.smsAccount()
	return rec.Settings, tok, err
}

func (s smsStore) AllowText(to string) error {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	return s.c.allowSend(to, true)
}

func (s smsStore) Mark() (smsapi.Mark, error) {
	raw, err := os.ReadFile(s.c.smsMarkPath())
	if errors.Is(err, os.ErrNotExist) {
		s.c.mu.Lock()
		rec, _, err := s.c.smsAccount()
		s.c.mu.Unlock()
		if err != nil {
			return smsapi.Mark{}, err
		}
		return smsapi.Mark{Since: time.Unix(rec.SetAt, 0).UTC()}, nil
	}
	if err != nil {
		return smsapi.Mark{}, err
	}
	var m smsapi.Mark
	if err := json.Unmarshal(raw, &m); err != nil {
		return smsapi.Mark{}, err
	}
	return m, nil
}

func (s smsStore) SetMark(m smsapi.Mark) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.c.smsMarkPath(), raw)
}

// Allow checks a MESSAGE or INVITE before sign.sock signs it: the same
// recipient rules, and for a MESSAGE the same budget, as a text over the
// HTTP account (sipsign.Limiter).
func (s signStore) Allow(ch sipsign.Challenge) error {
	c := s.c
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, _, err := c.sipAccount()
	if err != nil {
		return err
	}
	switch c.allowSend(sipsign.Recipient(ch.URI, rec.NoPlus), ch.Method == "MESSAGE") {
	case nil:
		return nil
	case smsapi.ErrLimited:
		return sipsign.ErrLimited
	}
	return sipsign.ErrRecipient
}

// serveSMS opens sms.sock in dir for the modem bridge's uid.
func serveSMS(dir string, c *custody, modemUID int) (*http.Server, error) {
	if err := runDir(dir); err != nil {
		return nil, err
	}
	ln, err := listen(dir, SMSSocket, modemUID)
	if err != nil {
		return nil, err
	}
	srv := newServer(smsapi.Handler(&smsapi.Service{Store: smsStore{c}, HTTP: c.smsHTTP, Now: c.now, Polled: c.smsPolled,
		Missed: func() { c.notify(noteSMSMissed) }}))
	srv.ReadTimeout = 10 * time.Second
	go srv.Serve(ln)
	return srv, nil
}

// smsRoutes adds the HTTP account's setup to the unlock socket.
func smsRoutes(mux *http.ServeMux, c *custody, read func(http.ResponseWriter, *http.Request, any) bool,
	reply func(http.ResponseWriter, int, any), fail func(http.ResponseWriter, error)) {
	mux.HandleFunc("/second-line/sms", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			smsapi.Settings
			Token string `json:"token"`
		}
		if !read(w, r, &req) {
			return
		}
		if err := c.setSMS(req.Settings, req.Token); err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/second-line/sms/status", func(w http.ResponseWriter, r *http.Request) {
		st, err := c.smsStatus()
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, http.StatusOK, st)
	})
	mux.HandleFunc("/second-line/sms/remove", func(w http.ResponseWriter, r *http.Request) {
		var req struct{}
		if !read(w, r, &req) {
			return
		}
		if err := c.removeSMS(); err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
