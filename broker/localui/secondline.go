package localui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/sipsign"
	"github.com/ghbmrk/agentos/broker/smsapi"
)

// SecondLine is the vault process's second-line routes on the unlock
// socket (egress K13), as the second line's page uses them; UnlockClient
// is the real one. The password goes to the vault process and is never
// read back (CRED-1).
type SecondLine interface {
	SecondLineStatus(ctx context.Context) (SecondLineStatus, error)
	SetSecondLine(ctx context.Context, s sipsign.Settings, password string) error
	ConfirmRealm(ctx context.Context, realm string) error
	RemoveSecondLine(ctx context.Context) error
	// The texting account over the provider's web API (egress K16); its
	// token is never read back either.
	SMSStatus(ctx context.Context) (SMSStatus, error)
	SetSMS(ctx context.Context, s smsapi.Settings, token string) error
	RemoveSMS(ctx context.Context) error
}

// SMSStatus is the texting account as the vault process reports it.
type SMSStatus struct {
	Set      bool            `json:"set"`
	Settings smsapi.Settings `json:"settings"`
}

// ProviderName is the provider as the page names it.
func (s SMSStatus) ProviderName() string {
	if s.Settings.Provider == smsapi.SignalWire {
		return "SignalWire"
	}
	return "Twilio"
}

// SecondLineStatus is the calling account as the vault process reports
// it, never with its password.
type SecondLineStatus struct {
	Set      bool             `json:"set"`
	Settings sipsign.Settings `json:"settings"`
	// RealmRecorded: the first registration recorded Realm (sipline SL3).
	RealmRecorded  bool   `json:"realm_recorded"`
	Realm          string `json:"realm,omitempty"`
	RealmConfirmed bool   `json:"realm_confirmed"`
	// WaitingForRegistration: no realm yet, and the window after setup is
	// still open.
	WaitingForRegistration bool `json:"waiting_for_registration"`
	// SetAt is when setup ran, in Unix seconds.
	SetAt int64 `json:"set_at"`
}

// SlowRegistration is how long the page waits for the first registration
// before saying what to check (UX-139-2).
const SlowRegistration = 2 * time.Minute

// SecondLineStatus implements SecondLine.
func (u *UnlockClient) SecondLineStatus(ctx context.Context) (SecondLineStatus, error) {
	var st SecondLineStatus
	err := u.do(ctx, http.MethodGet, "/second-line/status", nil, &st)
	return st, err
}

// SetSecondLine implements SecondLine.
func (u *UnlockClient) SetSecondLine(ctx context.Context, s sipsign.Settings, password string) error {
	return u.do(ctx, http.MethodPost, "/second-line", struct {
		sipsign.Settings
		Password string `json:"password"`
	}{s, password}, nil)
}

// ConfirmRealm implements SecondLine.
func (u *UnlockClient) ConfirmRealm(ctx context.Context, realm string) error {
	return u.do(ctx, http.MethodPost, "/second-line/confirm", map[string]string{"realm": realm}, nil)
}

// RemoveSecondLine implements SecondLine.
func (u *UnlockClient) RemoveSecondLine(ctx context.Context) error {
	return u.do(ctx, http.MethodPost, "/second-line/remove", struct{}{}, nil)
}

// SMSStatus implements SecondLine.
func (u *UnlockClient) SMSStatus(ctx context.Context) (SMSStatus, error) {
	var st SMSStatus
	err := u.do(ctx, http.MethodGet, "/second-line/sms/status", nil, &st)
	return st, err
}

// SetSMS implements SecondLine.
func (u *UnlockClient) SetSMS(ctx context.Context, s smsapi.Settings, token string) error {
	return u.do(ctx, http.MethodPost, "/second-line/sms", struct {
		smsapi.Settings
		Token string `json:"token"`
	}{s, token}, nil)
}

// RemoveSMS implements SecondLine.
func (u *UnlockClient) RemoveSMS(ctx context.Context) error {
	return u.do(ctx, http.MethodPost, "/second-line/sms/remove", struct{}{}, nil)
}

// do sends one request to the unlock socket and decodes a 200 reply into
// out; 204 is success with no reply. Refusals are VaultError with the
// vault process's fixed message, or none.
func (u *UnlockClient) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		// The request may carry the account's password.
		defer clear(b)
		rd = bytes.NewReader(b)
	}
	to := url.URL{Scheme: "http", Host: "agentos-egress", Path: path}
	req, err := http.NewRequestWithContext(ctx, method, to.String(), rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := u.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	lr := io.LimitReader(resp.Body, 16<<10)
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusOK:
		if out == nil {
			return nil
		}
		if err := json.NewDecoder(lr).Decode(out); err != nil {
			return fmt.Errorf("vault: unreadable reply: %w", err)
		}
		return nil
	}
	var e struct {
		Error string `json:"error"`
	}
	// Msg stays empty without the vault process's own wording, so the
	// page never shows the owner a made-up or internal reason.
	_ = json.NewDecoder(lr).Decode(&e)
	return &VaultError{resp.StatusCode, e.Error}
}

// secondLineView is the second line's page.
type secondLineView struct {
	// Locked: the vault is not open; Down: the vault process is not
	// answering.
	Locked, Down bool
	St           SecondLineStatus
	// Realm is the recorded realm as shown; RealmExact is what the
	// confirm form sends back; Matches: it is the domain or server host
	// the owner entered.
	Realm, RealmExact string
	Matches           bool
	// Form holds what the owner typed, never the password.
	Form sipsign.Settings
	// Removing asks first (UX-139-1); Slow: the first registration has
	// taken SlowRegistration or longer.
	Removing, Slow bool
	// SMS is the texting account; SMSForm what the owner typed for it,
	// never the token; SMSRemoving asks first.
	SMS         SMSStatus
	SMSForm     smsapi.Settings
	SMSRemoving bool
	Err         string
	Refresh     string
}

// secondLine serves the second line's page behind sign-in (CH-7): set up
// the calling account, confirm the realm its first registration recorded
// (sipline SL3), or remove it (ADP-12, P2-3c).
func (s *Server) secondLine(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	v := secondLineView{}
	vs, err := s.cfg.Vault.Status(ctx)
	switch {
	case err != nil && !isVaultError(err):
		v.Down, v.Refresh = true, "5"
		s.render(w, "secondline", v)
		return
	case err != nil || vs.State != "open":
		v.Locked = true
		s.render(w, "secondline", v)
		return
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		var err error
		switch r.PostForm.Get("step") {
		case "set":
			v.Form = sipsign.Settings{Server: r.PostForm.Get("server"), Domain: r.PostForm.Get("domain"), User: r.PostForm.Get("user"),
				Number: r.PostForm.Get("number"), NoPlus: r.PostForm.Get("no_plus") == "1"}
			err = s.cfg.SecondLine.SetSecondLine(ctx, v.Form, r.PostForm.Get("password"))
		case "confirm":
			err = s.cfg.SecondLine.ConfirmRealm(ctx, r.PostForm.Get("realm"))
		case "remove":
			if r.PostForm.Get("confirm") != "1" {
				v.Removing = true
				break
			}
			err = s.cfg.SecondLine.RemoveSecondLine(ctx)
		case "sms-set":
			v.SMSForm = smsapi.Settings{Provider: r.PostForm.Get("provider"), Space: r.PostForm.Get("space"),
				Account: r.PostForm.Get("account"), Number: r.PostForm.Get("number")}
			err = s.cfg.SecondLine.SetSMS(ctx, v.SMSForm, r.PostForm.Get("token"))
		case "sms-remove":
			if r.PostForm.Get("confirm") != "1" {
				v.SMSRemoving = true
				break
			}
			err = s.cfg.SecondLine.RemoveSMS(ctx)
		default:
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		if err == nil && !v.Removing && !v.SMSRemoving {
			http.Redirect(w, r, "/second-line/", http.StatusSeeOther)
			return
		}
		if err != nil {
			v.Err = "That didn't go through. Try again."
			var ve *VaultError
			if errors.As(err, &ve) && ve.Status < http.StatusInternalServerError && ve.Msg != "" && ve.Msg != lockedMsg {
				v.Err = ve.Msg // the vault process's fixed owner wording (UX-116-1)
			}
		}
	}
	st, err := s.cfg.SecondLine.SecondLineStatus(ctx)
	if err != nil {
		// A refusal here is the vault locking since the check above.
		if v.Locked = isVaultError(err); !v.Locked {
			v.Down, v.Refresh = true, "5"
		}
		s.render(w, "secondline", v)
		return
	}
	v.St = st
	if v.SMS, err = s.cfg.SecondLine.SMSStatus(ctx); err != nil {
		if v.Locked = isVaultError(err); !v.Locked {
			v.Down, v.Refresh = true, "5"
		}
		s.render(w, "secondline", v)
		return
	}
	if v.SMSForm == (smsapi.Settings{}) && v.SMS.Set {
		v.SMSForm = v.SMS.Settings
	}
	if st.RealmRecorded {
		v.RealmExact = st.Realm
		v.Realm = showRealm(st.Realm)
		host := st.Settings.Server
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		v.Matches = v.Realm == st.Realm && (strings.EqualFold(st.Realm, st.Settings.Domain) || strings.EqualFold(st.Realm, host))
	}
	if st.WaitingForRegistration {
		v.Refresh = "5"
		v.Slow = !s.cfg.Now().Before(time.Unix(st.SetAt, 0).Add(SlowRegistration))
	}
	if v.Removing || v.SMSRemoving {
		v.Refresh = ""
	}
	if v.Form == (sipsign.Settings{}) && st.Set {
		v.Form = st.Settings
	}
	s.render(w, "secondline", v)
}

// lockedMsg is the vault process's refusal while locked (egress
// errLocked), which the page answers with its locked view instead.
const lockedMsg = "the vault is locked"

func isVaultError(err error) bool {
	var ve *VaultError
	return errors.As(err, &ve)
}

// showRealm returns the realm as the page shows it: as received when it
// is short printable ASCII, else quoted with every other character
// escaped, so a right-to-left override or an invisible character cannot
// make it read as another provider's name.
func showRealm(realm string) string {
	if len(realm) <= 80 {
		plain := true
		for i := 0; i < len(realm); i++ {
			if realm[i] < 0x21 || realm[i] > 0x7e {
				plain = false
				break
			}
		}
		if plain {
			return realm
		}
	}
	q := strconv.QuoteToASCII(realm)
	if len(q) > 120 {
		q = q[:120] + "…"
	}
	return q
}
