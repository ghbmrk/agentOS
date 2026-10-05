package localui

import (
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
}

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

// do sends one request to the unlock socket and decodes a 200 reply into
// out; 204 is success with no reply. Refusals are VaultError with the
// vault process's fixed message.
func (u *UnlockClient) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		// The request may carry the account's password.
		defer clear(b)
		rd = strings.NewReader(string(b))
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
	msg := "the vault process refused the request"
	if json.NewDecoder(lr).Decode(&e) == nil && e.Error != "" {
		msg = e.Error
	}
	return &VaultError{resp.StatusCode, msg}
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
	Form    sipsign.Settings
	Err     string
	Refresh string
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
			err = s.cfg.SecondLine.RemoveSecondLine(ctx)
		default:
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		if err == nil {
			http.Redirect(w, r, "/second-line/", http.StatusSeeOther)
			return
		}
		v.Err = "That didn't go through. Try again."
		var ve *VaultError
		if errors.As(err, &ve) && ve.Status < http.StatusInternalServerError && ve.Msg != "the vault is locked" {
			v.Err = ve.Msg // the vault process's fixed owner wording (UX-116-1)
		}
	}
	st, err := s.cfg.SecondLine.SecondLineStatus(ctx)
	if err != nil {
		v.Down, v.Refresh = true, "5"
		s.render(w, "secondline", v)
		return
	}
	v.St = st
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
	}
	if v.Form == (sipsign.Settings{}) && st.Set {
		v.Form = st.Settings
	}
	s.render(w, "secondline", v)
}

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
