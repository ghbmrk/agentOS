package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
	"unicode"

	"github.com/ghbmrk/agentos/broker/sipsign"
	"github.com/ghbmrk/agentos/broker/vault"
)

// The second line's calling account (ADP-12, sipline SL2 and SL3, P2-3c).
// The local UI sets it up on the unlock socket; the modem bridge reads its
// settings and has challenges answered on sign.sock, which admits only the
// bridge's uid. The password never leaves this process (CRED-1).

// SignSocket is the modem bridge's socket.
const SignSocket = "sign.sock"

// RealmWindow is how long after setup the first registration may record
// the provider's realm (SL3). Past it, setting the account up again
// reopens it.
const RealmWindow = 30 * time.Minute

var (
	errBadSIP          = uerr(http.StatusBadRequest, "those calling account settings were refused")
	errWeakSIPPassword = uerr(http.StatusBadRequest, "use the SIP password your provider generated, 12 to 256 characters")
)

// sipRecord is the settings entry: the settings, the realm once recorded,
// and when setup ran (Unix seconds), which opens RealmWindow.
type sipRecord struct {
	sipsign.Settings
	Realm string `json:"realm,omitempty"`
	SetAt int64  `json:"set_at"`
}

// sipStatus is what the local page reads; never the password.
type sipStatus struct {
	Set                    bool             `json:"set"`
	Settings               sipsign.Settings `json:"settings"`
	RealmRecorded          bool             `json:"realm_recorded"`
	WaitingForRegistration bool             `json:"waiting_for_registration"`
}

// sipPassword is a provider-generated password: printable, and long
// enough for the vault's redactor (vault.MinValueLen) and to resist
// guessing from a captured digest answer (SL2).
func sipPassword(p string) bool {
	if len(p) < vault.MinValueLen || len(p) > 256 {
		return false
	}
	for _, r := range p {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// setSIP stores the account while the vault is open. The password is an
// entry of its own (CRED-7) and goes first, so the settings entry, which
// resets the realm and opens the window, is only written beside it.
func (c *custody) setSIP(s sipsign.Settings, password string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return errLocked
	}
	if s.Check() != nil || hasOtherKind(c.v, sipsign.SettingsName, sipsign.KindSettings) || hasOtherKind(c.v, sipsign.PasswordName, sipsign.KindPassword) {
		return errBadSIP
	}
	if !sipPassword(password) {
		return errWeakSIPPassword
	}
	rec, err := json.Marshal(sipRecord{Settings: s, SetAt: c.now().Unix()})
	if err != nil {
		return errInternal
	}
	if err := c.v.Put(sipsign.PasswordName, sipsign.KindPassword, []byte(password)); err != nil {
		return c.putErr(err)
	}
	if err := c.v.Put(sipsign.SettingsName, sipsign.KindSettings, rec); err != nil {
		return c.putErr(err)
	}
	return nil
}

func (c *custody) putErr(err error) error {
	if errors.Is(err, vault.ErrRolledBack) {
		c.notify(noteRolledBack)
		return errRolledBack
	}
	return errInternal
}

// removeSIP deletes the account. Caller-facing: the local UI.
func (c *custody) removeSIP() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return errLocked
	}
	for _, n := range []struct{ name, kind string }{{sipsign.SettingsName, sipsign.KindSettings}, {sipsign.PasswordName, sipsign.KindPassword}} {
		if !hasKind(c.v, n.name, n.kind) {
			continue
		}
		if err := c.v.Delete(n.name); err != nil {
			return c.putErr(err)
		}
	}
	return nil
}

// sipAccount reads the account. Caller holds mu.
func (c *custody) sipAccount() (sipRecord, sipsign.Account, error) {
	if c.ph != open {
		return sipRecord{}, sipsign.Account{}, sipsign.ErrLocked
	}
	if !hasKind(c.v, sipsign.SettingsName, sipsign.KindSettings) || !hasKind(c.v, sipsign.PasswordName, sipsign.KindPassword) {
		return sipRecord{}, sipsign.Account{}, sipsign.ErrNoAccount
	}
	raw, ok1 := c.v.Secret(sipsign.SettingsName)
	pw, ok2 := c.v.Secret(sipsign.PasswordName)
	var rec sipRecord
	if !ok1 || !ok2 || json.Unmarshal([]byte(raw.Reveal()), &rec) != nil {
		return sipRecord{}, sipsign.Account{}, sipsign.ErrNoAccount
	}
	return rec, sipsign.Account{Username: rec.User, Password: pw.Reveal(), Realm: rec.Realm}, nil
}

// learning reports whether rec may still record a realm.
func (c *custody) learning(rec sipRecord) bool {
	return rec.Realm == "" && c.now().Before(time.Unix(rec.SetAt, 0).Add(RealmWindow))
}

func (c *custody) sipStatus() (sipStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, _, err := c.sipAccount()
	switch {
	case errors.Is(err, sipsign.ErrLocked):
		return sipStatus{}, errLocked
	case err != nil:
		return sipStatus{}, nil
	}
	return sipStatus{Set: true, Settings: rec.Settings, RealmRecorded: rec.Realm != "", WaitingForRegistration: c.learning(rec)}, nil
}

// signStore is the custody as sign.sock serves it (sipsign.Store).
type signStore struct{ c *custody }

func (s signStore) Account() (sipsign.Settings, sipsign.Account, error) {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	rec, a, err := s.c.sipAccount()
	return rec.Settings, a, err
}

// LearnRealm records the first registration's realm (SL3): only while none
// is recorded and within RealmWindow of setup.
func (s signStore) LearnRealm(realm string) (sipsign.Account, error) {
	c := s.c
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, a, err := c.sipAccount()
	if err != nil {
		return sipsign.Account{}, err
	}
	if realm == "" || !c.learning(rec) {
		return sipsign.Account{}, sipsign.ErrRealm
	}
	rec.Realm = realm
	raw, err := json.Marshal(rec)
	if err != nil {
		return sipsign.Account{}, err
	}
	if err := c.v.Put(sipsign.SettingsName, sipsign.KindSettings, raw); err != nil {
		c.putErr(err)
		return sipsign.Account{}, sipsign.ErrRealm
	}
	a.Realm = realm
	return a, nil
}

// serveSign opens sign.sock in dir for the modem bridge's uid.
func serveSign(dir string, c *custody, modemUID int) (*http.Server, error) {
	if err := runDir(dir); err != nil {
		return nil, err
	}
	ln, err := listen(dir, SignSocket, modemUID)
	if err != nil {
		return nil, err
	}
	srv := newServer(sipsign.Handler(signStore{c}))
	go srv.Serve(ln)
	return srv, nil
}

// secondLineRoutes adds the account's setup to the unlock socket.
func secondLineRoutes(mux *http.ServeMux, c *custody, read func(http.ResponseWriter, *http.Request, any) bool,
	reply func(http.ResponseWriter, int, any), fail func(http.ResponseWriter, error)) {
	mux.HandleFunc("/second-line", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			sipsign.Settings
			Password string `json:"password"`
		}
		if !read(w, r, &req) {
			return
		}
		if err := c.setSIP(req.Settings, req.Password); err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/second-line/status", func(w http.ResponseWriter, r *http.Request) {
		st, err := c.sipStatus()
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, http.StatusOK, st)
	})
	mux.HandleFunc("/second-line/remove", func(w http.ResponseWriter, r *http.Request) {
		var req struct{}
		if !read(w, r, &req) {
			return
		}
		if err := c.removeSIP(); err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
