package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
	"unicode"

	"github.com/ghbmrk/agentos/broker/modelroute"
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

// Setup refusals: one fixed reason per field, never the value entered
// (UX-116-1).
var (
	errSIPServer       = uerr(http.StatusBadRequest, "Enter the server as a host name and port, like sip.example.net:5061.")
	errSIPDomain       = uerr(http.StatusBadRequest, "Enter the SIP domain as a host name, like example.net.")
	errSIPUser         = uerr(http.StatusBadRequest, "The SIP user name has a character providers don't use. Copy it exactly from your provider.")
	errSIPNumber       = uerr(http.StatusBadRequest, "Enter the number with its country code, like +44 7700 900123.")
	errSIPOtherKind    = uerr(http.StatusBadRequest, "I already hold a different credential under this name. Remove the second line first, then set it up again.")
	errWeakSIPPassword = uerr(http.StatusBadRequest, "Use the SIP password your provider generated, 12 to 256 characters. If it is shorter, have the provider generate a new one.")
	errSIPRealm        = uerr(http.StatusConflict, "That is not the provider name I recorded. Check it again on this page.")
)

// Owner notices when the account changes (S2 on #116).
const (
	noteSIPReplaced = "The second line's calling account was replaced on my Wi-Fi page."
	noteSIPRemoved  = "The second line's calling account was removed on my Wi-Fi page."
)

// sipFieldErr maps a sipsign refusal to its owner wording.
func sipFieldErr(err error) error {
	switch err {
	case sipsign.ErrServer:
		return errSIPServer
	case sipsign.ErrDomain:
		return errSIPDomain
	case sipsign.ErrUser:
		return errSIPUser
	case sipsign.ErrNumber:
		return errSIPNumber
	}
	return errInternal
}

// sipRecord is the settings entry: the settings, the realm once recorded,
// whether the owner confirmed it, and when setup ran (Unix seconds), which
// opens RealmWindow. Until the realm is confirmed only REGISTER is signed
// (sipsign.Account.RegisterOnly; security R1 on #116, closing K13's
// residual).
type sipRecord struct {
	sipsign.Settings
	Realm     string `json:"realm,omitempty"`
	Confirmed bool   `json:"confirmed,omitempty"`
	SetAt     int64  `json:"set_at"`
}

// sipStatus is what the local page reads; never the password.
type sipStatus struct {
	Set                    bool             `json:"set"`
	Settings               sipsign.Settings `json:"settings"`
	RealmRecorded          bool             `json:"realm_recorded"`
	Realm                  string           `json:"realm,omitempty"`
	RealmConfirmed         bool             `json:"realm_confirmed"`
	WaitingForRegistration bool             `json:"waiting_for_registration"`
	// SetAt is when setup ran (Unix seconds), so the page can say what to
	// check while the first registration is slow (UX-139-2).
	SetAt int64 `json:"set_at"`
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
	s = s.Normalize()
	if err := s.Check(); err != nil {
		return sipFieldErr(err)
	}
	if hasOtherKind(c.v, sipsign.SettingsName, sipsign.KindSettings) || hasOtherKind(c.v, sipsign.PasswordName, sipsign.KindPassword) {
		return errSIPOtherKind
	}
	if !sipPassword(password) {
		return errWeakSIPPassword
	}
	replacing := hasKind(c.v, sipsign.SettingsName, sipsign.KindSettings)
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
	if replacing {
		c.notify(noteSIPReplaced)
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
	removed := false
	for _, n := range []struct{ name, kind string }{{sipsign.SettingsName, sipsign.KindSettings}, {sipsign.PasswordName, sipsign.KindPassword}} {
		if !hasKind(c.v, n.name, n.kind) {
			continue
		}
		if err := c.v.Delete(n.name); err != nil {
			return c.putErr(err)
		}
		removed = true
	}
	if removed {
		c.notify(noteSIPRemoved)
	}
	return nil
}

// confirmRealm records that the owner checked the realm the first
// registration recorded, which lets the account sign texts and calls.
func (c *custody) confirmRealm(realm string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, _, err := c.sipAccount()
	switch {
	case errors.Is(err, sipsign.ErrLocked):
		return errLocked
	case err != nil, rec.Realm == "" || realm != rec.Realm:
		return errSIPRealm
	}
	rec.Confirmed = true
	raw, err := json.Marshal(rec)
	if err != nil {
		return errInternal
	}
	if err := c.v.Put(sipsign.SettingsName, sipsign.KindSettings, raw); err != nil {
		return c.putErr(err)
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
	return rec, sipsign.Account{Username: rec.User, Password: pw.Reveal(), Realm: rec.Realm, RegisterOnly: !rec.Confirmed}, nil
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
	return sipStatus{Set: true, Settings: rec.Settings, RealmRecorded: rec.Realm != "", Realm: rec.Realm, RealmConfirmed: rec.Confirmed,
		WaitingForRegistration: c.learning(rec), SetAt: rec.SetAt}, nil
}

// secondLineState is the second line's state for agentosd's STATUS and
// digest lines (potency R1 on #139): a recorded realm the owner has not
// confirmed, or no registration within RealmWindow of setup.
func (c *custody) secondLineState() (modelroute.SecondLineState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, _, err := c.sipAccount()
	switch {
	case errors.Is(err, sipsign.ErrLocked):
		return modelroute.SecondLineOK, errLocked
	case err != nil, rec.Confirmed:
		return modelroute.SecondLineOK, nil
	case rec.Realm != "":
		return modelroute.SecondLineConfirm, nil
	case !c.learning(rec):
		return modelroute.SecondLineUnreached, nil
	}
	return modelroute.SecondLineOK, nil
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
	rec.Realm, rec.Confirmed = realm, false
	raw, err := json.Marshal(rec)
	if err != nil {
		return sipsign.Account{}, err
	}
	if err := c.v.Put(sipsign.SettingsName, sipsign.KindSettings, raw); err != nil {
		c.putErr(err)
		return sipsign.Account{}, sipsign.ErrRealm
	}
	a.Realm, a.RegisterOnly = realm, true
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
	// A request is a few hundred bytes; a peer that trickles one is cut
	// off rather than holding a connection (S3 on #116).
	srv.ReadTimeout = 10 * time.Second
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
	mux.HandleFunc("/second-line/confirm", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Realm string `json:"realm"`
		}
		if !read(w, r, &req) {
			return
		}
		if err := c.confirmRealm(req.Realm); err != nil {
			fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
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
