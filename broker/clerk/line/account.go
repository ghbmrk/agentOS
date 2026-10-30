package line

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/sipsign"
)

// The account's slots. They sit under clerk.DeviceSlots because DeviceKey is
// the one lend whose contract fits a digest password: the clerk store lends
// it for one call, wipes it after, and the call returns only a proof made
// with it (CLK-1). The clerk runs in its own process with its own store, so
// no device clerk shares these slots (ASSUMPTIONS.md CLK8-3).
const (
	slots        = clerk.DeviceSlots + "second-line/"
	slotPassword = slots + "password"
	slotAccount  = slots + "account"
)

// MinPassword is the shortest password setup takes: a digest response is
// offline-guessable for a weak one, so only a provider-generated password
// of at least 12 characters (sipline SL2).
const MinPassword = 12

// RealmWindow is how long after setup the realm may be learned from the
// first registration (sipline SL3), in ms.
const RealmWindow = 30 * 60 * 1000

// Errors from setup and the realm steps.
var (
	ErrShortPassword = errors.New("line: the password is shorter than 12 characters")
	ErrNoAccount     = errors.New("line: no second line is set up")
	ErrRealm         = errors.New("line: that is not the realm the line learned")
)

// Record is the account other than its password: its settings, and the
// realm learned from the first registration and whether the owner
// confirmed it (SL3). Nothing in it is secret; it is sealed beside the
// password so a restore moves both together.
type Record struct {
	Settings       sipsign.Settings `json:"settings"`
	Realm          string           `json:"realm,omitempty"`
	RealmConfirmed bool             `json:"realm_confirmed,omitempty"`
	SetAt          int64            `json:"set_at"`
}

// Account is the second line's account on the clerk's sealed store.
type Account struct {
	secrets *clerk.Secrets
	clock   clerk.Clock
	mu      sync.Mutex // serializes record writes
}

// Set checks the settings and seals the account, replacing any earlier one
// and its realm. A refusal names the field (sipsign's per-field errors) or
// the password's length, never a value.
func (a *Account) Set(s sipsign.Settings, password string) error {
	s = s.Normalize()
	if err := s.Check(); err != nil {
		return err
	}
	if len(password) < MinPassword {
		return ErrShortPassword
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.secrets.RemovePrefix(slots, ""); err != nil {
		return err
	}
	if err := a.secrets.Put(slotPassword, clerk.KindStatic, []byte(password)); err != nil {
		return err
	}
	return a.put(Record{Settings: s, SetAt: a.clock.Now()})
}

// Remove erases the account: both slots, in one write.
func (a *Account) Remove() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.secrets.RemovePrefix(slots, "")
}

// Record reads the account record; false when none is set.
func (a *Account) Record() (Record, bool) {
	var rec Record
	if !a.secrets.Has(slotAccount) {
		return rec, false
	}
	err := a.secrets.DeviceKey(slotAccount)(func(b []byte) error { return json.Unmarshal(b, &rec) })
	return rec, err == nil
}

func (a *Account) hasPassword() bool { return a.secrets.Has(slotPassword) }

// ConfirmRealm is the owner confirming, on the page, the realm the line
// learned (SL3); only then does the clerk sign a text.
func (a *Account) ConfirmRealm(realm string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec, ok := a.Record()
	if !ok {
		return ErrNoAccount
	}
	if rec.Realm == "" || rec.Realm != realm {
		return ErrRealm
	}
	rec.RealmConfirmed = true
	return a.put(rec)
}

// learnRealm records realm as the account's, unconfirmed, if none is
// recorded and setup was within RealmWindow.
func (a *Account) learnRealm(realm string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec, ok := a.Record()
	switch {
	case !ok:
		return ErrNoAccount
	case rec.Realm != "":
		return nil
	case a.clock.Now()-rec.SetAt > RealmWindow:
		return sipsign.ErrRealm
	}
	rec.Realm = realm
	return a.put(rec)
}

func (a *Account) put(rec Record) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return a.secrets.Put(slotAccount, clerk.KindStatic, b)
}

// sign answers c with acct's password, lent for this one call. The realm
// in acct is the recorded one, or the one being learned.
func (a *Account) sign(ctx context.Context, rec Record, realm string, c sipsign.Challenge) (string, error) {
	var auth string
	err := a.secrets.DeviceKey(slotPassword)(func(p []byte) error {
		acct := sipsign.Account{Username: rec.Settings.User, Password: string(p), Realm: realm, RegisterOnly: !rec.RealmConfirmed}
		var err error
		auth, err = acct.Sign(ctx, c)
		return err
	})
	return auth, err
}
