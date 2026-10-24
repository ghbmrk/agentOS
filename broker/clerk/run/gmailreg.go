package run

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// The household's Google registration kept apart from any grant (#3055).
// A grant's slot holds the registration it was given with, so it would go
// with the slot when the owner removes the account, switches to IMAP or
// disconnects Gmail. The clerk's process keeps the registration of each
// grant it sets up in a file of its own, sealed under the clerk's Sealer as
// the record of read mail is, so the next sign-in needs none from the owner.
// It is no slot of the account's store: clerk.NewAPI and clerk.NewSignIn
// refuse a store holding a second slot (CLK-1). A file that does not load
// counts as missing, and the owner enters the registration again.
const (
	regFile = "gmail.reg"
	maxReg  = 4 << 10
)

func regAAD() []byte { return []byte("agentOS gmail registration\n") }

// loadReg reads dir's kept registration; ok is false if there is none, or
// the file is not the clerk's own, past its bound, not sealed as a
// registration under s, or holds no ID and secret.
func loadReg(dir string, s clerk.Sealer) (r clerk.Registration, ok bool) {
	f, err := os.OpenFile(filepath.Join(dir, regFile), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return r, false
	}
	defer f.Close()
	if privfile.CheckFile(f) != nil {
		return r, false
	}
	blob, err := io.ReadAll(io.LimitReader(f, maxReg+1))
	if err != nil || len(blob) > maxReg {
		return r, false
	}
	plain, err := s.Open(blob, regAAD())
	if err != nil {
		return r, false
	}
	defer clear(plain)
	var g gmailRegistration
	if json.Unmarshal(plain, &g) != nil || g.ID == "" || g.Secret == "" {
		return r, false
	}
	return clerk.Registration{ID: g.ID, Secret: g.Secret}, true
}

// saveReg seals r as dir's kept registration, replacing any before.
func saveReg(dir string, s clerk.Sealer, r clerk.Registration) error {
	plain, err := json.Marshal(gmailRegistration{r.ID, r.Secret})
	if err != nil {
		return err
	}
	defer clear(plain)
	blob, err := s.Seal(plain, regAAD())
	if err != nil {
		return err
	}
	if len(blob) > maxReg {
		return errors.New("run: the registration is past its bound")
	}
	return privfile.WriteAtomic(dir, regFile, blob, nil)
}

// keepReg keeps the registration grant was sealed with, the grant a sign-in
// just set up an account with.
func keepReg(dir string, s clerk.Sealer, grant []byte) error {
	var g struct {
		ID     string `json:"client_id"`
		Secret string `json:"client_secret"`
	}
	if s == nil {
		return errNoSealer
	}
	if json.Unmarshal(grant, &g) != nil || g.ID == "" || g.Secret == "" {
		return errors.New("run: the grant holds no registration")
	}
	return saveReg(dir, s, clerk.Registration{ID: g.ID, Secret: g.Secret})
}
