package run

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// The durable record of Gmail grants owed a give-back (#3028, closing
// TN-gmail-socket-b's crash windows). Before a setup or a removal drops a
// Gmail account's grant, and before a sign-in puts a new grant in a slot
// the settings do not yet name, the grant's store is added to the record;
// once the change is made and the grant given back, or kept because the
// account uses it, it leaves the record. The mail process replays the
// record at start (NewMailHost), before it reads: a grant whose account is
// set up with it stays, and any other is given back to Google and its
// slot, if the store still holds it, dropped, so a crash between the
// change and the give-back leaves no grant unrevoked and untold.
//
// Each entry is a store of its own holding the one slot, sealed under the
// clerk's Sealer as the account's store seals it (MarshalBinary: sealed
// blobs only), so the grant is never opened here; the file is sealed again
// under its own AAD, as gmail.reg is. It is no file RemoveMail drops: a
// removal's give-back is owed after the account is gone.
const (
	giveFile = "gmail.giveback"
	maxGive  = 64 << 10
)

func giveAAD() []byte { return []byte("agentOS gmail give-back\n") }

// owed is one grant owed a give-back: its slot, the address of its
// account (for the owner's notice if Google keeps it), and its own store.
type owed struct {
	Slot    string          `json:"slot"`
	Address string          `json:"address"`
	Store   json.RawMessage `json:"store"`
}

// errGiveRecord: the record is not the clerk's own, past its bound, or not
// sealed as a give-back record under the sealer.
var errGiveRecord = errors.New("run: the record of grants owed a give-back does not load")

// loadOwed reads dir's record: none when there is no file.
func loadOwed(dir string, s clerk.Sealer) ([]owed, error) {
	f, err := os.OpenFile(filepath.Join(dir, giveFile), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errGiveRecord
	}
	defer f.Close()
	if privfile.CheckFile(f) != nil {
		return nil, errGiveRecord
	}
	blob, err := io.ReadAll(io.LimitReader(f, maxGive+1))
	if err != nil || len(blob) > maxGive || s == nil {
		return nil, errGiveRecord
	}
	plain, err := s.Open(blob, giveAAD())
	defer clear(plain)
	var o []owed
	if err != nil || json.Unmarshal(plain, &o) != nil {
		return nil, errGiveRecord
	}
	return o, nil
}

// saveOwed seals o as dir's record, or removes the file when o is empty.
// stop, for tests only, is privfile.WriteAtomic's.
func saveOwed(dir string, s clerk.Sealer, o []owed, stop func(i int) bool) error {
	if len(o) == 0 {
		return removeFiles(dir, giveFile, giveFile+".tmp")
	}
	if s == nil {
		return errNoSealer
	}
	plain, err := json.Marshal(o)
	if err != nil {
		return err
	}
	blob, err := s.Seal(plain, giveAAD())
	if err != nil {
		return err
	}
	if len(blob) > maxGive {
		return errors.New("run: the record of grants owed a give-back is past its bound")
	}
	return privfile.WriteAtomic(dir, giveFile, blob, stop)
}

// owe adds slot of sec, a store holding that slot only, for the account at
// addr, to the record; h.mu is held. An error means nothing may change: the caller makes no change.
func (h *MailHost) owe(slot, addr string, sec *clerk.Secrets) error {
	b, err := sec.MarshalBinary()
	if err != nil {
		return err
	}
	o, err := loadOwed(h.dir, h.cfg.Sealer)
	if err != nil {
		return err
	}
	o = slices.DeleteFunc(o, func(e owed) bool { return e.Slot == slot })
	return saveOwed(h.dir, h.cfg.Sealer, append(o, owed{Slot: slot, Address: addr, Store: b}), h.cfg.giveStop)
}

// owedNew adds grant, a sign-in's new grant for slot (the account at addr),
// to the record before it is put in the account's store.
func (h *MailHost) owedNew(slot, addr string, grant []byte) error {
	if h.cfg.Sealer == nil {
		return errNoSealer
	}
	sec := clerk.NewSecrets(h.cfg.Sealer, nil)
	if err := sec.Put(slot, clerk.KindGrant, grant); err != nil {
		return err
	}
	return h.owe(slot, addr, sec)
}

// paid drops slot from the record; h.mu is held. A failed write leaves the
// entry, which the next start settles the same way.
func (h *MailHost) paid(slot string) {
	o, err := loadOwed(h.dir, h.cfg.Sealer)
	if err != nil {
		return
	}
	n := len(o)
	if o = slices.DeleteFunc(o, func(e owed) bool { return e.Slot == slot }); len(o) != n {
		_ = saveOwed(h.dir, h.cfg.Sealer, o, h.cfg.giveStop)
	}
}

// settleOwed replays the record at start, with h.mu held and before any
// read: each grant the account is set up with stays; every other is given
// back and its slot dropped from the account's store if it is there, which
// a crash before the settings were written leaves. A grant Google keeps,
// or an entry or record that does not load, is told with the step that
// ends it, never one that would end the set-up account's grant (keptNote,
// CH-12). The record goes once every entry is settled.
func (h *MailHost) settleOwed() {
	o, err := loadOwed(h.dir, h.cfg.Sealer)
	if err != nil {
		h.notify(false, h.keptNote("")) // which account it was for is lost with the record
		_ = saveOwed(h.dir, h.cfg.Sealer, nil, nil)
		return
	}
	if len(o) == 0 {
		return
	}
	for _, e := range o {
		if h.setUp(e.Slot) && h.sec.Has(e.Slot) {
			continue // the change did not happen, or this grant is the account's
		}
		if h.sec.Has(e.Slot) {
			_ = h.sec.Remove(e.Slot) // a slot nothing names
		}
		sec := clerk.NewSecrets(h.cfg.Sealer, nil)
		var g *gmailSignIn
		if err = sec.UnmarshalBinary(e.Store); err == nil && sec.Len() == 1 && sec.Has(e.Slot) {
			g, err = h.newGmailSignIn(sec, e.Slot, "")
		} else if err == nil {
			err = errGiveRecord
		}
		if err != nil || g.in.Revoke(h.ctx) != clerk.DRevoked {
			h.notify(false, h.keptNote(e.Address))
		}
	}
	_ = saveOwed(h.dir, h.cfg.Sealer, nil, h.cfg.giveStop)
}
