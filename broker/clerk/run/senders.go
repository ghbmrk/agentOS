package run

import (
	"bytes"
	"cmp"
	"encoding/gob"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// The mail clerk's record of who writes to the owner (MAIL-world-b2): the
// senders read (inbox's SendersStep) gives VRB-2's History, KnownSenders
// and Contacts from the mailbox itself. It is trusted input: a forged
// record with old dates would make a new sender look long known. So, as the
// record of read mail (seen.go), it is sealed under the clerk's Sealer and
// bound to the account's slot, its size is checked before it is read, and a
// record that does not load starts over, which gives no history until the
// read is through again (fail closed).
const (
	sendersFile = "senders.rec"
	// maxSendersRec bounds the sealed record before it is read. A record
	// within inbox.SendersMax and inbox.ContactsMax, each address at most
	// 254 bytes, is under 6.5 MiB with its gob marks; one past a bound is
	// saved empty (sealedSenders.Over).
	maxSendersRec = 8 << 20
)

// sendersStepMax is how many mails one step of the senders read reads, and
// sendersPause how long the worker waits between steps while there is more
// to read (MailConfig.stepMax and pause in tests).
const (
	sendersStepMax = 2000
	sendersPause   = 10 * time.Second
)

// sealedSenders is the record as sealed. Over is set once a bound was
// passed: the record then holds nothing more and gives no history.
type sealedSenders struct {
	Rec  inbox.SendersRecord
	Over bool
}

func sendersAAD(slot string) []byte { return []byte("agentOS senders record\n" + slot) }

// loadSenders reads dir's record for the account at slot; a record that is
// missing or does not load (too large, not the clerk's own file, not sealed
// under this sealer and account, or not a record) is an empty one.
func loadSenders(dir string, s clerk.Sealer, slot string) sealedSenders {
	f, err := os.OpenFile(filepath.Join(dir, sendersFile), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return sealedSenders{}
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || privfile.CheckFile(f) != nil || fi.Size() > maxSendersRec {
		return sealedSenders{}
	}
	blob := make([]byte, fi.Size())
	if _, err := io.ReadFull(f, blob); err != nil {
		return sealedSenders{}
	}
	plain, err := s.Open(blob, sendersAAD(slot))
	if err != nil {
		return sealedSenders{}
	}
	defer clear(plain)
	var r sealedSenders
	if gob.NewDecoder(bytes.NewReader(plain)).Decode(&r) != nil || !r.Over && r.Rec.Over() {
		return sealedSenders{}
	}
	return r
}

// saveSenders seals r as dir's record of senders for the account at slot.
// stop, for tests only, is privfile.WriteAtomic's; nil runs every step.
func saveSenders(dir string, s clerk.Sealer, slot string, r sealedSenders, stop func(i int) bool) error {
	var plain bytes.Buffer
	if err := gob.NewEncoder(&plain).Encode(r); err != nil {
		return err
	}
	defer clear(plain.Bytes())
	blob, err := s.Seal(plain.Bytes(), sendersAAD(slot))
	if err != nil {
		return err
	}
	if len(blob) > maxSendersRec {
		return errors.New("run: the record of who writes to the owner is past its bound")
	}
	return privfile.WriteAtomic(dir, sendersFile, blob, stop)
}

// sendersState is how far the senders read is, for the world and STATUS.
type sendersState int

const (
	sendersReading sendersState = iota // not yet through once: no history
	sendersFull                        // through, within bounds, last step read
	sendersFailed                      // the last step failed: no history until one reads
	sendersOver                        // a bound passed: no history
)

// history is the world's three fields from a full record: one Delivery per
// sender at its earliest arrival's day (UTC), the senders, and the sent-to
// addresses, each sorted. Their capacity is their length, so a world that
// appends to one does not write into another's.
func history(r inbox.SendersRecord) (h []inbox.Delivery, known, contacts []string) {
	for a, t := range r.Senders {
		known = append(known, a)
		h = append(h, inbox.Delivery{From: a, Folder: "inbox", Date: time.Unix(t, 0).UTC().Format(time.DateOnly)})
	}
	for a := range r.Sent {
		contacts = append(contacts, a)
	}
	slices.Sort(known)
	slices.Sort(contacts)
	slices.SortFunc(h, func(a, b inbox.Delivery) int { return cmp.Compare(a.From, b.From) })
	return slices.Clip(h), slices.Clip(known), slices.Clip(contacts)
}

// readSenders is one step of the senders read for the account as it is
// now, run as the worker's step beside planSenders: h.mu is held, and
// released while the mailbox is read, under h.stepping, which setup,
// removal and the Gmail sign-in wait for (idle), so the record is never
// written for an account that has changed. The record is loaded once per
// account and kept in memory between steps. Retaking h.mu, the step's
// result goes to the world only if the account is unchanged, and only then
// does a sign-in failure stop the clerk, as a step's does (Do). more is
// whether to step again after sendersPause.
func (h *MailHost) readSenders() (more bool) {
	for h.stepping != nil {
		h.wait()
	}
	if h.stop != nil {
		return false
	}
	changes := h.changes
	s, err := readMail(h.dir)
	if err != nil {
		return false
	}
	slot := slotOf(s)
	rec := h.srec
	if rec == nil || h.srecAt != changes {
		r := loadSenders(h.dir, h.cfg.Sealer, slot)
		rec = &r
	}
	done := make(chan struct{})
	h.stepping = done
	h.mu.Unlock()
	if !rec.Over {
		var box mailbox
		if box, err = boxFor(s, h.sec, h.cfg); err == nil {
			more, err = box.SendersStep(h.ctx, &rec.Rec, cmp.Or(h.cfg.stepMax, sendersStepMax))
		}
		if rec.Rec.Over() {
			*rec, more = sealedSenders{Over: true}, false
		}
		// A record that cannot be saved stands in memory; the next start
		// reads again from the one saved before.
		_ = saveSenders(h.dir, h.cfg.Sealer, slot, *rec, nil)
	}
	st := sendersFull
	switch {
	case rec.Over:
		st = sendersOver
	case err != nil:
		st, more = sendersFailed, false
	case !rec.Rec.Complete():
		st = sendersReading
	}
	var hist []inbox.Delivery
	var known, contacts []string
	if st == sendersFull {
		hist, known, contacts = history(rec.Rec)
	}
	h.mu.Lock()
	h.stepping = nil
	close(done)
	if h.changes == changes {
		h.srec, h.srecAt = rec, changes
		if stops(err) {
			why, next := trouble(err, nil)
			h.why, h.stop = "I stopped working in your mailbox: "+why+". "+next, err
		}
		h.ws.keepSenders(changes, st, hist, known, contacts)
		h.sendersWhy = ""
		if err != nil {
			h.sendersWhy, _ = trouble(err, nil)
		}
	}
	if h.cfg.stepped != nil {
		h.cfg.stepped(more, st == sendersFull)
	}
	return more
}

// sendersLine is STATUS's line while the senders read gives no history, or
// "" once it does; why is the failed step's reason (trouble).
func sendersLine(st sendersState, why string) string {
	switch st {
	case sendersReading:
		return "Unsubscribing waits until I have read through your mailbox once, to learn who writes to you."
	case sendersFailed:
		return "Unsubscribing is paused: I could not finish reading who writes to you: " + why + ". I'll try again at my next read of your mail, within a day."
	case sendersOver:
		return "Unsubscribing is off: more people write to you, or you write to more people, than I can keep track of."
	}
	return ""
}
