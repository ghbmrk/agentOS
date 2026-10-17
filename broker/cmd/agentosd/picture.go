package main

import (
	"log"
	"sync/atomic"

	"github.com/ghbmrk/agentos/broker/journal"
)

// pictureJournal journals each picture texted to the owner line (an MMS
// notice, CH12-mms-c) once the journal is open: the owner line's ops are
// served by the daemon, so none arrives before. The record says only
// whether the owner sent it, never the number.
type pictureJournal struct {
	record atomic.Pointer[func(journal.PictureNote) error]
}

func (p *pictureJournal) open(record func(journal.PictureNote) error) { p.record.Store(&record) }

// tell is modemlink's Config.Picture.
func (p *pictureJournal) tell(owner bool) {
	r := p.record.Load()
	if r == nil {
		return
	}
	n := journal.PictureNote{From: journal.PictureOther}
	if owner {
		n.From = journal.PictureOwner
	}
	if err := (*r)(n); err != nil {
		log.Printf("a picture texted to the box was not journaled: %v", err)
	}
}
