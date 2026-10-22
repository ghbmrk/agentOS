package main

import (
	"context"
	"errors"
	"log"
	"sync/atomic"

	"github.com/ghbmrk/agentos/broker/journal"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// pauseGate is the gate as the owner's FORGET uses it (forget.go).
type pauseGate interface {
	Submit(journal.Intent) (journal.Status, error)
	Authorize(context.Context, string) (journal.Status, error)
	Dispatch(context.Context, string) (journal.Status, error)
}

type pauseGateBox struct{ g pauseGate }

// ownerNotify texts the owner FORGET's fixed-wording notices once the
// owner channel is attached, through its pacer (CH-15).
type ownerNotify struct {
	ch atomic.Pointer[ownerch.Channel]
}

// send texts the owner an update (W5-Dc-r1b QH-9).
func (n *ownerNotify) send(text string) {
	ch := n.ch.Load()
	if ch == nil {
		log.Printf("forget: owner notice not sent: owner channel not attached")
		return
	}
	if err := ch.Post(ownerch.ClassUpdate, text); err != nil {
		log.Printf("forget: owner notice not sent: %v", err)
	}
}

// try sends text to the owner as an update, reporting whether it went or
// was held: the hold keeps it (CH-15).
func (n *ownerNotify) try(text string) error {
	ch := n.ch.Load()
	if ch == nil {
		return errors.New("owner channel not attached")
	}
	return ch.Inform(text)
}
