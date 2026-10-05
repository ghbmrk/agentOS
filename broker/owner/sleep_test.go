package owner

import (
	"testing"
	"time"
)

// REQ: RES-1

// PE7 (condition 2): the sleeper does not stop the agent while a queued
// auto-reply or held effect is inside its undo window, and it reads when
// the owner last sent a message the control handler ran.
func TestUndoOpenAndLastActive(t *testing.T) {
	r := newRig(t, nil)
	if r.ch.UndoOpen() || !r.ch.LastActive().IsZero() {
		t.Fatal("a fresh channel reports an open undo window or owner activity")
	}
	res, err := r.ch.QueueAutoReply(AutoReply{Ref: "r1", Recipients: []string{"sam@example.com"}, Body: "Sounds good."})
	if err != nil || res.Queued == nil {
		t.Fatalf("%+v %v", res, err)
	}
	r.inbox()
	if !r.ch.UndoOpen() {
		t.Fatal("a queued auto-reply is not an open undo window")
	}
	r.advance(10 * time.Minute)
	if len(r.ch.DueAutoReplies()) != 1 {
		t.Fatal("reply not released")
	}
	if r.ch.UndoOpen() {
		t.Fatal("a released reply still counted")
	}
	r.unlock()
	at := r.clock()
	r.say("book a table for two")
	if got := r.ch.LastActive(); !got.Equal(at) {
		t.Fatalf("LastActive %v, want %v", got, at)
	}
}
