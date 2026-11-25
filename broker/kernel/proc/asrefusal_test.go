package proc

// REQ: LOG-7

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// A metered call's answer is no refusal when it succeeded, the kernel's own
// refusal when it carries one, however wrapped, and a broken-log refusal
// naming the failure otherwise, so no call starts on a ledger it could not
// reach (#6023).
func TestAnAnswerReadsAsItsRefusal(t *testing.T) {
	if rf := asRefusal(nil); rf != nil {
		t.Fatalf("a success: %v", rf)
	}
	held := key.Refuse(kernel.CHeld, "spend-task")
	if rf := asRefusal(fmt.Errorf("call: %w", held)); rf != held {
		t.Fatalf("a wrapped refusal: %v", rf)
	}
	if rf := asRefusal(errors.New("socket cut")); rf == nil || rf.Code() != kernel.CBroken || rf.Detail != "socket cut" {
		t.Fatalf("a lost answer: %v", rf)
	}
}
