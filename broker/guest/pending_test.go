package guest

import (
	"fmt"
	"testing"
)

// REQ: RES-1

// PE7 (condition 2): the sleeper does not stop the agent while an owner
// message to it is queued or handed out and not yet answered. Another
// machine's messages do not count.
func TestOwnerPendingUntilAnswered(t *testing.T) {
	r := newRig(t, nil)
	r.client("m1")
	r.client("m2")
	if r.p.OwnerPending("m1") || r.p.OwnerPending("none") {
		t.Fatal("pending with no message")
	}
	id, err := r.p.DeliverOwner("m1", "book the dentist", true)
	if err != nil {
		t.Fatal(err)
	}
	if !r.p.OwnerPending("m1") || r.p.OwnerPending("m2") {
		t.Fatal("a queued message is not pending on its machine alone")
	}
	r.do("m1", "GET", "/owner/next", "")
	if !r.p.OwnerPending("m1") {
		t.Fatal("a handed-out message is not pending")
	}
	if code, _ := r.do("m1", "POST", "/owner/reply", fmt.Sprintf(`{"id":%q,"text":"done"}`, id)); code != 204 {
		t.Fatal("reply")
	}
	if r.p.OwnerPending("m1") {
		t.Fatal("an answered message is still pending")
	}
}
