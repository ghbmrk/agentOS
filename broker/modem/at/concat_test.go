package at_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem/at"
)

// REQ: CH-1

// firstPart stores only part 1 of a two-part text from from, and waits
// until the driver has taken it.
func (r *rig) firstPart(t *testing.T, from string, ref byte) []string {
	t.Helper()
	parts, err := at.EncodeDeliver(from, strings.Repeat("part of a long text ", 12), ref)
	if err != nil || len(parts) != 2 {
		t.Fatal(len(parts), err)
	}
	r.dev.StorePDU(parts[0])
	eventually(t, "part taken", func() bool { return r.dev.Stored() == 0 })
	return parts
}

// Hostile senders filling the reassembly buffer with first parts cannot
// push out the owner's long text before its last part arrives: the owner
// has slots only the owner's number can use (security review 2, finding 7).
func TestCH1OwnersLongTextSurvivesAFloodOfFirstParts(t *testing.T) {
	r := newRig(t, vendors[1], at.KeysInBand, nil)
	owner := r.firstPart(t, ownerNum, 1)
	for i := 0; i < 40; i++ {
		r.firstPart(t, fmt.Sprintf("+1555700%04d", i), byte(i))
	}
	// 40 strangers' texts, at most 28 kept: the oldest 12 are dropped.
	eventually(t, "strangers' oldest dropped", func() bool { return r.m.Dropped() == 12 })
	r.dev.StorePDU(owner[1])
	if got := r.text(); got.From != ownerNum || !strings.HasPrefix(got.Text, "part of a long text") {
		t.Fatalf("got %+v", got)
	}
}

// One sender keeps at most 4 texts pending; a fifth drops that sender's
// own oldest, never another sender's.
func TestCH1PerSenderCapDropsOnlyThatSendersOldest(t *testing.T) {
	r := newRig(t, vendors[1], at.KeysInBand, nil)
	const a, b = "+15557000001", "+15557000002"
	aText := r.firstPart(t, a, 1)
	var bTexts [][]string
	for i := 1; i <= 5; i++ {
		bTexts = append(bTexts, r.firstPart(t, b, byte(i)))
	}
	eventually(t, "b's oldest dropped", func() bool { return r.m.Dropped() == 1 })
	r.dev.StorePDU(aText[1])
	if got := r.text(); got.From != a {
		t.Fatalf("got %+v, want a's text", got)
	}
	// b's newest four are whole once their last parts come; its first is
	// gone, so its last part starts a new text that never completes.
	for _, p := range bTexts[1:] {
		r.dev.StorePDU(p[1])
		if got := r.text(); got.From != b {
			t.Fatalf("got %+v, want b's text", got)
		}
	}
	r.dev.StorePDU(bTexts[0][1])
	eventually(t, "taken", func() bool { return r.dev.Stored() == 0 })
	select {
	case got := <-r.m.Inbox():
		t.Fatalf("b's dropped text delivered: %q", got.Text)
	case <-time.After(50 * time.Millisecond):
	}
}

// The owner's own slots are capped like anyone's: a fifth pending owner
// text drops the owner's oldest, and an alphanumeric sender spelling the
// owner's number gets no owner slot.
func TestCH1OwnerSlotsAreTheOwnersNumberOnly(t *testing.T) {
	r := newRig(t, vendors[1], at.KeysInBand, nil)
	for i := 1; i <= 5; i++ {
		r.firstPart(t, ownerNum, byte(i))
	}
	eventually(t, "owner's oldest dropped", func() bool { return r.m.Dropped() == 1 })
	// 28 strangers fill the shared slots; an alpha sender spelling the
	// owner's number is a stranger, so it drops the oldest stranger, and
	// no owner text is lost.
	for i := 0; i < 28; i++ {
		r.firstPart(t, fmt.Sprintf("+1555700%04d", i), byte(i))
	}
	r.dev.StorePDU(at.DeliverAlphaPart("15550000001", strings.Repeat("x", 300), 77))
	eventually(t, "a stranger dropped, not the owner", func() bool { return r.m.Dropped() == 2 })
	r.dev.StorePDU(at.DeliverAlphaPart("15550000001", strings.Repeat("y", 300), 78))
	eventually(t, "another stranger dropped", func() bool { return r.m.Dropped() == 3 })
	if n := r.m.PendingFrom(ownerNum); n != 4 {
		t.Fatalf("owner has %d texts pending, want 4", n)
	}
}
