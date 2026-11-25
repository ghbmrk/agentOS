package proc

// REQ: LOG-4, KRN-7, MAIL-keys
//
// MUT-kill-6305-proc (#6367): bounds and refusals on the kernel's socket
// calls and a clerk's view, each checked by what they answer.

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// named takes a label of exactly MaxLabel bytes and refuses one longer.
func TestNamedTakesALabelUpToItsBound(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	named := OwnerSide.ops["named"]
	for n, want := range map[int]bool{MaxLabel: true, MaxLabel + 1: false} {
		raw, _ := json.Marshal(labelArgs{Label: strings.Repeat("a", n)})
		var err error
		b.h.With(func(k *kernel.Kernel) error { _, err = named(k, b.now, raw); return nil })
		if (err == nil) != want || !want && !errors.Is(err, ErrArgs) {
			t.Fatalf("named with a %d-byte label: %v", n, err)
		}
	}
}

// An erase the kernel refuses crosses the socket as the call's error, not
// as a confirmation.
func TestARefusedEraseIsTheCallsError(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	raw, _ := json.Marshal("notasubject")
	got, err := OwnerSide.procOps["erase"](b.h, b.now, raw)
	if err == nil || got != nil {
		t.Fatalf("erase of a name that is no subject: %#v, %v; want the refusal", got, err)
	}
}

// A view's ledger answers only for the dispatch it was taken at.
func TestAViewsLedgerIsItsDispatchsOnly(t *testing.T) {
	l := map[key.ID][]key.Use{{1}: {{}}}
	for name, s := range map[string]*snapshot{
		"no dispatch": {Ledger: l},
		"another seq": {Ledger: l, Dispatch: &kernel.Dispatch{Seq: 8}},
		"its own":     {Ledger: l, Dispatch: &kernel.Dispatch{Seq: 7}},
	} {
		got := len(s.LedgerBefore(7).Uses(key.ID{1}))
		if want := map[bool]int{true: 1, false: 0}[name == "its own"]; got != want {
			t.Fatalf("%s: %d uses, want %d", name, got, want)
		}
	}
}

// A clerk's cgroup path is taken up to 1024 bytes and no longer.
func TestACgroupPathUpToItsBound(t *testing.T) {
	unit := "/u.service"
	for n, want := range map[int]bool{1024: true, 1025: false} {
		c := "/" + strings.Repeat("a", n-1-len(unit)) + unit
		if got := ValidCgroup(c); got != want || len(c) != n {
			t.Fatalf("a %d-byte cgroup path: %v, want %v", len(c), got, want)
		}
	}
}
