package kernel_test

// REQ: KRN-1

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// Open is the Log's only constructor: a zero Log and a nil *Log refuse every
// call with ErrNoLog and hold no entries, and Boot refuses them, so nothing
// panics on a Log Open did not make; a copy of an opened Log is the same log,
// so an append through either shows in both and in the store (KRN-1, #4574).
// Catches a nil record reached through Log.p, and copies that diverge.
func TestLogOpenIsTheOnlyConstructor(t *testing.T) {
	for _, l := range []*kernel.Log{{}, nil} {
		if _, err := l.Append(1, kernel.TTaskOpened, 1, map[string]string{"task": "t"}); !errors.Is(err, kernel.ErrNoLog) {
			t.Fatalf("append to a Log Open did not make: %v", err)
		}
		if err := l.Anchor(); !errors.Is(err, kernel.ErrNoLog) {
			t.Fatalf("anchor of a Log Open did not make: %v", err)
		}
		if l.Entries() != nil || l.Len() != 0 {
			t.Fatal("a Log Open did not make holds entries")
		}
		if _, err := kernel.Boot(l, nil, nil, 0); !errors.Is(err, kernel.ErrNoLog) {
			t.Fatalf("boot over a Log Open did not make: %v", err)
		}
	}

	r := newRig(t)
	n := r.k.Log().Len()
	cp := *r.k.Log()
	must(t, r.k.OpenTask(1, "t1"))
	if cp.Len() != n+1 || r.k.Log().Len() != n+1 {
		t.Fatalf("after one append the copy has %d entries and the log %d, want %d", cp.Len(), r.k.Log().Len(), n+1)
	}
	if _, err := cp.Append(2, kernel.TTaskOpened, 1, map[string]string{"task": "t2"}); err != nil {
		t.Fatal(err)
	}
	re, err := kernel.Open(cfg(r))
	must(t, err)
	if !kernel.Same(re.Entries(), r.k.Log().Entries()) || !kernel.Same(cp.Entries(), re.Entries()) {
		t.Fatal("a copy of the log diverged from it or from the store")
	}
}
