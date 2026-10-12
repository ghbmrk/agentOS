package firstboot

// REQ: HW-1, ONB-7

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
)

// F10: a start before the latch resets what an earlier start may have
// provisioned; a confirmed card's vault is never touched, and a latch that
// cannot be read stops the start rather than reset anything.
func TestResetUnlatched(t *testing.T) {
	for name, tc := range map[string]struct {
		state   []byte
		loadErr error
		reset   bool
		fails   bool
	}{
		"first start":      {reset: true},
		"latch unset":      {state: []byte(`{"card_confirmed":false}`), reset: true},
		"confirmed":        {state: []byte(`{"card_confirmed":true}`)},
		"corrupt latch":    {state: []byte("{"), fails: true},
		"unreadable latch": {loadErr: errors.New("io"), fails: true},
	} {
		var st Store = &change.MemStore{}
		if tc.state != nil {
			if err := st.Save(tc.state); err != nil {
				t.Fatal(err)
			}
		}
		if tc.loadErr != nil {
			st = loadFails{tc.loadErr}
		}
		resets := 0
		err := ResetUnlatched(st, func() error { resets++; return nil })
		if (err != nil) != tc.fails || (resets == 1) != tc.reset || resets > 1 {
			t.Errorf("%s: err %v, resets %d", name, err, resets)
		}
	}
	st := &change.MemStore{}
	if err := ResetUnlatched(st, func() error { return errors.New("busy") }); err == nil {
		t.Fatal("a failed reset passed")
	}
	if err := ResetUnlatched(st, nil); err == nil {
		t.Fatal("no reset accepted")
	}
}

type loadFails struct{ err error }

func (l loadFails) Load() ([]byte, error) { return nil, l.err }
func (l loadFails) Save([]byte) error     { return l.err }
