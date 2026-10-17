package localsrv

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: CH-7, CH-18

// fuzzSession is the model's copy of one minted session, kept until the
// server forgets it: signed out, evicted, or dropped when found dead.
type fuzzSession struct {
	tok   string
	until time.Time
	locks uint64
	n     int
}

// FuzzSessions (FUZZ-2): over any sequence of sign-ins with the right or a
// wrong code, sign-outs, session checks, owner locks and clock moves, a
// token is accepted exactly when it is one of the MaxSessions newest,
// before its time and minted under the current lock count; a signed-out,
// expired, locked-out or evicted token is never accepted again; and no
// more than WrongPerMinute wrong codes reach the owner in any minute.
func FuzzSessions(f *testing.F) {
	f.Add([]byte{0, 0, 2, 0, 1, 0, 2, 0})
	f.Add([]byte{1, 1, 1, 1, 1, 1, 0, 5, 3, 0, 0})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2, 16})
	f.Add([]byte{0, 0, 4, 2, 0, 3, 5, 4, 0, 0, 5, 1, 2, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		r := newRig(t)
		var minted []string
		var held []fuzzSession      // the sessions the server holds, oldest first
		dead := map[string]string{} // token: why it may never be accepted again
		var wrong []time.Time       // wrong codes in the last minute
		var seen []time.Time        // every wrong code the owner saw
		n := 0
		at := func(i int) byte {
			if i < len(b) {
				return b[i]
			}
			return 0
		}
		locks := func() uint64 {
			r.own.mu.Lock()
			defer r.own.mu.Unlock()
			return r.own.locks
		}
		signIns := func() int {
			r.own.mu.Lock()
			defer r.own.mu.Unlock()
			return r.own.signIns
		}
		// accepts is the model's verdict on tok now, dropping a dead
		// session as the server does when it checks one.
		accepts := func(tok string) bool {
			for i, s := range held {
				if s.tok != tok {
					continue
				}
				if r.now.Before(s.until) && s.locks == locks() {
					return true
				}
				dead[tok] = "expired or locked"
				held = append(held[:i], held[i+1:]...)
				return false
			}
			return false
		}
		for i, ops := 0, 0; i < len(b) && ops < 64; ops++ {
			op := at(i) % 6
			arg := at(i + 1)
			i += 2
			what := fmt.Sprintf("op %d at %v", ops, r.now.Format(time.TimeOnly))
			switch op {
			case 0, 1: // sign in, with the right code or a wrong one
				try := good
				if op == 1 {
					try = "000000"
				}
				cut := r.now.Add(-time.Minute)
				for len(wrong) > 0 && !wrong[0].After(cut) {
					wrong = wrong[1:]
				}
				limited := len(wrong) >= WrongPerMinute
				before := signIns()
				out, err := r.call(localapi.OpSignIn, localapi.SignIn{Code: try})
				if limited {
					if code(err) != localapi.ErrLimited || signIns() != before {
						t.Fatalf("%s: sign-in over the wrong-code budget: %v, %d owner calls", what, err, signIns()-before)
					}
					continue
				}
				if err != nil || signIns() != before+1 {
					t.Fatalf("%s: sign-in: %v, %d owner calls", what, err, signIns()-before)
				}
				ses := out.(localapi.Session)
				if op == 1 {
					if ses.Token != "" || ses.Refusal == "" {
						t.Fatalf("%s: a wrong code gave %+v", what, ses)
					}
					wrong = append(wrong, r.now)
					seen = append(seen, r.now)
					inMinute := 0
					for _, w := range seen {
						if w.After(r.now.Add(-time.Minute)) {
							inMinute++
						}
					}
					if inMinute > WrongPerMinute {
						t.Fatalf("%s: %d wrong codes reached the owner in a minute", what, inMinute)
					}
					continue
				}
				if ses.Token == "" || dead[ses.Token] != "" {
					t.Fatalf("%s: sign-in gave token %q", what, ses.Token)
				}
				n++
				minted = append(minted, ses.Token)
				held = append(held, fuzzSession{tok: ses.Token, until: ses.Until, locks: locks(), n: n})
				if len(held) > MaxSessions {
					dead[held[0].tok] = "evicted"
					held = held[1:]
				}
			case 2, 3: // check a session or sign out, with a minted token or garbage
				tok := strings.Repeat(fmt.Sprintf("%02x", arg), localapi.TokenBytes)
				if len(minted) > 0 && arg < 0xf0 {
					tok = minted[int(arg)%len(minted)]
				}
				why := dead[tok]
				want := accepts(tok)
				var err error
				if op == 2 {
					_, err = r.call(localapi.OpSession, localapi.Auth{Token: tok})
				} else {
					_, err = r.call(localapi.OpSignOut, localapi.Auth{Token: tok})
				}
				if got := err == nil; got != want {
					t.Fatalf("%s: op %d on token %d accepted %v, want %v (%s)", what, op, int(arg), got, want, why)
				}
				if err != nil && code(err) != localapi.ErrUnauthorized {
					t.Fatalf("%s: refusal %v", what, err)
				}
				if op == 3 && want {
					dead[tok] = "signed out"
					for j, s := range held {
						if s.tok == tok {
							held = append(held[:j], held[j+1:]...)
							break
						}
					}
				}
			case 4: // the owner locks
				r.own.mu.Lock()
				r.own.locks++
				r.own.mu.Unlock()
			case 5: // the clock moves
				r.now = r.now.Add([]time.Duration{time.Second, 20 * time.Second, 59 * time.Second, 61 * time.Second, 30 * time.Minute, 61 * time.Minute}[arg%6])
			}
			// No more than MaxSessions minted tokens are accepted now.
			if op == 5 || op == 4 {
				continue
			}
			ok := 0
			for _, tok := range minted {
				why := dead[tok]
				want := accepts(tok)
				_, err := r.call(localapi.OpSession, localapi.Auth{Token: tok})
				if err == nil {
					ok++
					if why != "" {
						t.Fatalf("%s: a token %s is accepted again", what, why)
					}
				}
				if (err == nil) != want {
					t.Fatalf("%s: token accepted %v, want %v", what, err == nil, want)
				}
			}
			if ok > MaxSessions {
				t.Fatalf("%s: %d tokens accepted", what, ok)
			}
		}
	})
}
