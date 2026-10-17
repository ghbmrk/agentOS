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
	f.Fuzz(func(t *testing.T, b []byte) { fuzzSessions(t, t, b, nil) })
}

// fuzzT is the part of testing.T the oracle reports through, so a control
// can hand it a recorder and show that a planted defect is reported.
type fuzzT interface {
	Helper()
	Fatalf(format string, args ...any)
}

type stopRun struct{}

type recorder struct{ msgs []string }

func (r *recorder) Helper() {}

func (r *recorder) Fatalf(format string, args ...any) {
	r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
	panic(stopRun{})
}

func (r *recorder) run(f func(fuzzT)) (msgs []string) {
	defer func() {
		if p := recover(); p != nil {
			if _, ok := p.(stopRun); !ok {
				panic(p)
			}
		}
		msgs = r.msgs
	}()
	f(r)
	return r.msgs
}

// fuzzSessions drives the sessions as the input says. call2, when set,
// stands in for the server's ops: a planted defect.
func fuzzSessions(t *testing.T, rep fuzzT, b []byte, call2 func(r *rig, op string, args any) (any, error)) {
	r := newRig(t)
	call := r.call
	if call2 != nil {
		call = func(op string, args any) (any, error) { return call2(r, op, args) }
	}
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
			out, err := call(localapi.OpSignIn, localapi.SignIn{Code: try})
			if limited {
				if code(err) != localapi.ErrLimited || signIns() != before {
					rep.Fatalf("%s: sign-in over the wrong-code budget: %v, %d owner calls", what, err, signIns()-before)
				}
				continue
			}
			if err != nil || signIns() != before+1 {
				rep.Fatalf("%s: sign-in: %v, %d owner calls", what, err, signIns()-before)
			}
			ses := out.(localapi.Session)
			if op == 1 {
				if ses.Token != "" || ses.Refusal == "" {
					rep.Fatalf("%s: a wrong code gave %+v", what, ses)
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
					rep.Fatalf("%s: %d wrong codes reached the owner in a minute", what, inMinute)
				}
				continue
			}
			if ses.Token == "" || dead[ses.Token] != "" {
				rep.Fatalf("%s: sign-in gave token %q", what, ses.Token)
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
				_, err = call(localapi.OpSession, localapi.Auth{Token: tok})
			} else {
				_, err = call(localapi.OpSignOut, localapi.Auth{Token: tok})
			}
			if got := err == nil; got != want {
				rep.Fatalf("%s: op %d on token %d accepted %v, want %v (%s)", what, op, int(arg), got, want, why)
			}
			if err != nil && code(err) != localapi.ErrUnauthorized {
				rep.Fatalf("%s: refusal %v", what, err)
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
			_, err := call(localapi.OpSession, localapi.Auth{Token: tok})
			if err == nil {
				ok++
				if why != "" {
					rep.Fatalf("%s: a token %s is accepted again", what, why)
				}
			}
			if (err == nil) != want {
				rep.Fatalf("%s: token accepted %v, want %v", what, err == nil, want)
			}
		}
		if ok > MaxSessions {
			rep.Fatalf("%s: %d tokens accepted", what, ok)
		}
	}
}

// Each control plants a defect in the server's ops and shows the oracle
// reports it, then shows the real server passes the same input.
func TestFuzzSessionsReportsAPlantedDefect(t *testing.T) {
	signOutIgnored := func(r *rig, op string, args any) (any, error) {
		if op == localapi.OpSignOut {
			return nil, nil
		}
		return r.call(op, args)
	}
	acceptsAnyToken := func(r *rig, op string, args any) (any, error) {
		if op == localapi.OpSession {
			return nil, nil
		}
		return r.call(op, args)
	}
	for name, c := range map[string]struct {
		in   []byte
		call func(*rig, string, any) (any, error)
	}{
		"sign-out does nothing": {[]byte{0, 0, 3, 0, 2, 0}, signOutIgnored},
		"any token accepted":    {[]byte{0, 0, 2, 255}, acceptsAnyToken},
	} {
		var rec recorder
		if len(rec.run(func(ft fuzzT) { fuzzSessions(t, ft, c.in, c.call) })) == 0 {
			t.Errorf("%s: the oracle did not report the planted defect", name)
		}
		rec = recorder{}
		if msgs := rec.run(func(ft fuzzT) { fuzzSessions(t, ft, c.in, nil) }); len(msgs) != 0 {
			t.Errorf("%s: the real server reported: %v", name, msgs)
		}
	}
}
