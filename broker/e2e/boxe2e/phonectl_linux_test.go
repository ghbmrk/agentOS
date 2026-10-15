package main

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
)

// fakeClock is shared by the driver and the owner channel: the driver's
// sleeps move it on, with a short real pause so the channel can answer.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) sleep(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
	time.Sleep(10 * time.Millisecond)
}

type idleEngine struct{}

func (idleEngine) Stop(context.Context) (journal.StopReport, error) { return journal.StopReport{}, nil }
func (idleEngine) Resume() error                                    { return nil }
func (idleEngine) Stopped() bool                                    { return false }
func (idleEngine) List() []journal.Status                           { return nil }

// setupPage answers GET /setup as the setup page does: 303 to /status
// once setup is done, the current step otherwise.
type setupPage bool

func (done setupPage) RoundTrip(r *http.Request) (*http.Response, error) {
	h := http.Header{}
	st, body := http.StatusOK, `<h2>7. AI</h2>`
	if done {
		st, body = http.StatusSeeOther, ""
		h.Set("Location", "/status")
	}
	return &http.Response{StatusCode: st, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

// boxLine is the box's SIM with the channel reading from in, so a case's
// mutate can put a fault in the inbound path: it sees each text before the
// channel does and returns the text to pass on.
type boxLine struct {
	*modem.Line
	in chan modem.SMS
}

func (b *boxLine) Inbox() <-chan modem.SMS { return b.in }

var codeRe = regexp.MustCompile(`^STATUS ([0-9]{6})$`)

// REQ: CH-1, CH-3, CH-11, CH-14. phoneControl runs against a real owner
// channel and control handler on the carrier simulator: it passes, and it
// fails when the box answers the unpaired number, takes its text as the
// owner's, or runs STATUS without a fresh code's unlock (E9).
func TestPhoneControlAgainstTheOwnerChannel(t *testing.T) {
	seed := []byte("12345678901234567890")
	base := time.Date(2026, 10, 15, 12, 0, 5, 0, time.UTC)
	step := base.Unix() / 30
	cases := []struct {
		name string
		// st is the channel's saved state; enrolled marks the window the
		// enrolment used as the driver's last.
		st       owner.State
		enrolled bool
		done     setupPage
		mutate   func(l *modem.Line, c *modem.Carrier, m modem.SMS) modem.SMS
		want     string // "" passes
	}{
		{name: "pass", st: owner.State{LastStep: step}, enrolled: true, done: true},
		{name: "setup not finished", st: owner.State{LastStep: step}, enrolled: true, want: `setup not finished: GET /setup 200 "" at "7. AI"`},
		{name: "stranger answered", st: owner.State{LastStep: step}, enrolled: true, done: true,
			mutate: func(l *modem.Line, _ *modem.Carrier, m modem.SMS) modem.SMS {
				if m.From == strangerNum {
					_ = l.Send(strangerNum, "Running.")
				}
				return m
			}, want: "1 text(s) went to the unpaired number"},
		{name: "stranger taken as the owner", st: owner.State{LastStep: step}, enrolled: true, done: true,
			mutate: func(_ *modem.Line, c *modem.Carrier, m modem.SMS) modem.SMS {
				if m.From == strangerNum {
					m.From = phoneNum
				}
				return m
			}, want: "unpaired number's text drew status"},
		{name: "already unlocked (a local sign-in)", st: owner.State{LastStep: step, UnlockedUntil: base.Add(time.Hour)}, enrolled: true, done: true,
			want: "status reply with no unlock first"},
		{name: "code only in an unlocked session", st: owner.State{LastStep: step, UnlockedUntil: base.Add(time.Hour)}, enrolled: true, done: true,
			mutate: func(_ *modem.Line, _ *modem.Carrier, m modem.SMS) modem.SMS {
				if s := codeRe.FindStringSubmatch(m.Text); s != nil && m.From == phoneNum {
					m.Text = s[1]
				}
				return m
			}, want: "already unlocked"},
		{name: "code dropped", st: owner.State{LastStep: step}, enrolled: true, done: true,
			mutate: func(_ *modem.Line, _ *modem.Carrier, m modem.SMS) modem.SMS {
				if codeRe.MatchString(m.Text) && m.From == phoneNum {
					m.Text = "STATUS"
				}
				return m
			}, want: "drew locked"},
		{name: "enrolment's window reused", st: owner.State{LastStep: step}, done: true, want: "drew wrong-code"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clk := &fakeClock{t: base}
			carrier := modem.NewCarrier()
			carrier.SetClock(clk.now)
			line := carrier.Line(boxNum)
			box := &boxLine{Line: line, in: make(chan modem.SMS, 64)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case m := <-line.Inbox():
						if c.mutate != nil {
							n := len(carrier.Log())
							m = c.mutate(line, carrier, m)
							box.in <- m
							// The channel reads in arrival order: let the
							// mutant's text be answered before the next.
							for end := time.Now().Add(2 * time.Second); time.Now().Before(end) && !answered(carrier.Log()[n:]); {
								time.Sleep(time.Millisecond)
							}
							continue
						}
						box.in <- m
					}
				}
			}()
			store := &owner.MemStore{}
			if err := store.Save(c.st); err != nil {
				t.Fatal(err)
			}
			ch, err := owner.New(owner.Config{Owner: phoneNum, Modem: box, Engine: idleEngine{}, Store: store,
				Secrets:  owner.Secrets{TOTPSeed: seed, GridSeed: []byte("synthetic-grid-seed")},
				Location: time.UTC, Now: clk.now})
			if err != nil {
				t.Fatal(err)
			}
			go ch.Run(ctx)
			d := &driver{carrier: carrier, seed: seed, now: clk.now, sleep: clk.sleep,
				phone: &http.Client{Transport: c.done, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
			if c.enrolled {
				d.codeStep = step
			}
			err = d.phoneControl()
			switch {
			case c.want == "" && err != nil:
				t.Fatal(err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("%v, want %q", err, c.want)
			}
		})
	}
}

// answered reports whether a text from the box is among ms.
func answered(ms []modem.SMS) bool {
	for _, m := range ms {
		if m.From == boxNum {
			return true
		}
	}
	return false
}
