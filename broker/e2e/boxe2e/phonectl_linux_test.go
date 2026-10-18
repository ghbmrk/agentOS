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
	"github.com/ghbmrk/agentos/broker/modemlink"
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
	in   chan modem.SMS
	hold func(to, text string) // when set, runs before each reply is sent
}

func (b *boxLine) Inbox() <-chan modem.SMS { return b.in }

func (b *boxLine) Send(to, text string) error {
	if b.hold != nil {
		b.hold(to, text)
	}
	return b.Line.Send(to, text)
}

// holdLate holds the second status reply to the paired phone, which in a
// case that takes the stranger's text as the owner's is the one that text
// drew, until the barrier's HELP has been answered and the driver's clock
// has moved 3 s on from then: the reply lands after the barrier's, while
// the driver still reads the log, as a run route's reply from its own
// goroutine can on the box.
func holdLate(ctx context.Context, carrier *modem.Carrier, clk *fakeClock) func(to, text string) {
	var mu sync.Mutex
	statuses := 0
	return func(to, text string) {
		if to != phoneNum || replyKind(text) != "status" {
			return
		}
		mu.Lock()
		statuses++
		n := statuses
		mu.Unlock()
		if n != 2 {
			return
		}
		var since time.Time
		for end := time.Now().Add(10 * time.Second); time.Now().Before(end); {
			if since.IsZero() && barrierAnswered(carrier.Log()) {
				since = clk.now()
			}
			if !since.IsZero() && !clk.now().Before(since.Add(3*time.Second)) {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Millisecond):
			}
		}
	}
}

// barrierAnswered reports whether the box has answered HELP to the paired
// phone after the stranger's text.
func barrierAnswered(log []modem.SMS) bool {
	stranger := false
	for _, m := range log {
		switch {
		case m.From == strangerNum:
			stranger = true
		case stranger && m.From == boxNum && m.To == phoneNum && replyKind(m.Text) == "help":
			return true
		}
	}
	return false
}

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
		late     bool   // holdLate holds the reply the stranger's text drew
		want     string // "" passes
		notice   bool   // the box's line sends recoveryNotice before its first reply
		note     string // the step's note, "" for none
	}{
		{name: "pass", st: owner.State{LastStep: step}, enrolled: true, done: true},
		{name: "recovery notice passed over and noted", st: owner.State{LastStep: step}, enrolled: true, done: true,
			notice: true, note: "passed-over recovery notices=1 texts=2 requests=1|lost-send kind=request via=owner-channel-sendrequest"},
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
		{name: "stranger taken as the owner, reply after the barrier's", st: owner.State{LastStep: step}, enrolled: true, done: true, late: true,
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
			if c.late {
				box.hold = holdLate(ctx, carrier, clk)
			}
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case m := <-line.Inbox():
						if c.notice {
							c.notice = false
							_ = line.Send(phoneNum, recoveryNotice)
						}
						if c.mutate != nil {
							n := len(carrier.Log())
							m = c.mutate(line, carrier, m)
							box.in <- m
							if c.late {
								// The held reply must not be waited for.
								continue
							}
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
			var notes []string
			d := &driver{carrier: carrier, seed: seed, now: clk.now, sleep: clk.sleep,
				phone: &http.Client{Transport: c.done, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
				note:  func(s string) { notes = append(notes, s) },
				agentosdLog: func() string {
					return "setup: done\n" + modemlink.MissedLog + " kind=request via owner.(*Channel).sendRequest\n"
				}}
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
			if got := strings.Join(notes, "|"); got != c.note {
				t.Fatalf("notes %q, want %q", got, c.note)
			}
		})
	}
}

// recoveryNotice is modemlink's notice after an outage that lost one
// approval request and one other text, as recoveryText words it.
const recoveryNotice = "I couldn't text you from 12:00 to 12:05. 1 approval request and 1 other text didn't reach you; your agent can ask again."

// answered reports whether a text from the box is among ms.
func answered(ms []modem.SMS) bool {
	for _, m := range ms {
		if m.From == boxNum {
			return true
		}
	}
	return false
}
