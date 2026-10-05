// Package modem is the owner channel's view of the box's SIM (SPEC CH-1),
// plus a carrier simulator for P1 (PLAN P1-5). The real modem driver (P2-3)
// implements the same Modem interface.
//
// The simulator is deterministic and in-memory: lines are phone numbers on
// one carrier, texts are delivered in order, and each text's SMS segment
// count is computed the way a GSM network bills it, so tests can hold the
// broker to CH-12's segment budget.
package modem

import (
	"errors"
	"sync"
	"time"
	"unicode/utf16"
)

// SMS is one delivered text.
type SMS struct {
	From, To string
	Text     string
	At       time.Time
	Segments int
	// Spoofed marks a text whose sender was forged with Carrier.Inject. Only
	// tests read it: a real network gives the broker no such signal.
	Spoofed bool
	// Alphanumeric marks a sender given as a text sender ID (TP-OA type
	// 101) rather than a phone number. Such an ID can spell anything,
	// including the owner's number, so it is never the owner (CH-1).
	Alphanumeric bool
	// Ref, when set, names a text the driver keeps until the taker acks
	// it (at.Config.KeepUntilAck); a re-read of the same text has the same
	// Ref.
	Ref string
	// Owner marks a text from the owner's number (at.Config.Owner), never
	// a named sender: its reader retries it whether or not it was kept.
	Owner bool
}

// Modem is one SIM: it sends texts from its own number and delivers what
// arrives for it.
type Modem interface {
	Number() string
	Send(to, text string) error
	Inbox() <-chan SMS
}

// ErrDown is returned by a line whose modem is unplugged or offline.
var ErrDown = errors.New("modem: line is down")

// Carrier is a simulated mobile network.
type Carrier struct {
	mu    sync.Mutex
	lines map[string]*Line
	log   []SMS
	now   func() time.Time
}

// NewCarrier returns an empty network.
func NewCarrier() *Carrier {
	return &Carrier{lines: map[string]*Line{}, now: time.Now}
}

// SetClock sets the time stamped on texts.
func (c *Carrier) SetClock(now func() time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

// Line returns the line for number, creating it on first use.
func (c *Carrier) Line(number string) *Line {
	c.mu.Lock()
	defer c.mu.Unlock()
	if l, ok := c.lines[number]; ok {
		return l
	}
	l := &Line{c: c, number: number, inbox: make(chan SMS, 1024)}
	c.lines[number] = l
	return l
}

// Inject delivers a text whose sender number is forged, as SMS spoofing
// allows on real networks.
func (c *Carrier) Inject(from, to, text string) {
	c.deliver(SMS{From: from, To: to, Text: text, Spoofed: true})
}

// Log returns every text the network carried, oldest first.
func (c *Carrier) Log() []SMS {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]SMS(nil), c.log...)
}

func (c *Carrier) deliver(m SMS) {
	m.Segments, _ = Segments(m.Text)
	c.mu.Lock()
	m.At = c.now()
	c.log = append(c.log, m)
	dst := c.lines[m.To]
	c.mu.Unlock()
	if dst != nil {
		dst.inbox <- m
	}
}

// Line is one number on the carrier: the box's modem or a phone.
type Line struct {
	c      *Carrier
	number string
	inbox  chan SMS
	mu     sync.Mutex
	down   bool
}

var _ Modem = (*Line)(nil)

// Number is the line's own number.
func (l *Line) Number() string { return l.number }

// Inbox delivers texts sent to this line.
func (l *Line) Inbox() <-chan SMS { return l.inbox }

// SetDown simulates the modem going offline (true) or back (false).
func (l *Line) SetDown(down bool) {
	l.mu.Lock()
	l.down = down
	l.mu.Unlock()
}

// Send texts to another number from this line.
func (l *Line) Send(to, text string) error {
	l.mu.Lock()
	down := l.down
	l.mu.Unlock()
	if down {
		return ErrDown
	}
	l.c.deliver(SMS{From: l.number, To: to, Text: text})
	return nil
}

// gsmBasic and gsmExt are GSM 03.38's default alphabet and its extension
// table; an extension character costs two septets.
const (
	gsmBasic = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?" +
		"¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
	gsmExt = "^{}\\[~]|€\f"
)

// Segments returns how many SMS segments text takes and whether it fits
// GSM-7. A single GSM-7 segment holds 160 septets and each part of a
// concatenated one 153; UCS-2 holds 70 and 67 UTF-16 units.
func Segments(text string) (n int, gsm7 bool) {
	septets := 0
	gsm7 = true
	for _, r := range text {
		switch {
		case containsRune(gsmBasic, r):
			septets++
		case containsRune(gsmExt, r):
			septets += 2
		default:
			gsm7 = false
		}
	}
	single, multi := 160, 153
	units := septets
	if !gsm7 {
		single, multi = 70, 67
		units = len(utf16.Encode([]rune(text)))
	}
	if units <= single {
		return 1, gsm7
	}
	return (units + multi - 1) / multi, gsm7
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
