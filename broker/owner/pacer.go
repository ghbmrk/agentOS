package owner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/ghbmrk/agentos/broker/control"
)

// The pacer holds unsolicited texts to the owner in quiet hours and past
// the hourly allowance, and sends them later in order (CH-15, W5-Dc-r1a).
// Replies to the owner's own messages never pass through it (SG-r1-4).

// Class is an unsolicited text's urgency class (CH-15, SG-r1-2).
type Class string

const (
	// ClassSecurity is always urgent: a security text is never held.
	ClassSecurity Class = "security"
	// ClassApproval and ClassAgent are urgent only if the owner says so.
	ClassApproval Class = "approval"
	ClassAgent    Class = "agent"
	// ClassUpdate is never urgent.
	ClassUpdate Class = "update"
)

const (
	// DefaultTextsPerHour is the allowance when the owner set none.
	DefaultTextsPerHour = 3
	// MaxTextsPerHour is the most TEXTS takes.
	MaxTextsPerHour = 20
	// MaxHeld is the most texts the hold keeps (SG-r1-3).
	MaxHeld = 32
)

// pacingForms answers a pacing setting with a bad value (QH-6).
const pacingForms = "Settings: QUIET 22-7 (hours 0 to 23) or QUIET OFF, TEXTS 1 to 20 (texts an hour), URGENT APPROVAL ON or OFF, URGENT AGENT ON or OFF. Security alerts always go at once."

// pacingHelp is HELP's line for the pacing settings.
const pacingHelp = "QUIET 22-7 or QUIET OFF: quiet hours. TEXTS 3: texts an hour. URGENT APPROVAL or AGENT ON/OFF."

const pacingNotSaved = "Setting not saved. Nothing changed. Try again."

// Pacing is the owner's pacing setting. The zero value is the default:
// no quiet hours, DefaultTextsPerHour, and only security urgent.
type Pacing struct {
	// QuietFrom and QuietTo are minutes of the box-local day
	// (Config.Location); equal means no quiet hours. The window may wrap
	// past midnight.
	QuietFrom int `json:"quiet_from,omitempty"`
	QuietTo   int `json:"quiet_to,omitempty"`
	// PerHour is the unsolicited texts allowed in any hour; 0 means
	// DefaultTextsPerHour.
	PerHour int `json:"per_hour,omitempty"`
	// Urgent lists the classes beyond security that go at once
	// (approval, agent).
	Urgent []Class `json:"urgent,omitempty"`
}

// valid reports whether p is a setting the owner could have made.
func (p Pacing) valid() bool {
	day := 24 * 60
	if p.QuietFrom < 0 || p.QuietFrom >= day || p.QuietTo < 0 || p.QuietTo >= day {
		return false
	}
	if p.PerHour < 0 || p.PerHour > MaxTextsPerHour {
		return false
	}
	for _, u := range p.Urgent {
		if u != ClassApproval && u != ClassAgent {
			return false
		}
	}
	return true
}

func (p Pacing) perHour() int {
	if p.PerHour == 0 {
		return DefaultTextsPerHour
	}
	return p.PerHour
}

func (p Pacing) urgent(class Class) bool {
	switch class {
	case ClassSecurity:
		return true
	case ClassApproval, ClassAgent:
		for _, u := range p.Urgent {
			if u == class {
				return true
			}
		}
	}
	return false
}

// HeldText is one text waiting in the hold, already disclosed and fitted.
type HeldText struct {
	Text  string `json:"text"`
	Class Class  `json:"class,omitempty"`
	// Agent marks agent-derived text (Notify, NotifyAs).
	Agent bool      `json:"agent,omitempty"`
	At    time.Time `json:"at"`
	// Subjects are what the text says about, opaque to the channel; a
	// text with subjects is sent only while the Current hook says they
	// still hold (PACE-1).
	Subjects []string `json:"subjects,omitempty"`
}

// CurrentHook reports whether a text about these subjects is still true
// (SetCurrent).
type CurrentHook func(subjects []string) bool

// SetCurrent sets the hook that confirms a text's subjects when it is
// sent (PostAbout); nil removes it. Without a hook a text with subjects
// is never sent unconfirmed: a paced one waits in the hold until a hook
// is set, so a restart outside quiet hours cannot lose a true one before
// its owner is wired (L3 on #708); an urgent one is dropped.
func (c *Channel) SetCurrent(h CurrentHook) {
	if h == nil {
		c.current.Store(nil)
		return
	}
	c.current.Store(&h)
}

// stillCurrent reports whether held text h may be sent: it has no
// subjects, or the Current hook confirms them. Call it without c.mu: the
// hook takes its owner's lock.
func (c *Channel) stillCurrent(h HeldText) bool {
	if len(h.Subjects) == 0 {
		return true
	}
	hook := c.current.Load()
	return hook != nil && (*hook)(h.Subjects)
}

// PostAbout is Post for a text that is true only while its subjects
// hold, such as a security "Cleared" line (PACE-1). Held, it keeps its
// subjects, and it is sent only if the Current hook confirms them then;
// otherwise it is dropped, unsent and uncounted. With no hook yet it
// waits in the hold (SetCurrent).
func (c *Channel) PostAbout(class Class, text string, subjects []string) error {
	if c.cfg.Modem == nil {
		return errors.New("owner: no modem")
	}
	return c.postHeld(class, HeldText{Text: control.Fit(Disclose(text)), Subjects: append([]string(nil), subjects...)})
}

// checkPacing fails a bad saved setting closed to the defaults (QH-1).
// The log line names no value.
func checkPacing(st *State) {
	if !st.Pacing.valid() {
		log.Printf("owner: saved pacing setting is invalid; using the defaults")
		st.Pacing = Pacing{}
	}
}

// Post texts the owner an unsolicited broker text of the given class
// (QH-2). An urgent class goes at once. Any other is held, saved in owner
// state, while it is quiet hours, the hourly allowance is spent, or older
// texts are still held; otherwise it goes now. Every text sent counts
// toward the hour.
func (c *Channel) Post(class Class, text string) error {
	if c.cfg.Modem == nil {
		return errors.New("owner: no modem")
	}
	return c.post(class, control.Fit(Disclose(text)), false)
}

// postTemplate is Post for a broker template, such as an alert carrying
// the broker's own codes, which does not pass through Disclose (CH-19).
func (c *Channel) postTemplate(class Class, text string) error {
	return c.post(class, control.Fit(text), false)
}

// sendTemplate sends a broker template at once, never held, and counts
// it.
func (c *Channel) sendTemplate(text string) error {
	return c.sendCounted(control.Fit(text))
}

// post is Post for text already disclosed and fitted. agent marks
// agent-derived text, which a release never packs with another text.
func (c *Channel) post(class Class, text string, agent bool) error {
	return c.postHeld(class, HeldText{Text: text, Agent: agent})
}

// postHeld is post for h, whose Class and At it sets.
func (c *Channel) postHeld(class Class, h HeldText) error {
	text := h.Text
	if c.Urgent(class) {
		if !c.stillCurrent(h) {
			return nil
		}
		return c.sendCounted(text)
	}
	c.pmu.Lock()
	defer c.pmu.Unlock()
	// Older held texts go first. A failed release leaves them held, and
	// this one then waits behind them.
	_ = c.releasePaced()
	now := c.cfg.Now()
	wait := len(h.Subjects) > 0 && c.current.Load() == nil
	c.mu.Lock()
	st := &c.codes.st
	if wait || len(st.Held) > 0 || st.HeldDropped > 0 || c.quietLocked(now) || c.allowanceLocked(now) == 0 {
		err := c.codes.commit(func(s *State) {
			h.Class, h.At = class, now
			s.Held = append(s.Held, h)
			if n := len(s.Held) - MaxHeld; n > 0 {
				s.Held = append([]HeldText(nil), s.Held[n:]...)
				s.HeldDropped += n
			}
		})
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()
	if !c.stillCurrent(h) {
		return nil
	}
	return c.sendCounted(text)
}

// NotifyAs is Notify with a caller-chosen class, for agent-derived text
// that belongs to another class (QH-2).
func (c *Channel) NotifyAs(class Class, text string) error {
	if c.cfg.Modem == nil {
		return errors.New("owner: no modem")
	}
	if text = Disclose(text); text != Hidden {
		text = AgentPrefix + text
	}
	return c.post(class, control.Fit(text), true)
}

// sendCounted sends text to the owner and, if it went, counts it.
func (c *Channel) sendCounted(text string) error {
	if err := c.cfg.Modem.Send(c.cfg.Owner, text); err != nil {
		return err
	}
	c.countSent()
	return nil
}

// countSent counts one unsolicited text sent now toward the hour. The
// count is kept even if saving it fails.
func (c *Channel) countSent() {
	now := c.cfg.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.saveLocked(func(s *State) { s.Sent = append(recentSends(s.Sent, now), now) })
}

// saveLocked commits f; if the save fails, it still applies f in memory
// and returns the error. It is for changes that record what already
// happened (a text sent), which must hold for this run either way.
func (c *Channel) saveLocked(f func(*State)) error {
	err := c.codes.commit(f)
	if err != nil {
		next := copyState(c.codes.st)
		f(&next)
		c.codes.st = next
	}
	return err
}

// recentSends keeps the sends from the hour before now. A send dated
// after now (the clock stepped back) is dropped, as Boot refuses a future
// Asked, so it cannot hold the allowance spent until the clock catches up.
func recentSends(sent []time.Time, now time.Time) []time.Time {
	var out []time.Time
	for _, t := range sent {
		if !t.After(now) && now.Sub(t) < time.Hour {
			out = append(out, t)
		}
	}
	return out
}

// Release sends held texts when it is not quiet hours and the allowance
// has room, oldest first, packed into as few texts as fit (QH-4). A text
// leaves the hold only after it was sent; a send error keeps it and is
// returned.
func (c *Channel) Release() error {
	if c.cfg.Modem == nil {
		return nil
	}
	c.pmu.Lock()
	defer c.pmu.Unlock()
	return c.releasePaced()
}

// releasePaced is Release with c.pmu held.
func (c *Channel) releasePaced() error {
	for {
		now := c.cfg.Now()
		c.mu.Lock()
		st := c.codes.st
		if (len(st.Held) == 0 && st.HeldDropped == 0) || c.quietLocked(now) || c.allowanceLocked(now) == 0 {
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()
		// A held text whose subjects no longer hold is dropped before
		// packing, unsent and uncounted (PACE-1); with no hook set yet,
		// one with subjects stays held and the rest go past it. Only
		// posts and releases change the hold, both under pmu, so its
		// indexes stay put.
		hook := c.current.Load()
		var stale, ready []int
		var send []HeldText
		for i, h := range st.Held {
			switch {
			case len(h.Subjects) > 0 && hook == nil:
				continue
			case len(h.Subjects) > 0 && !(*hook)(h.Subjects):
				stale = append(stale, i)
			default:
				ready, send = append(ready, i), append(send, h)
			}
		}
		if len(stale) > 0 {
			c.mu.Lock()
			err := c.saveLocked(func(s *State) {
				keep := s.Held[:0:0]
				for i, h := range s.Held {
					if !slices.Contains(stale, i) {
						keep = append(keep, h)
					}
				}
				s.Held = keep
			})
			c.mu.Unlock()
			if err != nil {
				return err
			}
			continue
		}
		if len(send) == 0 && st.HeldDropped == 0 {
			return nil
		}
		text, n, dropped := packHeld(st.HeldDropped, send)
		if err := c.cfg.Modem.Send(c.cfg.Owner, text); err != nil {
			return err
		}
		c.mu.Lock()
		// Only this release removes from the hold, under pmu, so the
		// held texts at ready[:n] are still the ones sent.
		sent := ready[:n]
		err := c.saveLocked(func(s *State) {
			keep := s.Held[:0:0]
			for i, h := range s.Held {
				if !slices.Contains(sent, i) {
					keep = append(keep, h)
				}
			}
			s.Held = keep
			s.HeldDropped -= dropped
			s.Sent = append(recentSends(s.Sent, now), now)
		})
		c.mu.Unlock()
		if err != nil {
			return err
		}
	}
}

// packHeld joins the dropped-texts line and the oldest held texts into
// one text of at most control.MaxText. Agent text always goes alone, so a
// " / " inside it cannot pass for the start of a broker text (CH-19). It
// returns the text, how many held texts it carries, and the drops it
// reports.
func packHeld(dropped int, held []HeldText) (string, int, int) {
	var parts []string
	size := 0
	add := func(s string) bool {
		n := len(s)
		if len(parts) > 0 {
			n += len(heldSep)
		}
		if len(parts) > 0 && size+n > control.MaxText {
			return false
		}
		parts = append(parts, s)
		size += n
		return true
	}
	if dropped > 0 {
		add(fmt.Sprintf("%d earlier texts were dropped while paced.", dropped))
	}
	n := 0
	for _, h := range held {
		if h.Agent && len(parts) > 0 {
			break
		}
		if !add(h.Text) {
			break
		}
		n++
		if h.Agent {
			break
		}
	}
	return control.Fit(strings.Join(parts, heldSep)), n, dropped
}

// heldSep joins packed texts; GSM-7 has no line break.
const heldSep = " / "

// Quiet reports whether t is inside the owner's quiet hours, box-local
// (QH-5).
func (c *Channel) Quiet(t time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.quietLocked(t)
}

func (c *Channel) quietLocked(t time.Time) bool {
	p := c.codes.st.Pacing
	if p.QuietFrom == p.QuietTo {
		return false
	}
	lt := t.In(c.cfg.Location)
	m := lt.Hour()*60 + lt.Minute()
	if p.QuietFrom < p.QuietTo {
		return m >= p.QuietFrom && m < p.QuietTo
	}
	return m >= p.QuietFrom || m < p.QuietTo
}

// Urgent reports whether a class goes at once, in quiet hours and past
// the allowance (QH-5).
func (c *Channel) Urgent(class Class) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.codes.st.Pacing.urgent(class)
}

// Allowance is the unsolicited texts left in the hour before now,
// counting approval requests and auto-reply notices (QH-5).
func (c *Channel) Allowance(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.allowanceLocked(now)
}

func (c *Channel) allowanceLocked(now time.Time) int {
	n := c.codes.st.Pacing.perHour() - len(recentSends(c.codes.st.Sent, now))
	if n < 0 {
		return 0
	}
	return n
}

// pacingSetting answers the owner's pacing settings (QH-6, SG-r1-5):
// QUIET a-b, QUIET OFF, TEXTS n, URGENT APPROVAL|AGENT ON|OFF. A message
// of another shape returns ok false. Locked, a pacing setting also
// returns ok false, so it gets the unlock prompt and changes nothing.
func (c *Channel) pacingSetting(msg string, unlocked bool) (string, bool) {
	f := settingWords(msg)
	if !pacingShape(f) {
		return "", false
	}
	if !unlocked {
		return "", false
	}
	var change func(*Pacing)
	var reply func(Pacing) string
	switch f[0] {
	case "QUIET":
		if f[1] == "OFF" {
			change = func(p *Pacing) { p.QuietFrom, p.QuietTo = 0, 0 }
			reply = func(p Pacing) string {
				return fmt.Sprintf("Quiet hours off. Texts go at any hour, up to %d an hour.", p.perHour())
			}
			break
		}
		a, b := hourArg(f[1]), hourArg(f[2])
		if a < 0 || b < 0 || a == b {
			return pacingForms, true
		}
		change = func(p *Pacing) { p.QuietFrom, p.QuietTo = a*60, b*60 }
		reply = func(p Pacing) string {
			return fmt.Sprintf("Quiet hours set: %02d:00 to %02d:00. Texts wait until then, except %s. Reply QUIET OFF to end them.", a, b, urgentNames(p))
		}
	case "TEXTS":
		n, err := strconv.Atoi(f[1])
		if err != nil || n < 1 || n > MaxTextsPerHour {
			return pacingForms, true
		}
		change = func(p *Pacing) { p.PerHour = n }
		reply = func(p Pacing) string {
			return fmt.Sprintf("Texts set: %d an hour. More wait for the next hour, except %s and replies to you.", n, urgentNames(p))
		}
	case "URGENT":
		class := Class(strings.ToLower(f[1]))
		if (class != ClassApproval && class != ClassAgent) || (f[2] != "ON" && f[2] != "OFF") {
			return pacingForms, true
		}
		on := f[2] == "ON"
		change = func(p *Pacing) {
			var u []Class
			for _, x := range p.Urgent {
				if x != class {
					u = append(u, x)
				}
			}
			if on {
				u = append(u, class)
			}
			p.Urgent = u
		}
		name := "Approval requests"
		if class == ClassAgent {
			name = "Agent texts"
		}
		reply = func(Pacing) string {
			if on {
				return name + " now go at once, in quiet hours too."
			}
			return name + " now wait for quiet hours to end and for room in the hourly limit."
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.codes.commit(func(s *State) {
		p := s.Pacing
		p.Urgent = append([]Class(nil), p.Urgent...)
		change(&p)
		s.Pacing = p
	}); err != nil {
		return pacingNotSaved, true
	}
	return reply(c.codes.st.Pacing), true
}

// pacingShape reports whether f has a pacing setting's shape, valid
// values or not; other messages go on to the agent.
func pacingShape(f []string) bool {
	if len(f) == 0 {
		return false
	}
	switch f[0] {
	case "QUIET":
		return (len(f) == 2 && f[1] == "OFF") || (len(f) == 3 && isDigits(f[1]) && isDigits(f[2]))
	case "TEXTS":
		return len(f) == 2 && isDigits(f[1])
	case "URGENT":
		if len(f) != 3 {
			return false
		}
		switch f[1] {
		case "SECURITY", "APPROVAL", "AGENT", "UPDATE":
			return true
		}
	}
	return false
}

// urgentNames names what still goes at once, for the settings replies.
func urgentNames(p Pacing) string {
	names := []string{"security alerts"}
	if p.urgent(ClassApproval) {
		names = append(names, "approval requests")
	}
	if p.urgent(ClassAgent) {
		names = append(names, "agent texts")
	}
	if len(names) == 1 {
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// hourArg reads an hour of the day, or -1.
func hourArg(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || len(s) > 2 || n < 0 || n > 23 {
		return -1
	}
	return n
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// settingWords splits a message as control.Parse does: punctuation is
// space and letters are upper case (CH-11).
func settingWords(msg string) []string {
	return strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToUpper(r)
		}
		return ' '
	}, msg))
}

// settings is the control handler's Settings hook: the pacing settings,
// then the box's own (cfg.Settings).
func (c *Channel) settings(ctx context.Context, msg string, unlocked bool) (string, bool) {
	if pacingShape(settingWords(msg)) {
		return c.pacingSetting(msg, unlocked)
	}
	if c.cfg.Settings != nil {
		return c.cfg.Settings(ctx, msg, unlocked)
	}
	return "", false
}

// HeldNote is STATUS's line for the hold (W5-Dc-r1b QH-10): how many
// texts wait and why, and how many the cap dropped (OP-9). Empty while
// nothing is held.
func (c *Channel) HeldNote() string {
	now := c.cfg.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.codes.st
	n, dropped := len(st.Held), st.HeldDropped
	if n == 0 && dropped == 0 {
		return ""
	}
	var parts []string
	if n > 0 {
		texts := fmt.Sprintf("%d texts", n)
		if n == 1 {
			texts = "1 text"
		}
		if c.quietLocked(now) {
			to := st.Pacing.QuietTo
			parts = append(parts, fmt.Sprintf("%s held until %02d:%02d (quiet hours).", texts, to/60, to%60))
		} else {
			parts = append(parts, fmt.Sprintf("%s held: %d an hour.", texts, st.Pacing.perHour()))
		}
	}
	if dropped > 0 {
		if dropped == 1 {
			parts = append(parts, "1 earlier text was dropped.")
		} else {
			parts = append(parts, fmt.Sprintf("%d earlier texts were dropped.", dropped))
		}
	}
	return strings.Join(parts, " ")
}
