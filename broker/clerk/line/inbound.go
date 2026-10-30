package line

// MainNumberText answers the owner when they text the second line, as
// modem/secondline's does (its copy, since the clerk does not link that
// package).
const MainNumberText = "This is your box's second line. Text your box on its main number."

// mainEvery is the least time between two MainNumberText replies, in ms.
const mainEvery = 60 * 60 * 1000

// Text is one text to the line as the line process hands it on (sipline
// SL5): From is a number only the provider vouched for; otherwise Named is
// set and From is the sender's name.
type Text struct {
	From  string
	Named bool
	Words string
	At    int64
}

// Item is an inbound text as a planner may see it: untrusted data under
// Label, its sender shown as sipline's vouched rules allow.
type Item struct {
	Label  string
	Sender string
	Words  string
	At     int64
}

// Reply is a text the line sends back on its own: only MainNumberText to
// the owner.
type Reply struct {
	To, Words string
}

// Inbound shapes a text to the line (CLK-8, CH-1). A text from the owner's
// number reaches no planner: it gets MainNumberText, at most once an hour.
// Any other text is an untrusted item, logged as one (D-154 rule 7).
func (c *Clerk) Inbound(t Text) (*Item, *Reply) {
	if !t.Named && sameNumber(t.From, c.cfg.Numbers.Owner) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.lastMain != 0 && t.At-c.lastMain < mainEvery {
			return nil, nil
		}
		c.lastMain = t.At
		return nil, &Reply{To: c.cfg.Numbers.Owner, Words: MainNumberText}
	}
	it := &Item{Label: Label, Sender: t.From, Words: t.Words, At: t.At}
	if t.Named {
		it.Sender = "named sender " + t.From
	}
	c.mu.Lock()
	c.log(Entry{Kind: EntryInbound, From: it.Sender, Words: t.Words, Label: Label})
	c.mu.Unlock()
	return it, nil
}
