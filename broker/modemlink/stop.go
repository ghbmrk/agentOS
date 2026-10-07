package modemlink

import (
	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/modem"
)

// ownerStop reports whether text is an exact STOP under CH-11's grammar
// (the whole message, ignoring case and punctuation). Only the owner's
// number reaches this check; "stop everything" is task chat.
func ownerStop(text string) bool {
	return control.Parse(text).Word == control.WordStop
}

// putFirstLocked puts m ahead of every text waiting in the inbox, keeping
// their order (security R1 at bc36b57: STOP is handled first). Inbound is
// the inbox's only sender and holds l.mu, so after the drain there is room
// for m and all but, with a full inbox, the newest text, which gives way
// and is noted as a drop.
func (l *Link) putFirstLocked(m modem.SMS) {
	var held []modem.SMS
drain:
	for {
		select {
		case h := <-l.inbox:
			held = append(held, h)
		default:
			break drain
		}
	}
	if len(held) >= cap(l.inbox) {
		held = held[:cap(l.inbox)-1]
		l.dropped = true
	}
	l.inbox <- m
	for _, h := range held {
		l.inbox <- h
	}
}
