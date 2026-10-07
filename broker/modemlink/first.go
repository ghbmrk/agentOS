package modemlink

// FirstSlack is how far SendFirst may go past MaxQueued, so a STOP or
// STATUS reply still goes when other texts fill the queue.
const FirstSlack = 4

// SendFirst is Send for a reply that must not wait behind other texts: a
// STOP or STATUS reply goes ahead of every text still queued for the
// bridge (security R2 on #170), up to FirstSlack past a full queue. Texts
// already handed to the bridge stay ahead of it. While the owner line is
// down it fails as down and is counted like any other text.
func (l *Link) SendFirst(to, text string) error { return l.send(to, text, false, true) }

// aheadLocked queues it after the replies already sent first and before
// every other queued text, telling each text it passes that it waits one
// more SendWait. Caller holds mu.
func (l *Link) aheadLocked(it *item) {
	at := 0
	for at < len(l.queue) && l.queue[at].first {
		at++
	}
	it.first = true
	for _, q := range l.queue[at:] {
		if q.bump != nil {
			select {
			case q.bump <- struct{}{}:
			default:
			}
		}
	}
	l.queue = append(l.queue[:at], append([]*item{it}, l.queue[at:]...)...)
}
