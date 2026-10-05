package sipline

import "time"

// ParseAnswer exposes parseAnswer's verdict to the external tests.
func ParseAnswer(body []byte, private bool) error {
	_, err := parseAnswer(body, private)
	return err
}

// ParseOffer exposes parseOffer's verdict and the tag to echo.
func ParseOffer(body []byte, private bool) (string, error) {
	a, err := parseOffer(body, private)
	return a.tag, err
}

// SetInbound shortens the waits for a call to the line and sets the clock
// the clip limits read, until the returned restore is called.
// SetPollEvery sets how often the line polls its texting account.
func SetPollEvery(d time.Duration) (restore func()) {
	p := pollEvery
	pollEvery = d
	return func() { pollEvery = p }
}

func SetInbound(ack, latch time.Duration, clock func() time.Time) (restore func()) {
	a, l, n := ackWait, latchWait, now
	ackWait, latchWait, now = ack, latch, clock
	return func() { ackWait, latchWait, now = a, l, n }
}
