// Package speech is the box's side of the speech process (VOICE-ro-b,
// briefs/VOICE-ro.md): one untrusted process, run in a sandbox per call,
// that holds the recognizer and the synthesizer. A Client implements
// call.Recognizer and call.Synthesizer over the process's stream and treats
// every frame it sends as a claim: a frame that does not parse, or that
// names audio or a sentence the box never sent, ends the session (rule 1),
// so the call loop plays its failed clip.
//
// One Client serves one call: Listen is called once, and Speak is called
// one sentence at a time or concurrently.
package speech

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/call"
	"github.com/ghbmrk/agentos/broker/speech/wire"
)

var (
	// ErrEnded is the session's end when the process closed its stream.
	ErrEnded = errors.New("speech: the process ended")
	// ErrTooLong fails a sentence whose audio is longer than its text
	// allows (rule 3).
	ErrTooLong = errors.New("speech: audio longer than its sentence allows")
	// ErrSentence refuses a sentence the wire cannot carry unchanged.
	ErrSentence = errors.New("speech: sentence not sendable")
	// ErrFailed is the process's own refusal of a sentence.
	ErrFailed = errors.New("speech: the synthesizer failed")
)

const (
	// maxAudio is the most audio any one sentence may have (rule 3).
	maxAudio = 40 * time.Second
	// marks bounds the audio positions kept to map an end of speech to
	// the box's clock: about a minute and a half of 20 ms frames.
	maxMarks = 4096
	// queue bounds frames waiting for the writer.
	queue = 64
)

// AudioLimit is the most audio, in bytes, a sentence of the given length
// in runes may have: 1 s plus 250 ms a rune, at most 40 s (rule 3).
func AudioLimit(runes int) int {
	d := time.Second + time.Duration(runes)*250*time.Millisecond
	if d > maxAudio {
		d = maxAudio
	}
	return int(d/time.Millisecond) * wire.Rate / 1000 * 2
}

// mark is when the box forwarded the audio ending at sample end.
type mark struct {
	end uint64
	at  time.Time
}

type pending struct {
	limit int
	pcm   []byte
	done  chan error // buffered 1; written once
}

type frame struct {
	typ byte
	p   []byte
}

// Client is one call's session with the speech process.
type Client struct {
	now  func() time.Time
	out  chan frame
	dead chan struct{}
	in   chan call.Heard // reader to Listen's forwarder; never closed

	once     sync.Once
	mu       sync.Mutex
	err      error
	sent     uint64 // samples forwarded
	marks    []mark
	next     uint32 // the next sentence id
	pend     map[uint32]*pending
	listened bool
}

// New starts a session over the process's stream: r is what it writes,
// w what it reads. The caller closes the stream when the call ends; now is
// the box's clock (time.Now if nil).
func New(r io.Reader, w io.Writer, now func() time.Time) *Client {
	if now == nil {
		now = time.Now
	}
	c := &Client{now: now, out: make(chan frame, queue), dead: make(chan struct{}),
		in: make(chan call.Heard), pend: map[uint32]*pending{}}
	go c.write(w)
	go c.read(r)
	return c
}

// Err is why the session ended, or nil while it runs.
func (c *Client) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// fail ends the session once: every pending and later Speak gets err, and
// Listen's channel closes.
func (c *Client) fail(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = err
		// Removed as they are told, so a reply the reader is still
		// taking finds none to write to.
		for id, p := range c.pend {
			p.done <- err
			delete(c.pend, id)
		}
		c.mu.Unlock()
		close(c.dead)
	})
}

func (c *Client) send(ctx context.Context, f frame) error {
	select {
	case c.out <- f:
		return nil
	case <-c.dead:
		return c.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) write(w io.Writer) {
	for {
		select {
		case f := <-c.out:
			if err := wire.Write(w, f.typ, f.p); err != nil {
				c.fail(fmt.Errorf("speech: writing to the process: %w", err)) // the next pass sees dead
			}
		case <-c.dead:
			return
		}
	}
}

// Listen forwards the call's speech to the process and returns what it
// hears. The channel closes when the session ends or ctx does; ctx's end
// also ends the session, since a Client serves one call. A second Listen
// gets a closed channel.
func (c *Client) Listen(ctx context.Context, speech <-chan []byte) <-chan call.Heard {
	heard := make(chan call.Heard)
	c.mu.Lock()
	again := c.listened
	c.listened = true
	c.mu.Unlock()
	if again {
		close(heard)
		return heard
	}
	go func() {
		select {
		case <-ctx.Done():
			c.fail(ctx.Err())
		case <-c.dead:
		}
	}()
	go c.forward(ctx, speech)
	go func() {
		defer close(heard)
		for {
			select {
			case h := <-c.in:
				select {
				case heard <- h:
				case <-c.dead: // the outer select returns
				}
			case <-c.dead:
				return
			}
		}
	}()
	return heard
}

func (c *Client) forward(ctx context.Context, speech <-chan []byte) {
	var carry []byte // a chunk's odd last byte, the first half of the next sample
	for {
		var pcm []byte
		var ok bool
		select {
		case pcm, ok = <-speech:
			if !ok {
				return
			}
		case <-c.dead:
			return
		}
		pcm = append(carry, pcm...) // a copy, so carry never aliases the line's buffer
		carry = nil
		if len(pcm)%2 == 1 {
			carry = []byte{pcm[len(pcm)-1]}
			pcm = pcm[:len(pcm)-1]
		}
		for len(pcm) > 0 {
			n := min(len(pcm), wire.MaxPayload)
			c.mu.Lock()
			c.sent += uint64(n / 2)
			c.marks = append(c.marks, mark{end: c.sent, at: c.now()})
			c.marks = c.marks[max(0, len(c.marks)-maxMarks):]
			c.mu.Unlock()
			if c.send(ctx, frame{wire.Audio, pcm[:n]}) != nil {
				return
			}
			pcm = pcm[n:]
		}
	}
}

// Speak has the process synthesize one checked sentence and returns its
// audio. A sentence the wire cannot carry unchanged is refused here, not
// altered. If ctx ends first, Speak returns at once and the sentence's late
// audio is dropped (rule 4).
func (c *Client) Speak(ctx context.Context, sentence string) ([]byte, error) {
	if _, err := wire.Text([]byte(sentence)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSentence, err)
	}
	p := &pending{limit: AudioLimit(utf8.RuneCountInString(sentence)), done: make(chan error, 1)}
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return nil, err
	}
	id := c.next
	c.next++
	c.pend[id] = p
	c.mu.Unlock()
	drop := func() {
		c.mu.Lock()
		delete(c.pend, id)
		c.mu.Unlock()
	}
	if err := c.send(ctx, frame{wire.Speak, wire.EncodeID(id, []byte(sentence))}); err != nil {
		drop()
		return nil, err
	}
	select {
	case err := <-p.done:
		if err != nil {
			return nil, err
		}
		return p.pcm, nil
	case <-ctx.Done():
		drop()
		return nil, ctx.Err()
	}
}

func (c *Client) read(r io.Reader) {
	for {
		typ, p, err := wire.Read(r)
		switch {
		case errors.Is(err, io.EOF):
			err = ErrEnded
		case err == nil:
			err = c.take(typ, p)
		}
		if err != nil {
			c.fail(err)
			return
		}
	}
}

// take handles one frame from the process; an error ends the session.
func (c *Client) take(typ byte, p []byte) error {
	switch typ {
	case wire.Heard:
		f, err := wire.DecodeHeard(p)
		if err != nil {
			return err
		}
		h, err := c.heard(f)
		if err != nil {
			return err
		}
		select {
		case c.in <- h:
		case <-c.dead:
		}
		return nil
	case wire.Spoken, wire.Done:
		id, rest, err := wire.DecodeID(p)
		if err != nil {
			return err
		}
		return c.reply(typ, id, rest)
	}
	return fmt.Errorf("%w: type %d from the process", wire.ErrFrame, typ)
}

// heard maps a transcript's end of speech to the box's clock (rule 2).
func (c *Client) heard(f wire.HeardFrame) (call.Heard, error) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.listened {
		return call.Heard{}, fmt.Errorf("%w: transcript before any listening", wire.ErrFrame)
	}
	h := call.Heard{Text: f.Text, Final: f.Final}
	if f.End == 0 {
		return h, nil
	}
	if f.End > c.sent {
		return call.Heard{}, fmt.Errorf("%w: end of speech at sample %d, past the %d sent", wire.ErrFrame, f.End, c.sent)
	}
	// The line's audio is real time, so the frame that ends at m.end
	// arrived at m.at and sample End was heard (m.end-End)/Rate before it.
	// 0 < End <= sent, and the newest mark ends at sent, so one is found.
	m := c.marks[sort.Search(len(c.marks), func(i int) bool { return c.marks[i].end >= f.End })]
	at := m.at.Add(-time.Duration(m.end-f.End) * time.Second / wire.Rate)
	if at.After(now) {
		at = now
	}
	h.End = at
	return h, nil
}

func (c *Client) reply(typ byte, id uint32, rest []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id >= c.next {
		return fmt.Errorf("%w: reply to sentence %d, never asked", wire.ErrFrame, id)
	}
	p := c.pend[id]
	if typ == wire.Spoken {
		if err := wire.PCM(rest); err != nil {
			return err
		}
		if p == nil {
			return nil // cancelled or already failed: dropped (rule 4)
		}
		if len(p.pcm)+len(rest) > p.limit {
			p.done <- ErrTooLong
			delete(c.pend, id)
		} else {
			p.pcm = append(p.pcm, rest...)
		}
		return nil
	}
	if len(rest) != 1 || rest[0] > wire.Failed {
		return fmt.Errorf("%w: done status", wire.ErrFrame)
	}
	if p == nil {
		return nil
	}
	delete(c.pend, id)
	if rest[0] == wire.Failed {
		p.done <- ErrFailed
	} else {
		p.done <- nil
	}
	return nil
}

var (
	_ call.Recognizer  = (*Client)(nil)
	_ call.Synthesizer = (*Client)(nil)
)
