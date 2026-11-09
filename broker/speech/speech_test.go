package speech

// REQ: CH-5, CH-17, CH-21

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/call"
	"github.com/ghbmrk/agentos/broker/speech/wire"
)

// proc is the far side of a session: the test plays the speech process.
type proc struct {
	t  *testing.T
	r  *io.PipeReader // what the box sends
	w  *io.PipeWriter // what the process sends
	bw *io.PipeWriter
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }

var t0 = time.Date(2026, 11, 9, 18, 0, 0, 0, time.UTC)

func session(t *testing.T, now func() time.Time) (*Client, *proc) {
	t.Helper()
	br, bw := io.Pipe() // box to process
	pr, pw := io.Pipe() // process to box
	c := New(pr, bw, now)
	p := &proc{t: t, r: br, w: pw, bw: bw}
	t.Cleanup(func() { pw.Close(); br.Close(); bw.Close() })
	return c, p
}

func (p *proc) send(typ byte, payload []byte) {
	p.t.Helper()
	if err := wire.Write(p.w, typ, payload); err != nil {
		p.t.Fatalf("process write: %v", err)
	}
}

func (p *proc) raw(b []byte) {
	if _, err := p.w.Write(b); err != nil {
		p.t.Fatalf("process write: %v", err)
	}
}

func (p *proc) recv(want byte) []byte {
	p.t.Helper()
	typ, b, err := wire.Read(p.r)
	if err != nil || typ != want {
		p.t.Fatalf("process read: type %d, %v; want type %d", typ, err, want)
	}
	return b
}

// ended waits for the session to end and checks it ends every use.
func ended(t *testing.T, c *Client, heard <-chan call.Heard) {
	t.Helper()
	select {
	case _, ok := <-heard:
		if ok {
			t.Fatal("a transcript came through instead of the session ending")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the session did not end")
	}
	if !errors.Is(c.Err(), wire.ErrFrame) {
		t.Fatalf("Err = %v, want a bad frame", c.Err())
	}
	if _, err := c.Speak(context.Background(), "Hello."); err == nil {
		t.Fatal("Speak worked after the session ended")
	}
}

func listen(c *Client) (<-chan call.Heard, chan []byte) {
	speech := make(chan []byte)
	return c.Listen(context.Background(), speech), speech
}

func TestBadFrameEndsTheSession(t *testing.T) {
	for name, frame := range map[string][]byte{
		"unknown type":     {9, 0, 0, 0, 0},
		"audio to the box": {wire.Audio, 0, 0, 0, 2, 0, 0},
		"oversize":         {wire.Heard, 0x7f, 0, 0, 0},
		"cut heard":        {wire.Heard, 0, 0, 0, 3, 1, 0, 0},
		"bad final flag":   append([]byte{wire.Heard, 0, 0, 0, 9, 2}, make([]byte, 8)...),
		"not UTF-8":        append(append([]byte{wire.Heard, 0, 0, 0, 10, 1}, make([]byte, 8)...), 0xff),
		"bad done status":  {wire.Done, 0, 0, 0, 5, 0, 0, 0, 0, 7},
	} {
		t.Run(name, func(t *testing.T) {
			c, p := session(t, nil)
			heard, _ := listen(c)
			if name == "bad done status" {
				go c.Speak(context.Background(), "Hi.")
				p.recv(wire.Speak)
			}
			p.raw(frame)
			ended(t, c, heard)
		})
	}
}

func TestControlCharacterEndsTheSession(t *testing.T) {
	for _, text := range []string{"press\u202e1", "hi\x00", "a\u200bb", "line\nbreak", "\u0085"} {
		c, p := session(t, nil)
		heard, _ := listen(c)
		p.send(wire.Heard, wire.EncodeHeard(wire.HeardFrame{Final: true, Text: text}))
		ended(t, c, heard)
	}
	// The box refuses to send such a sentence rather than alter it.
	c, _ := session(t, nil)
	if _, err := c.Speak(context.Background(), "press\u202e 1"); !errors.Is(err, ErrSentence) {
		t.Fatalf("Speak of a sentence with a format character = %v, want ErrSentence", err)
	}
}

func TestUnaskedReplyEndsTheSession(t *testing.T) {
	for _, typ := range []byte{wire.Spoken, wire.Done} {
		c, p := session(t, nil)
		heard, _ := listen(c)
		payload := []byte{0, 0}
		if typ == wire.Done {
			payload = []byte{wire.OK}
		}
		p.send(typ, wire.EncodeID(0, payload))
		ended(t, c, heard)
	}
	// A transcript before the box listens is unasked too.
	c, p := session(t, nil)
	p.send(wire.Heard, wire.EncodeHeard(wire.HeardFrame{Text: "hello"}))
	if _, err := c.Speak(context.Background(), "Hi."); err == nil {
		t.Fatal("Speak worked after an unasked transcript")
	}
}

func TestEndIsTheBoxClock(t *testing.T) {
	clk := &clock{t: t0}
	c, p := session(t, clk.now)
	heard, speech := listen(c)
	// Two 100 ms frames, forwarded at 100 ms and 200 ms.
	for i := 1; i <= 2; i++ {
		clk.set(t0.Add(time.Duration(i) * 100 * time.Millisecond))
		speech <- make([]byte, 1600)
		p.recv(wire.Audio)
	}
	clk.set(t0.Add(5 * time.Second)) // a slow recognizer
	p.send(wire.Heard, wire.EncodeHeard(wire.HeardFrame{Final: true, End: 1200, Text: "what is due"}))
	h := <-heard
	if want := t0.Add(150 * time.Millisecond); !h.End.Equal(want) || h.Text != "what is due" || !h.Final {
		t.Fatalf("heard %+v, want End %v", h, want)
	}
	p.send(wire.Heard, wire.EncodeHeard(wire.HeardFrame{End: 1, Text: "w"}))
	if h := <-heard; !h.End.Equal(t0.Add(100*time.Millisecond - 99875*time.Microsecond)) {
		t.Fatalf("first sample's End = %v", h.End)
	}
	p.send(wire.Heard, wire.EncodeHeard(wire.HeardFrame{Text: "no end"}))
	if h := <-heard; !h.End.IsZero() {
		t.Fatalf("an unstated end of speech became %v, want zero", h.End)
	}
}

func TestEndPastTheAudioEndsTheSession(t *testing.T) {
	c, p := session(t, nil)
	heard, speech := listen(c)
	speech <- make([]byte, 1600)
	p.recv(wire.Audio)
	// End later than the 800 samples sent would put the end of speech in
	// the future and hold back the one-moment clip.
	p.send(wire.Heard, wire.EncodeHeard(wire.HeardFrame{Final: true, End: 801, Text: "hello"}))
	ended(t, c, heard)
}

func TestAudioBoundedByText(t *testing.T) {
	c, p := session(t, nil)
	heard, _ := listen(c)
	limit := AudioLimit(3) // "Hi." is 1.75 s
	if limit != 28000 {
		t.Fatalf("AudioLimit(3) = %d bytes, want 28000", limit)
	}
	if AudioLimit(10000) != 40*wire.Rate*2 {
		t.Fatalf("AudioLimit is not capped at 40 s")
	}
	speak := func(n int) ([]byte, error) {
		type res struct {
			pcm []byte
			err error
		}
		done := make(chan res, 1)
		go func() { pcm, err := c.Speak(context.Background(), "Hi."); done <- res{pcm, err} }()
		id, _, _ := wire.DecodeID(p.recv(wire.Speak))
		for n > 0 {
			k := min(n, wire.MaxPayload-4)
			p.send(wire.Spoken, wire.EncodeID(id, make([]byte, k)))
			n -= k
		}
		p.send(wire.Done, wire.EncodeID(id, []byte{wire.OK}))
		r := <-done
		return r.pcm, r.err
	}
	if pcm, err := speak(limit); err != nil || len(pcm) != limit {
		t.Fatalf("audio at the limit: %d bytes, %v", len(pcm), err)
	}
	if _, err := speak(limit + 2); !errors.Is(err, ErrTooLong) {
		t.Fatalf("audio over the limit: %v, want ErrTooLong", err)
	}
	// The sentence failed; the session did not.
	if c.Err() != nil {
		t.Fatalf("session ended: %v", c.Err())
	}
	select {
	case <-heard:
		t.Fatal("transcripts closed")
	default:
	}
}

func TestOddAudioEndsTheSession(t *testing.T) {
	c, p := session(t, nil)
	heard, _ := listen(c)
	errc := make(chan error, 1)
	go func() { _, err := c.Speak(context.Background(), "Hi."); errc <- err }()
	p.recv(wire.Speak)
	p.send(wire.Spoken, wire.EncodeID(0, []byte{1, 2, 3}))
	if err := <-errc; !errors.Is(err, wire.ErrFrame) {
		t.Fatalf("pending Speak got %v, want the session's bad frame", err)
	}
	ended(t, c, heard)
}

func TestCancelledSentenceIsDropped(t *testing.T) {
	c, p := session(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { _, err := c.Speak(ctx, "First."); errc <- err }()
	p.recv(wire.Speak)
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Speak = %v", err)
	}
	type res struct {
		pcm []byte
		err error
	}
	done := make(chan res, 1)
	go func() { pcm, err := c.Speak(context.Background(), "Second."); done <- res{pcm, err} }()
	id, _, _ := wire.DecodeID(p.recv(wire.Speak))
	if id != 1 {
		t.Fatalf("second sentence id %d", id)
	}
	// The first sentence's late audio arrives first and must not be played.
	p.send(wire.Spoken, wire.EncodeID(0, bytes.Repeat([]byte{1}, 100)))
	p.send(wire.Done, wire.EncodeID(0, []byte{wire.OK}))
	p.send(wire.Spoken, wire.EncodeID(1, bytes.Repeat([]byte{2}, 10)))
	p.send(wire.Done, wire.EncodeID(1, []byte{wire.OK}))
	r := <-done
	if r.err != nil || !bytes.Equal(r.pcm, bytes.Repeat([]byte{2}, 10)) {
		t.Fatalf("second sentence got %v, %v", r.pcm, r.err)
	}
	// A failed status fails only its sentence.
	go func() { _, err := c.Speak(context.Background(), "Third."); errc <- err }()
	p.recv(wire.Speak)
	p.send(wire.Done, wire.EncodeID(2, []byte{wire.Failed}))
	if err := <-errc; !errors.Is(err, ErrFailed) {
		t.Fatalf("failed sentence = %v", err)
	}
}

func TestProcessEndEndsTheSession(t *testing.T) {
	c, p := session(t, nil)
	heard, _ := listen(c)
	p.w.Close()
	if _, ok := <-heard; ok {
		t.Fatal("transcripts went on after the process ended")
	}
	if !errors.Is(c.Err(), ErrEnded) {
		t.Fatalf("Err = %v", c.Err())
	}
	// A second Listen gets a closed channel.
	if _, ok := <-c.Listen(context.Background(), nil); ok {
		t.Fatal("second Listen delivered")
	}
}

func FuzzClient(f *testing.F) {
	var seed bytes.Buffer
	wire.Write(&seed, wire.Heard, wire.EncodeHeard(wire.HeardFrame{Final: true, End: 10, Text: "what is due"}))
	wire.Write(&seed, wire.Spoken, wire.EncodeID(0, []byte{0, 0}))
	wire.Write(&seed, wire.Done, wire.EncodeID(0, []byte{wire.OK}))
	f.Add(seed.Bytes())
	f.Add([]byte{wire.Heard, 0, 0, 0, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, stream []byte) {
		c := New(bytes.NewReader(stream), io.Discard, nil)
		speech := make(chan []byte, 1)
		speech <- make([]byte, 160)
		heard := c.Listen(context.Background(), speech)
		go c.Speak(context.Background(), "Hello.")
		for h := range heard {
			if _, err := wire.Text([]byte(h.Text)); err != nil {
				t.Fatalf("a transcript the wire refuses came through: %q", h.Text)
			}
		}
		if c.Err() == nil {
			t.Fatal("transcripts closed while the session ran")
		}
	})
}
