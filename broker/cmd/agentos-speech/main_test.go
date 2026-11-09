package main

// REQ: CH-5, CH-17

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/speech"
	"github.com/ghbmrk/agentos/broker/speech/wire"
)

// echo hears "heard N" after each audio frame, N the samples so far, and
// speaks 160 bytes a rune; "fail" fails.
type echo struct{ said chan string }

func (e echo) Recognize(ctx context.Context, audio <-chan []byte) <-chan wire.HeardFrame {
	out := make(chan wire.HeardFrame)
	go func() {
		defer close(out)
		var n uint64
		for pcm := range audio {
			n += uint64(len(pcm) / 2)
			select {
			case out <- wire.HeardFrame{Final: true, End: n, Text: "what is due"}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

func (e echo) Synthesize(ctx context.Context, text string) ([]byte, error) {
	if e.said != nil {
		e.said <- text
	}
	if text == "fail." {
		return nil, errors.New("engine failed")
	}
	return bytes.Repeat([]byte{7}, 160*len([]rune(text))), nil
}

// pair runs Serve against the real box-side client.
func pair(t *testing.T, e Engine) (*speech.Client, *io.PipeWriter, chan error) {
	br, bw := io.Pipe()
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), br, pw, e); pw.Close() }()
	t.Cleanup(func() { bw.Close(); pr.Close() })
	return speech.New(pr, bw, nil), bw, done
}

func TestServeRoundTrip(t *testing.T) {
	said := make(chan string, 4)
	c, bw, done := pair(t, echo{said})
	speechIn := make(chan []byte)
	heard := c.Listen(context.Background(), speechIn)
	before := time.Now()
	speechIn <- make([]byte, 1600)
	h := <-heard
	if h.Text != "what is due" || !h.Final || h.End.Before(before) || h.End.After(time.Now()) {
		t.Fatalf("heard %+v", h)
	}
	// Long audio crosses several frames.
	long := strings.Repeat("a", 400) + "."
	pcm, err := c.Speak(context.Background(), long)
	if err != nil || len(pcm) != 160*401 {
		t.Fatalf("Speak: %d bytes, %v", len(pcm), err)
	}
	if got := <-said; got != long {
		t.Fatalf("the engine was given %q", got)
	}
	if _, err := c.Speak(context.Background(), "fail."); !errors.Is(err, speech.ErrFailed) {
		t.Fatalf("failed sentence: %v", err)
	}
	<-said
	if pcm, err := c.Speak(context.Background(), "Hi."); err != nil || len(pcm) != 480 {
		t.Fatalf("Speak after a failure: %d bytes, %v", len(pcm), err)
	}
	<-said
	// The box closing its stream ends the session cleanly.
	bw.Close()
	if err := <-done; err != nil {
		t.Fatalf("Serve = %v after the box closed its stream", err)
	}
}

func TestServeRefusesABadFrame(t *testing.T) {
	for name, stream := range map[string][]byte{
		"heard to the process": {wire.Heard, 0, 0, 0, 0},
		"odd audio":            {wire.Audio, 0, 0, 0, 1, 0},
		"control character":    append([]byte{wire.Speak, 0, 0, 0, 6, 0, 0, 0, 0}, "a\x1b"...),
		"cut":                  {wire.Speak, 0, 0},
	} {
		var out bytes.Buffer
		if err := Serve(context.Background(), bytes.NewReader(stream), &out, echo{}); !errors.Is(err, wire.ErrFrame) {
			t.Errorf("%s: Serve = %v, want a bad frame", name, err)
		}
	}
	var out bytes.Buffer
	if err := Serve(context.Background(), bytes.NewReader(nil), &out, echo{}); err != nil {
		t.Fatalf("a clean end: %v", err)
	}
}

func TestNoEngineFailsClosed(t *testing.T) {
	if engine != nil {
		t.Skip("this build has an engine")
	}
	var errOut bytes.Buffer
	in := bytes.NewReader(nil)
	if code := run(context.Background(), nil, engine, in, io.Discard, &errOut); code == 0 || !strings.Contains(errOut.String(), "no engine") {
		t.Fatalf("run without an engine = %d, %q", code, errOut.String())
	}
	if code := run(context.Background(), []string{"-x"}, echo{}, in, io.Discard, &errOut); code == 0 {
		t.Fatal("run took arguments")
	}
}
