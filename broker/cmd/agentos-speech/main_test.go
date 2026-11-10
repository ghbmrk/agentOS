package main

// REQ: CH-5, CH-17

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
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

// stuck ignores closed audio and runs until its context ends; its
// synthesizer takes slow to answer, or waits for the context if slow is 0.
type stuck struct{ slow time.Duration }

func (stuck) Recognize(ctx context.Context, audio <-chan []byte) <-chan wire.HeardFrame {
	out := make(chan wire.HeardFrame)
	go func() { <-ctx.Done(); close(out) }()
	return out
}

func (s stuck) Synthesize(ctx context.Context, text string) ([]byte, error) {
	if s.slow == 0 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	time.Sleep(s.slow)
	return []byte{1, 2}, nil
}

func frames(t *testing.T, fs ...[2]any) []byte {
	var b bytes.Buffer
	for _, f := range fs {
		if err := wire.Write(&b, f[0].(byte), f[1].([]byte)); err != nil {
			t.Fatal(err)
		}
	}
	return b.Bytes()
}

func serveWithin(t *testing.T, ctx context.Context, in io.Reader, out io.Writer, e Engine) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, in, out, e) }()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return")
		return nil
	}
}

func TestServeEndsTheEngineOnABadFrame(t *testing.T) {
	// The engine stops only when its context ends, so a bad frame must end it.
	err := serveWithin(t, context.Background(), bytes.NewReader([]byte{9, 0, 0, 0, 0}), io.Discard, stuck{})
	if !errors.Is(err, wire.ErrFrame) {
		t.Fatalf("Serve = %v", err)
	}
	// A Speak too short to name its sentence is a bad frame.
	if err := Serve(context.Background(), bytes.NewReader(frames(t, [2]any{wire.Speak, []byte{0, 0, 1}})), io.Discard, echo{}); !errors.Is(err, wire.ErrFrame) {
		t.Fatalf("short Speak: Serve = %v", err)
	}
	// A read error is returned as it is.
	if err := Serve(context.Background(), iotest.ErrReader(io.ErrClosedPipe), io.Discard, echo{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("read error: Serve = %v", err)
	}
}

func TestServeFinishesSentencesBeforeACleanEnd(t *testing.T) {
	var out bytes.Buffer
	in := frames(t, [2]any{wire.Speak, wire.EncodeID(3, []byte("Hi."))})
	if err := Serve(context.Background(), bytes.NewReader(in), &out, stuckDone{stuck{slow: 50 * time.Millisecond}}); err != nil {
		t.Fatal(err)
	}
	want := frames(t, [2]any{wire.Spoken, wire.EncodeID(3, []byte{1, 2})}, [2]any{wire.Done, wire.EncodeID(3, []byte{wire.OK})})
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("Serve wrote %v before returning, want %v", out.Bytes(), want)
	}
	// A failed write is Serve's error.
	if err := Serve(context.Background(), bytes.NewReader(in), errWriter{}, stuckDone{stuck{slow: time.Millisecond}}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("write error: Serve = %v", err)
	}
}

// stuckDone's recognizer ends when its audio closes.
type stuckDone struct{ stuck }

func (stuckDone) Recognize(ctx context.Context, audio <-chan []byte) <-chan wire.HeardFrame {
	out := make(chan wire.HeardFrame)
	go func() {
		for range audio {
		}
		close(out)
	}()
	return out
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, io.ErrShortWrite }

func TestServeStopsWhenItsContextEnds(t *testing.T) {
	// Nothing reads the audio and nothing finishes a sentence: more frames
	// than the queues hold, then the context ends.
	var fs [][2]any
	for i := 0; i < 80; i++ {
		fs = append(fs, [2]any{wire.Audio, []byte{0, 0}})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := serveWithin(t, ctx, bytes.NewReader(frames(t, fs...)), io.Discard, stuck{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("audio: Serve = %v", err)
	}
	fs = nil
	for i := 0; i < 10; i++ {
		fs = append(fs, [2]any{wire.Speak, wire.EncodeID(uint32(i), []byte("Hi."))})
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if err := serveWithin(t, ctx2, bytes.NewReader(frames(t, fs...)), io.Discard, stuck{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("sentences: Serve = %v", err)
	}
}

func TestRunServesWithAnEngine(t *testing.T) {
	var errOut bytes.Buffer
	if code := run(context.Background(), nil, echo{}, bytes.NewReader(nil), io.Discard, &errOut); code != 0 {
		t.Fatalf("run with an engine = %d, %q", code, errOut.String())
	}
	if code := run(context.Background(), nil, echo{}, bytes.NewReader([]byte{9, 0, 0, 0, 0}), io.Discard, &errOut); code == 0 {
		t.Fatal("run served a bad frame")
	}
}

func TestWriteErrorEndsTheEngine(t *testing.T) {
	// The recognizer runs until its context ends, so a failed write must
	// end it, or Serve waits for ever.
	in := frames(t, [2]any{wire.Speak, wire.EncodeID(0, []byte("Hi."))})
	if err := serveWithin(t, context.Background(), bytes.NewReader(in), errWriter{}, stuck{slow: time.Millisecond}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Serve = %v", err)
	}
}
