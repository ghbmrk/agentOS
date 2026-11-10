package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/ghbmrk/agentos/broker/speech/wire"
)

// Serve runs one call's session: Audio frames feed the recognizer, whose
// transcripts go back as Heard frames; each Speak frame is synthesized in
// turn and goes back as Spoken chunks and a Done. A frame that does not
// parse ends the session with an error; the box closing stdin ends it
// cleanly.
func Serve(ctx context.Context, in io.Reader, out io.Writer, e Engine) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wmu sync.Mutex
	var werr error
	send := func(typ byte, p []byte) {
		wmu.Lock()
		defer wmu.Unlock()
		if werr == nil {
			if werr = wire.Write(out, typ, p); werr != nil {
				cancel()
			}
		}
	}

	audio := make(chan []byte, 64)
	speak := make(chan speakReq, 4)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for h := range e.Recognize(ctx, audio) {
			send(wire.Heard, wire.EncodeHeard(h))
		}
	}()
	go func() {
		defer wg.Done()
		for r := range speak {
			pcm, err := e.Synthesize(ctx, r.text)
			status := wire.OK
			if err != nil || wire.PCM(pcm) != nil {
				pcm, status = nil, wire.Failed
			}
			for len(pcm) > 0 {
				n := min(len(pcm), wire.MaxPayload-4)
				send(wire.Spoken, wire.EncodeID(r.id, pcm[:n]))
				pcm = pcm[n:]
			}
			send(wire.Done, wire.EncodeID(r.id, []byte{status}))
		}
	}()

	err := readLoop(ctx, in, audio, speak)
	close(audio)
	close(speak)
	if err != nil {
		cancel()
	}
	wg.Wait()
	if err == nil {
		err = werr // every writer is done: wg.Wait orders this read after theirs
	}
	return err
}

type speakReq struct {
	id   uint32
	text string
}

func readLoop(ctx context.Context, in io.Reader, audio chan<- []byte, speak chan<- speakReq) error {
	for {
		typ, p, err := wire.Read(in)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch typ {
		case wire.Audio:
			if err := wire.PCM(p); err != nil {
				return err
			}
			select {
			case audio <- p:
			case <-ctx.Done():
				return ctx.Err()
			}
		case wire.Speak:
			id, rest, err := wire.DecodeID(p)
			if err != nil {
				return err
			}
			text, err := wire.Text(rest)
			if err != nil {
				return err
			}
			select {
			case speak <- speakReq{id, text}:
			case <-ctx.Done():
				return ctx.Err()
			}
		default:
			return fmt.Errorf("%w: unknown frame type %d", wire.ErrFrame, typ)
		}
	}
}
