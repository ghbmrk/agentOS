// Command agentos-speech is the voice assistant's speech process
// (VOICE-ro-b, briefs/VOICE-ro.md): the recognizer and the synthesizer of
// one owner call. It reads wire frames (broker/speech/wire) on stdin and
// writes them on stdout, and touches nothing else: the box runs it in a
// sandbox per call with no network and a read-only root, and everything it
// writes is a claim the box-side client checks (broker/speech).
//
// It sees only the call's audio and sentences the call loop has already
// checked (rule 5). An engine is compiled in by a build tag (part b2);
// without one the program refuses to start, failing closed.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/ghbmrk/agentos/broker/speech/wire"
)

// Engine is a recognizer and a synthesizer. Recognize reads the call's
// audio until it closes and proposes transcripts, End counted in samples
// from the first; its channel closes when it stops. Synthesize returns a
// sentence's 8 kHz S16_LE mono audio.
type Engine interface {
	Recognize(ctx context.Context, audio <-chan []byte) <-chan wire.HeardFrame
	Synthesize(ctx context.Context, text string) ([]byte, error)
}

// engine is set by a tagged build's init; nil in the default build.
var engine Engine

// errNoEngine is the untagged build's refusal.
var errNoEngine = errors.New("agentos-speech: no engine in this build")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], engine, os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, e Engine, in io.Reader, out, errOut io.Writer) int {
	err := error(nil)
	switch {
	case len(args) != 0:
		err = fmt.Errorf("agentos-speech: unexpected arguments %q", args)
	case e == nil:
		err = errNoEngine
	default:
		err = Serve(ctx, in, out, e)
	}
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	return 0
}
