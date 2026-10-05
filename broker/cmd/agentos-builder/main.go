// Command agentos-builder is the brief client in Loop 1's builder image
// (W3-builder-image, C-3c-3). It runs inside a private lb- machine as its
// first process. It is guest code: untrusted, and trusted by nothing in the
// broker, which treats whatever it submits as compromised (loopbuild B4).
//
// Its one socket (/run/agentos/broker.sock) serves the job and nothing
// else: it reads the brief (GET /brief), asks the model for a candidate
// through the metered model route (/model/...), checks the files locally
// with the skill format's own validator (the image's toolchain), and
// submits them (POST /candidate). A refusal, local or the broker's, goes
// back to the model, up to -rounds times. With nothing to submit it says
// so (POST /done), so the job ends at once.
//
// Usage: agentos-builder [flags]
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	sock := flag.String("socket", "/run/agentos/broker.sock", "the machine's broker socket")
	model := flag.String("model", "broker-default", "model name sent on the model route; the broker's rule picks the route")
	rounds := flag.Int("rounds", defaultRounds, "model calls before giving up")
	maxTokens := flag.Int("max-tokens", defaultMaxTokens, "output tokens per model call")
	flag.Parse()

	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", *sock)
	}}}
	b := &builder{hc: hc, model: *model, rounds: *rounds, maxTokens: *maxTokens, logf: log.Printf}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := b.run(ctx); err != nil {
		log.Printf("builder: %v", err)
	}
	if os.Getpid() != 1 {
		return
	}
	// As PID 1, wait to be destroyed: the job is over either way.
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
		case <-time.After(time.Hour):
		}
	}
}
