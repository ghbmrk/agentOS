package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/ghbmrk/agentos/broker/apnet"
	"github.com/ghbmrk/agentos/broker/durable"
)

// apUpText is the owner's one text when the access point keeps failing to
// come up on the card's network (#1525, CH-12): fixed wording, GSM-7 in
// one segment, a step the owner can take. It points only at the newest
// card: the previous password is never brought back.
const apUpText = "My Wi-Fi is not coming back up on your card's network. Restart me, then join my Wi-Fi with your newest Owner Card."

// apUpEvery is how often agentosd looks at agentos-ap's failure count.
const apUpEvery = 10 * time.Second

// apUpNoticedPath is where agentosd notes, root-only beside the network
// file, which version of it the owner was texted about, so a restart of
// agentosd does not text again.
func apUpNoticedPath(apNet string) string {
	return filepath.Join(filepath.Dir(apNet), "ap-up-noticed")
}

// apUpCheck texts the owner apUpText once agentos-ap has counted
// apnet.UpFailureBound failures of the current version of the network
// file, once per version: a record of a version since replaced is
// stale and ignored. The version is noted only after inform succeeds, so
// a text that does not go is tried at the next look.
func apUpCheck(apNet string, inform func(string) error) error {
	f, err := apnet.ReadUpFailures(apNet)
	if err != nil || f.Count < apnet.UpFailureBound {
		return err
	}
	id, err := apnet.NetworkID(apNet)
	if errors.Is(err, os.ErrNotExist) || err == nil && id != f.Network {
		return nil
	}
	if err != nil {
		return err
	}
	noticed := apUpNoticedPath(apNet)
	b, err := readSmall(noticed, 256)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if bytes.Equal(b, []byte(id)) {
		return nil
	}
	if err := inform(apUpText); err != nil {
		return err
	}
	if err := durable.WriteFile(noticed, []byte(id), 0o600); err != nil && !errors.Is(err, durable.ErrDirSync) {
		return err
	}
	return nil
}

// readSmall reads at most limit bytes of path, refusing a longer file.
func readSmall(path string, limit int64) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = errors.New("too long")
	}
	return b, err
}

// watchAPUp runs apUpCheck every apUpEvery until ctx ends, logging a
// failure only when it differs from the last.
func watchAPUp(ctx context.Context, apNet string, inform func(string) error) {
	tick := time.NewTicker(apUpEvery)
	defer tick.Stop()
	last := ""
	for {
		msg := ""
		if err := apUpCheck(apNet, inform); err != nil {
			msg = err.Error()
		}
		if msg != last && msg != "" {
			log.Printf("access point failure notice: %s", msg)
		}
		last = msg
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
