package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/modelroute"
)

// The second line's owner lines (potency R1 on #139): STATUS shows them
// while they last (CH-12's exception lines), and the digest repeats them.
const (
	secondLineConfirmLine   = "Second line: confirm your provider on the box's Wi-Fi page. Texts and calls wait until you do."
	secondLineUnreachedLine = "Second line: the box couldn't reach your provider. Check the server name and password on the box's Wi-Fi page."
)

// secondLineEvery is how often agentosd asks the vault process.
const secondLineEvery = time.Minute

// secondLine keeps the vault process's second-line state (egress K13) for
// STATUS and the digest. STATUS reads the cached state, so a slow vault
// process never holds up the owner channel.
type secondLine struct {
	get func(context.Context) (modelroute.SecondLineState, error)

	mu sync.Mutex
	st modelroute.SecondLineState
}

// refresh asks once. A locked vault reads as nothing to do here (the
// unlock prompt is its own line); a vault process that does not answer
// keeps the last state.
func (s *secondLine) refresh(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := s.get(ctx)
	switch {
	case errors.Is(err, modelroute.ErrVaultLocked):
		st = modelroute.SecondLineOK
	case err != nil:
		return
	}
	s.mu.Lock()
	s.st = st
	s.mu.Unlock()
}

func (s *secondLine) run(ctx context.Context) {
	t := time.NewTicker(secondLineEvery)
	defer t.Stop()
	for {
		s.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Note is STATUS's second-line line, or "" (a control.Handler note).
func (s *secondLine) Note() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.st {
	case modelroute.SecondLineConfirm:
		return secondLineConfirmLine
	case modelroute.SecondLineUnreached:
		return secondLineUnreachedLine
	}
	return ""
}

// Digest repeats the line in each digest while it lasts.
func (s *secondLine) Digest() []string {
	if l := s.Note(); l != "" {
		return []string{l}
	}
	return nil
}
