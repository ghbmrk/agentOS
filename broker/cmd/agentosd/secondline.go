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
	secondLineUnreachedLine = "Second line: the box couldn't reach your provider. Check the server name and password on the box's Wi-Fi page, or remove it there."
	// The texting account's lines (UX-159-1), once its polls have failed
	// for modelroute.TextsQuiet.
	textsSignInLine    = "Second line: texts aren't arriving because the box couldn't sign in to your texting account. Check the account ID and auth token on the box's Wi-Fi page, or remove it there."
	textsUnreachedLine = "Second line: texts aren't arriving because the box couldn't reach your texting provider. Nothing to do unless it lasts; you can remove the texting account on the box's Wi-Fi page."
)

// secondLineEvery is how often agentosd asks the vault process.
const secondLineEvery = time.Minute

// secondLine keeps the vault process's second-line state (egress K13) for
// STATUS and the digest. STATUS reads the cached state, so a slow vault
// process never holds up the owner channel.
type secondLine struct {
	get func(context.Context) (modelroute.SecondLineState, error)
	// texts, if set, asks about the texting account (egress K16).
	texts func(context.Context) (modelroute.TextsState, error)

	mu sync.Mutex
	st modelroute.SecondLineState
	tx modelroute.TextsState
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

// refreshTexts asks about the texting account, on the same rules.
func (s *secondLine) refreshTexts(ctx context.Context) {
	if s.texts == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := s.texts(ctx)
	switch {
	case errors.Is(err, modelroute.ErrVaultLocked):
		tx = modelroute.TextsOK
	case err != nil:
		return
	}
	s.mu.Lock()
	s.tx = tx
	s.mu.Unlock()
}

func (s *secondLine) run(ctx context.Context) {
	t := time.NewTicker(secondLineEvery)
	defer t.Stop()
	for {
		s.refresh(ctx)
		s.refreshTexts(ctx)
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

// TextsNote is STATUS's texting-account line, or "".
func (s *secondLine) TextsNote() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.tx {
	case modelroute.TextsSignIn:
		return textsSignInLine
	case modelroute.TextsUnreached:
		return textsUnreachedLine
	}
	return ""
}

// Digest repeats the lines in each digest while they last.
func (s *secondLine) Digest() []string {
	var out []string
	for _, l := range []string{s.Note(), s.TextsNote()} {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}
