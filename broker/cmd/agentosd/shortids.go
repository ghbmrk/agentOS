package main

import (
	"sync/atomic"

	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// lateShortIDs is the change pipeline's Config.ShortID: the owner channel's
// allocator once the daemon attaches, and "" (the pipeline's own sequence)
// before then or with no owner channel (W5, change C11).
type lateShortIDs struct {
	ch atomic.Pointer[ownerch.Channel]
}

func (s *lateShortIDs) ShortID(taken func(string) bool) (string, error) {
	ch := s.ch.Load()
	if ch == nil {
		return "", nil
	}
	return ch.ShortID(taken)
}
