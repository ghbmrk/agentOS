// Package keptmore is CH-20m: MORE sends the next SMS part of a kept
// reply that was not redirected. A redirected private reply never yields
// to MORE (SIM-swap protection; UX ruling on #148).
package keptmore

import (
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"
)

// SMSSegment is one GSM-7 text body bound (bytes).
const SMSSegment = 153

// Reply is one kept agent reply.
type Reply struct {
	ID         string
	Text       string
	Redirected bool // emailed / private redirect: MORE refused
	Offset     int  // runes already sent by MORE
}

// Store holds kept replies the owner may page with MORE.
type Store struct {
	mu   sync.Mutex
	byID map[string]*Reply
}

// Put records or replaces a kept reply.
func (s *Store) Put(r Reply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byID == nil {
		s.byID = map[string]*Reply{}
	}
	cp := r
	s.byID[r.ID] = &cp
}

// Refused is the fixed reply when MORE would bypass SIM-swap protection.
const Refused = "MORE is only for replies I kept on the box, not ones I emailed."

// Empty is when there is nothing left to send.
const Empty = "Nothing more to send."

// More returns the next SMS-sized part of the reply, or a fixed refusal.
func (s *Store) More(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.byID[id]
	if r == nil {
		return "", fmt.Errorf("keptmore: unknown %s", id)
	}
	if r.Redirected {
		return Refused, nil
	}
	runes := []rune(r.Text)
	if r.Offset >= len(runes) {
		return Empty, nil
	}
	// Pack up to SMSSegment bytes of UTF-8 without splitting a rune.
	var b strings.Builder
	n := 0
	i := r.Offset
	for i < len(runes) {
		sz := utf8.RuneLen(runes[i])
		if n+sz > SMSSegment {
			break
		}
		b.WriteRune(runes[i])
		n += sz
		i++
	}
	r.Offset = i
	return b.String(), nil
}
