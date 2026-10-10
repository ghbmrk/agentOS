// Package fold hands a guest a short stand-in for an oversized tool result
// and keeps the original for that machine to read back. Nothing is summarized
// by a model (ARC-2). A result within the budget is returned unchanged.
package fold

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"unicode/utf8"
)

const (
	// Max is the most bytes of a tool result handed to the guest inline.
	Max = 8 << 10
	// Head is the prefix of an oversized result the stand-in still carries.
	Head = 256
	// perMachine and machineBytes bound what the broker keeps for one
	// machine; totalBytes bounds what it keeps for all of them.
	perMachine   = 32
	machineBytes = 4 << 20
	totalBytes   = 64 << 20
)

// StandIn is the JSON a guest receives instead of an oversized result.
type StandIn struct {
	Folded bool   `json:"folded"`
	ID     string `json:"id"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
	Head   string `json:"head"`
}

// Store keeps full results per machine. A machine cannot read another's,
// and one machine's results never displace another's: a machine over its
// own bounds loses its own oldest result, and a result that cannot be held
// without displacing another machine's is handed back whole. A result
// dropped that way, or lost when the broker restarts, cannot be read again;
// calling the tool again may repeat its effect, so it is not a substitute.
type Store struct {
	mu sync.Mutex
	ms map[string][]rec // oldest first
	n  int
}

type rec struct {
	id   string
	body string
}

// Hand returns body unchanged when it fits inline or cannot be held.
// Otherwise it stores body and returns a stand-in. The stand-in is not
// itself stored.
func (s *Store) Hand(machine, body string) string {
	if s == nil || len(body) <= Max || len(body) > machineBytes {
		return body
	}
	id := newID()
	sum := sha256.Sum256([]byte(body))
	in := StandIn{Folded: true, ID: id, Bytes: len(body), SHA256: hex.EncodeToString(sum[:]), Head: prefix(body, Head)}
	b, err := json.Marshal(in)
	if err != nil {
		return body
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	own := s.ms[machine]
	// Plan which of the caller's own oldest results make room, and hold
	// nothing if the whole store would still overflow.
	used := 0
	for _, r := range own {
		used += len(r.body)
	}
	drop, freed := 0, 0
	for drop < len(own) && (len(own)-drop >= perMachine || used-freed+len(body) > machineBytes) {
		freed += len(own[drop].body)
		drop++
	}
	if s.n-freed+len(body) > totalBytes {
		return body
	}
	if s.ms == nil {
		s.ms = map[string][]rec{}
	}
	clear(own[:drop]) // the backing array must not keep dropped bodies alive
	s.ms[machine] = append(own[drop:], rec{id: id, body: body})
	s.n += len(body) - freed
	return string(b)
}

// Read returns the original result for machine and id.
func (s *Store) Read(machine, id string) (string, bool) {
	if s == nil || machine == "" || id == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.ms[machine] {
		if r.id == id {
			return r.body, true
		}
	}
	return "", false
}

// Drop forgets every result held for machine. The plane calls it when the
// machine is destroyed, so a later machine reusing the ID reads nothing.
func (s *Store) Drop(machine string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.ms[machine] {
		s.n -= len(r.body)
	}
	delete(s.ms, machine)
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

func prefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
