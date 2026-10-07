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
	// perMachine and totalBytes bound what the broker keeps.
	perMachine = 32
	totalBytes = 4 << 20
)

// StandIn is the JSON a guest receives instead of an oversized result.
type StandIn struct {
	Folded bool   `json:"folded"`
	ID     string `json:"id"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
	Head   string `json:"head"`
}

// Store keeps full results per machine. A machine cannot read another's.
// The broker dropping a result, or restarting, makes Read fail; the guest
// can call the tool again.
type Store struct {
	mu    sync.Mutex
	order []rec
	n     int
}

type rec struct {
	machine string
	id      string
	body    string
}

// Hand returns body unchanged when it fits. Otherwise it stores body and
// returns a stand-in. The stand-in is not itself stored.
func (s *Store) Hand(machine, body string) string {
	if s == nil || len(body) <= Max {
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
	s.order = append(s.order, rec{machine: machine, id: id, body: body})
	s.n += len(body)
	s.evict(machine)
	return string(b)
}

// Read returns the original result for machine and id.
func (s *Store) Read(machine, id string) (string, bool) {
	if s == nil || machine == "" || id == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.order {
		if r.machine == machine && r.id == id {
			return r.body, true
		}
	}
	return "", false
}

func (s *Store) evict(machine string) {
	count := map[string]int{}
	for _, r := range s.order {
		count[r.machine]++
	}
	for len(s.order) > 0 && (s.n > totalBytes || count[machine] > perMachine) {
		old := s.order[0]
		s.order = s.order[1:]
		s.n -= len(old.body)
		count[old.machine]--
	}
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
