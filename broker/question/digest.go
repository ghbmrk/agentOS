package question

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"unicode/utf8"
)

var ErrDigestSnapshot = errors.New("question: invalid digest snapshot")
var ErrDigestPersistence = errors.New("question: durable digest requires a state path")

// DigestSnapshot captures an immutable prefix and only the guard counters it
// rendered. Question text within fixed templates remains quoted untrusted data.
// Its private receipt acknowledges source data, never effect/answer authority.
type DigestSnapshot struct {
	Generation    uint64   `json:"generation"`
	Hash          string   `json:"hash"`
	Lines         []string `json:"lines"`
	Prefix        []string `json:"prefix,omitempty"`
	Refused       int      `json:"refused,omitempty"`
	More          int      `json:"more,omitempty"`
	NotAskedLines int      `json:"not_asked_lines,omitempty"`
}
type digestState struct {
	Schema  int             `json:"schema"`
	Key     []byte          `json:"key"`
	Seq     uint64          `json:"seq"`
	Acked   uint64          `json:"acked"`
	Pending *DigestSnapshot `json:"pending,omitempty"`
}

func digestClone[T any](v T) T {
	raw, _ := json.Marshal(v)
	var out T
	_ = json.Unmarshal(raw, &out)
	return out
}
func (b *Book) digestReceipt(s DigestSnapshot) string {
	s.Hash = ""
	raw, _ := json.Marshal(s)
	h := hmac.New(sha256.New, b.digestSource.Key)
	_, _ = h.Write([]byte("agentos/question/digest/v1\x00"))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func (b *Book) validDigest(s DigestSnapshot) bool {
	if len(b.digestSource.Key) != 32 || s.Generation == 0 || len(s.Lines) == 0 || len(s.Lines) > 64 || len(s.Prefix) > 64 || len(s.Prefix) > len(s.Lines) || s.Refused < 0 || s.More < 0 || s.NotAskedLines < 0 {
		return false
	}
	total := 0
	for _, line := range s.Lines {
		if line == "" || len(line) > 4096 || !utf8.ValidString(line) {
			return false
		}
		total += len(line)
	}
	if total > 64<<10 {
		return false
	}
	for i, line := range s.Prefix {
		if line != s.Lines[i] {
			return false
		}
	}
	expected := b.digestReceipt(s)
	return len(s.Hash) == 64 && hmac.Equal([]byte(expected), []byte(s.Hash))
}
func (b *Book) checkDigestSource() error {
	st := b.digestSource
	if st.Schema == 0 && len(st.Key) == 0 && st.Seq == 0 && st.Acked == 0 && st.Pending == nil {
		return nil
	}
	if st.Schema != 1 || len(st.Key) != 32 || st.Acked > st.Seq || b.refused < 0 || b.notAskedLines < 0 || b.notAskedMore < 0 {
		return ErrDigestSnapshot
	}
	if st.Pending != nil && (!b.validDigest(*st.Pending) || st.Pending.Generation != st.Seq || st.Pending.Generation <= st.Acked) {
		return ErrDigestSnapshot
	}
	return nil
}
func (b *Book) digestDiskState() *digestState {
	if b.digestSource.Schema == 0 {
		return nil
	}
	st := b.digestSource
	return &st
}
func (b *Book) digestFail(err error) error {
	b.digestBroken = fmt.Errorf("question: digest storage outcome uncertain; reopen required: %w", err)
	return b.digestBroken
}
func renderDigest(prefix []string, refused, more int) []string {
	out := slices.Clone(prefix)
	if refused > 0 {
		n := fmt.Sprintf("%d answers", refused)
		if refused == 1 {
			n = "1 answer"
		}
		out = append(out, n+" to the agent's questions held a code or key and were not passed on. If that was not you, reply STOP.")
	}
	if more > 0 {
		out = append(out, fmt.Sprintf("Not asked: %d more of the agent's questions were held (texts paced or quiet hours), so the agent went ahead without asking.", more))
	}
	return out
}

// PeekDigest opts a persisted Book into nonconsuming snapshot delivery. Sources
// without Config.Path cannot claim durable generations and are refused.
func (b *Book) PeekDigest() (*DigestSnapshot, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cfg.Path == "" {
		return nil, ErrDigestPersistence
	}
	if b.digestBroken != nil {
		return nil, b.digestBroken
	}
	if err := b.checkDigestSource(); err != nil {
		return nil, err
	}
	if pending := b.digestSource.Pending; pending != nil {
		if err := b.persist(); err != nil {
			return nil, b.digestFail(err)
		}
		s := digestClone(*pending)
		return &s, nil
	}
	if len(b.digest) == 0 && b.refused == 0 && b.notAskedMore == 0 {
		return nil, nil
	}
	if b.digestSource.Seq == math.MaxUint64 {
		return nil, ErrDigestSnapshot
	}
	s := DigestSnapshot{Generation: b.digestSource.Seq + 1}
	total := 0
	add := func(line string) bool {
		if len(s.Lines) >= 64 || total+len(line) > 64<<10 {
			return false
		}
		s.Lines = append(s.Lines, line)
		total += len(line)
		return true
	}
	for _, line := range b.digest {
		if line == "" || len(line) > 4096 || !utf8.ValidString(line) {
			return nil, ErrDigestSnapshot
		}
		if !add(line) {
			break
		}
		s.Prefix = append(s.Prefix, line)
		if strings.HasPrefix(line, "Not asked:") {
			s.NotAskedLines++
		}
	}
	for _, line := range renderDigest(nil, b.refused, 0) {
		if add(line) {
			s.Refused = b.refused
		}
	}
	for _, line := range renderDigest(nil, 0, b.notAskedMore) {
		if add(line) {
			s.More = b.notAskedMore
		}
	}
	if len(s.Lines) == 0 || s.NotAskedLines > b.notAskedLines {
		return nil, ErrDigestSnapshot
	}
	previous := digestClone(b.digestSource)
	if len(b.digestSource.Key) == 0 {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		b.digestSource.Key = key
		b.digestSource.Schema = 1
	}
	s.Hash = b.digestReceipt(s)
	b.digestSource.Seq = s.Generation
	b.digestSource.Pending = &s
	if err := b.persist(); err != nil {
		b.digestSource = previous
		return nil, b.digestFail(err)
	}
	out := digestClone(s)
	return &out, nil
}

// AckDigest follows durable queue admission. Only captured prefix/counters are
// consumed. Any failed save restores pending state and requires reopen.
func (b *Book) AckDigest(s DigestSnapshot) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cfg.Path == "" {
		return ErrDigestPersistence
	}
	if b.digestBroken != nil {
		return b.digestBroken
	}
	if err := b.checkDigestSource(); err != nil {
		return err
	}
	if !b.validDigest(s) || s.Generation > b.digestSource.Seq {
		return ErrDigestSnapshot
	}
	if s.Generation <= b.digestSource.Acked {
		if err := b.persist(); err != nil {
			return b.digestFail(err)
		}
		return nil
	}
	if b.digestSource.Pending == nil || b.digestSource.Pending.Hash != s.Hash || len(b.digest) < len(s.Prefix) || !slices.Equal(b.digest[:len(s.Prefix)], s.Prefix) || b.refused < s.Refused || b.notAskedMore < s.More || b.notAskedLines < s.NotAskedLines {
		return ErrDigestSnapshot
	}
	before := digestClone(b.digestSource)
	digest, refused, more, lines := b.digest, b.refused, b.notAskedMore, b.notAskedLines
	b.digest = slices.Clone(b.digest[len(s.Prefix):])
	b.refused -= s.Refused
	b.notAskedMore -= s.More
	b.notAskedLines -= s.NotAskedLines
	b.digestSource.Acked = s.Generation
	b.digestSource.Pending = nil
	if err := b.persist(); err != nil {
		b.digestSource = before
		b.digest, b.refused, b.notAskedMore, b.notAskedLines = digest, refused, more, lines
		return b.digestFail(err)
	}
	return nil
}
