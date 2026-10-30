// Package totp is the code generator's code (RFC 6238 over RFC 4226: SHA-1,
// six digits, 30-second steps), as the owner's phone shows it (CH-4, ONB-6).
// It links nothing of the owner channel, so the root setup step and the
// checker check a code without linking the parsers of the owner's texts.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"time"
)

// Step is a code's lifetime, in seconds.
const Step = 30

// At is the code for t.
func At(seed []byte, t time.Time) string { return hotp(seed, uint64(t.Unix()/Step)) }

// Match checks code as the owner channel does (O6): the current step or the
// one before, never at or before after (the last step spent). It returns
// the step that matched.
func Match(seed []byte, code string, now time.Time, after int64) (int64, bool) {
	if len(seed) == 0 {
		return 0, false
	}
	cur := now.Unix() / Step
	for _, s := range []int64{cur, cur - 1} {
		if s > after && subtle.ConstantTimeCompare([]byte(code), []byte(hotp(seed, uint64(s)))) == 1 {
			return s, true
		}
	}
	return 0, false
}

func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}
