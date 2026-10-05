package owner

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

// Secrets are the verifiers for the high tier (CH-4). They live only in the
// vault (CRED-8): the broker receives them after the vault opens, so a copy
// of the drive cannot compute codes. The vault package (P1-3) supplies them.
type Secrets struct {
	// TOTPSeed is the code generator's shared secret (RFC 6238, SHA-1,
	// 30-second steps, 6 digits: what iPhone Passwords and Android
	// authenticators use by default).
	TOTPSeed []byte
	// GridSeed derives the paper grid printed on the Owner Card's
	// detachable sheet.
	GridSeed []byte
}

// Verifier checks code-generator codes where the seed is held: the vault
// process (egress K7), so the seed never reaches the broker. It accepts the
// current 30-second step or the one before, never at or before after (the
// channel's last accepted step) nor its own last accepted step, and spends
// a step that matches. counted is false for the silent checks of O5, which
// the vault process bounds apart from the rest, so a flood of them never
// refuses a counted check. An error means no check ran, and the channel
// counts nothing; a *VerifyError says why.
type Verifier interface {
	VerifyTOTP(code string, after int64, counted bool) (step int64, ok bool, err error)
}

// VerifyFailure says why a Verifier could not check a code.
type VerifyFailure int

const (
	// VaultDown: the vault process was not reached; nothing was checked.
	VaultDown VerifyFailure = iota
	// VaultLocked: the vault is not open, so the seed is not readable.
	VaultLocked
	// VerifyPaused: too many wrong codes reached the vault process;
	// checks resume at Until.
	VerifyPaused
	// VerifyLost: the code was sent but no answer came, so it may have
	// been spent.
	VerifyLost
)

// VerifyError is a Verifier's reason for not checking a code.
type VerifyError struct {
	Kind  VerifyFailure
	Until time.Time // VerifyPaused only
}

func (e *VerifyError) Error() string {
	return [...]string{"vault process down", "vault locked", "verify paused", "verify answer lost"}[e.Kind]
}

const (
	totpStep   = 30 // seconds
	codeDigits = 6
)

// hotp is RFC 4226 with SHA-1.
func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	return truncate(m.Sum(nil))
}

// truncate is RFC 4226 dynamic truncation to codeDigits digits.
func truncate(sum []byte) string {
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", codeDigits, bin%1_000_000)
}

// totpAt is the code for Unix time t.
func totpAt(key []byte, t int64) string { return hotp(key, uint64(t/totpStep)) }

// Grid geometry: columns A-J, rows 1-10, so a cell label is at most three
// characters ("J10") and the grid has 100 single-use cells (CH-18).
const (
	gridCols = "ABCDEFGHIJ"
	gridRows = 10
)

// GridLabels lists every cell label in printing order.
func GridLabels() []string {
	var out []string
	for r := 1; r <= gridRows; r++ {
		for _, c := range gridCols {
			out = append(out, fmt.Sprintf("%c%d", c, r))
		}
	}
	return out
}

// GridCell is the 6-digit value printed in cell label. The Owner Card
// generator (P2-2) prints GridCell for every label in GridLabels.
func GridCell(seed []byte, label string) string {
	m := hmac.New(sha256.New, seed)
	m.Write([]byte("agentos-grid-v1:" + label))
	return truncate(m.Sum(nil))
}
