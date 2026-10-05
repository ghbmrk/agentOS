package recovery

import (
	"crypto/hmac"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/vault"
)

// TOTPSeedBytes is the code-generator seed length (160 bits, RFC 4226's
// recommendation for SHA-1), as the vault process's init writes.
const TOTPSeedBytes = 20

// Enrollment is a new code-generator seed for the local page to show as an
// otpauth:// link and QR code (ONB-6), never texted (CH-6).
type Enrollment struct {
	URI string
}

// String keeps the seed out of logs.
func (Enrollment) String() string { return "[code-generator enrollment]" }

// ReEnroll replaces the code-generator seed after a lost phone (REC-3). It
// needs the recovery key, entered on the box's Wi-Fi page (local is that
// page's confirmation), since an owner without the phone has no code to
// give. The seed is replaced in the vault, so the lost phone's codes stop
// working at once; the paper grid is unchanged. The caller ends the owner
// channel's session (EndSession), and the owner confirms enrollment with
// one code from the new seed, as at setup (ONB-3).
func ReEnroll(b *Box, rk RecoveryKey, local bool, r io.Reader) (Enrollment, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !local {
		return Enrollment{}, errors.New("recovery: re-enrollment happens on the box's Wi-Fi page")
	}
	if err := (Auth{Recovery: rk}).check(b); err != nil {
		return Enrollment{}, err
	}
	seed, err := random(r, TOTPSeedBytes)
	if err != nil {
		return Enrollment{}, err
	}
	defer wipe(seed)
	if k, ok := entryKind(b.V, SeedName); ok && k != vault.KindTOTPSeed {
		return Enrollment{}, ErrWrongKind
	}
	if err := b.V.Put(SeedName, vault.KindTOTPSeed, seed); err != nil {
		return Enrollment{}, err
	}
	return Enrollment{URI: otpauth(seed)}, nil
}

func otpauth(seed []byte) string {
	q := url.Values{}
	q.Set("secret", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed))
	q.Set("issuer", "AgentOS")
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/AgentOS:box?" + q.Encode()
}

// PairingTTL bounds a number-change pairing code.
const PairingTTL = 15 * time.Minute

// NumberChange is a pending move of the owner's number (REC-3, lost SIM or
// number). The local page shows Code after the recovery key is entered;
// the owner texts it to the box from the new number, which proves the new
// number the way setup's first text does (§8.1).
type NumberChange struct {
	Code    string
	Expires time.Time

	mu    sync.Mutex
	wrong int
}

// BeginNumberChange checks the recovery key (entered on the local page)
// and returns a pairing code for the owner to text from the new number.
func BeginNumberChange(b *Box, rk RecoveryKey, local bool, now time.Time, r io.Reader) (*NumberChange, error) {
	if !local {
		return nil, errors.New("recovery: a number change starts on the box's Wi-Fi page")
	}
	if err := (Auth{Recovery: rk}).check(b); err != nil {
		return nil, err
	}
	x, err := random(r, 8)
	if err != nil {
		return nil, err
	}
	var n uint64
	for _, c := range x {
		n = n<<8 | uint64(c)
	}
	return &NumberChange{Code: fmt.Sprintf("%08d", n%100_000_000), Expires: now.Add(PairingTTL)}, nil
}

// Texts are what the box sends when the number changes: one to each side.
type Texts struct {
	ToOld, ToNew string
}

// ErrPairing is a pairing text that does not complete the change.
var ErrPairing = errors.New("recovery: not the pairing code, or it expired")

// Complete finishes the change when a text whose whole body is the pairing
// code arrives from a number other than the current owner's, and returns
// the new owner number. Three wrong codes end the attempt (CH-18); only a
// body of eight digits counts as a try, so other texts cannot use them up.
// The new number is announced to the old one, with how to undo it, so an
// owner who did not ask learns of it (REC-3). The caller restarts the
// owner channel on the new number with the session ended (EndSession), so
// the new number must unlock with a code before chat runs.
func (nc *NumberChange) Complete(current, from, text string, now time.Time) (string, Texts, error) {
	if nc == nil {
		return "", Texts{}, ErrPairing
	}
	nc.mu.Lock()
	defer nc.mu.Unlock()
	if now.After(nc.Expires) || nc.wrong >= 3 || from == "" || from == current {
		return "", Texts{}, ErrPairing
	}
	body := trimSpace(text)
	if !eightDigits(body) {
		return "", Texts{}, ErrPairing
	}
	if !hmac.Equal([]byte(body), []byte(nc.Code)) {
		nc.wrong++
		return "", Texts{}, ErrPairing
	}
	nc.Expires = time.Time{}
	return from, Texts{
		ToOld: fmt.Sprintf("AgentOS: the owner number moved to %s with the recovery key. This number can no longer control the box. If you did not do this, enter the recovery key on the box's Wi-Fi page to move it back.", tail(from)),
		ToNew: "AgentOS: this is now the owner number. Text a code from your code generator to unlock. HELP for commands.",
	}, nil
}

func eightDigits(s string) bool {
	if len(s) != 8 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// RestoreNotice is the owner text after a restore (REC-2).
func RestoreNotice(rep Report) string {
	if rep.Source == "drive" {
		return "AgentOS: Box restored from its old drive. Pre-allowances and today's budget are paused until you review them on the box page (one step). Grants you revoked recently may appear there; leave them off."
	}
	d := rep.Created.UTC().Format("2006-01-02")
	return fmt.Sprintf("AgentOS: Box restored from a backup made %s. Pre-allowances and today's budget are paused until you review them on the box page (one step). Grants you revoked after %s appear there; leave them off.", d, d)
}

// EndSession ends the owner channel's session unlock and, after a new
// grid, forgets spent cells of the old one, through the channel's own
// store. The channel is restarted on the new identity afterwards.
func EndSession(st owner.Store, newGrid bool) error {
	s, err := st.Load()
	if err != nil {
		return err
	}
	s.UnlockedUntil = time.Time{}
	if newGrid {
		s.GridUsed = nil
	}
	return st.Save(s)
}

func tail(n string) string {
	if len(n) <= 4 {
		return n
	}
	return "..." + n[len(n)-4:]
}

func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\n' || s[j-1] == '\r' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}
