// Package card generates and prints the Owner Card (SPEC §3.1, PLAN P2-2):
// the box's Wi-Fi name and password with a QR code that joins it, the setup
// secret and its short setup code, the vault passphrase with its QR code,
// and two detachable sheets, the paper approval-code grid (CH-4) and the
// recovery key (REC-1). The card is also the manual (ONB-7).
//
// Generation and printing need nothing outside this package: no network, no
// service (ONB-1, DEP-2). Provisioning the drive from a card (vault slots,
// the grid seed inside the vault) belongs to the vault and recovery
// packages; this package only produces the values.
package card

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// Alphabet for every typed card value: 32 symbols (5 bits each), with no
// I, O, 0 or 1, so nothing is misread from paper.
const Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// Sizes. Bits are 5 per Alphabet symbol.
const (
	// PassphraseWords from the 7,776-word list: 90 bits, above §3.1's 80.
	PassphraseWords = 7
	// wifiSymbols: 80 bits. With WPA3-SAE an offline guess is not
	// possible; 80 bits also holds under the WPA2 opt-in (CH-7), whose
	// handshake can be attacked offline.
	wifiSymbols = 16
	// setupSymbols: 130 bits.
	setupSymbols = 26
	// setupCodeSymbols: 40 bits, guessable only online through the box's
	// rate-limited pairing (localui).
	setupCodeSymbols = 8
	// recoverySymbols: 160 bits.
	recoverySymbols = 32
	gridSeedBytes   = 32
	nameSymbols     = 4
)

// Card holds one Owner Card's values. Everything but GridSeed is printed;
// the grid is printed as its cells (owner.GridCell).
type Card struct {
	// WiFiName is the box's access point name (CH-7). Not secret.
	WiFiName        string
	WiFiPassword    string
	SetupSecret     string
	SetupCode       string
	VaultPassphrase string
	GridSeed        []byte
	RecoveryKey     string
}

// Generate makes a new card from r, which must be a cryptographic source in
// production (crypto/rand.Reader).
func Generate(r io.Reader) (*Card, error) {
	sym := func(n int) (string, error) { return symbols(r, n) }
	name, err := sym(nameSymbols)
	if err != nil {
		return nil, err
	}
	wifi, err := sym(wifiSymbols)
	if err != nil {
		return nil, err
	}
	setup, err := sym(setupSymbols)
	if err != nil {
		return nil, err
	}
	rec, err := sym(recoverySymbols)
	if err != nil {
		return nil, err
	}
	pass, err := passphrase(r)
	if err != nil {
		return nil, err
	}
	seed := make([]byte, gridSeedBytes)
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, err
	}
	c := &Card{
		WiFiName:        "AgentOS-" + name,
		WiFiPassword:    group(wifi, 4),
		SetupSecret:     group(setup, 4),
		VaultPassphrase: pass,
		GridSeed:        seed,
		RecoveryKey:     group(rec, 4),
	}
	c.SetupCode = SetupCodeFor(c.SetupSecret)
	return c, c.Validate()
}

// Validate checks that every value has its full size.
func (c *Card) Validate() error {
	check := func(name, v string, n int) error {
		s := Normalize(v)
		if len(s) != n {
			return fmt.Errorf("card: %s has %d symbols, want %d", name, len(s), n)
		}
		for _, ch := range s {
			if !strings.ContainsRune(Alphabet, ch) {
				return fmt.Errorf("card: %s has a symbol outside the alphabet", name)
			}
		}
		return nil
	}
	if !strings.HasPrefix(c.WiFiName, "AgentOS-") {
		return errors.New("card: Wi-Fi name")
	}
	for _, e := range []error{
		check("Wi-Fi password", c.WiFiPassword, wifiSymbols),
		check("setup secret", c.SetupSecret, setupSymbols),
		check("recovery key", c.RecoveryKey, recoverySymbols),
	} {
		if e != nil {
			return e
		}
	}
	if c.SetupCode != SetupCodeFor(c.SetupSecret) {
		return errors.New("card: setup code does not match the setup secret")
	}
	ws := strings.Fields(c.VaultPassphrase)
	if len(ws) != PassphraseWords {
		return fmt.Errorf("card: passphrase has %d words, want %d", len(ws), PassphraseWords)
	}
	for _, w := range ws {
		if _, ok := wordIndex[w]; !ok {
			return fmt.Errorf("card: passphrase word %q is not on the list", w)
		}
	}
	if len(c.GridSeed) < gridSeedBytes {
		return errors.New("card: grid seed too short")
	}
	return nil
}

// SetupCodeFor derives the short setup code from the setup secret. It is
// not derived from the vault passphrase and never unlocks anything (CRED-8);
// it only pairs the owner's number during setup (§8.1, ONB-6).
func SetupCodeFor(secret string) string {
	m := hmac.New(sha256.New, []byte(Normalize(secret)))
	m.Write([]byte("agentos setup code v1"))
	sum := m.Sum(nil)
	var b strings.Builder
	for i := 0; i < setupCodeSymbols; i++ {
		b.WriteByte(Alphabet[sum[i]&31])
	}
	return group(b.String(), 4)
}

// CheckSetupCode reports whether typed is the setup code for secret,
// ignoring case, spaces and dashes.
func CheckSetupCode(secret, typed string) bool {
	want := Normalize(SetupCodeFor(secret))
	return subtle.ConstantTimeCompare([]byte(want), []byte(Normalize(typed))) == 1
}

// Normalize upper-cases a typed card value and drops spaces and dashes.
func Normalize(s string) string {
	s = strings.ToUpper(s)
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '\t' {
			return -1
		}
		return r
	}, s)
}

// NormalizePassphrase is the canonical form of a typed or scanned vault
// passphrase: lower case, single spaces. The vault's passphrase slot (P2-4)
// derives its key from this form.
func NormalizePassphrase(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

func symbols(r io.Reader, n int) (string, error) {
	b := make([]byte, n)
	for i := range b {
		k, err := uniform(r, len(Alphabet))
		if err != nil {
			return "", err
		}
		b[i] = Alphabet[k]
	}
	return string(b), nil
}

func passphrase(r io.Reader) (string, error) {
	ws := make([]string, PassphraseWords)
	for i := range ws {
		k, err := uniform(r, len(words))
		if err != nil {
			return "", err
		}
		ws[i] = words[k]
	}
	return strings.Join(ws, " "), nil
}

// uniform draws an unbiased integer in [0, n).
func uniform(r io.Reader, n int) (int, error) {
	k, err := crand.Int(r, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("card: randomness: %w", err)
	}
	return int(k.Int64()), nil
}

func group(s string, n int) string {
	var parts []string
	for len(s) > n {
		parts = append(parts, s[:n])
		s = s[n:]
	}
	return strings.Join(append(parts, s), "-")
}

// WiFiQR is the standard Wi-Fi joining payload phone cameras read. T:WPA
// covers WPA2 and WPA3 networks on current iOS and Android.
func WiFiQR(ssid, password string) string {
	esc := strings.NewReplacer(`\`, `\\`, `;`, `\;`, `,`, `\,`, `:`, `\:`, `"`, `\"`)
	return "WIFI:T:WPA;S:" + esc.Replace(ssid) + ";P:" + esc.Replace(password) + ";;"
}
