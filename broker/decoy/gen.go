package decoy

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"io"
	"strings"
)

// The generators of the kinds the box makes itself. Each follows the kind's
// published format, checksum included, and draws every free character from
// r, so a decoy differs from a real value only in which issuer would accept
// it. Each value names its source format.

const (
	base62  = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	b32     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b64     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b64url  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	awsHigh = "QRSTUVWXYZ234567" // b32 symbols with the top bit set
)

// uniform returns an index below n, uniform, by rejection sampling over one
// byte when n fits one and two bytes otherwise, so the accepted range is never
// empty. n above 1<<16 is refused.
func uniform(r io.Reader, n int) (int, error) {
	if n <= 0 || n > 1<<16 {
		return 0, ErrTooMany
	}
	width := 1
	if n > 256 {
		width = 2
	}
	space := 1 << (8 * width)
	limit := space - space%n
	var buf [2]byte
	for {
		if _, err := io.ReadFull(r, buf[:width]); err != nil {
			return 0, err
		}
		v := int(buf[0])
		if width == 2 {
			v = v<<8 | int(buf[1])
		}
		if v < limit {
			return v % n, nil
		}
	}
}

// draw returns n symbols of alphabet, each uniform.
func draw(r io.Reader, alphabet string, n int) (string, error) {
	out := make([]byte, 0, n)
	for len(out) < n {
		i, err := uniform(r, len(alphabet))
		if err != nil {
			return "", err
		}
		out = append(out, alphabet[i])
	}
	return string(out), nil
}

// gitHub: a classic personal access token as GitHub published it (2021):
// "ghp_", 30 base62 characters, then the CRC32 of those 30 in base62, six
// characters, zero-padded.
func gitHub(r io.Reader) (string, error) {
	body, err := draw(r, base62, 30)
	if err != nil {
		return "", err
	}
	return "ghp_" + body + base62Pad(uint64(crc32.ChecksumIEEE([]byte(body))), 6), nil
}

func base62Pad(v uint64, n int) string {
	out := make([]byte, n)
	for i := n - 1; i >= 0; i-- {
		out[i] = base62[v%62]
		v /= 62
	}
	return string(out)
}

// awsKeyID: an AWS access key ID, "AKIA" and 16 base32 symbols. The first
// symbol carries the top bit of the encoded account, which is set in every
// key AWS issues today, so it is drawn from the upper half.
func awsKeyID(r io.Reader) (string, error) {
	first, err := draw(r, awsHigh, 1)
	if err != nil {
		return "", err
	}
	rest, err := draw(r, b32, 15)
	return "AKIA" + first + rest, err
}

// awsSecret: an AWS secret access key, 40 base64 symbols.
func awsSecret(r io.Reader) (string, error) { return draw(r, b64, 40) }

// anthropic: an Anthropic API key, "sk-ant-api03-", 93 base64url symbols and
// "AA".
func anthropic(r io.Reader) (string, error) {
	body, err := draw(r, b64url, 93)
	return "sk-ant-api03-" + body + "AA", err
}

// openAI: an OpenAI project key, "sk-proj-", 74 base64url symbols, the
// marker "T3BlbkFJ" (base64 of "OpenAI") and 74 more.
func openAI(r io.Reader) (string, error) {
	a, err := draw(r, b64url, 74)
	if err != nil {
		return "", err
	}
	b, err := draw(r, b64url, 74)
	return "sk-proj-" + a + "T3BlbkFJ" + b, err
}

// recoveryCode: one account recovery code as GitHub prints them, five and
// five lower-case hex digits.
func recoveryCode(r io.Reader) (string, error) {
	var b [5]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", err
	}
	h := hex.EncodeToString(b[:])
	return h[:5] + "-" + h[5:], nil
}

// sshKey: an unencrypted OpenSSH ed25519 private key with an empty comment,
// in OpenSSH's own container (PROTOCOL.key) and PEM wrapping, as ssh-keygen
// writes it: lines of 70 base64 characters.
func sshKey(r io.Reader) (string, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(r, seed); err != nil {
		return "", err
	}
	var check [4]byte
	if _, err := io.ReadFull(r, check[:]); err != nil {
		return "", err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	str := func(b []byte, s []byte) []byte {
		return append(binary.BigEndian.AppendUint32(b, uint32(len(s))), s...)
	}
	pubBlob := str(str(nil, []byte("ssh-ed25519")), pub)
	sec := append(append([]byte(nil), check[:]...), check[:]...)
	sec = str(sec, []byte("ssh-ed25519"))
	sec = str(sec, pub)
	sec = str(sec, priv)
	sec = str(sec, nil) // comment
	for i := byte(1); len(sec)%8 != 0; i++ {
		sec = append(sec, i)
	}
	b := []byte("openssh-key-v1\x00")
	b = str(b, []byte("none"))
	b = str(b, []byte("none"))
	b = str(b, nil)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = str(b, pubBlob)
	b = str(b, sec)
	enc := base64.StdEncoding.EncodeToString(b)
	var s strings.Builder
	s.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	for len(enc) > 70 {
		s.WriteString(enc[:70] + "\n")
		enc = enc[70:]
	}
	s.WriteString(enc + "\n-----END OPENSSH PRIVATE KEY-----\n")
	return s.String(), nil
}
