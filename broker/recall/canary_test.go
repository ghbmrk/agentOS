package recall

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// Synthetic canaries shaped like tools/canary.py's kinds. Never real values.

const (
	b62      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b32      = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	password = b62 + "!#$%&*+=?@^_~"
)

type canary struct{ kind, value, core string }

func pick(t *testing.T, alphabet string, n int) string {
	t.Helper()
	var b strings.Builder
	for i := 0; i < n; i++ {
		k, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			t.Fatal(err)
		}
		b.WriteByte(alphabet[k.Int64()])
	}
	return b.String()
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func mintCanaries(t *testing.T) []canary {
	t.Helper()
	api := pick(t, b62, 40)
	bearer := base64.RawURLEncoding.EncodeToString(randBytes(t, 32))
	cookie := hex.EncodeToString(randBytes(t, 32))
	pw := pick(t, password, 24)
	seed := base32.StdEncoding.EncodeToString(randBytes(t, 20))
	key := base64.StdEncoding.EncodeToString(randBytes(t, 48))
	rc := pick(t, b32, 30)
	var groups []string
	for i := 0; i < 30; i += 5 {
		groups = append(groups, rc[i:i+5])
	}
	return []canary{
		{"api_key", "sk-" + api, api},
		{"bearer_token", bearer, bearer},
		{"session_cookie", cookie, cookie},
		{"password", pw, pw},
		{"totp_seed", seed, seed},
		{"private_key", "-----BEGIN PRIVATE KEY-----\n" + key + "\n-----END PRIVATE KEY-----", key},
		{"recovery_code", strings.Join(groups, "-"), rc},
	}
}

// leaked reports any canary whose core has a 15-character fragment in data
// (the canary harness's window), raw or with dashes stripped.
func leaked(cs []canary, data string) []string {
	flat := strings.ReplaceAll(data, "-", "")
	var out []string
	for _, c := range cs {
		for i := 0; i+15 <= len(c.core); i++ {
			frag := c.core[i : i+15]
			if strings.Contains(data, frag) || strings.Contains(flat, frag) {
				out = append(out, c.kind)
				break
			}
		}
	}
	return out
}
