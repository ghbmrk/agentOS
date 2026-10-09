package recall

import (
	crand "crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math/rand/v2"
	"os"
	"strconv"
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

// canarySeedEnv replays a failing run: set it to the seed a failure logged.
const canarySeedEnv = "RECALL_CANARY_SEED"

// canaryRand returns a generator seeded from canarySeedEnv, or from a fresh
// random seed, and logs the seed if the test fails, so any random failure
// can be replayed exactly.
func canaryRand(t *testing.T) *rand.Rand {
	t.Helper()
	var seed uint64
	if v := os.Getenv(canarySeedEnv); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			t.Fatalf("%s: %v", canarySeedEnv, err)
		}
		seed = n
	} else {
		var b [8]byte
		if _, err := crand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		seed = binary.LittleEndian.Uint64(b[:])
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("canary seed %d (replay with %s=%d)", seed, canarySeedEnv, seed)
		}
	})
	return rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
}

func pick(r *rand.Rand, alphabet string, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(alphabet[r.IntN(len(alphabet))])
	}
	return b.String()
}

func randBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

func mintCanaries(r *rand.Rand) []canary {
	api := pick(r, b62, 40)
	bearer := base64.RawURLEncoding.EncodeToString(randBytes(r, 32))
	cookie := hex.EncodeToString(randBytes(r, 32))
	pw := pick(r, password, 24)
	seed := base32.StdEncoding.EncodeToString(randBytes(r, 20))
	key := base64.StdEncoding.EncodeToString(randBytes(r, 48))
	rc := pick(r, b32, 30)
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
