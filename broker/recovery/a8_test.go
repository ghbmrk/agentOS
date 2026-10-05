package recovery

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-1, CRED-8, REC-1
// Acceptance: A8 (plaintext scan), through the A5 canary harness
//
// TestA8CanaryOnTheDrive is the canary target registered in
// assurance/canary-targets.json (A5) for what a drive and its backups hold
// at rest (A8): the harness's canaries go into the vault, the box backs up,
// restores onto a new drive, re-confirms, re-enrolls and rotates, and then
// every byte of both drives and the backup goes to the surface, as anyone
// holding the drive could read it. The harness scans it for the canaries in
// every encoding; this test scans it for the vault data key, the
// code-generator seed, the grid seed, the recovery key and the passphrase,
// which the harness does not know. Run alone, it mints its own canaries.

type plantCanary struct{ Kind, Value string }

func plantCanaries(t *testing.T) ([]plantCanary, bool) {
	path := os.Getenv("CANARY_PLANT")
	if path == "" {
		var cs []plantCanary
		for _, k := range []string{"api_key", "bearer_token", "session_cookie", "password", "totp_seed", "private_key", "recovery_code"} {
			b := make([]byte, 24)
			rand.Read(b)
			v := "cnry-" + k + "-" + hex.EncodeToString(b)
			if k == "totp_seed" {
				v = base32.StdEncoding.EncodeToString(b)
			}
			cs = append(cs, plantCanary{k, v})
		}
		return cs, false
	}
	b, err := os.ReadFile(path)
	must(t, err)
	var plant struct{ Canaries []plantCanary }
	must(t, json.Unmarshal(b, &plant))
	return plant.Canaries, true
}

func TestA8CanaryOnTheDrive(t *testing.T) {
	cs, harness := plantCanaries(t)
	x := newBox(t)
	x.withPassphrase()
	var acked []string
	for _, c := range cs {
		switch c.Kind {
		case "totp_seed":
			// The code generator's seed is stored decoded, as enrollment
			// does; the harness also looks for the decoded bytes.
			seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(strings.ToUpper(c.Value), "="))
			if err != nil {
				seed = []byte(c.Value)
			}
			must(t, x.b.V.Put(SeedName, vault.KindTOTPSeed, seed))
		default:
			must(t, x.b.V.Put("canary-"+c.Kind, c.Kind, []byte(c.Value)))
		}
		h := sha256.Sum256([]byte(c.Value))
		acked = append(acked, hex.EncodeToString(h[:])[:16])
	}
	before := x.card
	bk := x.backup()
	must(t, os.WriteFile(filepath.Join(x.dir, "broker", "backup.agentos"), bk, 0o600))
	nb, dst, err := x.restore(bk, x.rk, t0)
	must(t, err)
	_, err = Reconfirm(nb, Answer{Standing: []Standing{{"G1", "x"}}, Keep: []string{"G1"}}, Auth{Recovery: x.rk}, t0)
	must(t, err)
	_, err = x.rotate([]Part{PartWiFi, PartGrid, PartSetup}, Auth{Code: true, Local: true}, nil)
	must(t, err)
	after, err := x.b.LoadCard()
	must(t, err)

	surface := os.Getenv("CANARY_SURFACE_DIR")
	if surface == "" {
		surface = t.TempDir()
	}
	copyTree(t, x.dir, filepath.Join(surface, "old-drive"))
	copyTree(t, dst, filepath.Join(surface, "new-drive"))
	if harness {
		ack, _ := json.Marshal(map[string][]string{"loaded": acked})
		must(t, os.WriteFile(os.Getenv("CANARY_ACK"), ack, 0o600))
	}

	needles := append(x.needles(before), x.needles(after)...)
	for _, c := range cs {
		needles = append(needles, Needle{Name: "canary " + c.Kind, Value: []byte(c.Value), Text: true})
	}
	s, err := NewScanner(needles)
	must(t, err)
	got, skipped, err := s.Tree(surface)
	must(t, err)
	if len(got) != 0 || len(skipped) != 0 {
		t.Fatalf("plaintext holds secret material: %v (skipped %v)", got, skipped)
	}
}

// copyTree copies every regular file under src to dst.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	n := 0
	must(t, filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		out := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
			return err
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		o, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(o, in)
		if cerr := o.Close(); err == nil {
			err = cerr
		}
		n++
		return err
	}))
	if n == 0 {
		t.Fatalf("nothing to copy from %s", src)
	}
}
