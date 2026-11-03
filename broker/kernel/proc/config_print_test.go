package proc

// REQ: CLK-1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
)

// A KernelConfig prints as its type alone, never the log key, the head key
// or the link key, in every verb its Format covers (fmt skips it under %w
// and %p, DECOY-b-8) (CLK-1, #4574). Catches a boot error or debug line
// that formats the config and puts the keys in an unsealed log.
func TestKernelConfigPrintsNoKey(t *testing.T) {
	var logKey [32]byte
	for i := range logKey {
		logKey[i] = byte(0xa0 + i)
	}
	head := ed25519.NewKeyFromSeed(logKey[:])
	link := ed25519.NewKeyFromSeed(append(logKey[1:], 7))
	c := KernelConfig{Key: logKey, Pub: head.Public().(ed25519.PublicKey), Sign: head, LinkKey: link}
	if got := fmt.Sprintf("%v %+v", c, &c); got != "proc.KernelConfig proc.KernelConfig" {
		t.Fatalf("a config prints as %q", got)
	}
	for _, v := range []any{c, &c} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%t", "%e", "%c", "%U", "%o", "%b"} {
			out := strings.ToLower(fmt.Sprintf(verb, v))
			for _, s := range [][]byte{logKey[:], head.Seed(), link.Seed()} {
				for _, f := range []string{hex.EncodeToString(s), strings.Trim(fmt.Sprint(s), "[]"), strings.Trim(fmt.Sprintf(verb, s), "[]")} {
					if len(f) >= 10 && strings.Contains(out, strings.ToLower(f)) {
						t.Errorf("%s of %T shows a key", verb, v)
					}
				}
			}
		}
	}
}

// The process kernel and its counter anchor print no private key: not the
// head key, the link key, a held recovery card, the log key or the
// anchor's signing key, in sixteen verbs (%w and %p included), bare and in
// holders with unexported pointer and interface fields (CLK-1, DECOY-b-8,
// #4719). The keys sit behind a pointer to a pointer, which fmt prints as an
// address at any depth; a holder of the same key in a plain field shows it,
// so the check can see one. Catches a debug or error line that formats the
// kernel and puts the head key in an unsealed log.
func TestProcKernelPrintsNoKey(t *testing.T) {
	data := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	var logKey, linkSeed [32]byte
	for i := range logKey {
		logKey[i], linkSeed[i] = byte(0x91+i), byte(0x31+i)
	}
	link := ed25519.NewKeyFromSeed(linkSeed[:])
	ca, _ := testPageCA(t)
	logPath := filepath.Join(data, "log")
	h, err := OpenKernel(KernelConfig{
		Log: logPath, Anchor: anchor(t, logPath), Key: logKey, Pub: headPub, Sign: headPriv, Anchors: anchors, LinkKey: link,
		KeyDir: filepath.Join(data, "keys"), BackupDir: filepath.Join(data, "backups"), Recipient: recipientWire(t, testRK),
		ContentDir: filepath.Join(data, "content"), Stores: []string{"vision"}, PageCA: ca,
	}, 1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	card := bytes.Repeat([]byte{0x6b, 0x4c}, handoff.MadeCardLen/2)
	h.HoldRecoveryCard(bytes.Clone(card))
	if _, err := h.RecoveryCardID(); err != nil {
		t.Fatal(err)
	}
	_, _, signer, a := newAnchor(t)
	secrets := [][]byte{headPriv.Seed(), link.Seed(), logKey[:], card[:handoff.CardKeyLen], signer.Seed()}
	type holder struct {
		k *Kernel
		a *CounterAnchor
		v any
	}
	hd := holder{h, a, h}
	if keyShown(secrets, h, a, hd, &hd) {
		t.Error("the process kernel or its anchor prints a key")
	}
	type plain struct{ k ed25519.PrivateKey }
	if !keyShown(secrets, &holder{v: &plain{headPriv}}) {
		t.Error("no print showed a key in a plain field: the check cannot see one")
	}
}

// keyShown formats each of vs in sixteen verbs and reports whether any
// output holds a secret: raw, as hex, as decimal bytes or in the verb's own
// form of the bytes.
func keyShown(secrets [][]byte, vs ...any) bool {
	shown := false
	for _, v := range vs {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%t", "%e", "%c", "%U", "%o", "%b", "%w", "%p"} {
			out := strings.ToLower(fmt.Sprintf(verb, v))
			for _, s := range secrets {
				for _, f := range []string{string(s), hex.EncodeToString(s), strings.Trim(fmt.Sprint(s), "[]"), strings.Trim(fmt.Sprintf(verb, s), "[]")} {
					shown = shown || len(f) >= 10 && strings.Contains(out, strings.ToLower(f))
				}
			}
		}
	}
	return shown
}
