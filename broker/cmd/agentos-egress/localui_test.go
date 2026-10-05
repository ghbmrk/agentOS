package main

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/png"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"rsc.io/qr"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/localui"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-8

// TestLocalPageClientAgainstVaultProcess holds the local UI's unlock
// client (P2-4e) to the real unlock socket: a passphrase read back from
// its QR code makes the unlock pending with a ticket, a wrong code is
// refused with the tries left and keeps it pending, the right code opens
// the vault, and the vault process's refusals arrive as VaultError with
// their fixed messages.
func TestLocalPageClientAgainstVaultProcess(t *testing.T) {
	dir := t.TempDir()
	vp, kp := filepath.Join(dir, "state", "vault"), filepath.Join(dir, "state", "vault.keys")
	var card bytes.Buffer
	if err := initCmd([]string{"-vault", vp, "-keys", kp}, &card); err != nil {
		t.Fatal(err)
	}
	pass, seed := readCard(t, card.String())
	clk := &clock{t: time.Now()}
	c, err := newCustody(&custody{
		statePath: filepath.Join(dir, "state", "unlock.json"),
		open:      func(p string) (*vault.Vault, error) { return vault.OpenSealed(vp, kp, vault.Passphrase(p)) },
		build:     func(*vault.Vault) (*egress.Proxy, error) { return nil, nil },
		ttl:       15 * time.Minute,
		now:       clk.now,
		notify:    func(string) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.lock()
	run := filepath.Join(dir, "run")
	srvs, err := serve(run, c, testRouter(t), nil, nil, os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, s := range srvs {
			s.Close()
		}
	}()
	ctx := context.Background()
	u := localui.NewUnlockClient(filepath.Join(run, UnlockSocket))

	if st, err := u.Status(ctx); err != nil || st.State != "locked" || st.PIN {
		t.Fatalf("status: %+v %v", st, err)
	}
	var ve *localui.VaultError
	if _, _, err := u.Unlock(ctx, "wrong "+pass); !errors.As(err, &ve) || ve.Status != http.StatusForbidden || ve.Msg != "the passphrase does not open this vault" {
		t.Fatalf("wrong passphrase: %v", err)
	}
	clk.add(MinAttemptGap)

	// The page scans the passphrase from a photo of its QR code.
	code, err := qr.Encode(pass, qr.M)
	if err != nil {
		t.Fatal(err)
	}
	// Eight pixels a module with the four-module quiet zone, as a
	// screenshot of the card would be.
	const mod = 8
	pic := image.NewGray(image.Rect(0, 0, (code.Size+8)*mod, (code.Size+8)*mod))
	for i := range pic.Pix {
		pic.Pix[i] = 0xff
	}
	for y := 0; y < pic.Rect.Dy(); y++ {
		for x := 0; x < pic.Rect.Dx(); x++ {
			if code.Black(x/mod-4, y/mod-4) {
				pic.Pix[y*pic.Stride+x] = 0
			}
		}
	}
	var img bytes.Buffer
	if err := png.Encode(&img, pic); err != nil {
		t.Fatal(err)
	}
	scanned, err := localui.ScanPassphrase(img.Bytes())
	if err != nil || scanned != pass {
		t.Fatalf("scan: %q %v", scanned, err)
	}
	st, ticket, err := u.Unlock(ctx, scanned)
	if err != nil || st.State != "pending" || ticket == "" || st.Expires.IsZero() {
		t.Fatalf("unlock: %+v %q %v", st, ticket, err)
	}
	if _, err := u.Confirm(ctx, "not-the-ticket", totp(seed, clk.now()), false); !errors.As(err, &ve) {
		t.Fatalf("foreign ticket: %v", err)
	}
	if _, err := u.Confirm(ctx, ticket, "000000", false); !errors.As(err, &ve) || ve.Msg != "wrong code; 2 tries left" {
		t.Fatalf("wrong code: %v", err)
	}
	if st, err := u.Status(ctx); err != nil || st.State != "pending" {
		t.Fatalf("after a wrong code: %+v %v", st, err)
	}
	if st, err := u.Confirm(ctx, ticket, totp(seed, clk.now()), false); err != nil || st.State != "open" {
		t.Fatalf("confirm: %+v %v", st, err)
	}
	// Without the TPM slot (P2-4b) the vault process has no PIN unlock.
	if _, err := u.UnlockPIN(ctx, "1234"); !errors.As(err, &ve) {
		t.Fatalf("PIN without a TPM slot: %v", err)
	}
}

// P2-4g (UX lens on #63), against the real vault and unlock socket: the
// old passphrase opens beside a passphrase change that crashed before the
// vault sealed it, and the vault process reports the change unfinished
// while the unlock is pending and once open, until the vault is locked.
func TestUnfinishedPassphraseChangeReported(t *testing.T) {
	dir := t.TempDir()
	vp, kp := filepath.Join(dir, "state", "vault"), filepath.Join(dir, "state", "vault.keys")
	var card bytes.Buffer
	if err := initCmd([]string{"-vault", vp, "-keys", kp}, &card); err != nil {
		t.Fatal(err)
	}
	pass, seed := readCard(t, card.String())
	beforeVault, beforeKeys := readFileT(t, vp), readFileT(t, kp)
	v, err := vault.OpenSealed(vp, kp, vault.Passphrase(pass))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Rekey(vault.Passphrase(pass), vault.Passphrase("violet harbor kettle summit ribbon falcon meadow")); err != nil {
		t.Fatal(err)
	}
	v.Close()
	// The drive as a crash before the seal leaves it.
	after := readFileT(t, kp)
	writeFileT(t, vp, beforeVault)
	writeFileT(t, kp, beforeKeys)
	writeFileT(t, kp+".next", after)

	clk := &clock{t: time.Now()}
	var notes []string
	c, err := newCustody(&custody{
		statePath: filepath.Join(dir, "state", "unlock.json"),
		open:      func(p string) (*vault.Vault, error) { return vault.OpenSealed(vp, kp, vault.Passphrase(p)) },
		build:     func(*vault.Vault) (*egress.Proxy, error) { return nil, nil },
		ttl:       15 * time.Minute,
		now:       clk.now,
		notify:    func(s string) { notes = append(notes, s) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.lock()
	run := filepath.Join(dir, "run")
	srvs, err := serve(run, c, testRouter(t), nil, nil, os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, s := range srvs {
			s.Close()
		}
	}()
	ctx := context.Background()
	u := localui.NewUnlockClient(filepath.Join(run, UnlockSocket))

	st, ticket, err := u.Unlock(ctx, pass)
	if err != nil || !st.ChangeUnfinished {
		t.Fatalf("unlock: %+v %v", st, err)
	}
	if st, err := u.Status(ctx); err != nil || st.State != "pending" || !st.ChangeUnfinished {
		t.Fatalf("pending status: %+v %v", st, err)
	}
	if st, err := u.Confirm(ctx, ticket, totp(seed, clk.now()), false); err != nil || st.State != "open" || !st.ChangeUnfinished {
		t.Fatalf("confirm: %+v %v", st, err)
	}
	// One owner text when the vault opens, since a trusted PC's unlock
	// never reaches the page (P2-4h).
	// It follows the unlock notice (UX-104-1).
	n, follows := 0, false
	for i, s := range notes {
		if s == noteChangeUnfinished {
			n++
			follows = i > 0 && notes[i-1] == "vault unlocked"
		}
	}
	if n != 1 || !follows {
		t.Fatalf("owner notes %q", notes)
	}
	c.lock()
	if st, err := u.Status(ctx); err != nil || st.ChangeUnfinished {
		t.Fatalf("after lock: %+v %v", st, err)
	}
}

func readFileT(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFileT(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
