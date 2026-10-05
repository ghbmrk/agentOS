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
	srvs, err := serve(run, c, testRouter(t), os.Getuid(), os.Getuid())
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
	if _, err := u.Confirm(ctx, "not-the-ticket", totp(seed, clk.now())); !errors.As(err, &ve) {
		t.Fatalf("foreign ticket: %v", err)
	}
	if _, err := u.Confirm(ctx, ticket, "000000"); !errors.As(err, &ve) || ve.Msg != "wrong code; 2 tries left" {
		t.Fatalf("wrong code: %v", err)
	}
	if st, err := u.Status(ctx); err != nil || st.State != "pending" {
		t.Fatalf("after a wrong code: %+v %v", st, err)
	}
	if st, err := u.Confirm(ctx, ticket, totp(seed, clk.now())); err != nil || st.State != "open" {
		t.Fatalf("confirm: %+v %v", st, err)
	}
	// Without the TPM slot (P2-4b) the vault process has no PIN unlock.
	if _, err := u.UnlockPIN(ctx, "1234"); !errors.As(err, &ve) {
		t.Fatalf("PIN without a TPM slot: %v", err)
	}
}
