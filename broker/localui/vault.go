package localui

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Vault is the vault process's unlock socket (cmd/agentos-egress, egress
// K4-K5) as the vault unlock page uses it; UnlockClient is the real one.
type Vault interface {
	Status(ctx context.Context) (VaultStatus, error)
	// Unlock sends the vault passphrase. On success the unlock is pending
	// and the ticket is what Confirm must carry.
	Unlock(ctx context.Context, passphrase string) (VaultStatus, string, error)
	// Confirm sends the code-generator code for a pending unlock.
	// keepTrusted is "Keep this PC trusted" after a changed boot path
	// (VaultStatus.BootChanged, P2-4b).
	Confirm(ctx context.Context, ticket, code string, keepTrusted bool) (VaultStatus, error)
	// UnlockPIN sends the boot PIN of a trusted PC (CRED-8, P2-4b).
	UnlockPIN(ctx context.Context, pin string) (VaultStatus, error)
}

// VaultStatus is the vault process's state: locked, opening, pending or
// open.
type VaultStatus struct {
	State string
	// Expires is when a pending unlock is discarded without its code.
	Expires time.Time
	// PIN reports that this PC is trusted with a boot PIN and waits for
	// it (P2-4b; never set by a vault process without the TPM slot).
	PIN bool
	// BootChanged reports that a trusted PC started a boot path the box
	// never approved, so the TPM slot did not open (P2-4b). Updated and
	// SecureBoot name the likely cause: a box update, or changed Secure
	// Boot settings on the PC.
	BootChanged, Updated, SecureBoot bool
	// KeptTrusted, after Confirm, reports that this PC stays trusted.
	KeptTrusted bool
}

// VaultError is a refusal from the vault process: its HTTP status and its
// fixed message (for example "wrong code; 2 tries left").
type VaultError struct {
	Status int
	Msg    string
}

func (e *VaultError) Error() string { return "vault: " + e.Msg }

// UnlockClient talks to the vault process's unlock socket. Only the local
// UI's uid may connect to it (SO_PEERCRED), so the passphrase never passes
// through agentosd (egress K4).
type UnlockClient struct {
	c *http.Client
}

// NewUnlockClient returns a client for the unlock socket at path.
func NewUnlockClient(path string) *UnlockClient {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	// An unlock runs one Argon2id derivation (about 1 s, K2); allow for a
	// slow box.
	return &UnlockClient{c: &http.Client{Transport: tr, Timeout: 60 * time.Second}}
}

// wireStatus is the socket's state reply.
type wireStatus struct {
	State   string `json:"state"`
	Expires string `json:"expires"`
	Ticket  string `json:"ticket"`
	PIN     bool   `json:"pin"`
	Error   string `json:"error"`

	BootChanged bool `json:"boot_changed"`
	Updated     bool `json:"updated"`
	SecureBoot  bool `json:"secure_boot"`
	KeptTrusted bool `json:"kept_trusted"`
}

func (w wireStatus) status() VaultStatus {
	st := VaultStatus{State: w.State, PIN: w.PIN, BootChanged: w.BootChanged, Updated: w.Updated,
		SecureBoot: w.SecureBoot, KeptTrusted: w.KeptTrusted}
	if t, err := time.Parse(time.RFC3339, w.Expires); err == nil {
		st.Expires = t
	}
	return st
}

func (u *UnlockClient) call(ctx context.Context, method, path string, body any) (wireStatus, error) {
	var out wireStatus
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return out, err
		}
		rd = bytes.NewReader(b)
	}
	// The host is a placeholder; the transport dials the unlock socket.
	to := url.URL{Scheme: "http", Host: "agentos-egress", Path: path}
	req, err := http.NewRequestWithContext(ctx, method, to.String(), rd)
	if err != nil {
		return out, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := u.c.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	derr := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&out)
	if resp.StatusCode != http.StatusOK {
		msg := out.Error
		if derr != nil || msg == "" {
			msg = "the vault process refused the request"
		}
		return out, &VaultError{resp.StatusCode, msg}
	}
	if derr != nil {
		return out, fmt.Errorf("vault: unreadable reply: %w", derr)
	}
	return out, nil
}

// Status implements Vault.
func (u *UnlockClient) Status(ctx context.Context) (VaultStatus, error) {
	w, err := u.call(ctx, http.MethodGet, "/status", nil)
	return w.status(), err
}

// Unlock implements Vault.
func (u *UnlockClient) Unlock(ctx context.Context, passphrase string) (VaultStatus, string, error) {
	w, err := u.call(ctx, http.MethodPost, "/unlock", map[string]string{"passphrase": passphrase})
	if err == nil && w.Ticket == "" {
		err = errors.New("vault: unlock reply carries no ticket")
	}
	return w.status(), w.Ticket, err
}

// Confirm implements Vault.
func (u *UnlockClient) Confirm(ctx context.Context, ticket, code string, keepTrusted bool) (VaultStatus, error) {
	w, err := u.call(ctx, http.MethodPost, "/confirm", map[string]any{"ticket": ticket, "code": code, "keep_trusted": keepTrusted})
	return w.status(), err
}

// UnlockPIN implements Vault.
func (u *UnlockClient) UnlockPIN(ctx context.Context, pin string) (VaultStatus, error) {
	w, err := u.call(ctx, http.MethodPost, "/unlock-pin", map[string]string{"pin": pin})
	return w.status(), err
}

// vaultCookie binds a pending unlock's ticket to the phone that sent the
// passphrase, so another phone on the Wi-Fi can neither answer nor spoil
// it (egress K5).
const vaultCookie = "agentos_vault"

// vaultPending is the one pending unlock this UI started.
type vaultPending struct {
	key    string // SHA-256 of the phone's cookie token
	ticket string
}

type vaultView struct {
	State string
	PIN   bool
	// Boot is the changed-boot-path notice (P2-4b), "" for none.
	Boot string
	// Keep offers "Keep this PC trusted"; KeepOn ticks it.
	Keep, KeepOn bool
	// Kept: the unlock kept this PC trusted.
	Kept    bool
	Mine    bool
	Expires string
	Err     string
	Down    bool
	Refresh string
}

// vaultUnlock serves /unlock/vault: the unknown-host unlock (CRED-8) on
// the box's Wi-Fi, open without sign-in like /unlock (CH-7). The
// passphrase is scanned from a photo of the Owner Card or typed, never
// sent by text or voice (CH-6); the code-generator code follows on the
// same phone. ServeHTTP has already refused cross-site posts.
func (s *Server) vaultUnlock(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.vaultPage(w, r, "")
	case http.MethodPost:
		s.vaultPost(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) vaultPage(w http.ResponseWriter, r *http.Request, errText string) {
	v := vaultView{Err: errText}
	st, err := s.cfg.Vault.Status(r.Context())
	if err != nil {
		v.Down, v.Refresh = true, "5"
		s.render(w, "vault", v)
		return
	}
	v.State, v.PIN = st.State, st.PIN
	if st.BootChanged {
		// Wording and default as ruled in the #42 review: tick "Keep
		// this PC trusted" only when the cause is known to be benign.
		v.Keep, v.KeepOn = true, st.Updated || st.SecureBoot
		switch {
		case st.Updated:
			v.Boot = "Box updated. Unlock once with your passphrase and a code; this PC stays trusted after that."
		case st.SecureBoot:
			v.Boot = "Secure Boot settings on this PC changed. If you updated firmware, unlock with your card to keep this PC trusted."
		default:
			v.Boot = "This PC started the box in a way it hasn't before. If you didn't change anything, the drive may have been tampered with. Unlock only if you're sure."
		}
	}
	s.mu.Lock()
	v.Kept = s.vaultKept && st.State == "open"
	s.mu.Unlock()
	s.mu.Lock()
	if st.State == "pending" {
		v.Mine = s.vaultPend != nil && s.vaultPend.key == vaultKey(r)
	} else {
		s.vaultPend = nil
	}
	s.mu.Unlock()
	if !st.Expires.IsZero() {
		v.Expires = st.Expires.In(s.cfg.Now().Location()).Format("15:04")
	}
	if st.State == "opening" {
		v.Refresh = "2"
	}
	s.render(w, "vault", v)
}

func (s *Server) vaultPost(w http.ResponseWriter, r *http.Request) {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct == "multipart/form-data" {
		s.vaultPassphrase(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	switch r.PostFormValue("step") {
	case "code":
		s.vaultCode(w, r, strings.TrimSpace(r.PostFormValue("code")), r.PostFormValue("keep") == "1")
	case "pin":
		s.vaultPIN(w, r, strings.TrimSpace(r.PostFormValue("pin")))
	default:
		s.vaultPage(w, r, "")
	}
}

// vaultPassphrase reads the passphrase form: a photo of the card's QR
// code, typed words, or both, typed words first. The multipart body is
// read part by part into memory, never spooled to a temporary file, so
// the passphrase never reaches the drive.
func (s *Server) vaultPassphrase(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxPhotoBytes+64<<10)
	mr, err := r.MultipartReader()
	if err != nil {
		s.vaultPage(w, r, "The box could not read that form. Try again.")
		return
	}
	var photo []byte
	var typed string
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			s.vaultPage(w, r, "The photo is too large or did not arrive whole. Try again, or type the words.")
			return
		}
		switch p.FormName() {
		case "photo":
			if photo, err = readPhoto(p); err != nil {
				s.vaultPage(w, r, "The photo is too large or did not arrive whole. Try again, or type the words.")
				return
			}
		case "passphrase":
			b, _ := io.ReadAll(io.LimitReader(p, 1<<10))
			typed = strings.TrimSpace(string(b))
		}
		p.Close()
	}
	pass := typed
	if pass == "" && len(photo) > 0 {
		if pass, err = s.scan(photo); err != nil {
			s.vaultPage(w, r, scanText(err))
			return
		}
	}
	clear(photo)
	if pass == "" {
		s.vaultPage(w, r, "Take a photo of the passphrase code, or type the words.")
		return
	}
	st, ticket, err := s.cfg.Vault.Unlock(r.Context(), pass)
	if err != nil {
		s.vaultPage(w, r, vaultText(err))
		return
	}
	b := make([]byte, 32)
	if _, err := io.ReadFull(s.cfg.Rand, b); err != nil {
		s.vaultPage(w, r, "Something went wrong. Try again.")
		return
	}
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	s.vaultPend = &vaultPending{key: tokenKey(tok), ticket: ticket}
	s.mu.Unlock()
	c := &http.Cookie{Name: vaultCookie, Value: tok, Path: "/unlock/vault", HttpOnly: true, SameSite: http.SameSiteStrictMode}
	if !st.Expires.IsZero() {
		c.Expires = st.Expires
	}
	http.SetCookie(w, c)
	http.Redirect(w, r, "/unlock/vault", http.StatusSeeOther)
}

func (s *Server) vaultCode(w http.ResponseWriter, r *http.Request, code string, keep bool) {
	s.mu.Lock()
	var ticket string
	if p := s.vaultPend; p != nil && p.key == vaultKey(r) {
		ticket = p.ticket
	}
	s.mu.Unlock()
	if ticket == "" {
		s.vaultPage(w, r, "This unlock was started on another phone. Enter the code there.")
		return
	}
	st, err := s.cfg.Vault.Confirm(r.Context(), ticket, code, keep)
	if err != nil {
		// A wrong code keeps the unlock pending (egress K5); any other
		// refusal ended it, and vaultPage forgets the ticket.
		s.vaultPage(w, r, vaultText(err))
		return
	}
	s.mu.Lock()
	s.vaultPend, s.vaultKept = nil, st.KeptTrusted
	s.mu.Unlock()
	http.Redirect(w, r, "/unlock/vault", http.StatusSeeOther)
}

func (s *Server) vaultPIN(w http.ResponseWriter, r *http.Request, pin string) {
	if _, err := s.cfg.Vault.UnlockPIN(r.Context(), pin); err != nil {
		s.vaultPage(w, r, vaultText(err))
		return
	}
	http.Redirect(w, r, "/unlock/vault", http.StatusSeeOther)
}

// scan reads one photo at a time; a second upload meanwhile is refused
// rather than queued, so uploads cannot pile up in memory.
func (s *Server) scan(photo []byte) (string, error) {
	select {
	case s.scanning <- struct{}{}:
		defer func() { <-s.scanning }()
	default:
		return "", ErrScanBusy
	}
	return ScanPassphrase(photo)
}

func vaultKey(r *http.Request) string {
	c, err := r.Cookie(vaultCookie)
	if err != nil || c.Value == "" {
		return "-"
	}
	return tokenKey(c.Value)
}

func scanText(err error) string {
	switch {
	case errors.Is(err, ErrWiFiQR):
		return "That is the Wi-Fi code. Take a photo of the vault passphrase code on your card instead."
	case errors.Is(err, ErrNoQR):
		return "No QR code found in that photo. Hold the card flat in good light, fill most of the photo with the passphrase code, and try again, or type the words."
	case errors.Is(err, ErrManyQR):
		return "That photo holds more than one passphrase-like code. Take a photo of the vault passphrase code alone."
	case errors.Is(err, ErrPhotoSize):
		return "That photo is too large for the box. Take a smaller one, or type the words."
	case errors.Is(err, ErrScanBusy):
		return "The box is reading another photo. Try again in a moment."
	}
	return "The box cannot read that file. Take a photo (JPEG or PNG), or type the words."
}

// vaultText turns a vault process refusal into the page's line. Its
// messages are fixed strings from a trusted process (egress K5-K7); the
// two an owner most often meets get plainer words.
func vaultText(err error) string {
	var ve *VaultError
	if !errors.As(err, &ve) {
		return "The vault is not answering. Wait a moment and try again."
	}
	switch ve.Msg {
	case "the passphrase does not open this vault":
		return "Those words do not open this box. Check them against your card, or take the photo again."
	case "wait a moment before trying again":
		return "Wait a moment, then try again."
	}
	m := strings.TrimSpace(ve.Msg)
	if m == "" {
		return "The vault refused that. Try again."
	}
	r, n := utf8.DecodeRuneInString(m)
	m = string(unicode.ToUpper(r)) + m[n:]
	if !strings.HasSuffix(m, ".") {
		m += "."
	}
	return m
}
