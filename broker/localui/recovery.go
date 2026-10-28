package localui

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"html/template"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/localapi"
)

// The Recovery key page (REC-4, BAK-1; MIG-4-recovery-r4a, route A of
// D-201): the owner replaces the recovery key on the running box. In
// order: the passphrase scanned or typed here, or the current recovery key
// typed (STO-2: on this page, never by text or voice); the new card,
// shown and confirmed (card.Display, rotating the recovery key alone);
// then a hardware key's tap over the change agentosd names, after which
// agentosd asks the kernel, the keeper and the kernel again. Nothing
// leaves this process before the card's confirm, so an owner who leaves
// before it changes nothing. The new card is made here (agentosd links no
// card code, ARC-2) and its key goes to agentosd as card.StoreRecoveryKey's
// 32 bytes; the factor and that key live only in this process's memory,
// for one pending replacement bound to the session that started it.

// Recovery is the Recovery key page's ops on agentosd (localapi
// RecoveryOps). A refusal is a Refused with one of localapi.RecoveryCodes.
type Recovery interface {
	RecoveryBegin(ctx context.Context, session string, next []byte) (localapi.RecoveryBegun, error)
	RecoveryRotate(ctx context.Context, session, factor string, secret, next, authData, clientData, sig []byte) (localapi.RecoveryDone, error)
}

// recoveryCallFor bounds the rotation call: the keeper stretches a
// passphrase, and the kernel anchors its approval.
const recoveryCallFor = 90 * time.Second

func (a AgentosdPasskeys) RecoveryBegin(ctx context.Context, session string, next []byte) (localapi.RecoveryBegun, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var out localapi.RecoveryBegun
	err := a.Owner.Call(ctx, localapi.OpRecoveryBegin, localapi.RecoveryBegin{Token: session, Next: next}, &out)
	return out, err
}

func (a AgentosdPasskeys) RecoveryRotate(ctx context.Context, session, factor string, secret, next, authData, clientData, sig []byte) (localapi.RecoveryDone, error) {
	ctx, cancel := context.WithTimeout(ctx, recoveryCallFor)
	defer cancel()
	var out localapi.RecoveryDone
	err := a.Owner.Call(ctx, localapi.OpRecoveryRotate, localapi.RecoveryRotate{Token: session, Factor: factor, Secret: secret, Next: next,
		AuthenticatorData: authData, ClientDataJSON: clientData, Signature: sig}, &out)
	return out, err
}

// RecoveryPendingFor is how long a started replacement waits for its
// card's confirm and tap; then it is dropped, and the factor with it.
const RecoveryPendingFor = 15 * time.Minute

// storeRecoveryKey is card.StoreRecoveryKey of a typed, pasted or
// file-read recovery key: CR and LF go first, so a key with a trailing
// newline, or printed one group per line, reads as the card does (the
// #3412 Security finding recorded on #3409; card.Normalize drops only
// space, dash and tab).
func storeRecoveryKey(s string) ([]byte, error) {
	return card.StoreRecoveryKey(strings.NewReplacer("\r", "", "\n", "").Replace(s))
}

// recoveryPending is the one replacement this page holds.
type recoveryPending struct {
	starter string // the starting session's tokenKey
	token   string // that session, for agentosd's checks
	until   time.Time
	factor  string
	secret  []byte
	display *card.Display           // the new card, until confirmed
	next    []byte                  // its 32-byte key, once confirmed
	begun   *localapi.RecoveryBegun // the tap's challenge, once confirmed
}

// recoveryState guards the pending replacement. Its lock is never held
// while a display method runs: the display's provision takes it.
type recoveryState struct {
	mu sync.Mutex
	p  *recoveryPending
}

// take returns the pending replacement of the session tok, dropping one
// past its time.
func (s *Server) recoveryTake(tok string) *recoveryPending {
	s.recovery.mu.Lock()
	p := s.recovery.p
	if p != nil && !s.cfg.Now().Before(p.until) {
		s.recovery.p = nil
		s.recovery.mu.Unlock()
		s.recoveryWipe(p)
		return nil
	}
	s.recovery.mu.Unlock()
	if p == nil || tok == "" || p.starter != tokenKey(tok) {
		return nil
	}
	return p
}

// recoveryDrop drops p if it is still the pending one, and wipes it.
func (s *Server) recoveryDrop(p *recoveryPending) {
	s.recovery.mu.Lock()
	if s.recovery.p == p {
		s.recovery.p = nil
	}
	s.recovery.mu.Unlock()
	s.recoveryWipe(p)
}

// recoveryWipe clears p's factor and key under the lock, then erases its
// card outside it (the display's provision takes the lock).
func (s *Server) recoveryWipe(p *recoveryPending) {
	s.recovery.mu.Lock()
	clear(p.secret)
	clear(p.next)
	d := p.display
	p.display = nil
	s.recovery.mu.Unlock()
	if d != nil {
		d.Discard()
	}
}

// recoveryStart replaces any pending replacement with one for tok's
// session on the factor, and makes its card.
func (s *Server) recoveryStart(tok, factor string, secret []byte) error {
	p := &recoveryPending{starter: tokenKey(tok), token: tok, until: s.cfg.Now().Add(RecoveryPendingFor), factor: factor, secret: secret}
	d, err := card.NewDisplay(card.DisplayConfig{Generate: s.cfg.RecoveryCard, Rotate: &card.Parts{Recovery: true},
		Provision: func(c *card.Card) error { return s.recoveryConfirmed(p, c) },
		Discarded: func() { s.recoveryDiscarded(p) }})
	if err != nil {
		clear(secret)
		return err
	}
	p.display = d
	s.recovery.mu.Lock()
	old := s.recovery.p
	s.recovery.p = p
	s.recovery.mu.Unlock()
	if old != nil {
		s.recoveryWipe(old)
	}
	return nil
}

// recoveryDiscarded is the display's discard (its own cancel button): the
// replacement goes with its card. It runs with the display locked, so it
// only detaches and clears; it never calls back into the display.
func (s *Server) recoveryDiscarded(p *recoveryPending) {
	s.recovery.mu.Lock()
	defer s.recovery.mu.Unlock()
	if s.recovery.p == p {
		s.recovery.p = nil
	}
	clear(p.secret)
	clear(p.next)
	p.display = nil
}

// recoveryConfirmed is the display's provision, once the owner typed back
// a group of the new key: the first step that reaches agentosd, which
// answers the tap's challenge. A refusal keeps the card on the display.
func (s *Server) recoveryConfirmed(p *recoveryPending, c *card.Card) error {
	next, err := storeRecoveryKey(c.RecoveryKey)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	b, err := s.cfg.Recovery.RecoveryBegin(ctx, p.token, next)
	if err != nil {
		clear(next)
		return err
	}
	s.recovery.mu.Lock()
	defer s.recovery.mu.Unlock()
	if s.recovery.p != p {
		clear(next)
		return card.ErrDiscard
	}
	p.next, p.begun, p.display = next, &b, nil
	return nil
}

// recoveryText is the owner's wording for each refusal; none carries a
// value, and anything else reads as agentosd not answering.
func recoveryText(err error) string {
	var r Refused
	errors.As(err, &r)
	switch string(r) {
	case localapi.ErrRecoveryNotAnchor:
		return "That tap was a phone passkey's. Only one of your hardware keys can replace the recovery key. Tap again, and choose your hardware key."
	case localapi.ErrRecoveryBadAssertion:
		return "That tap didn't match. Tap again with one of your hardware keys."
	case localapi.ErrRecoveryFactor:
		return "That passphrase or recovery key doesn't open my store. " + recoveryKeepAll + " If an earlier replacement finished, the newest card is the one that opens it. Then start again."
	case localapi.ErrRecoveryStale:
		return "Something changed since you started: another replacement finished, or too much time passed. " + recoveryKeepAll + " Then start again."
	case localapi.ErrRecoveryBusy:
		return "Another replacement is running. Try again in a minute."
	case localapi.ErrRecoverySetup:
		return "Finish setup first."
	case localapi.ErrLimited:
		return "Too many tries. Wait a minute, then try again."
	case localapi.ErrUnauthorized:
		return "Your sign-in ended. Sign in again, then start again."
	}
	return "I couldn't reach the part of me that keeps your recovery key. Try again in a minute."
}

// recoveryWrongTap is a refusal of the tap itself, which tapping again
// can mend.
func recoveryWrongTap(err error) bool {
	var r Refused
	errors.As(err, &r)
	return string(r) == localapi.ErrRecoveryBadAssertion || string(r) == localapi.ErrRecoveryNotAnchor
}

// The page's fixed lines. Whether a replacement took effect is known only
// when the page says Done: an earlier call whose answer was lost, from
// this phone or another, before or after a restart, may have rewritten the
// store, and nothing on the owner side records that. So no other line
// says what is in effect; each says to keep every card (recoveryKeepAll).
const (
	recoveryKeepAll     = "Keep all your cards until a replacement says Done: only then do I know which one opens my store."
	recoveryDoneText    = "Done. Your new card is in effect: keep it safe, and destroy your older cards, which no longer open my store. I take a backup sealed to the new key within a minute."
	recoveryLaterText   = "Done. Your new card is in effect: keep it safe, and destroy your older cards, which no longer open my store. I finish moving backups to the new key within a few minutes."
	recoveryUnsureText  = "I couldn't tell whether that finished. " + recoveryKeepAll + " Try the tap again."
	recoveryCancelText  = "Cancelled. " + recoveryKeepAll
	recoveryExpiredText = "That replacement took too long and was dropped. " + recoveryKeepAll + " Then start again."
)

// recoveryView is the page in one of its steps: "" the factor, "tap" the
// hardware key's tap over the change shown.
type recoveryView struct {
	RP        string
	Step      string
	Old, Next string
	Challenge string
	Err, Done string
}

// recoveryPage serves /recovery/ behind sign-in, and the new card at
// /recovery/card to the session that started the replacement only.
func (s *Server) recoveryPage(w http.ResponseWriter, r *http.Request) {
	tok := cookieToken(r)
	if r.URL.Path == "/card" {
		p := s.recoveryTake(tok)
		var d *card.Display
		if p != nil {
			s.recovery.mu.Lock()
			d = p.display
			s.recovery.mu.Unlock()
		}
		if d == nil {
			http.Redirect(w, r, "/recovery/", http.StatusSeeOther)
			return
		}
		mine := func(r *http.Request) bool { return s.recoveryTake(cookieToken(r)) == p }
		d.Handler(mine, "/recovery/").ServeHTTP(w, r)
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	v := recoveryView{RP: s.cfg.PasskeyRPID}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.recoveryShow(w, tok, v)
		return
	case http.MethodPost:
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		v.Err = s.recoveryFactor(w, r, tok)
		if v.Err == "" {
			http.Redirect(w, r, "/recovery/card", http.StatusSeeOther)
			return
		}
		s.recoveryShow(w, tok, v)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	p := s.recoveryTake(tok)
	switch r.PostForm.Get("step") {
	case "cancel":
		if p != nil {
			s.recoveryDrop(p)
		}
		v.Done = recoveryCancelText
	case "rotate":
		v.Err, v.Done = s.recoveryRotate(r, tok, p)
	default:
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	s.recoveryShow(w, tok, v)
}

// recoveryShow renders the step the session's pending replacement is at.
func (s *Server) recoveryShow(w http.ResponseWriter, tok string, v recoveryView) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", vaultCSP)
	if p := s.recoveryTake(tok); p != nil {
		s.recovery.mu.Lock()
		b := p.begun
		s.recovery.mu.Unlock()
		if b != nil {
			w.Header().Set("Content-Security-Policy", passkeyCSP)
			v.Step, v.Old, v.Next, v.Challenge = "tap", b.Old, b.Next, base64.StdEncoding.EncodeToString(b.Challenge)
		} else if v.Err == "" && v.Done == "" {
			v.Step = "card"
		}
	}
	s.render(w, "recovery", v)
}

// recoveryFactor reads the factor form, a photo of the passphrase code,
// typed passphrase words or a typed recovery key, and starts the
// replacement; it returns the owner's line on a refusal. The multipart
// body is read part by part into memory, never spooled to a file.
func (s *Server) recoveryFactor(w http.ResponseWriter, r *http.Request, tok string) string {
	select {
	case s.scanning <- struct{}{}:
		defer func() { <-s.scanning }()
	default:
		return scanText(ErrScanBusy)
	}
	http.NewResponseController(w).SetReadDeadline(time.Now().Add(uploadWindow))
	r.Body = http.MaxBytesReader(w, r.Body, MaxPhotoBytes+64<<10)
	mr, err := r.MultipartReader()
	if err != nil {
		return "I could not read that form. Try again."
	}
	var photo []byte
	defer func() { clear(photo) }()
	var words, key string
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "The photo is too large or did not arrive whole. Try again, or type the words."
		}
		switch part.FormName() {
		case "photo":
			clear(photo)
			if photo, err = readPhoto(part); err != nil {
				return "The photo is too large or did not arrive whole. Try again, or type the words."
			}
		case "passphrase", "recovery":
			b, _ := io.ReadAll(io.LimitReader(part, 1<<10))
			if part.FormName() == "passphrase" {
				words = strings.TrimSpace(string(b))
			} else {
				key = strings.TrimSpace(string(b))
			}
			clear(b)
		}
		part.Close()
	}
	var factor string
	var secret []byte
	switch {
	case key != "":
		k, err := storeRecoveryKey(key)
		var m *card.MistypedError
		if errors.As(err, &m) {
			return m.Error()[len("card: "):] + "."
		} else if err != nil {
			return "That isn't a recovery key. Type all eight groups from your card."
		}
		factor, secret = localapi.RecoveryFactorRecovery, k
	default:
		pass := words
		if pass == "" && len(photo) > 0 {
			if pass, err = scanSafe(photo); err != nil {
				return scanText(err)
			}
		}
		if pass = card.NormalizePassphrase(pass); pass == "" {
			return "Take a photo of the passphrase code, or type the passphrase words or your recovery key."
		}
		if len(pass) > localapi.MaxRecoveryPassphrase {
			return "That passphrase is longer than any card's. Check it and try again."
		}
		factor, secret = localapi.RecoveryFactorPassphrase, []byte(pass)
	}
	if err := s.recoveryStart(tok, factor, secret); err != nil {
		return "I couldn't make a new card. Try again."
	}
	return ""
}

// recoveryRotate sends the tap with the factor and the confirmed key; it
// returns the page's error or done line.
func (s *Server) recoveryRotate(r *http.Request, tok string, p *recoveryPending) (errText, done string) {
	if p == nil {
		return recoveryExpiredText, ""
	}
	// Copies, so a cancel or a new start that wipes p meanwhile does not
	// race the call; they are cleared when it returns.
	s.recovery.mu.Lock()
	ready := p.begun != nil
	factor, secret, next := p.factor, bytes.Clone(p.secret), bytes.Clone(p.next)
	s.recovery.mu.Unlock()
	defer func() { clear(secret); clear(next) }()
	if !ready {
		return "Confirm your new card first.", ""
	}
	f := r.PostForm
	ad, ok1 := formBytes(f.Get("ad"), localapi.MaxPasskeyAssertion)
	cd, ok2 := formBytes(f.Get("cd"), localapi.MaxPasskeyAssertion)
	sig, ok3 := formBytes(f.Get("sig"), localapi.MaxPasskeyAssertion)
	if !ok1 || !ok2 || !ok3 {
		return recoveryText(Refused(localapi.ErrRecoveryBadAssertion)), ""
	}
	ctx, cancel := context.WithTimeout(r.Context(), recoveryCallFor)
	defer cancel()
	d, err := s.cfg.Recovery.RecoveryRotate(ctx, tok, factor, secret, next, ad, cd, sig)
	var ref Refused
	switch {
	case err == nil:
		s.recoveryDrop(p)
		if d.Switched {
			return "", recoveryDoneText
		}
		return "", recoveryLaterText
	case recoveryWrongTap(err), refused(err, localapi.ErrRecoveryBusy), refused(err, localapi.ErrLimited):
		// The replacement stays for another tap.
		return recoveryText(err), ""
	case !errors.As(err, &ref) || string(ref) == localapi.ErrRecoveryUnavailable:
		// No answer: the keeper may have written before it was lost; the
		// replacement stays for another tap.
		return recoveryUnsureText, ""
	}
	s.recoveryDrop(p)
	return recoveryText(err), ""
}

func init() {
	template.Must(tmpl.Parse(`{{define "recovery"}}{{template "head" ""}}
<h1>Recovery key</h1>
{{with .Err}}<p class="err">{{.}}</p>{{end}}{{with .Done}}<p class="ok">{{.}}</p>{{end}}
<p class="err" id="pk-msg"></p>
{{if eq .Step "tap"}}
<h2>Tap your hardware key</h2>
<p>Your new card is confirmed but not in effect yet. Your hardware key signs exactly this change of backup key; check it, then tap.</p>
<p>From: <span class="mono">{{if .Old}}{{.Old}}{{else}}none (I have no backup key yet){{end}}</span><br>To: <span class="mono">{{.Next}}</span></p>
<form method="post" action="/recovery/" id="pk-finish" data-rp="{{.RP}}" data-challenge="{{.Challenge}}"><input type="hidden" name="step" value="rotate"><input type="hidden" name="ad"><input type="hidden" name="cd"><input type="hidden" name="sig"></form>
<p><button type="button" id="pk-tap">Tap a hardware key to replace it</button></p>
<form method="post" action="/recovery/"><input type="hidden" name="step" value="cancel"><button class="plain">Cancel</button></form>
<script>{{passkeyjs}}</script>
{{else if eq .Step "card"}}
<p>Your new card is waiting. <a href="/recovery/card">Show it and confirm it</a>.</p>
<form method="post" action="/recovery/"><input type="hidden" name="step" value="cancel"><button class="plain">Cancel</button></form>
{{else}}
<p>Replace your recovery key with a new card. This replacement changes nothing until you have confirmed the new card and tapped one of your hardware keys, and I say Done. Backups made before the change still open with the old key.</p>
<p>First, show me the card that opens my store (if you hold more than one, start with the newest): take a photo of its passphrase code, or type the passphrase words, or type its recovery key.</p>
<form method="post" action="/recovery/" enctype="multipart/form-data">
<label>Photo of the passphrase code<input type="file" name="photo" id="photo" accept="image/*" capture="environment"></label>
<label>Or the passphrase words<input type="password" name="passphrase" autocomplete="off" maxlength="512"></label>
<label>Or your recovery key<textarea name="recovery" rows="2" autocomplete="off" spellcheck="false" maxlength="128"></textarea></label>
<p><button>Continue</button></p></form>
<script>{{shrinkjs}}</script>
{{end}}
{{template "foot"}}{{end}}`))
}
