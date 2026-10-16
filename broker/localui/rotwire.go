package localui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
)

// Owner Card rotation wired to the vault process (REC-4,
// CTRL-card-rot-wire). The box page starts a rotation in the vault process
// with the owner's proof; the vault process holds the recovery Pending
// while this page shows the new parts (card.Display in rotation mode); the
// owner's confirm commits exactly the shown parts there. ARC-2: agentosd
// links no card code, so the display lives here, in agentos-localui.
//
// #1090 security review: (R1) Provision maps the vault process's commit
// refusals onto the display's outcomes: 410 (lapsed or dropped; nothing
// changed) is card.ErrDiscard, 409 (a slot was rewritten but the card not
// stored) is card.ErrInEffect, anything else keeps the card for a retry.
// (R2, CRED-1) the display's discard (the page's cancel, a replacing start,
// a lapse) cancels the vault process's Pending, which also lapses by its
// own timer at recovery.PendingTTL.
//
// #1175 security review S-R1: every rotation carries a random ID that
// Start draws and the vault process echoes; commit and cancel carry it,
// and the vault process answers 410 to one naming another rotation, so a
// late commit cannot land under a newer rotation and a stale display's
// discard cannot drop a newer one. The page draws the ID (not the vault
// process) so that a begin that got no answer can still be cancelled by
// it. #1175 UX review U-R1: while a replaced code generator is not yet
// confirmed, the start page offers to show it again with the recovery key.
//
// #1316: the committed result can carry the new code generator's seed, so
// it is the confirming session's alone (bound to a hash of its token), it
// expires with the rotation's confirm window, and the enroll and show
// pages clear it, as does Start; a commit answered after any of these
// stores none.

// RotationVault is the vault process's rotation ops on the unlock socket;
// UnlockClient is the real one.
type RotationVault interface {
	BeginRotation(ctx context.Context, b RotationBegin) (RotationStarted, error)
	CommitRotation(ctx context.Context, id string, c card.Card) (RotationResult, error)
	CancelRotation(ctx context.Context, id string) error
	ConfirmEnrollment(ctx context.Context, code string) (bool, error)
	ShowEnrollment(ctx context.Context, recoveryKey string) (string, error)
	// EnrollmentPending reports a replaced code generator whose first
	// code has not been typed yet.
	EnrollmentPending(ctx context.Context) (bool, error)
}

// RotationBegin is the owner's request: the parts to replace and the
// proof. Code is a code from the owner's code generator; Recovery, the
// current recovery key, replaces it. Passphrase is the current vault
// passphrase, needed to replace the passphrase or the recovery key. PIN
// is this PC's boot PIN, for a recovery key rotation on a PC trusted with
// one. ID names the rotation (S-R1); Start draws it.
type RotationBegin struct {
	ID, Code, Recovery, Passphrase, PIN string
	Parts                               card.Parts
}

// newRotationID is a fresh rotation ID: 32 hex digits from crypto/rand.
func newRotationID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RotationStarted is the vault process's held rotation.
type RotationStarted struct {
	Parts    card.Parts
	WiFiName string
	// Lost: the rotation replaces a lost card (every part).
	Lost    bool
	Expires time.Time
}

// RotationResult is a committed rotation: notes for the owner, how many
// PCs must be trusted again, and the new code generator's enrollment
// (an otpauth URI) when the setup secret was replaced.
type RotationResult struct {
	Notes      []string
	Retrust    int
	Enrollment string
}

// commitTimeout bounds one commit: a recovery key rotation re-encrypts
// the vault's data.
const commitTimeout = 2 * time.Minute

// resultTTL bounds a committed result when the vault process gave no
// confirm window; it is recovery.PendingTTL.
const resultTTL = 30 * time.Minute

// Rotation is the box's card rotation (RotationCard) over the vault
// process. Lock order: a display's lock before mu; mu is never held while
// calling into a display.
type Rotation struct {
	// Generate makes the new card; card.Generate when nil (tests wrap it).
	Generate func(io.Reader) (*card.Card, error)
	// Journal records the display's fixed events; optional.
	Journal func(event string)
	// Now is the clock; time.Now when nil.
	Now func() time.Time

	v       RotationVault
	startMu sync.Mutex // serializes Start
	// postMu serializes the display's posts, so that provision, which runs
	// within one, knows its confirmer. Lock order: postMu, then the
	// display's lock, then mu.
	postMu    sync.Mutex
	confirmer string // under postMu: the posting session's tokenKey
	// wifi, under postMu and mu, has agentosd put a committed Wi-Fi
	// password on the air with the posting session's token (#1191); the
	// network comes from the vault process, not the page (#1522).
	wifi func() error
	mu   sync.Mutex
	d    *card.Display
	// until is the waiting rotation's confirm window.
	until time.Time
	// gen counts what voids a commit's result: a start, an enroll or a
	// show. A commit stores its result only if gen held across it.
	gen uint64
	// res is the last commit's result, shown once on the done page to
	// resOwner (a tokenKey) until resUntil.
	res      *RotationResult
	resOwner string
	resUntil time.Time
}

// NewRotation returns the box's card rotation over v.
func NewRotation(v RotationVault) *Rotation { return &Rotation{v: v} }

func (r *Rotation) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Display implements RotationCard.
func (r *Rotation) Display() *card.Display {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.d
}

// Start discards any waiting rotation (cancelling it in the vault
// process), begins a new one there and makes its display.
func (r *Rotation) Start(ctx context.Context, b RotationBegin) error {
	r.startMu.Lock()
	defer r.startMu.Unlock()
	r.mu.Lock()
	old := r.d
	r.d = nil
	r.voidLocked()
	r.mu.Unlock()
	if old != nil {
		// A card in effect cannot be cancelled; the vault process has
		// already dropped its rotation then.
		_ = old.Discard()
	}
	id, err := newRotationID()
	if err != nil {
		return err
	}
	b.ID = id
	st, err := r.v.BeginRotation(ctx, b)
	var ve *VaultError
	switch {
	case err == nil:
	case errors.As(err, &ve) && ve.Status < http.StatusInternalServerError:
		return err // refused: the vault process holds nothing for id
	default:
		// No answer, or a failure in the vault process: it may hold a
		// rotation for id, or begin it later. Cancel it by its ID; the
		// vault process refuses a begin it already saw cancelled (S-R1).
		r.cancel(id)
		return err
	}
	until := st.Expires
	if max := r.now().Add(resultTTL); until.IsZero() || until.After(max) {
		until = max
	}
	parts := st.Parts
	d, err := card.NewDisplay(card.DisplayConfig{Generate: r.Generate, Journal: r.Journal, Rotate: &parts,
		WiFiName:  st.WiFiName,
		Provision: func(c *card.Card) error { return r.provision(id, c) },
		Discarded: func() { r.cancel(id) }})
	if err != nil {
		r.cancel(id)
		return err
	}
	r.mu.Lock()
	r.d, r.until = d, until
	r.mu.Unlock()
	return nil
}

// provision is the display's provisioner: it commits the shown parts in
// the vault process (#1090 R1) under the display's rotation ID (S-R1). It
// runs with the display locked, and within serveCard's post with postMu
// held; otherwise it has no confirmer and its result shows to none.
func (r *Rotation) provision(id string, c *card.Card) error {
	r.mu.Lock()
	gen := r.gen
	r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), commitTimeout)
	defer cancel()
	res, err := r.v.CommitRotation(ctx, id, *c)
	r.mu.Lock()
	wifi := r.wifi
	r.mu.Unlock()
	var ve *VaultError
	switch {
	case err == nil:
		if c.WiFiPassword != "" {
			res = withWiFiNote(res, handOffWiFi(wifi, c))
		}
		r.mu.Lock()
		if r.gen == gen && r.confirmer != "" {
			r.res, r.resOwner, r.resUntil = &res, r.confirmer, r.until
		}
		r.mu.Unlock()
		return nil
	case errors.As(err, &ve) && ve.Status == http.StatusGone:
		return fmt.Errorf("%w: %s", card.ErrDiscard, ve.Msg)
	case errors.As(err, &ve) && ve.Status == http.StatusConflict:
		// The owner keeps this card (card.ErrInEffect): its Wi-Fi goes on
		// the air, so a lost old card stops joining (#1191).
		return inEffect(fmt.Errorf("%w: %s", card.ErrInEffect, ve.Msg), wifi, c)
	case errors.As(err, &ve) && ve.Status < http.StatusInternalServerError:
		return err // refused before anything was written; kept for a retry
	}
	// No answer, or a failure in the vault process: the commit may have
	// stored the card, and a retry would then get 410 and erase a card in
	// effect. The owner keeps both cards (card.ErrInEffect's text) and the
	// vault's rotation, if still waiting, is dropped (#1090 R2).
	r.cancel(id)
	return inEffect(fmt.Errorf("%w: %v", card.ErrInEffect, err), wifi, c)
}

// wifiKeptInEffect is the note an in-effect card's page adds when its
// Wi-Fi password could not go on the air (#1523, REC-4). It asks for the
// Wi-Fi part on the next card: after no answer the vault may owe nothing,
// so a next card without it would leave the old password on the air
// (#1614 U-1).
const wifiKeptInEffect = "My Wi-Fi may still use your old card's password: I could not switch it. Join it with your old card for now, and include the Wi-Fi password when you start your next card."

// inEffect hands off the Wi-Fi of a card the owner keeps (err wraps
// card.ErrInEffect) and adds the note that says whether it switched
// (#1614 U-2): a hand-off that took the vault's network proves the card's
// Wi-Fi was committed.
func inEffect(err error, wifi func() error, c *card.Card) error {
	if c.WiFiPassword == "" {
		return err
	}
	if handOffWiFi(wifi, c) {
		return &card.Noted{Err: err, Note: wifiSwitchedNote}
	}
	return &card.Noted{Err: err, Note: wifiKeptInEffect}
}

// handOffWiFi has agentosd write the card's Wi-Fi network for the access
// point (#1191), once the vault process committed the card or may have
// (card.ErrInEffect: the owner keeps it); a card it refused leaves the old
// password on the air. It reports whether the access point switches.
func handOffWiFi(wifi func() error, c *card.Card) bool {
	return c.WiFiPassword != "" && wifi != nil && wifi() == nil
}

// wifiSwitchedNote tells the owner the Wi-Fi switched and how to rejoin.
const wifiSwitchedNote = "My Wi-Fi now uses your new card's password. If your phone drops off, rejoin with the Wi-Fi QR code on your new card."

// withWiFiNote adds to a committed rotation's notes what its Wi-Fi does.
func withWiFiNote(res RotationResult, switched bool) RotationResult {
	note := "My Wi-Fi still uses your old card's password: I could not switch it. Join it with your old card for now, and replace the Wi-Fi password again from Home."
	if switched {
		note = wifiSwitchedNote
	}
	res.Notes = append(append([]string(nil), res.Notes...), note)
	return res
}

// cancel drops the vault process's pending rotation id (#1090 R2, S-R1);
// a newer rotation stays. It runs from the display's discard, with the
// display locked.
func (r *Rotation) cancel(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// On failure the vault process's own timer still drops it at
	// recovery.PendingTTL.
	_ = r.v.CancelRotation(ctx, id)
}

// serveCard serves the display d to the session posting r, with the
// display's own checks (signedIn is the session check); a post holds
// postMu so that provision binds the result to its session. wifi hands a
// committed Wi-Fi password to agentosd as that session (#1191).
func (rot *Rotation) serveCard(d *card.Display, signedIn func(*http.Request) bool, wifi func(r *http.Request) error, next string, w http.ResponseWriter, r *http.Request) {
	h := d.Handler(signedIn, next)
	if r.Method != http.MethodPost {
		h.ServeHTTP(w, r)
		return
	}
	rot.postMu.Lock()
	defer rot.postMu.Unlock()
	rot.confirmer = ""
	if tok := cookieToken(r); tok != "" {
		rot.confirmer = tokenKey(tok)
		rot.setWiFi(func() error { return wifi(r) })
	}
	defer func() { rot.confirmer = ""; rot.setWiFi(nil) }()
	h.ServeHTTP(w, r)
}

func (rot *Rotation) setWiFi(f func() error) {
	rot.mu.Lock()
	rot.wifi = f
	rot.mu.Unlock()
}

// voidLocked drops the result and voids any commit still waiting for its
// answer (#1316). It runs with mu held.
func (r *Rotation) voidLocked() {
	r.gen++
	r.res, r.resOwner, r.resUntil = nil, "", time.Time{}
}

// void is voidLocked under mu.
func (r *Rotation) void() {
	r.mu.Lock()
	r.voidLocked()
	r.mu.Unlock()
}

// takeResult returns the last commit's result once, to the session that
// confirmed it, within its window (#1316); to another session, nil.
func (r *Rotation) takeResult(req *http.Request) *RotationResult {
	tok := cookieToken(req)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.res == nil {
		return nil
	}
	if !r.now().Before(r.resUntil) {
		r.res, r.resOwner, r.resUntil = nil, "", time.Time{}
		return nil
	}
	if tok == "" || r.resOwner != tokenKey(tok) {
		return nil
	}
	res := r.res
	r.res, r.resOwner, r.resUntil = nil, "", time.Time{}
	return res
}

// partNames are the vault process's names for the card parts.
var partNames = []string{"wifi", "setup", "passphrase", "grid", "recovery"}

func partSet(p *card.Parts, name string) bool {
	switch name {
	case "wifi":
		p.WiFi = true
	case "setup":
		p.Setup = true
	case "passphrase":
		p.Passphrase = true
	case "grid":
		p.Grid = true
	case "recovery":
		p.Recovery = true
	default:
		return false
	}
	return true
}

func partList(p card.Parts) []string {
	var out []string
	for i, on := range []bool{p.WiFi, p.Setup, p.Passphrase, p.Grid, p.Recovery} {
		if on {
			out = append(out, partNames[i])
		}
	}
	return out
}

// BeginRotation implements RotationVault.
func (u *UnlockClient) BeginRotation(ctx context.Context, b RotationBegin) (RotationStarted, error) {
	var out struct {
		ID       string   `json:"id"`
		Parts    []string `json:"parts"`
		WiFiName string   `json:"wifi_name"`
		Lost     bool     `json:"lost"`
		Expires  string   `json:"expires"`
	}
	err := u.do(ctx, http.MethodPost, "/rotate/begin", struct {
		ID         string   `json:"id"`
		Code       string   `json:"code"`
		Recovery   string   `json:"recovery"`
		Passphrase string   `json:"passphrase"`
		PIN        string   `json:"pin"`
		Parts      []string `json:"parts"`
	}{b.ID, b.Code, b.Recovery, b.Passphrase, b.PIN, partList(b.Parts)}, &out)
	if err != nil {
		return RotationStarted{}, err
	}
	if out.ID != b.ID {
		return RotationStarted{}, errors.New("vault: the rotation begun is not the one asked for")
	}
	st := RotationStarted{WiFiName: out.WiFiName, Lost: out.Lost}
	for _, n := range out.Parts {
		if !partSet(&st.Parts, n) {
			return RotationStarted{}, fmt.Errorf("vault: unknown card part %q", n)
		}
	}
	st.Expires, _ = time.Parse(time.RFC3339, out.Expires)
	return st, nil
}

// CommitRotation implements RotationVault. The body carries the new
// parts; do clears its encoding after the send.
func (u *UnlockClient) CommitRotation(ctx context.Context, id string, c card.Card) (RotationResult, error) {
	var out struct {
		Notes      []string `json:"notes"`
		Retrust    int      `json:"retrust"`
		Enrollment string   `json:"enrollment"`
	}
	err := u.do(ctx, http.MethodPost, "/rotate/commit", struct {
		ID              string `json:"id"`
		WiFiPassword    string `json:"wifi_password,omitempty"`
		SetupSecret     string `json:"setup_secret,omitempty"`
		SetupCode       string `json:"setup_code,omitempty"`
		VaultPassphrase string `json:"vault_passphrase,omitempty"`
		GridSeed        []byte `json:"grid_seed,omitempty"`
		RecoveryKey     string `json:"recovery_key,omitempty"`
	}{id, c.WiFiPassword, c.SetupSecret, c.SetupCode, c.VaultPassphrase, c.GridSeed, c.RecoveryKey}, &out)
	if err != nil {
		return RotationResult{}, err
	}
	return RotationResult{Notes: out.Notes, Retrust: out.Retrust, Enrollment: out.Enrollment}, nil
}

// CancelRotation implements RotationVault.
func (u *UnlockClient) CancelRotation(ctx context.Context, id string) error {
	return u.do(ctx, http.MethodPost, "/rotate/cancel", struct {
		ID string `json:"id"`
	}{id}, nil)
}

// EnrollmentPending implements RotationVault.
func (u *UnlockClient) EnrollmentPending(ctx context.Context) (bool, error) {
	var out struct {
		Pending bool `json:"enrollment_pending"`
	}
	err := u.do(ctx, http.MethodPost, "/rotate/status", struct{}{}, &out)
	return out.Pending, err
}

// ConfirmEnrollment implements RotationVault.
func (u *UnlockClient) ConfirmEnrollment(ctx context.Context, code string) (bool, error) {
	var out struct {
		Confirmed bool `json:"confirmed"`
	}
	err := u.do(ctx, http.MethodPost, "/rotate/enroll", struct {
		Code string `json:"code"`
	}{code}, &out)
	return out.Confirmed, err
}

// ShowEnrollment implements RotationVault.
func (u *UnlockClient) ShowEnrollment(ctx context.Context, recoveryKey string) (string, error) {
	var out struct {
		Enrollment string `json:"enrollment"`
	}
	err := u.do(ctx, http.MethodPost, "/rotate/show-enrollment", struct {
		Recovery string `json:"recovery"`
	}{recoveryKey}, &out)
	return out.Enrollment, err
}

// rotateView is the rotation pages' view.
type rotateView struct {
	Err, Msg string
	// Done: the done page; Notes and QR are the commit's result.
	Done  bool
	Notes []string
	QR    template.HTML
	// Enroll: show the code form for a new code generator.
	Enroll bool
	// Pending: on the start page, a replaced code generator is not yet
	// confirmed, so offer to show it again (U-R1).
	Pending bool
}

func init() {
	template.Must(tmpl.Parse(`{{define "rotate"}}{{template "head" ""}}
{{if .Done}}<h1>Card parts replaced</h1>
{{with .Err}}<p class="err">{{.}}</p>{{end}}{{with .Msg}}<p class="ok">{{.}}</p>{{end}}
{{range .Notes}}<p>{{.}}</p>{{end}}
{{if .QR}}<p>Scan this into your code generator app, then type the code it shows. It is shown once here; until you confirm it, Replace Owner Card parts on Home shows it again with your new recovery key.</p><div class="qr">{{.QR}}</div>{{end}}
{{if .Enroll}}<form method="post" action="/rotate/enroll"><label>Code from the new generator<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code"></label><button>Confirm</button></form>
<details><summary>Show the code generator again</summary><form method="post" action="/rotate/show"><label>Recovery key<input type="password" name="recovery" autocomplete="off"></label><button>Show</button></form></details>{{end}}
<p><a href="/home">Home</a></p>
{{else}}<h1>Replace Owner Card parts</h1>
{{with .Err}}<p class="err">{{.}}</p>{{end}}
{{if .Pending}}<h2>Show the new code generator</h2>
<p>Your new code generator is not confirmed yet. Type your recovery key to show it again, scan it, then type the code it shows.</p>
<form method="post" action="/rotate/show"><label>Recovery key<input type="password" name="recovery" autocomplete="off"></label><button>Show the new code generator</button></form>
{{end}}<p>I make new values for the parts you choose and show them for you to print. Nothing changes until you confirm the new card.</p>
<form method="post" action="/rotate/">
<p><label><input type="checkbox" name="parts" value="wifi"> Wi-Fi password</label><br>
<label><input type="checkbox" name="parts" value="setup"> Setup secret and code generator</label><br>
<label><input type="checkbox" name="parts" value="passphrase"> Vault passphrase</label><br>
<label><input type="checkbox" name="parts" value="grid"> Code grid</label><br>
<label><input type="checkbox" name="parts" value="recovery"> Recovery key</label></p>
<label>Code from your code generator<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code"></label>
<p class="muted">Or, instead of a code, your current recovery key:</p>
<label>Recovery key<input type="password" name="recovery" autocomplete="off"></label>
<label>Current vault passphrase (to replace the passphrase or recovery key)<input type="password" name="passphrase" autocomplete="off"></label>
<label>This PC's boot PIN, if it has one (to replace the recovery key)<input type="password" name="pin" autocomplete="off"></label>
<button>Make the new card</button></form>
<p><a href="/home">Home</a></p>{{end}}
{{template "foot"}}{{end}}`))
}

// rotatePages serves the rotation's start, done, enroll and show pages
// under /rotate/ (Mount strips the prefix); the display itself is at
// /rotate/card (rotationCard).
func (s *Server) rotatePages(rot *Rotation) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			s.rotateStart(w, r, rot)
		case "/done":
			s.rotateDone(w, r, rot)
		case "/enroll":
			s.post(func(w http.ResponseWriter, r *http.Request) { s.rotateEnroll(w, r, rot) })(w, r)
		case "/show":
			s.post(func(w http.ResponseWriter, r *http.Request) { s.rotateShow(w, r, rot) })(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func (s *Server) rotateStart(w http.ResponseWriter, r *http.Request, rot *Rotation) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.render(w, "rotate", rotateView{Pending: enrollmentPending(r.Context(), rot)})
		return
	case http.MethodPost:
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	b := RotationBegin{Code: r.PostForm.Get("code"), Recovery: r.PostForm.Get("recovery"),
		Passphrase: r.PostForm.Get("passphrase"), PIN: r.PostForm.Get("pin")}
	for _, n := range r.PostForm["parts"] {
		if !partSet(&b.Parts, n) {
			w.WriteHeader(http.StatusBadRequest)
			s.render(w, "rotate", rotateView{Err: "Choose the card parts to replace."})
			return
		}
	}
	if partList(b.Parts) == nil {
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, "rotate", rotateView{Err: "Choose the card parts to replace."})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := rot.Start(ctx, b); err != nil {
		code, msg := vaultRefusal(err)
		w.WriteHeader(code)
		s.render(w, "rotate", rotateView{Err: msg})
		return
	}
	http.Redirect(w, r, "/rotate/card", http.StatusSeeOther)
}

// enrollmentPending asks the vault process whether a replaced code
// generator waits for its first code; no answer shows no offer.
func enrollmentPending(ctx context.Context, rot *Rotation) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ok, err := rot.v.EnrollmentPending(ctx)
	return err == nil && ok
}

// vaultRefusal is the status and owner-facing reason for a vault
// process error: its own fixed message, never an internal one.
func vaultRefusal(err error) (int, string) {
	var ve *VaultError
	if errors.As(err, &ve) {
		if ve.Msg != "" {
			return ve.Status, "I could not do that: " + ve.Msg + "."
		}
		return ve.Status, "I could not do that. Try again."
	}
	return http.StatusServiceUnavailable, "I am not answering on the vault side yet. Try again in a minute."
}

// rotateDone shows the committed rotation's notes and new code generator
// once; later visits go home.
func (s *Server) rotateDone(w http.ResponseWriter, r *http.Request, rot *Rotation) {
	res := rot.takeResult(r)
	if res == nil {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return
	}
	v := rotateView{Done: true, Notes: res.Notes}
	if res.Enrollment != "" {
		qr, err := card.QRSVG(res.Enrollment)
		if err != nil {
			v.Err = "I could not draw the code generator. Show it again with your recovery key."
		}
		v.QR, v.Enroll = qr, true
	}
	s.render(w, "rotate", v)
}

func (s *Server) rotateEnroll(w http.ResponseWriter, r *http.Request, rot *Rotation) {
	rot.void() // #1316: the unfetched result goes, and any late commit's
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	ok, err := rot.v.ConfirmEnrollment(ctx, r.PostFormValue("code"))
	v := rotateView{Done: true, Enroll: true}
	switch {
	case err != nil:
		code, msg := vaultRefusal(err)
		v.Err = msg
		w.WriteHeader(code)
	case !ok:
		v.Err = "That code did not match. Check the new entry in your code generator and try again."
		w.WriteHeader(http.StatusUnprocessableEntity)
	default:
		v.Enroll, v.Msg = false, "The new code generator is confirmed."
	}
	s.render(w, "rotate", v)
}

func (s *Server) rotateShow(w http.ResponseWriter, r *http.Request, rot *Rotation) {
	rot.void() // #1316: as rotateEnroll
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	uri, err := rot.v.ShowEnrollment(ctx, r.PostFormValue("recovery"))
	v := rotateView{Done: true, Enroll: true}
	if err != nil {
		code, msg := vaultRefusal(err)
		v.Err = msg
		w.WriteHeader(code)
		s.render(w, "rotate", v)
		return
	}
	if v.QR, err = card.QRSVG(uri); err != nil {
		v.Err = "I could not draw the code generator."
	}
	s.render(w, "rotate", v)
}
