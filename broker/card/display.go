package card

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// ErrNotConfirmed is what Confirm returns when the typed word or group
// does not match the card: the display stays.
var ErrNotConfirmed = errors.New("card: the word or group did not match the card")

// ErrDisplayGone is what the display returns after the confirm step erased
// its copy of the card.
var ErrDisplayGone = errors.New("card: I keep no copy of the card")

// ErrDiscard, wrapped in a Provision error, says the card can no longer
// take effect (a rotation that lapsed): the display erases its copy
// instead of keeping it for a retry.
var ErrDiscard = errors.New("card: this card can no longer take effect")

// ErrInEffect, wrapped in a Provision error, says part of the card took
// effect before a later step failed (a rotation's partial write). The
// owner has just typed values back from their copy, and a retry cannot
// finish (the rotation is used up), so the display erases its copy, as
// after a full confirm, and refuses a later cancel: the owner keeps the
// new card and the current one, and a new rotation, started with either
// card's factor that opens the drive, finishes the rest.
var ErrInEffect = errors.New("card: part of this card is already in effect")

// inEffectProblem is the page's note once part of the card is in effect:
// it names the one step that finishes the rotation (CH-12). It holds in
// every partial state: some parts may still be the current card's (the
// setup secret and grid take effect last, and a failed
// recovery-key write leaves the old key in effect), so the owner keeps
// both cards and finishes with whichever one opens the drive; the next
// rotation must replace every part this one rotated (#1090 review F3).
const inEffectProblem = "Part of your new card is already in effect, but I could not finish. Keep the new card, and your current one if you still have it. Finish now: start a new card from my Wi-Fi page, using the passphrase or recovery key from whichever card works."

// cancelledGone and confirmedGone answer a display whose card was erased,
// naming the page as the owner texts do (CH-12).
const (
	cancelledGone = "This new card was cancelled and erased; your current card stays in effect. Start again from my Wi-Fi page."
	confirmedGone = "You confirmed your Owner Card, so I keep no copy of it. If you lose it, you can replace it with a new card from my Wi-Fi page."
)

// Noted wraps a Provision error with a fixed note that the page adds to
// the owner's text once the card is in effect (REC-4): Err decides the
// outcome, Note says what else the owner must know. Note is a fixed
// string; no card text goes in it.
type Noted struct {
	Err  error
	Note string
}

func (n *Noted) Error() string { return n.Err.Error() }
func (n *Noted) Unwrap() error { return n.Err }

// Parts are the card secrets a rotation replaces (REC-4).
type Parts struct{ Setup, Passphrase, Grid, Recovery bool }

func (p Parts) any() bool { return p.Setup || p.Passphrase || p.Grid || p.Recovery }

// Answers are the values typed back from the printed or saved card. Word
// and Group are a passphrase word and a recovery key group; Check is the
// one value a rotation that replaces neither asks for instead.
type Answers struct{ Word, Group, Check string }

// checkKind is the value a rotation without a new passphrase or recovery
// key asks for.
type checkKind int

const (
	checkNone  checkKind = iota
	checkSetup           // the setup code
	checkGrid            // the grid check code
)

// DisplayConfig configures NewDisplay. Provision and Authority are
// required.
type DisplayConfig struct {
	// Authority is the page authority's certificate (DER): the card and
	// every rotation sheet print its fingerprint (HW-1, CH-9, REC-4).
	// NewDisplay refuses with ErrNoAuthority, before drawing any
	// randomness, when it is missing or fails CheckAuthority. It is
	// public, and kept apart from Card, the secrets wipeCard clears.
	Authority []byte
	// Rand is the box's randomness; crypto/rand.Reader when nil. Every
	// value on the card comes from it, at the box, never from the image.
	Rand io.Reader
	// Generate makes the card; Generate when nil (tests wrap it).
	Generate func(io.Reader) (*Card, error)
	// Provision writes what the box keeps of the card (vault slots and the
	// stored values, recovery.Provision). It runs once the owner has
	// confirmed holding the card, before the display copy is erased, and
	// may run again with the same card after an error. It must not keep
	// the *Card: the display wipes it afterwards.
	Provision func(*Card) error
	// Journal records the step's events. It is passed fixed event strings
	// only, never card text.
	Journal func(event string)
	// Rotate, when set, makes a rotation display (REC-4): the card carries
	// new values for these parts only (the rest are blank), the sheet
	// shows only them, and the confirm asks for a word
	// of a new passphrase, a group of a new recovery key, or else one
	// check value of the new parts.
	Rotate *Parts
	// Made, with Rotate, says the new parts are already in effect (the
	// lost-card route, D-201 route B: the box made them at boot): the
	// page offers no cancel and does not say the current card stays, and
	// the confirm only records that the owner holds them.
	Made bool
	// Discarded, when set, runs once when the display discards an
	// unconfirmed card: the page's cancel, or a provisioner's ErrDiscard.
	// A rotation's wire cancels the vault's pending rotation here, so the
	// typed passphrase it holds goes at once (#1090 review R2, CRED-1).
	// It runs with the display locked and must not call back into it.
	Discarded func()
}

// Display is one Owner Card the box generated (at first boot, HW-1, or the
// new parts of a rotation, REC-4), shown to the paired phone until the
// owner confirms values typed from the printed or saved card: one
// passphrase word and one recovery key group at first boot. Then the box
// provisions from it and erases its copy.
type Display struct {
	mu        sync.Mutex
	c         *Card
	sheet     []byte // the printable card (HTML)
	word      int    // 0-based passphrase word asked for; -1 for none
	group     int    // 0-based recovery key group asked for; -1 for none
	check     checkKind
	rotate    bool
	made      bool
	provision func(*Card) error
	journal   func(string)
	discardFn func()
	confirmed bool
	discarded bool
	inEffect  bool
	note      string // a Noted in-effect error's note, shown after inEffectProblem
}

// Journal events. Fixed strings: no card text ever reaches the journal.
const (
	EventShown     = "owner card: generated and shown"
	EventMismatch  = "owner card: confirm did not match"
	EventProvFail  = "owner card: provisioning failed; card kept on display"
	EventInEffect  = "owner card: confirmed, partly in effect, display copy erased"
	EventConfirmed = "owner card: confirmed, provisioned, display copy erased"
	EventDiscarded = "owner card: discarded unconfirmed, display copy erased"
)

// NewDisplay generates a card from the box's randomness and prepares its
// display. Nothing is written anywhere until Confirm.
func NewDisplay(cfg DisplayConfig) (*Display, error) {
	if cfg.Provision == nil {
		return nil, errors.New("card: display needs a provisioner")
	}
	if err := CheckAuthority(cfg.Authority); err != nil {
		return nil, err
	}
	fp := Fingerprint(cfg.Authority)
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.Generate == nil {
		cfg.Generate = Generate
	}
	if cfg.Journal == nil {
		cfg.Journal = func(string) {}
	}
	if cfg.Rotate != nil && !cfg.Rotate.any() {
		return nil, errors.New("card: a rotation needs at least one part")
	}
	c, err := cfg.Generate(cfg.Rand)
	if err != nil {
		return nil, err
	}
	// The whole card is validated before a rotation keeps only its parts.
	if err := c.Validate(); err != nil {
		wipeCard(c)
		return nil, err
	}
	d := &Display{c: c, word: -1, group: -1, provision: cfg.Provision, journal: cfg.Journal, discardFn: cfg.Discarded}
	ask := Parts{Passphrase: true, Recovery: true}
	if cfg.Rotate != nil {
		ask, d.rotate, d.made = *cfg.Rotate, true, cfg.Made
		keepParts(c, ask)
		switch {
		case ask.Passphrase || ask.Recovery:
		case ask.Setup:
			d.check = checkSetup
		default:
			d.check = checkGrid
		}
		d.sheet, err = rotationHTML(c, ask, fp)
	} else {
		d.sheet, err = HTML(c, fp)
	}
	if err == nil && ask.Passphrase {
		d.word, err = uniform(cfg.Rand, PassphraseWords)
	}
	if err == nil && ask.Recovery {
		d.group, err = uniform(cfg.Rand, recoveryGroups)
	}
	if err != nil {
		d.eraseLocked()
		return nil, err
	}
	cfg.Journal(EventShown)
	return d, nil
}

// keepParts blanks every secret of c a rotation of p does not replace.
func keepParts(c *Card, p Parts) {
	if !p.Setup {
		c.SetupSecret, c.SetupCode = "", ""
	}
	if !p.Passphrase {
		c.VaultPassphrase = ""
	}
	if !p.Grid {
		wipe(c.GridSeed)
		c.GridSeed = nil
	}
	if !p.Recovery {
		c.RecoveryKey = ""
	}
}

// Asks is the passphrase word and recovery key group (1-based) the
// confirm step asks for; 0 is one it does not ask for. The positions are
// not secret.
func (d *Display) Asks() (word, group int) { return d.word + 1, d.group + 1 }

// Prompt asks the owner for the confirm values.
func (d *Display) Prompt() string {
	if !d.rotate {
		return fmt.Sprintf("Type word %d of your vault passphrase and group %d of your recovery key.", d.word+1, d.group+1)
	}
	switch {
	case d.word >= 0 && d.group >= 0:
		return fmt.Sprintf("Type word %d of your new vault passphrase and group %d of your new recovery key.", d.word+1, d.group+1)
	case d.word >= 0:
		return fmt.Sprintf("Type word %d of your new vault passphrase.", d.word+1)
	case d.group >= 0:
		return fmt.Sprintf("Type group %d of your new recovery key.", d.group+1)
	case d.check == checkSetup:
		return "Type your new setup code."
	}
	return "Type the check code printed under your new grid."
}

// Page is the display page: the card with print, save and confirm
// controls that do not print.
func (d *Display) Page() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pageLocked("")
}

func (d *Display) pageLocked(problem string) ([]byte, error) {
	if d.c == nil {
		return nil, ErrDisplayGone
	}
	var ctl bytes.Buffer
	v := struct {
		Prompt, Problem    string
		Rotate, Made       bool
		Word, Group, Check bool
	}{d.Prompt(), problem, d.rotate, d.made, d.word >= 0, d.group >= 0, d.check != checkNone}
	if err := controlsTmpl.Execute(&ctl, v); err != nil {
		return nil, err
	}
	i := bytes.Index(d.sheet, []byte("<body>"))
	if i < 0 {
		return nil, errors.New("card: sheet has no body")
	}
	i += len("<body>")
	out := make([]byte, 0, len(d.sheet)+ctl.Len())
	out = append(append(append(out, d.sheet[:i]...), ctl.Bytes()...), d.sheet[i:]...)
	return out, nil
}

// Confirm checks the typed word and group against the card, ignoring
// case, spaces and dashes. A mismatch returns ErrNotConfirmed and keeps
// the display. A match provisions; if that fails the display stays and
// the error is returned, unless it wraps ErrDiscard or ErrInEffect, which
// erase the display; otherwise the display copy is erased.
func (d *Display) Confirm(word, group string) error {
	return d.ConfirmAnswers(Answers{Word: word, Group: group})
}

// ConfirmAnswers is Confirm with every value a display may ask for; the
// ones it does not ask for are ignored.
func (d *Display) ConfirmAnswers(a Answers) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.c == nil {
		return ErrDisplayGone
	}
	ok := 1
	match := func(got, want []byte) {
		ok &= subtle.ConstantTimeCompare(got, want)
		wipe(got, want)
	}
	if d.word >= 0 {
		match([]byte(NormalizePassphrase(a.Word)), []byte(NormalizePassphrase(strings.Fields(d.c.VaultPassphrase)[d.word])))
	}
	if d.group >= 0 {
		match([]byte(Normalize(a.Group)), []byte(Normalize(strings.Split(d.c.RecoveryKey, "-")[d.group])))
	}
	switch d.check {
	case checkSetup:
		match([]byte(Normalize(a.Check)), []byte(Normalize(d.c.SetupCode)))
	case checkGrid:
		match([]byte(Normalize(a.Check)), []byte(GridCheck(d.c.GridSeed)))
	}
	if ok != 1 {
		d.journal(EventMismatch)
		return ErrNotConfirmed
	}
	if err := d.provision(d.c); err != nil {
		switch {
		case errors.Is(err, ErrInEffect):
			// Confirmed from the owner's copy, which is now the card in
			// effect; a retry cannot finish, so keep nothing.
			d.inEffect = true
			if n := (*Noted)(nil); errors.As(err, &n) {
				d.note = n.Note
			}
			d.eraseLocked()
			d.journal(EventInEffect)
		case errors.Is(err, ErrDiscard):
			d.discardLocked()
		default:
			d.journal(EventProvFail)
		}
		return fmt.Errorf("card: provisioning: %w", err)
	}
	d.confirmed = true
	d.eraseLocked()
	d.journal(EventConfirmed)
	return nil
}

// Discard erases the display copy without provisioning: an aborted
// rotation, whose new values never take effect. Later calls do nothing.
// Once part of the card is in effect it refuses, returning ErrInEffect:
// the rotation can no longer be cancelled.
func (d *Display) Discard() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.inEffect {
		return ErrInEffect
	}
	if d.c != nil {
		d.discardLocked()
	}
	return nil
}

func (d *Display) discardLocked() {
	d.discarded = true
	d.eraseLocked()
	d.journal(EventDiscarded)
	if d.discardFn != nil {
		d.discardFn()
	}
}

// Confirmed reports whether the owner confirmed and the box provisioned.
func (d *Display) Confirmed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.confirmed
}

// eraseLocked wipes the display copy. Byte values are zeroed; Go strings
// cannot be, so they are dropped for the collector (ASSUMPTIONS.md C13).
func (d *Display) eraseLocked() {
	wipe(d.sheet)
	d.sheet = nil
	if d.c != nil {
		wipeCard(d.c)
		d.c = nil
	}
}

func wipeCard(c *Card) {
	wipe(c.GridSeed)
	*c = Card{}
}

func wipe(bs ...[]byte) {
	for _, b := range bs {
		clear(b)
	}
}

// String keeps the display out of logs.
func (d *Display) String() string { return "[owner card display]" }

// GoString keeps the display out of %#v.
func (d *Display) GoString() string { return d.String() }

// String keeps a card out of logs: no card value is ever formatted.
func (Card) String() string { return "[owner card]" }

// GoString keeps a card out of %#v.
func (c Card) GoString() string { return c.String() }

// maxForm bounds a confirm POST.
const maxForm = 4 << 10

// Handler serves the display to the paired phone only (paired reports it):
// GET shows the page, GET ?save=1 downloads the bare card, POST confirms
// and redirects to next; on a rotation display a POST with cancel=1
// discards it and redirects to next. After the confirm every request gets 410. The
// local UI mounts it behind its own address checks.
func (d *Display) Handler(paired func(*http.Request) bool, next string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'")
		if !paired(r) {
			http.Error(w, "Only the phone that set me up can see the Owner Card.", http.StatusForbidden)
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			d.serveGet(w, r)
		case http.MethodPost:
			if !sameOrigin(r) {
				http.Error(w, "Open this page from my Wi-Fi page.", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxForm)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Bad form.", http.StatusBadRequest)
				return
			}
			if d.rotate && !d.made && r.PostFormValue("cancel") == "1" {
				if d.Discard() != nil {
					d.gone(w)
					return
				}
				http.Redirect(w, r, next, http.StatusSeeOther)
				return
			}
			err := d.ConfirmAnswers(Answers{Word: r.PostFormValue("word"), Group: r.PostFormValue("group"), Check: r.PostFormValue("check")})
			switch {
			case err == nil:
				http.Redirect(w, r, next, http.StatusSeeOther)
			case errors.Is(err, ErrDisplayGone), errors.Is(err, ErrDiscard), errors.Is(err, ErrInEffect):
				d.gone(w)
			case errors.Is(err, ErrNotConfirmed):
				d.servePage(w, http.StatusUnprocessableEntity, "That did not match your card. Check the word and group and type them again.")
			default:
				d.servePage(w, http.StatusInternalServerError, "I could not save the card's settings. Your card is still good; try again.")
			}
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
		}
	})
}

func (d *Display) serveGet(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("save") != "1" {
		d.servePage(w, http.StatusOK, "")
		return
	}
	d.mu.Lock()
	if d.c == nil {
		d.mu.Unlock()
		d.gone(w)
		return
	}
	b := bytes.Clone(d.sheet)
	d.mu.Unlock()
	defer wipe(b)
	name := "agentos-owner-card.html"
	if d.rotate {
		name = "agentos-new-card-parts.html"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Write(b)
}

func (d *Display) servePage(w http.ResponseWriter, code int, problem string) {
	d.mu.Lock()
	b, err := d.pageLocked(problem)
	d.mu.Unlock()
	if errors.Is(err, ErrDisplayGone) {
		d.gone(w)
		return
	}
	if err != nil {
		http.Error(w, "I could not show the card.", http.StatusInternalServerError)
		return
	}
	defer wipe(b)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	w.Write(b)
}

func (d *Display) gone(w http.ResponseWriter) {
	d.mu.Lock()
	discarded, inEffect, note := d.discarded, d.inEffect, d.note
	d.mu.Unlock()
	if inEffect {
		if note != "" {
			note = " " + note
		}
		http.Error(w, inEffectProblem+note, http.StatusGone)
		return
	}
	if discarded {
		http.Error(w, cancelledGone, http.StatusGone)
		return
	}
	http.Error(w, confirmedGone, http.StatusGone)
}

// sameOrigin refuses a POST another site's page sends: an Origin header,
// when present, must name this host.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return r.Header.Get("Sec-Fetch-Site") != "cross-site"
	}
	u, err := url.Parse(o)
	return err == nil && u.Host == r.Host
}

var controlsTmpl = template.Must(template.New("controls").Parse(`
<div class="noprint" style="font-family:system-ui,sans-serif;border:2px solid #000;padding:4mm;margin:4mm">
<style>@media print{.noprint{display:none}}</style>
<h1>{{if .Rotate}}Your new card parts{{else}}Your Owner Card{{end}}</h1>
<p><b>Print it now, or save it.</b> I keep no copy once you confirm.{{if .Made}} This new card's recovery key already opens my store, and your old card's recovery key no longer does.{{else if .Rotate}} Until you confirm, your current card stays in effect.{{end}} Do not take a screenshot or a photo: those end up in your phone's cloud.</p>
<p><button type="button" onclick="window.print()">Print</button> <a href="?save=1">Save as a file</a></p>
<form method="post">
<p>{{.Prompt}}</p>
{{if .Problem}}<p role="alert"><b>{{.Problem}}</b></p>{{end}}
<p>{{if .Word}}<label>Word <input name="word" autocomplete="off" autocapitalize="none" spellcheck="false"></label>
{{end}}{{if .Group}}<label>Group <input name="group" autocomplete="off" autocapitalize="characters" spellcheck="false"></label>
{{end}}{{if .Check}}<label>Check <input name="check" autocomplete="off" autocapitalize="characters" spellcheck="false"></label>
{{end}}
<button type="submit">Confirm</button></p>
</form>
{{if and .Rotate (not .Made)}}<form method="post"><input type="hidden" name="cancel" value="1"><p><button type="submit">Cancel: keep my current card</button></p></form>
{{end}}
</div>
`))
