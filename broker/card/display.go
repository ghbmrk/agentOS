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
var ErrDisplayGone = errors.New("card: the box keeps no copy of the card")

// DisplayConfig configures NewDisplay. Provision is required.
type DisplayConfig struct {
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
}

// Display is one Owner Card the box generated (at first boot, HW-1, or for
// a full rotation, REC-4), shown to the paired phone until the owner
// confirms one passphrase word and one recovery key group from the printed
// or saved card. Then the box provisions from it and erases its copy.
type Display struct {
	mu        sync.Mutex
	c         *Card
	sheet     []byte // the printable card (HTML)
	word      int    // 0-based passphrase word asked for
	group     int    // 0-based recovery key group asked for
	provision func(*Card) error
	journal   func(string)
	confirmed bool
}

// Journal events. Fixed strings: no card text ever reaches the journal.
const (
	EventShown     = "owner card: generated and shown"
	EventMismatch  = "owner card: confirm did not match"
	EventProvFail  = "owner card: provisioning failed; card kept on display"
	EventConfirmed = "owner card: confirmed, provisioned, display copy erased"
)

// NewDisplay generates a card from the box's randomness and prepares its
// display. Nothing is written anywhere until Confirm.
func NewDisplay(cfg DisplayConfig) (*Display, error) {
	if cfg.Provision == nil {
		return nil, errors.New("card: display needs a provisioner")
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.Generate == nil {
		cfg.Generate = Generate
	}
	if cfg.Journal == nil {
		cfg.Journal = func(string) {}
	}
	c, err := cfg.Generate(cfg.Rand)
	if err != nil {
		return nil, err
	}
	sheet, err := HTML(c)
	if err != nil {
		wipeCard(c)
		return nil, err
	}
	d := &Display{c: c, sheet: sheet, provision: cfg.Provision, journal: cfg.Journal}
	if d.word, err = uniform(cfg.Rand, PassphraseWords); err == nil {
		d.group, err = uniform(cfg.Rand, recoveryGroups)
	}
	if err != nil {
		d.eraseLocked()
		return nil, err
	}
	cfg.Journal(EventShown)
	return d, nil
}

// Asks is the passphrase word and recovery key group (1-based) the
// confirm step asks for. The positions are not secret.
func (d *Display) Asks() (word, group int) { return d.word + 1, d.group + 1 }

// Prompt asks the owner for the confirm values.
func (d *Display) Prompt() string {
	return fmt.Sprintf("Type word %d of your vault passphrase and group %d of your recovery key.", d.word+1, d.group+1)
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
	if err := controlsTmpl.Execute(&ctl, struct{ Prompt, Problem string }{d.Prompt(), problem}); err != nil {
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
// the error is returned; otherwise the display copy is erased.
func (d *Display) Confirm(word, group string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.c == nil {
		return ErrDisplayGone
	}
	wantW := []byte(NormalizePassphrase(strings.Fields(d.c.VaultPassphrase)[d.word]))
	wantG := []byte(Normalize(strings.Split(d.c.RecoveryKey, "-")[d.group]))
	gotW, gotG := []byte(NormalizePassphrase(word)), []byte(Normalize(group))
	ok := subtle.ConstantTimeCompare(gotW, wantW) & subtle.ConstantTimeCompare(gotG, wantG)
	wipe(wantW, wantG, gotW, gotG)
	if ok != 1 {
		d.journal(EventMismatch)
		return ErrNotConfirmed
	}
	if err := d.provision(d.c); err != nil {
		d.journal(EventProvFail)
		return fmt.Errorf("card: provisioning: %w", err)
	}
	d.confirmed = true
	d.eraseLocked()
	d.journal(EventConfirmed)
	return nil
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
// and redirects to next. After the confirm every request gets 410. The
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
			err := d.Confirm(r.PostFormValue("word"), r.PostFormValue("group"))
			switch {
			case err == nil:
				http.Redirect(w, r, next, http.StatusSeeOther)
			case errors.Is(err, ErrDisplayGone):
				gone(w)
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
		gone(w)
		return
	}
	b := bytes.Clone(d.sheet)
	d.mu.Unlock()
	defer wipe(b)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="agentos-owner-card.html"`)
	w.Write(b)
}

func (d *Display) servePage(w http.ResponseWriter, code int, problem string) {
	d.mu.Lock()
	b, err := d.pageLocked(problem)
	d.mu.Unlock()
	if errors.Is(err, ErrDisplayGone) {
		gone(w)
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

func gone(w http.ResponseWriter) {
	http.Error(w, "You confirmed your Owner Card, so I keep no copy of it. If you lose it, you can replace it with a new card from my box page.", http.StatusGone)
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
<h1>Your Owner Card</h1>
<p><b>Print it now, or save it.</b> I keep no copy once you confirm. Do not take a screenshot or a photo: those end up in your phone's cloud.</p>
<p><button type="button" onclick="window.print()">Print</button> <a href="?save=1">Save as a file</a></p>
<form method="post">
<p>{{.Prompt}}</p>
{{if .Problem}}<p role="alert"><b>{{.Problem}}</b></p>{{end}}
<p><label>Word <input name="word" autocomplete="off" autocapitalize="none" spellcheck="false"></label>
<label>Group <input name="group" autocomplete="off" autocapitalize="characters" spellcheck="false"></label>
<button type="submit">Confirm</button></p>
</form>
</div>
`))
