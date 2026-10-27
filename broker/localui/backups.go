package localui

import (
	"context"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// Backups is the Backups page's ops (BAK-1, BAK-2; MIG-4-recovery-e4b):
// agentosd lists the destinations the kernel holds with the only-copy
// notice, adds a second local drive on a hardware key's tap, and stops
// one with no tap. session is the phone's session token, which agentosd
// checks. A refusal is a Refused with one of localapi.BackupCodes.
type Backups interface {
	Backups(ctx context.Context, session string) (localapi.BackupChoice, error)
	BackupBegin(ctx context.Context, session string, p localapi.BackupPlace) (localapi.BackupBegun, error)
	BackupAdd(ctx context.Context, session string, p localapi.BackupPlace, n int, authData, clientData, sig []byte) error
	BackupRemove(ctx context.Context, session, name string) error
}

// The backup ops are agentosd's, on the same socket as its passkey ops,
// which they need: AgentosdPasskeys serves both.
func (a AgentosdPasskeys) Backups(ctx context.Context, session string) (localapi.BackupChoice, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var out localapi.BackupChoice
	err := a.Owner.Call(ctx, localapi.OpBackups, localapi.Auth{Token: session}, &out)
	return out, err
}

func (a AgentosdPasskeys) BackupBegin(ctx context.Context, session string, p localapi.BackupPlace) (localapi.BackupBegun, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var out localapi.BackupBegun
	err := a.Owner.Call(ctx, localapi.OpBackupBegin, localapi.BackupBegin{Token: session, Place: p}, &out)
	return out, err
}

func (a AgentosdPasskeys) BackupAdd(ctx context.Context, session string, p localapi.BackupPlace, n int, authData, clientData, sig []byte) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	return a.Owner.Call(ctx, localapi.OpBackupAdd, localapi.BackupAdd{Token: session, Place: p, N: n,
		AuthenticatorData: authData, ClientDataJSON: clientData, Signature: sig}, nil)
}

func (a AgentosdPasskeys) BackupRemove(ctx context.Context, session, name string) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	return a.Owner.Call(ctx, localapi.OpBackupRemove, localapi.BackupRemove{Token: session, Name: name}, nil)
}

// BackupTapAgainText is the tap step's answer when the tap was not a
// hardware key's: the challenge still stands, so the owner taps again.
const BackupTapAgainText = "That wasn't one of your hardware keys. Tap again, and choose your hardware key, not a phone's passkey."

// backupWrongTap is a refusal of the tap itself, which tapping again can
// mend.
func backupWrongTap(err error) bool {
	var r Refused
	errors.As(err, &r)
	return string(r) == localapi.ErrBackupBadAssertion || string(r) == localapi.ErrBackupNotAnchor
}

// backupText is the owner's wording for each refusal; none carries a
// value, and anything else reads as agentosd not answering.
func backupText(err error) string {
	var r Refused
	errors.As(err, &r)
	switch string(r) {
	case localapi.ErrBackupNotAnchor:
		return "That tap was a phone passkey's. Only one of your hardware keys can add a place for backups. Start again and tap a hardware key when asked."
	case localapi.ErrBackupBadAssertion:
		return "That tap didn't match. Start again, and tap one of your hardware keys when asked."
	case localapi.ErrBackupPlace:
		return "I can't use that folder. It must be a folder on a drive plugged into me, outside my own data, and the name only letters, digits, dots, dashes or underscores."
	case localapi.ErrBackupNameTaken:
		return "A place for backups already has that name, or had it. Choose another name."
	case localapi.ErrBackupStale:
		return "This page is out of date: a place was added or stopped since. Start again."
	case localapi.ErrBackupSetup:
		return "Finish setup first."
	case localapi.ErrBadArgs:
		return "Fill in a name and the full folder path, then start again."
	case localapi.ErrLimited:
		return "Too many tries. Wait a minute, then start again."
	case localapi.ErrUnauthorized:
		return "Your sign-in ended. Sign in again, then start again."
	}
	return "I couldn't reach the part of me that keeps your backups. Try again in a minute."
}

// backupsView is the Backups page in one of its steps: the list, or the
// hardware key's tap over the place it shows.
type backupsView struct {
	RP     string
	Choice localapi.BackupChoice
	// Step is "" or "tap".
	Step  string
	Place localapi.BackupPlace
	N     int
	// Challenge is the tap's challenge, base64.
	Challenge string
	Err, Done string
}

// formPlace is the destination the add form names: a second local drive.
func formPlace(f map[string][]string) localapi.BackupPlace {
	get := func(k string) string {
		if v := f[k]; len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	return localapi.BackupPlace{Name: get("name"), Kind: localapi.BackupKindDir, Locator: get("locator"), AppendOnly: get("append") == "1"}
}

// backupsPage serves /backups/ behind sign-in (CH-7): the only-copy
// notice, the places that hold backups, adding a second local drive on a
// hardware key's tap, and stopping one. GET only shows; every step that
// reaches agentosd is a same-origin form post. Its one script is the
// passkey page's (passkeyJS), whose get() runs the tap.
func (s *Server) backupsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", passkeyCSP)
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	tok := cookieToken(r)
	v := backupsView{RP: s.cfg.PasskeyRPID}
	list := func() {
		c, err := s.cfg.Backups.Backups(ctx, tok)
		if err != nil {
			v.Err = backupText(err)
		}
		v.Choice = c
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		list()
		s.render(w, "backups", v)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	f := r.PostForm
	switch f.Get("step") {
	case "begin":
		p := formPlace(f)
		b, err := s.cfg.Backups.BackupBegin(ctx, tok, p)
		if err != nil {
			v.Err = backupText(err)
			break
		}
		list()
		v.Step, v.Place, v.N, v.Challenge = "tap", p, b.N, base64.StdEncoding.EncodeToString(b.Challenge)
		s.render(w, "backups", v)
		return
	case "add":
		p := formPlace(f)
		n, nerr := strconv.Atoi(f.Get("n"))
		ad, ok1 := formBytes(f.Get("ad"), localapi.MaxPasskeyAssertion)
		cd, ok2 := formBytes(f.Get("cd"), localapi.MaxPasskeyAssertion)
		sig, ok3 := formBytes(f.Get("sig"), localapi.MaxPasskeyAssertion)
		var err error = Refused(localapi.ErrBackupBadAssertion)
		if nerr != nil {
			err = Refused(localapi.ErrBackupStale)
		} else if ok1 && ok2 && ok3 {
			err = s.cfg.Backups.BackupAdd(ctx, tok, p, n, ad, cd, sig)
		}
		// A wrong tap stays on the tap step with the same challenge, which
		// the form carries back.
		ch, ok := formBytes(f.Get("ch"), localapi.PasskeyChallenge)
		if backupWrongTap(err) && ok && len(ch) == localapi.PasskeyChallenge {
			list()
			v.Step, v.Place, v.N, v.Challenge, v.Err = "tap", p, n, base64.StdEncoding.EncodeToString(ch), BackupTapAgainText
			s.render(w, "backups", v)
			return
		}
		if err != nil {
			v.Err = backupText(err)
			break
		}
		v.Done = "Added. I take its first backup within a minute, and check it by reading it back."
	case "remove":
		if err := s.cfg.Backups.BackupRemove(ctx, tok, f.Get("name")); err != nil {
			v.Err = backupText(err)
			break
		}
		v.Done = "Stopped. I take no new backups there; the ones already there stay."
	default:
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	err := v.Err
	list()
	if err != "" {
		v.Err = err
	}
	s.render(w, "backups", v)
}

// backupDay is a backup's day as the page shows it, from kernel ms.
func backupDay(ms int64) string { return time.UnixMilli(ms).Format("2 Jan 2006") }

func init() {
	// passkeyjs is passkeys.go's too; files init in name order, so both add it.
	tmpl.Funcs(template.FuncMap{"backupday": backupDay, "passkeyjs": func() template.JS { return template.JS(passkeyJS) }})
	template.Must(tmpl.Parse(`{{define "backups"}}{{template "head" ""}}
<h1>Backups</h1>
{{with .Err}}<p class="err">{{.}}</p>{{end}}{{with .Done}}<p class="ok">{{.}}</p>{{end}}
<p class="err" id="pk-msg"></p>
{{range .Choice.Lines}}<p class="err">{{.}}</p>{{end}}
{{with .Choice.Wipeable}}<p class="err">These places keep no old copies, so a hacked box could wipe them: {{range $i, $n := .}}{{if $i}}, {{end}}<strong>{{$n}}</strong>{{end}}. Use a drive that keeps old copies.</p>{{end}}
{{if eq .Step "tap"}}
<h2>Add this place</h2>
<p>Your hardware key signs exactly this. Check it, then tap.</p>
<p>Name: <strong>{{.Place.Name}}</strong><br>Kind: a folder on a second drive<br>Folder: <span class="mono">{{.Place.Locator}}</span><br>Keeps old copies: <strong>{{if .Place.AppendOnly}}yes{{else}}no{{end}}</strong></p>
<form method="post" action="/backups/" id="pk-finish" data-rp="{{.RP}}" data-challenge="{{.Challenge}}"><input type="hidden" name="step" value="add"><input type="hidden" name="ch" value="{{.Challenge}}"><input type="hidden" name="n" value="{{.N}}"><input type="hidden" name="name" value="{{.Place.Name}}"><input type="hidden" name="locator" value="{{.Place.Locator}}">{{if .Place.AppendOnly}}<input type="hidden" name="append" value="1">{{end}}<input type="hidden" name="ad"><input type="hidden" name="cd"><input type="hidden" name="sig"></form>
<p><button type="button" id="pk-tap">Tap a hardware key to add it</button></p>
<p><a href="/backups/">Cancel</a></p>
{{else}}
<h2>Where backups go</h2>
{{range .Choice.Places}}<p><strong>{{.Name}}</strong> <span class="mono">{{.Locator}}</span><br><span class="muted">{{if .AppendOnly}}keeps old copies{{else}}keeps no old copies{{end}}; {{if .Newest}}newest checked backup {{backupday .Newest}}{{else}}no checked backup yet{{end}}</span></p>
<form method="post" action="/backups/"><input type="hidden" name="step" value="remove"><input type="hidden" name="name" value="{{.Name}}"><button class="plain">Stop backups here</button></form>{{else}}<p>No backup: I hold the only copy of your data.</p>{{end}}
{{if .Choice.NoKey}}<p class="muted">I have no backup key yet, so no backup can start until your recovery key is replaced.</p>{{end}}
<h2>Add a second drive</h2>
<p>Plug a drive into me, then name it and give the folder on it. Your hardware key signs the place before I send anything there.</p>
<form method="post" action="/backups/"><input type="hidden" name="step" value="begin">
<label>Name<input type="text" name="name" maxlength="64" required placeholder="drive2"></label>
<label>Folder<input type="text" name="locator" maxlength="1024" required placeholder="/media/drive2/agentos"></label>
<label><input type="checkbox" name="append" value="1"> This drive keeps old copies (it cannot be wiped)</label>
<p><button>Continue</button></p></form>
{{end}}
<script>{{passkeyjs}}</script>
{{template "foot"}}{{end}}`))
}
