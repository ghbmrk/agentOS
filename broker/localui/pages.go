package localui

import (
	"bytes"
	"html/template"
	"net/http"
)

// Pages carry no script and load nothing from outside the box (ONB-1).
// Live progress refreshes with a meta refresh (ONB-4).
var tmpl = template.Must(template.New("layout").Funcs(template.FuncMap{"phase": phaseText, "boxhost": func() string { return "" }, "shrinkjs": func() template.JS { return template.JS(shrinkJS) }}).Parse(`{{define "head"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{{if .}}<meta http-equiv="refresh" content="{{.}}">{{end}}
<title>AgentOS</title>
<style>
:root { --fg: #111; --bg: #fff; --muted: #555; --line: #ccc; --accent: #0a58ca; --bad: #b00020; }
@media (prefers-color-scheme: dark) { :root { --fg: #eee; --bg: #121212; --muted: #aaa; --line: #444; --accent: #6ea8fe; --bad: #ff6b81; } }
body { font: 17px/1.45 system-ui, sans-serif; color: var(--fg); background: var(--bg); margin: 0; padding: 16px; max-width: 34em; }
h1 { font-size: 1.4em; margin: .2em 0 .6em; } h2 { font-size: 1.1em; }
.muted { color: var(--muted); font-size: .9em; } .err { color: var(--bad); } .ok { font-weight: 600; }
input[type=text], input[type=password], input[type=tel], select { font: inherit; width: 100%; box-sizing: border-box; padding: .6em; margin: .3em 0 .8em; border: 1px solid var(--line); border-radius: 8px; background: var(--bg); color: var(--fg); }
button, .button { font: inherit; display: inline-block; padding: .7em 1.2em; border-radius: 8px; border: 0; background: var(--accent); color: #fff; text-decoration: none; margin: .2em 0; }
button.plain { background: none; color: var(--accent); padding: .4em 0; }
.stop { background: var(--bad); }
.qr { width: 220px; height: 220px; display: block; margin: .6em 0; }
.mono { font-family: ui-monospace, Menlo, Consolas, monospace; word-break: break-all; }
form { margin: .6em 0 1.2em; }
</style></head><body>{{end}}
{{define "foot"}}<p class="muted">Box page: <span class="mono">http://{{boxhost}}/</span></p></body></html>{{end}}

{{define "status"}}{{template "head" .Refresh}}
<h1>AgentOS</h1>
{{with .Msg}}<p class="ok">{{.}}</p>{{end}}
<p>Box: <b>{{phase .Progress.Phase}}</b></p>
{{if .HasOwner}}
<p>Actions: <b>{{if .Owner.Stopped}}stopped{{else}}running{{end}}</b></p>
{{if or .Owner.Challenged .Owner.LowLocked}}<p>Approvals by text are paused after wrong codes. Sign in here to turn them back on.</p>{{end}}
{{if .Owner.Stopped}}
<form method="post" action="/resume">{{if not .SignedIn}}<label>Code from your code generator<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required></label>{{end}}<button>RESUME</button></form>
{{else}}
<form method="post" action="/stop"><button class="stop">STOP all actions</button></form>
{{end}}
{{if .SignedIn}}<p><a href="/home">More</a></p><form method="post" action="/signout"><button class="plain">Sign out of this phone</button></form>
{{else}}<p><a href="/unlock">Sign in</a></p>{{end}}
{{else if not .Done}}<p><a class="button" href="/setup">Continue setup</a></p>{{end}}
{{template "foot"}}{{end}}

{{define "unlock"}}{{template "head" ""}}
<h1>Sign in</h1>
{{if .HasOwner}}
{{if .Challenged}}<p>Approvals by text are paused after wrong codes. Sign in here to turn them back on.</p>{{end}}
<form method="post" action="/unlock">
<input type="hidden" name="next" value="{{.Next}}">
<label>Code from your code generator{{with .Cell}}, or grid cell <b>{{.}}</b> from your card{{end}}
<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus></label>
{{with .Err}}<p class="err">{{.}}</p>{{end}}
<button>Sign in</button>
</form>
<p class="muted">This phone stays signed in for {{.Days}} days, or until the box restarts. Signing in also unlocks chat by text, and the box texts you that a phone signed in.</p>
{{else}}<p>Setup is not finished yet. <a href="/setup">Continue setup</a></p>{{end}}
{{if .Vault}}<p><a href="/unlock/vault">Unlock the box on a new PC</a></p>{{end}}
<p><a href="/status">Status</a></p>
{{template "foot"}}{{end}}

{{define "vault"}}{{template "head" .Refresh}}
<h1>Unlock the box</h1>
{{if .Down}}<p>The box is still starting. This page reloads by itself.</p>
{{else if eq .State "open"}}<p class="ok">The box is unlocked.{{if .Kept}} This PC stays trusted.{{end}}</p>
<p>To approve by text again, <a href="/unlock">sign in</a> with your next code.</p>
{{else if eq .State "opening"}}<p>Checking the passphrase. This page reloads by itself.</p>
{{else if eq .State "pending"}}{{if .Mine}}<p class="ok">Passphrase accepted.</p>
<form method="post" action="/unlock/vault"><input type="hidden" name="step" value="code">
<label>Code from your code generator, by {{.Expires}}
<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus></label>
{{if .Keep}}<label><input type="checkbox" name="keep" value="1"> Keep this PC trusted</label><br>{{end}}
{{with .Err}}<p class="err">{{.}}</p>{{end}}
<button>Unlock</button></form>
{{else}}{{with .Err}}<p class="err">{{.}}</p>{{end}}
<p>An unlock is waiting for a code on another phone or a closed page. It ends by itself at {{.Expires}}.</p>{{end}}
{{else}}
<p><b>If this drive was out of your hands, unlock it only on your trusted PC.</b></p>
{{with .Boot}}<p class="err">{{.}}</p>{{end}}
{{with .Err}}<p class="err">{{.}}</p>{{end}}
{{if .PIN}}<form method="post" action="/unlock/vault"><input type="hidden" name="step" value="pin">
<label>This PC is trusted and has a boot PIN. Enter it
<input type="password" name="pin" inputmode="numeric" autocomplete="off" required></label>
<button>Unlock</button></form>
<h2>Or use your Owner Card</h2>{{end}}
<form method="post" action="/unlock/vault" enctype="multipart/form-data"><input type="hidden" name="step" value="passphrase">
<label>Photo of the vault passphrase QR code on your card
<input type="file" name="photo" id="photo" accept="image/*"></label>
<p class="muted">Or type the passphrase words.</p>
<input type="text" name="passphrase" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" aria-label="Passphrase words">
<button>Next</button></form>
<p class="muted">Next, the box asks for a code from your code generator. The passphrase alone does not unlock it.</p>
<script>{{shrinkjs}}</script>
{{end}}
<p><a href="/status">Status</a></p>
{{template "foot"}}{{end}}

{{define "home"}}{{template "head" ""}}
<h1>AgentOS</h1>
<ul>{{range .}}<li><a href="{{.Path}}">{{.Title}}</a></li>{{else}}<li class="muted">Nothing else to show here yet.</li>{{end}}</ul>
<p><a href="/status">Status, STOP and RESUME</a></p>
{{template "foot"}}{{end}}

{{define "restart"}}{{if .}}<details><summary>Lost that phone? Start setup over</summary>
<form method="post" action="/setup/restart"><label>Reset secret, from your card's recovery sheet<input type="text" name="secret" autocomplete="off" autocapitalize="characters" spellcheck="false" required></label><button>Start over</button></form></details>
{{else}}<form method="post" action="/setup/restart"><button class="plain">Start setup over</button></form>{{end}}{{end}}

{{define "private"}}<label><input type="checkbox" name="private" value="1" checked> {{.Name}} may see your private data (mail, files) to do tasks. Recommended.</label><br>{{end}}

{{define "setup"}}{{template "head" .Refresh}}
<h1>Set up AgentOS</h1>
<p class="muted">Box: {{phase .Progress.Phase}}</p>
{{with .Err}}<p class="err">{{.}}</p>{{end}}

{{if eq .Step "network"}}
<h2>1. Home network</h2>
<form method="post" action="/setup/network">
<label>Your home Wi-Fi<select name="ssid">{{range .Networks}}<option>{{.}}</option>{{end}}</select></label>
<label>Its password<input type="text" name="password" autocomplete="off" autocapitalize="off" spellcheck="false"></label>
<button>Join</button>
</form>
<form method="post" action="/setup/network"><input type="hidden" name="ethernet" value="1"><button class="plain">I plugged in an Ethernet cable</button></form>

{{else if eq .Step "number"}}
<h2>2. Text your box</h2>
{{if .SMSLink}}<p><a class="button" href="{{.SMSLink}}">Text my box</a></p>
<p class="muted">Your messages app opens with the box's number and a code filled in. Press Send, then come back here.</p>
<p class="muted">Or text <span class="mono">PAIR {{.PairCode}}</span> to <span class="mono">{{.BoxNumber}}</span>. The setup code on your card works too.</p>
<p><a href="/box.vcf">Save the box's number as a contact</a></p>{{end}}
<details><summary>Enter my number instead</summary>
<form method="post" action="/setup/number"><label>Your mobile number<input type="tel" name="number" placeholder="+1 555 010 0000" autocomplete="tel"></label><button>Text me a code</button></form>
{{if .NumTo}}<form method="post" action="/setup/number-code"><label>Code texted to {{.NumTo}}<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code"></label><button>Confirm</button></form>{{end}}
</details>
<p><a href="/setup">I sent it</a></p>

{{else if eq .Step "claim"}}
<h2>2. Text your box</h2>
<p>Your number ({{.Paired}}) is paired. The box texted you a page code; type it here to continue on this phone.</p>
<form method="post" action="/setup/claim"><label>Page code<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required></label><button>Continue</button></form>
{{template "restart" true}}

{{else if eq .Step "elsewhere"}}
<h2>Setup in progress</h2>
<p>Setup is continuing on the phone that texted the box ({{.Paired}}). Finish it there.</p>
{{template "restart" true}}

{{else if eq .Step "codes"}}
<p class="muted">Paired with your number {{.Paired}}.</p>{{template "restart" false}}
<h2>3. Add approval codes</h2>
<p><a class="button" href="{{.OTPLink}}">Add approval codes</a></p>
<p class="muted">Your phone's code generator opens (on iPhone, the Passwords app). If it does not, scan this with another device, or type the key.</p>
{{.OTPQR}}
<p class="mono">{{.OTPSecret}}</p>
<form method="post" action="/setup/codes"><label>Type the 6-digit code it shows<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required></label><button>Confirm</button></form>

{{else if eq .Step "recovery"}}
<h2>4. Recovery sheet</h2>
<p>Tear the recovery key sheet off your card and store it somewhere safe, apart from the drive. You will rarely need it.</p>
<form method="post" action="/setup/recovery"><label><input type="checkbox" name="stored" value="1"> I stored the recovery sheet</label><br><button>Continue</button></form>

{{else if eq .Step "host"}}
<h2>5. This PC</h2>
<p>This PC becomes your box's trusted PC, so it restarts by itself after a power cut.</p>
<form method="post" action="/setup/host"><label><input type="checkbox" name="not_mine" value="1"> This is not my PC</label><br><button>Continue</button></form>
{{with .Defaults}}<p class="muted">Defaults: {{.}} Change them any time by text or here.</p>{{end}}

{{else if eq .Step "ai"}}
<h2>6. Connect AI</h2>
{{if not .Progress.Updated}}<p>The box is still updating. This step opens when it finishes.</p>
{{else}}<p class="muted">One is enough. You can add more later.</p>
{{range .Providers}}<h3>{{.Name}}{{if .Connected}}: connected{{end}}</h3>
{{if not .Connected}}
{{if .DeviceCode}}{{with index $.Device .ID}}<p>Open <a href="{{index . 0}}">{{index . 0}}</a> and enter <span class="mono">{{index . 1}}</span>.</p><p><a href="/setup">I signed in</a></p>{{else}}<form method="post" action="/setup/ai-device"><input type="hidden" name="provider" value="{{.ID}}">{{template "private" .}}<button>Sign in with {{.Name}}</button></form>{{end}}{{end}}
{{if .APIKey}}<form method="post" action="/setup/ai-key"><input type="hidden" name="provider" value="{{.ID}}">{{template "private" .}}<label>Or paste an API key<input type="password" name="key" autocomplete="off"></label><button class="plain">Save key</button></form>{{end}}
{{end}}{{end}}{{end}}
{{end}}
{{template "foot"}}{{end}}
`))

func phaseText(p string) string {
	switch p {
	case "ready":
		return "ready"
	case "updating":
		return "updating (setup can continue)"
	}
	return "starting"
}

// pagesFor returns the page set with this box's address in the footer, so
// the owner always sees where the box page lives.
func pagesFor(host string) *template.Template {
	return template.Must(tmpl.Clone()).Funcs(template.FuncMap{"boxhost": func() string { return host }})
}

// render writes a page, buffering it so a template error never leaves a
// half page.
func (s *Server) render(w http.ResponseWriter, name string, v any) {
	var b bytes.Buffer
	if err := s.pages.ExecuteTemplate(&b, name, v); err != nil {
		http.Error(w, "Page error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	b.WriteTo(w)
}
