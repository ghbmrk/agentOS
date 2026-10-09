package localui

import (
	"bytes"
	"html/template"
	"net/http"
)

// Pages load nothing from outside the box and carry no script, except the
// vault page's one hash-allowed photo shrink (ONB-1, L17).
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
.card { border-top: 1px solid var(--line); padding-top: .4em; }
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
<form method="post" action="/resume">{{if or (not .SignedIn) .AskCode}}<label>Code from your code generator<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required></label>{{end}}<button>RESUME</button></form>
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
<p class="muted">This phone stays signed in for {{.Days}} days, or until I restart. Signing in also unlocks chat by text, and I text you that a phone signed in.</p>
{{else}}<p>Setup is not finished yet. <a href="/setup">Continue setup</a></p>{{end}}
{{if .Vault}}<p><a href="/unlock/vault">Unlock me on a new PC</a></p>{{end}}
<p><a href="/status">Status</a></p>
{{template "foot"}}{{end}}

{{define "vault"}}{{template "head" .Refresh}}
<h1>Unlock me</h1>
{{if .Down}}<p>I am still starting. This page reloads by itself.</p>
{{else if eq .State "open"}}<p class="ok">I am unlocked.{{if .Kept}} This PC stays trusted.{{end}}</p>
{{with .Change}}<p>{{.}}</p>{{end}}
{{if .SignedIn}}<p>This phone is signed in, and chat by text is unlocked.</p>
{{else}}<p>To approve by text again, <a href="/unlock">sign in</a> with your next code.</p>{{end}}
{{else if eq .State "opening"}}<p>Checking the passphrase. This page reloads by itself.</p>
{{else if eq .State "pending"}}{{if .Mine}}<p class="ok">Passphrase accepted.</p>
{{with .Change}}<p>{{.}}</p>{{end}}
<form method="post" action="/unlock/vault"><input type="hidden" name="step" value="code">
<label>Code from your code generator, by {{.Expires}}
<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus></label>
{{if .Keep}}<label><input type="checkbox" name="keep" value="1"> Keep this PC trusted</label><br>{{end}}
{{with .Err}}<p class="err">{{.}}</p>{{end}}
<button>Unlock</button></form>
{{else}}{{with .Err}}<p class="err">{{.}}</p>{{end}}
<p>An unlock is waiting for a code on another phone or a closed page. It ends by itself at {{.Expires}}.</p>
<h2>Start over on this phone</h2>
<p class="muted">This cancels the unlock waiting on the other phone.</p>
{{template "vaultcard"}}{{end}}
{{else}}
<p><b>If this drive was out of your hands, unlock it only on your trusted PC.</b></p>
{{with .Boot}}<p class="err">{{.}}</p>{{end}}
{{with .Err}}<p class="err">{{.}}</p>{{end}}
{{if .PIN}}<form method="post" action="/unlock/vault"><input type="hidden" name="step" value="pin">
<label>This PC is trusted and has a boot PIN. Enter it
<input type="password" name="pin" inputmode="numeric" autocomplete="off" required></label>
<button>Unlock</button></form>
<h2>Or use your Owner Card</h2>{{end}}
{{template "vaultcard"}}
{{end}}
<p><a href="/status">Status</a></p>
{{template "foot"}}{{end}}

{{define "vaultcard"}}<form method="post" action="/unlock/vault" enctype="multipart/form-data"><input type="hidden" name="step" value="passphrase">
<label>Photo of the vault passphrase QR code on your card
<input type="file" name="photo" id="photo" accept="image/*"></label>
<p class="muted">Or type the passphrase words.</p>
<input type="text" name="passphrase" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" aria-label="Passphrase words">
<button>Next</button></form>
<p class="muted">Next, I ask for a code from your code generator. The passphrase alone does not unlock it.</p>
<script>{{shrinkjs}}</script>{{end}}

{{define "secondline"}}{{template "head" .Refresh}}
<h1>Second line</h1>
{{if .Down}}<p>I am still starting. This page reloads by itself.</p>
{{else if .Locked}}<p>I am locked, so I can't read or change the second line. <a href="/unlock/vault">Unlock me</a>, then come back here.</p>
{{else}}
{{with .Err}}<p class="err">{{.}}</p>{{end}}
{{if and .Removing .St.Set}}<p>Remove the second line? Texts and calls from {{.St.Settings.Number}} stop, and you'll need the provider's password to add it again.</p>
<form method="post" action="/second-line/"><input type="hidden" name="step" value="remove"><input type="hidden" name="confirm" value="1"><button class="stop">Remove</button></form>
<p><a href="/second-line/">Cancel</a></p>
{{else if .St.Set}}
{{if .St.RealmConfirmed}}<p class="ok">The second line is ready: {{.St.Settings.Number}} through {{.St.Settings.Domain}}.</p>
{{else if .St.RealmRecorded}}<p>I signed in to your provider, which calls itself <b class="mono">{{.Realm}}</b>.
{{if .Matches}}This matches the domain you entered.{{else}}This differs from the domain you entered ({{.St.Settings.Domain}}). Some providers use another name here; check it on your provider's setup page.{{end}}</p>
<p>Texts and calls start once you confirm it is your provider.</p>
<form method="post" action="/second-line/"><input type="hidden" name="step" value="confirm"><input type="hidden" name="realm" value="{{.RealmExact}}"><button>It is my provider</button></form>
<p class="muted">If it is not, remove the second line below and check the server name with your provider.</p>
{{else if .St.WaitingForRegistration}}<p>Waiting for me to sign in to your provider. This page reloads by itself.</p>
{{if .Slow}}<p>Still trying. If this doesn't change in a few minutes, check the server name, port and password with your provider.</p>{{end}}
{{else}}<p class="err">I didn't reach your provider within 30 minutes of setup. Check the server name and password with your provider, then save the account again.</p>{{end}}
<p class="muted">{{.St.Settings.User}} at {{.St.Settings.Server}}, number {{.St.Settings.Number}}.</p>
<details{{if and (not .St.RealmRecorded) (not .St.WaitingForRegistration)}} open{{end}}><summary>Change the account</summary>{{template "lineform" .Form}}</details>
<form method="post" action="/second-line/"><input type="hidden" name="step" value="remove"><button class="stop">Remove the second line</button></form>
<p class="muted">I text you when the account is changed or removed.</p>
{{else}}
<p>A second line lets me text and call businesses for you from my own number, a calling (SIP) account you hold with a provider. Your own number stays private.</p>
<p>First, in your provider's settings: turn on encrypted calls (SRTP), and turn off voicemail on this number, so callers hear my message asking them to text instead.</p>
{{template "lineform" .Form}}
{{end}}
<h2>Texts over your provider's web API</h2>
{{if and .SMSRemoving .SMS.Set}}<p>Remove the texting account? Texts from {{.SMS.Settings.Number}} stop until you add it again with the provider's auth token.</p>
<form method="post" action="/second-line/"><input type="hidden" name="step" value="sms-remove"><input type="hidden" name="confirm" value="1"><button class="stop">Remove</button></form>
<p><a href="/second-line/">Cancel</a></p>
{{else if .SMS.Set}}<p class="ok">Texts go through {{.SMS.ProviderName}} from {{.SMS.Settings.Number}}.</p>
<details><summary>Change the texting account</summary>{{template "smsform" .SMSForm}}</details>
<form method="post" action="/second-line/"><input type="hidden" name="step" value="sms-remove"><button class="stop">Remove the texting account</button></form>
{{else}}<p>Some providers' calling accounts can't send texts. If yours is Twilio or SignalWire, I can text through the provider's web API instead, from the same number.</p>
<p class="muted">For a US number, register it for A2P 10DLC (business texting) in your provider's console first, or carriers block the texts.</p>
<details{{if .SMSForm.Provider}} open{{end}}><summary>Set up texting</summary>{{template "smsform" .SMSForm}}</details>
{{end}}{{end}}
<p><a href="/home">More</a> · <a href="/status">Status</a></p>
{{template "foot"}}{{end}}

{{define "lineform"}}<form method="post" action="/second-line/"><input type="hidden" name="step" value="set">
<label>Server and port<input type="text" name="server" value="{{.Server}}" placeholder="sip.example.net:5061" autocapitalize="none" autocorrect="off" spellcheck="false" required></label>
<label>SIP domain<input type="text" name="domain" value="{{.Domain}}" placeholder="example.net" autocapitalize="none" autocorrect="off" spellcheck="false" required></label>
<label>SIP user name<input type="text" name="user" value="{{.User}}" autocapitalize="none" autocorrect="off" spellcheck="false" required></label>
<label>The account's phone number<input type="tel" name="number" value="{{.Number}}" placeholder="+44 7700 900123" required></label>
<label><input type="checkbox" name="no_plus" value="1"{{if .NoPlus}} checked{{end}}> My provider dials numbers without the + sign</label><br>
<label>SIP password your provider generated<input type="password" name="password" autocomplete="off" required></label>
<button>Save</button></form>{{end}}

{{define "smsform"}}<form method="post" action="/second-line/"><input type="hidden" name="step" value="sms-set">
<label>Provider<select name="provider"><option value="twilio"{{if eq .Provider "twilio"}} selected{{end}}>Twilio</option><option value="signalwire"{{if eq .Provider "signalwire"}} selected{{end}}>SignalWire</option></select></label>
<label>SignalWire space (leave empty for Twilio)<input type="text" name="space" value="{{.Space}}" placeholder="your-space" autocapitalize="none" autocorrect="off" spellcheck="false"></label>
<label>Account SID (Twilio) or Project ID (SignalWire)<input type="text" name="account" value="{{.Account}}" autocapitalize="none" autocorrect="off" spellcheck="false" required></label>
<label>The number texts come from<input type="tel" name="number" value="{{.Number}}" placeholder="+1 555 010 0000" required></label>
<label>Auth token from the provider's console<input type="password" name="token" autocomplete="off" required></label>
<button>Save</button></form>{{end}}

{{define "approvals"}}{{template "head" ""}}
<h1>Approvals</h1>
{{with .Msg}}<p class="ok">{{.}}</p>{{end}}{{with .Err}}<p class="err">{{.}}</p>{{end}}
{{range .Requests}}<section class="card"><h2>{{.ID}}{{with .Expires}} <span class="muted">Answer before {{.}}</span>{{end}}</h2>
{{if .Local}}<p class="muted">Can't be shown in a text, so it is asked only here.</p>{{end}}
{{range .Items}}<p>{{if .Unverified}}<b>Unverified:</b> I could not read these details from the source. {{end}}<b>{{.Verb}}</b> {{.Object}}{{with .Detail}}, {{.}}{{end}}{{with .Amount}}, <b>{{.}}</b>{{end}}</p>
{{with .Terms}}<ul>{{range .}}<li><b>{{.Label}}:</b> {{.Value}}</li>{{end}}</ul>{{end}}
{{with .Recipients}}<p>To {{len .}} recipient{{if ne (len .) 1}}s{{end}}, exactly as the action uses them:</p><ul>{{range .}}<li class="mono">{{.}}</li>{{end}}</ul>{{end}}
{{if .Odd}}<p class="err">Has an unusual character, shown as [U+…]. Letters from other alphabets can look like plain ones; deny if you didn't expect it.</p>{{end}}
<p class="muted">{{.Undo}}</p>{{end}}
<form method="post" action="/approvals/"><input type="hidden" name="id" value="{{.ID}}"><input type="hidden" name="tok" value="{{.Tok}}"><input type="hidden" name="sum" value="{{.Sum}}">
{{with .Lets}}<p>Approving lets your agent {{.}}.</p>{{end}}
<label>Code from your code generator (not the one I texted), to approve<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code"></label>
<button name="answer" value="approve">Approve</button> <button name="answer" value="deny" class="stop">Deny</button></form></section>
{{else}}<p>Nothing is waiting for you.</p>{{end}}
<p class="muted">Each answer here is texted to you.</p>
<p><a href="/home">More</a> · <a href="/status">Status</a></p>
{{template "foot"}}{{end}}

{{define "follow"}}{{template "head" ""}}
<h1>Update source</h1>
{{with .Msg}}<p class="ok">{{.}}</p><p><a class="button" href="/approvals/">Go to Approvals</a></p>{{end}}{{with .Err}}<p class="err">{{.}}</p>{{end}}
{{with .Sum}}<section class="card"><h2>What following this source means</h2>
<p>Its root file is version {{.Version}}{{with .Expires}}, good until {{.}} by my clock{{end}}.</p>
<ul>{{range .Roles}}<li>{{.Does}}: {{.Need}} of {{.Have}} keys must agree.</li>{{end}}</ul>
<details><summary>Its root keys</summary><ul>{{range .RootIDs}}<li class="mono">{{.}}</li>{{end}}</ul></details>
{{if .Odd}}<p class="err">A key has an unusual character, shown as [U+…]. Don't follow a source you didn't expect this from.</p>{{end}}
<p>Fingerprint: <span class="mono">{{.Print}}</span>, the same as on the approval.<br><span class="muted">In full: <span class="mono">{{.Digest}}</span>. Check it matches the one the source publishes.</span></p>
{{if .Project}}<p>These are the AgentOS project's own keys, as I shipped with them.</p>
<form method="post" action="/follow/"><input type="hidden" name="digest" value="{{.Digest}}"><input type="hidden" name="tok" value="{{$.Tok}}"><input type="hidden" name="project" value="1">
<button name="step" value="ask">Switch back to the AgentOS project</button></form></section>
{{else}}<p class="err">Whoever holds these keys can change any of my software. Follow only a source you trust.</p>
<form method="post" action="/follow/"><input type="hidden" name="digest" value="{{.Digest}}"><input type="hidden" name="tok" value="{{$.Tok}}">
<label>Your name for this source<input type="text" name="name" maxlength="{{$.MaxName}}" autocomplete="off" spellcheck="false" required></label>
<button name="step" value="ask">Ask to follow it</button></form></section>{{end}}
{{else}}{{if not $.Msg}}<p>I get my software updates from the AgentOS project. To get them from another source you trust, such as a fork, choose that source's root file (root.json). To switch back after the project changed its keys, choose its root files from the one I last trusted to the newest. Nothing changes until you approve it with a code.</p>
<form method="post" action="/follow/" enctype="multipart/form-data"><label>Root file<br><input type="file" name="root" accept=".json,application/json" multiple required></label><br>
<button name="step" value="show">Show what it means</button></form>{{end}}{{end}}
<p><a href="/home">More</a> · <a href="/approvals/">Approvals</a> · <a href="/status">Status</a></p>
{{template "foot"}}{{end}}

{{define "paused"}}{{template "head" ""}}
<h1>Paused</h1>
{{with .Msg}}<p class="ok">{{.}}</p>{{end}}{{with .Err}}<p class="err">{{.}}</p>{{end}}
{{range .Grants}}<section class="card"><h2>{{.ID}}</h2>
<p>Resuming lets this run again: {{.What}}</p><p class="muted">Paused by {{.By}}.</p>
{{if .Odd}}<p class="err">Has an unusual character, shown as [U+…]. Don't resume it if you didn't expect it.</p>{{end}}
<form method="post" action="/paused/"><input type="hidden" name="grant" value="{{.ID}}"><input type="hidden" name="pause" value="{{.Pause}}"><input type="hidden" name="tok" value="{{.Tok}}">
<button>Ask to resume</button></form></section>
{{else}}<p>Nothing is paused.</p>{{end}}
<p class="muted">Asking puts the resume under Approvals; you approve it there with a code from your code generator. Each answer is texted to you.</p>
<p><a href="/approvals/">Approvals</a> · <a href="/home">More</a> · <a href="/status">Status</a></p>
{{template "foot"}}{{end}}

{{define "notready"}}{{template "head" "30"}}
<h1>AgentOS</h1>
<p>I'm not ready yet. This page reloads by itself. If it stays like this for more than a few minutes, turn the PC off and on again.</p>
{{template "foot"}}{{end}}
{{define "home"}}{{template "head" ""}}
<h1>AgentOS</h1>
{{with .Waiting}}<p class="ok"><a href="/approvals/">{{.}} waiting for you</a></p>{{end}}
{{with .Msg}}<p class="ok">{{.}}</p>{{end}}
{{with .LineNote}}<p class="err">{{.}}</p>{{end}}
{{if .SIM}}<section class="card"><form method="post" action="/line/sim"><input type="hidden" name="sim" value="{{.SIM}}">
<p>Do this only if you put this SIM in my phone modem yourself. Whoever has my number's SIM gets your texts with me.</p>
<label>Code from your code generator{{with .Cell}}, or grid cell <b>{{.}}</b> from your card{{end}}
<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required></label>
{{with .Err}}<p class="err">{{.}}</p>{{end}}
<button>Use the SIM ending in {{.SIMEnds}} for my number</button></form></section>
{{else}}{{with .Err}}<p class="err">{{.}}</p>{{end}}{{end}}
{{with .LineTexts}}<h2>Texts with you</h2><ul>{{range .}}<li>{{.}}</li>{{end}}</ul>{{end}}
<ul>{{range .Mounts}}<li><a href="{{.Path}}">{{.Title}}</a></li>{{else}}<li class="muted">Nothing else to show here yet.</li>{{end}}</ul>
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
<p class="muted">Your messages app opens with my number and a code filled in. Press Send, then come back here.</p>
<p class="muted">Or text <span class="mono">PAIR {{.PairCode}}</span> to <span class="mono">{{.BoxNumber}}</span>. The setup code on your card works too.</p>
<p><a href="/box.vcf">Save my number as a contact</a></p>{{end}}
<details><summary>Enter your number instead</summary>
<form method="post" action="/setup/number"><label>Your mobile number<input type="tel" name="number" placeholder="+1 555 010 0000" autocomplete="tel"></label><button>Text me a code</button></form>
{{if .NumTo}}<form method="post" action="/setup/number-code"><label>Code texted to {{.NumTo}}<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code"></label><button>Confirm</button></form>{{end}}
</details>
<p><a href="/setup">I sent it</a></p>

{{else if eq .Step "claim"}}
<h2>2. Text your box</h2>
<p>Your number ({{.Paired}}) is paired. I texted you a page code; type it here to continue on this phone.</p>
<form method="post" action="/setup/claim"><label>Page code<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required></label><button>Continue</button></form>
{{template "restart" true}}

{{else if eq .Step "elsewhere"}}
<h2>Setup in progress</h2>
<p>Setup is continuing on the phone that texted me ({{.Paired}}). Finish it there.</p>
{{template "restart" true}}

{{else if eq .Step "codes"}}
<p class="muted">Paired with your number {{.Paired}}.</p>{{template "restart" false}}
<h2>3. Add approval codes</h2>
{{if .CodesUnavailable}}
{{else if .CodesEnrolled}}<p>Approval codes are already set up. If you no longer have the code generator, replace it with your recovery key after setup.</p>
<form method="post" action="/setup/codes"><input type="hidden" name="enrolled" value="1"><button>Continue</button></form>
{{else if .CodesShown}}<form method="post" action="/setup/codes"><label>Type the 6-digit code your code generator shows for AgentOS<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required></label><button>Confirm</button></form>
<form method="post" action="/setup/codes"><input type="hidden" name="new" value="1"><button>Show a new key</button></form>
{{else if .OTPLink}}<p><a class="button" href="{{.OTPLink}}">Add approval codes</a></p>
<p class="muted">Your phone's code generator opens (on iPhone, the Passwords app). If it does not, scan this with another device, or type the key. Only the newest key works.</p>
{{.OTPQR}}
<p class="mono">{{.OTPSecret}}</p>
<form method="post" action="/setup/codes"><label>Type the 6-digit code it shows<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required></label><button>Confirm</button></form>
{{end}}
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
{{if not .Progress.Updated}}{{if eq .Progress.Phase "offline"}}<p>I am offline, so I am running the version I shipped with. I update when I am next online, and this step opens after that.</p>
{{else}}<p>I am updating to the latest version first. This step opens when it finishes.</p>{{end}}
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
	case "offline":
		return "offline (setup can continue)"
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
