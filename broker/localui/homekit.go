package localui

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// HomeKit is the HomeKit page's ops (DEV-homekit part b2a, #3891; DEV-3,
// DEV-10, CH-3, CH-6): agentosd lists the HomeKit clerk's STATUS lines, its
// paired thermostats and the accessories the enforcer lists, and relays
// one step, checking a tier-4 step's approval code first. session is the
// phone's session token, which agentosd checks. A refusal is a Refused
// with one of localapi.HomeKitCodes.
type HomeKit interface {
	HomeKit(ctx context.Context, session string) (localapi.HomeKitList, error)
	HomeKitChange(ctx context.Context, c localapi.HomeKitChange) (localapi.HomeKitDone, error)
}

// AgentosdHomeKit is HomeKit over agentosd's HomeKit ops on localui.sock.
type AgentosdHomeKit struct{ Owner Owner }

func (a AgentosdHomeKit) HomeKit(ctx context.Context, session string) (localapi.HomeKitList, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var out localapi.HomeKitList
	err := a.Owner.Call(ctx, localapi.OpHomeKit, localapi.Auth{Token: session}, &out)
	return out, err
}

func (a AgentosdHomeKit) HomeKitChange(ctx context.Context, c localapi.HomeKitChange) (localapi.HomeKitDone, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var out localapi.HomeKitDone
	err := a.Owner.Call(ctx, localapi.OpHomeKitChange, c, &out)
	return out, err
}

// homekitText is the owner's wording for each refusal; none carries a
// value, and anything else reads as the clerk not answering.
func homekitText(err error) string {
	var r Refused
	errors.As(err, &r)
	switch string(r) {
	case localapi.ErrHomeKitApproval:
		return "That approval code didn't work. Type the code your code generator shows now."
	case localapi.ErrHomeKitCode:
		return "The thermostat refused that HomeKit code. Check the 8 digits it shows, then try again."
	case localapi.ErrHomeKitReset:
		return "The thermostat won't pair now. Reset HomeKit on it (on a T10 Pro: Menu, Installer Options, Reset, HomeKit), then try again."
	case localapi.ErrHomeKitRefused:
		return "I can't do that: the name is in use, your enforcer no longer lists that accessory, the bounds are outside what the thermostat takes, or I already hold as many thermostats as I can."
	case localapi.ErrHomeKitUnknown:
		return "No thermostat has that name. The list below is current."
	case localapi.ErrBadArgs:
		return "Fill in every field, then try again."
	case localapi.ErrLimited:
		return "Too many tries. Wait a minute, then try again."
	case localapi.ErrUnauthorized:
		return "Your sign-in ended. Sign in again, then try again."
	}
	return "I couldn't reach the part of me that runs your thermostats, or the thermostat itself. Try again in a minute."
}

// homekitSetpoints are the setpoints that take bounds, by HAP type, with
// the owner's words for them (clerk/homekit ThermostatRows).
var homekitSetpoints = map[string]string{"35": "target temperature", "12": "heating threshold", "D": "cooling threshold"}

// The bounds the form takes, in °C (a thermostat's own range is narrower,
// and the clerk checks it).
const homekitMinC, homekitMaxC = 0, 40

var (
	homekitNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	homekitCodeRE = regexp.MustCompile(`^[0-9]{8}$`)
)

// homekitCode reads the 8-digit HomeKit code the owner typed (CH-6), with
// or without its dashes or spaces, as XXX-XX-XXX.
func homekitCode(s string) (string, bool) {
	d := strings.NewReplacer("-", "", " ", "").Replace(s)
	if !homekitCodeRE.MatchString(d) {
		return "", false
	}
	return d[:3] + "-" + d[3:5] + "-" + d[5:], true
}

// homekitView is the HomeKit page: the list, and the confirm step of a
// change, which states what it does and takes the codes it needs.
type homekitView struct {
	List      localapi.HomeKitList
	Step      string // "" (the list) or "confirm"
	Change    localapi.HomeKitChange
	Err, Done string
}

// formHomeKitChange reads one step from the form against the list: a
// connect or re-pin takes a listed, unpaired accessory by the enforcer's
// device ID; a bounds step a setpoint and a range in °C.
func formHomeKitChange(f map[string][]string, list localapi.HomeKitList) (localapi.HomeKitChange, bool) {
	get := func(k string) string {
		if v := f[k]; len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	c := localapi.HomeKitChange{Step: get("step"), Name: get("name"), Device: get("device"), Code: get("code")}
	paired := false
	for _, d := range list.Devices {
		paired = paired || d.Name == c.Name
	}
	unpaired := false
	for _, l := range list.Listed {
		unpaired = unpaired || l.Device == c.Device && l.Unpaired
	}
	if hk := get("homekit_code"); hk != "" {
		code, ok := homekitCode(hk)
		if !ok {
			return c, false
		}
		c.HomeKitCode = code
	}
	switch c.Step {
	case localapi.HomeKitConnect:
		return c, homekitNameRE.MatchString(c.Name) && unpaired
	case localapi.HomeKitRepin:
		return c, paired && unpaired
	case localapi.HomeKitBounds:
		c.Char = get("char")
		lo, err1 := strconv.ParseFloat(get("min"), 64)
		hi, err2 := strconv.ParseFloat(get("max"), 64)
		if err1 != nil || err2 != nil || lo < homekitMinC || hi > homekitMaxC || lo > hi || homekitSetpoints[c.Char] == "" {
			return c, false
		}
		c.Min, c.Max = lo, hi
		return c, paired
	case localapi.HomeKitDisconnect:
		return c, paired
	}
	return c, false
}

// homekitPage serves /homekit/ behind sign-in (CH-7): the clerk's STATUS
// lines, the paired thermostats, the accessories the enforcer lists, and
// each step. A connect or re-pin goes through a confirm step that takes
// the thermostat's 8-digit HomeKit code (CH-6) and then the approval
// code; bounds take the approval code; a disconnect asks once more. GET
// only shows. The HomeKit code is never written back into the page.
func (s *Server) homekitPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	tok := cookieToken(r)
	var v homekitView
	list := func() {
		l, err := s.cfg.HomeKit.HomeKit(ctx, tok)
		if err != nil {
			v.Err = homekitText(err)
		}
		v.List = l
	}
	list()
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		s.render(w, "homekit", v)
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
	c, ok := formHomeKitChange(r.PostForm, v.List)
	if !ok {
		v.Err = homekitText(Refused(localapi.ErrBadArgs))
		if r.PostForm.Get("homekit_code") != "" && c.HomeKitCode == "" {
			v.Err = "A HomeKit code is 8 digits, as the thermostat shows it."
			c.Code = ""
			v.Step, v.Change = "confirm", c
		}
		s.render(w, "homekit", v)
		return
	}
	pairs := c.Step == localapi.HomeKitConnect || c.Step == localapi.HomeKitRepin
	// A step without the codes it needs, or a disconnect not yet
	// confirmed, shows the confirm step first.
	if (localapi.HomeKitTier4(c.Step) && c.Code == "") || (pairs && c.HomeKitCode == "") ||
		(c.Step == localapi.HomeKitDisconnect && r.PostForm.Get("confirm") != "1") {
		c.HomeKitCode, c.Code = "", ""
		v.Step, v.Change = "confirm", c
		s.render(w, "homekit", v)
		return
	}
	c.Token = tok
	done, err := s.cfg.HomeKit.HomeKitChange(ctx, c)
	if err != nil {
		v.Err = homekitText(err)
		if refused(err, localapi.ErrHomeKitApproval) || refused(err, localapi.ErrHomeKitCode) {
			c.HomeKitCode, c.Code, v.Step, v.Change = "", "", "confirm", c
		}
		s.render(w, "homekit", v)
		return
	}
	v.Err = ""
	list()
	v.Done = "Done."
	if done.Reset {
		v.Done = "I removed it here, but I couldn't reach the thermostat: reset HomeKit on it so it stops expecting me."
	}
	s.render(w, "homekit", v)
}

func init() {
	tmpl.Funcs(template.FuncMap{"setpoint": func(c string) string { return homekitSetpoints[c] }})
	template.Must(tmpl.Parse(`{{define "homekit"}}{{template "head" ""}}
<h1>HomeKit</h1>
{{with .Err}}<p class="err">{{.}}</p>{{end}}{{with .Done}}<p class="ok">{{.}}</p>{{end}}
{{if eq .Step "confirm"}}{{with .Change}}
<h2>{{if eq .Step "connect"}}Connect this thermostat{{else if eq .Step "repin"}}Re-pin this thermostat{{else if eq .Step "bounds"}}Confirm setpoint bounds{{else}}Disconnect this thermostat{{end}}</h2>
{{if .Name}}<p>Thermostat: <strong>{{.Name}}</strong>{{with .Device}}, accessory <span class="mono">{{.}}</span> from your enforcer{{end}}</p>{{end}}
{{if eq .Step "connect"}}<p>I pair with it as its only controller. It keeps its schedule, and I read it here on your home network; nothing goes to the internet.</p>{{end}}
{{if eq .Step "repin"}}<p>Reset HomeKit on the thermostat first (on a T10 Pro: Menu, Installer Options, Reset, HomeKit). Its new key replaces the old one; a thermostat with the old key is refused.</p>{{end}}
{{if eq .Step "bounds"}}<p>Inside <strong>{{.Min}}–{{.Max}} °C</strong> I may set the {{setpoint .Char}} and undo it; outside them every change needs your code generator's code.</p>{{end}}
{{if eq .Step "disconnect"}}<p>I remove my pairing from the thermostat and forget it. If I can't reach it, reset HomeKit on it afterwards.</p>{{end}}
<form method="post" action="/homekit/"><input type="hidden" name="step" value="{{.Step}}"><input type="hidden" name="name" value="{{.Name}}">{{with .Device}}<input type="hidden" name="device" value="{{.}}">{{end}}{{if eq .Step "bounds"}}<input type="hidden" name="char" value="{{.Char}}"><input type="hidden" name="min" value="{{.Min}}"><input type="hidden" name="max" value="{{.Max}}">{{end}}
{{if eq .Step "disconnect"}}<input type="hidden" name="confirm" value="1"><p><button>Disconnect</button></p>{{else}}{{if or (eq .Step "connect") (eq .Step "repin")}}<label>HomeKit code (the 8 digits on the thermostat)<input type="text" name="homekit_code" inputmode="numeric" autocomplete="off" maxlength="10" required></label>{{end}}
<label>Approval code from your code generator<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="16" required></label><p><button>Approve</button></p>{{end}}</form>
<p><a href="/homekit/">Cancel</a></p>
{{end}}{{else}}
{{range .List.Lines}}<p class="muted">{{.}}</p>{{end}}
<h2>Your thermostats</h2>
{{range .List.Devices}}<p><strong>{{.Name}}</strong>: {{.Type}}, key starts <strong class="mono">{{.Key}}</strong><br><span class="muted">{{.State}}{{range $c, $b := .Bounds}}; {{setpoint $c}} {{$b.Min}}–{{$b.Max}} °C{{end}}</span></p>
<form method="post" action="/homekit/"><input type="hidden" name="step" value="bounds"><input type="hidden" name="name" value="{{.Name}}"><label>Setpoint<select name="char"><option value="35">Target temperature</option><option value="12">Heating threshold</option><option value="D">Cooling threshold</option></select></label><label>From (°C)<input type="number" name="min" min="0" max="40" step="0.5" required></label><label>To (°C)<input type="number" name="max" min="0" max="40" step="0.5" required></label><button class="plain">Confirm bounds</button></form>
<form method="post" action="/homekit/"><input type="hidden" name="step" value="disconnect"><input type="hidden" name="name" value="{{.Name}}"><button class="plain">Disconnect</button></form>
{{else}}<p>No thermostat is connected.</p>{{end}}
{{if .List.Listed}}<h2>HomeKit accessories your enforcer found</h2>
{{range .List.Listed}}<p>HomeKit accessory <strong class="mono">{{.Device}}</strong> at <span class="mono">{{.Addr}}</span>{{if not .Unpaired}}: paired with something else. Reset HomeKit on it to connect it here.{{end}}</p>
{{if .Unpaired}}<form method="post" action="/homekit/"><input type="hidden" name="step" value="connect"><input type="hidden" name="device" value="{{.Device}}">
<label>Name it<input type="text" name="name" maxlength="32" pattern="[a-z][a-z0-9-]*" required placeholder="hall"></label>
<button>Connect</button></form>
{{if $.List.Devices}}<form method="post" action="/homekit/"><input type="hidden" name="step" value="repin"><input type="hidden" name="device" value="{{.Device}}">
<label>Re-pin thermostat<select name="name">{{range $.List.Devices}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select></label>
<button class="plain">Re-pin</button></form>{{end}}{{end}}{{end}}{{end}}
{{end}}
{{template "foot"}}{{end}}`))
}
