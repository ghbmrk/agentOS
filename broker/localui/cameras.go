package localui

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// Cameras is the Cameras page's ops (CAM-clerk part d, #3514; DEV-7,
// DEV-10): agentosd lists the camera clerk's STATUS lines, the connected
// cameras and the nodes the enforcer lists, and relays one step on a
// camera, checking a tier-4 step's approval code first. session is the
// phone's session token, which agentosd checks. A refusal is a Refused
// with one of localapi.CameraCodes.
type Cameras interface {
	Cameras(ctx context.Context, session string) (localapi.CameraList, error)
	CameraChange(ctx context.Context, c localapi.CameraChange) error
}

// AgentosdCameras is Cameras over agentosd's camera ops on localui.sock.
type AgentosdCameras struct{ Owner Owner }

func (a AgentosdCameras) Cameras(ctx context.Context, session string) (localapi.CameraList, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var out localapi.CameraList
	err := a.Owner.Call(ctx, localapi.OpCameras, localapi.Auth{Token: session}, &out)
	return out, err
}

func (a AgentosdCameras) CameraChange(ctx context.Context, c localapi.CameraChange) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	return a.Owner.Call(ctx, localapi.OpCameraChange, c, nil)
}

// cameraText is the owner's wording for each refusal; none carries a
// value, and anything else reads as the clerk not answering.
func cameraText(err error) string {
	var r Refused
	errors.As(err, &r)
	switch string(r) {
	case localapi.ErrCameraCode:
		return "That approval code didn't work. Type the code your code generator shows now."
	case localapi.ErrCameraRefused:
		return "I can't connect that camera: the name is in use, its address is not on your home network, or I already run as many cameras as I can."
	case localapi.ErrCameraUnknown:
		return "No camera has that name. The list below is current."
	case localapi.ErrBadArgs:
		return "Fill in every field, then try again."
	case localapi.ErrLimited:
		return "Too many tries. Wait a minute, then try again."
	case localapi.ErrUnauthorized:
		return "Your sign-in ended. Sign in again, then try again."
	}
	return "I couldn't reach the part of me that runs your cameras. Try again in a minute."
}

// cameraModes are the capture settings the owner chooses from (DEV-7).
var cameraModes = map[string]bool{"off": true, "continuous": true, "on-request": true}

// maxRetentionDays bounds the retention the form takes (the clerk's own
// bound is far above it).
const maxRetentionDays = 3650

// camerasView is the Cameras page: the list, and the confirm step of a
// tier-4 change, which states what it does and takes the code.
type camerasView struct {
	List      localapi.CameraList
	Step      string // "" (the list) or "confirm"
	Change    localapi.CameraChange
	Err, Done string
}

// formCameraChange reads one step from the form. A connect takes the
// listed node the form names by address, as the clerk's list gave it, and
// the first 8 characters of its fingerprint the owner read off the case
// label, which must match.
func formCameraChange(f map[string][]string, list localapi.CameraList) (localapi.CameraChange, bool) {
	get := func(k string) string {
		if v := f[k]; len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	c := localapi.CameraChange{Step: get("step"), ID: get("id"), Capture: get("capture"), Code: get("code")}
	switch c.Step {
	case localapi.CameraConnect:
		addr, label := get("addr"), strings.ToLower(get("label"))
		for _, n := range list.Listed {
			if n.Addr == addr {
				c.Node = n
			}
		}
		if c.Node.Addr == "" || len(label) != 8 || !strings.HasPrefix(c.Node.Key, label) || c.ID == "" {
			return c, false
		}
		c.Capture = "off"
	case localapi.CameraCapture:
		if !cameraModes[c.Capture] {
			return c, false
		}
	case localapi.CameraRetention:
		d, err := strconv.Atoi(get("days"))
		if err != nil || d < 0 || d > maxRetentionDays {
			return c, false
		}
		c.RetentionDays = d
	case localapi.CameraRepin:
		addr, label := get("addr"), strings.ToLower(get("label"))
		for _, n := range list.Listed {
			if n.Addr == addr {
				c.Node = n
			}
		}
		if c.Node.Addr == "" || len(label) != 8 || !strings.HasPrefix(c.Node.Key, label) {
			return c, false
		}
	case localapi.CameraDisconnect:
	default:
		return c, false
	}
	return c, c.ID != ""
}

// camerasPage serves /cameras/ behind sign-in (CH-7): the clerk's STATUS
// lines, the connected cameras, the nodes the enforcer lists, and each
// step on a camera. A tier-4 step goes through a confirm step that states
// what it does (for capture, whether it is continuous or on request, and
// that recording other people may need their consent, DEV-7) and takes
// the approval code; GET only shows.
func (s *Server) camerasPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	tok := cookieToken(r)
	var v camerasView
	list := func() {
		l, err := s.cfg.Cameras.Cameras(ctx, tok)
		if err != nil {
			v.Err = cameraText(err)
		}
		v.List = l
	}
	list()
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		s.render(w, "cameras", v)
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
	c, ok := formCameraChange(r.PostForm, v.List)
	if !ok {
		v.Err = cameraText(Refused(localapi.ErrBadArgs))
		if c.Step == localapi.CameraConnect || c.Step == localapi.CameraRepin {
			v.Err = "That doesn't match: check the first 8 characters of the key on the camera's label, and give the camera a name."
		}
		s.render(w, "cameras", v)
		return
	}
	// A tier-4 step without its code, or a disconnect not yet confirmed,
	// shows the confirm step first.
	if (localapi.CameraTier4(c.Step) && c.Code == "") || (c.Step == localapi.CameraDisconnect && r.PostForm.Get("confirm") != "1") {
		v.Step, v.Change = "confirm", c
		s.render(w, "cameras", v)
		return
	}
	c.Token = tok
	if err := s.cfg.Cameras.CameraChange(ctx, c); err != nil {
		v.Err = cameraText(err)
		if refused(err, localapi.ErrCameraCode) {
			c.Code, v.Step, v.Change = "", "confirm", c
		}
		s.render(w, "cameras", v)
		return
	}
	v.Err = ""
	list()
	v.Done = "Done."
	s.render(w, "cameras", v)
}

// keyHead is a fingerprint's first 8 characters, as the case label shows.
func keyHead(k string) string { return k[:min(8, len(k))] }

func init() {
	tmpl.Funcs(template.FuncMap{"keyhead": keyHead})
	template.Must(tmpl.Parse(`{{define "cameras"}}{{template "head" ""}}
<h1>Cameras</h1>
{{with .Err}}<p class="err">{{.}}</p>{{end}}{{with .Done}}<p class="ok">{{.}}</p>{{end}}
{{if eq .Step "confirm"}}{{with .Change}}
<h2>{{if eq .Step "connect"}}Connect this camera{{else if eq .Step "capture"}}Change capture{{else if eq .Step "retention"}}Change what is kept{{else if eq .Step "repin"}}Re-pin this camera{{else}}Disconnect this camera{{end}}</h2>
<p>Camera: <strong>{{.ID}}</strong>{{with .Node.Addr}} at <span class="mono">{{.}}</span>{{end}}</p>
{{if eq .Step "connect"}}<p>It connects with capture off: I open no stream until you turn capture on.</p>{{end}}
{{if eq .Step "capture"}}{{if eq .Capture "continuous"}}<p>Capture <strong>continuous</strong>: I record this camera whenever I run.</p>{{else if eq .Capture "on-request"}}<p>Capture <strong>on request</strong>: I record only within a task that names this camera.</p>{{else}}<p>Capture <strong>off</strong>: I stop recording.</p>{{end}}{{if ne .Capture "off"}}<p>Recording other people may need their consent under your local law. Video stays on this box: it is never in recall or my log.</p>{{end}}{{end}}
{{if eq .Step "retention"}}<p>{{if .RetentionDays}}I keep this camera's recordings, encrypted, for <strong>{{.RetentionDays}} days</strong>.{{else}}I keep nothing on disk: recordings stay in memory only, and what was kept is erased.{{end}}</p>{{end}}
{{if eq .Step "repin"}}<p>The camera's new key replaces the old one; a camera with the old key is refused.</p>{{end}}
{{if eq .Step "disconnect"}}<p>I stop using this camera and erase its key and every recording I kept.</p>{{end}}
<form method="post" action="/cameras/"><input type="hidden" name="step" value="{{.Step}}"><input type="hidden" name="id" value="{{.ID}}"><input type="hidden" name="capture" value="{{.Capture}}"><input type="hidden" name="days" value="{{.RetentionDays}}">{{with .Node.Addr}}<input type="hidden" name="addr" value="{{.}}">{{end}}{{if .Node.Key}}<input type="hidden" name="label" value="{{keyhead .Node.Key}}">{{end}}
{{if eq .Step "disconnect"}}<input type="hidden" name="confirm" value="1"><p><button>Disconnect and erase</button></p>{{else}}<label>Approval code from your code generator<input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="16" required></label><p><button>Approve</button></p>{{end}}</form>
<p><a href="/cameras/">Cancel</a></p>
{{end}}{{else}}
{{range .List.Lines}}<p class="muted">{{.}}</p>{{end}}
<h2>Your cameras</h2>
{{range .List.Cameras}}<p><strong>{{.ID}}</strong> <span class="mono">{{.Addr}}</span><br><span class="muted">capture {{.Capture}}; {{if .RetentionDays}}kept {{.RetentionDays}} days{{else}}nothing kept on disk{{end}}</span></p>
<form method="post" action="/cameras/"><input type="hidden" name="step" value="capture"><input type="hidden" name="id" value="{{.ID}}"><label>Capture<select name="capture"><option value="off">Off</option><option value="continuous">Continuous</option><option value="on-request">On request</option></select></label><button class="plain">Change capture</button></form>
<form method="post" action="/cameras/"><input type="hidden" name="step" value="retention"><input type="hidden" name="id" value="{{.ID}}"><label>Keep recordings for (days, 0 for none)<input type="number" name="days" min="0" max="3650" value="{{.RetentionDays}}"></label><button class="plain">Change what is kept</button></form>
<form method="post" action="/cameras/"><input type="hidden" name="step" value="disconnect"><input type="hidden" name="id" value="{{.ID}}"><button class="plain">Disconnect</button></form>
{{else}}<p>No camera is connected.</p>{{end}}
{{if .List.Listed}}<h2>Cameras your enforcer found</h2>
<p>Compare the first 8 characters of the key with the label on the camera's case before you connect it or re-pin a camera to it.</p>
{{range .List.Listed}}<p><span class="mono">{{.Addr}}</span>: key starts <strong class="mono">{{keyhead .Key}}</strong></p>
<form method="post" action="/cameras/"><input type="hidden" name="step" value="connect"><input type="hidden" name="addr" value="{{.Addr}}">
<label>Name it<input type="text" name="id" maxlength="40" pattern="[a-z][a-z0-9-]*" required placeholder="porch"></label>
<label>First 8 characters on its label<input type="text" name="label" maxlength="8" required></label>
<button>Connect</button></form>
<form method="post" action="/cameras/"><input type="hidden" name="step" value="repin"><input type="hidden" name="addr" value="{{.Addr}}">
<label>Re-pin camera<input type="text" name="id" maxlength="40" required></label>
<label>First 8 characters on its label<input type="text" name="label" maxlength="8" required></label>
<button class="plain">Re-pin</button></form>{{end}}{{end}}
{{end}}
{{template "foot"}}{{end}}`))
}
