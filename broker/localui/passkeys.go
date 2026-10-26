package localui

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// Passkeys is the owner's passkeys as the passkey page uses them
// (#2779a; KEY-4, REC-3): agentosd lists them from the kernel's log,
// enrols a phone passkey from the page's two WebAuthn ceremonies and cuts
// one off. session is the phone's session token, which agentosd checks.
// A refusal is a Refused with one of localapi.PasskeyCodes.
type Passkeys interface {
	List(ctx context.Context, session string) (localapi.PasskeyList, error)
	Begin(ctx context.Context, session string, point []byte) (challenge []byte, err error)
	Finish(ctx context.Context, session string, authData, clientData, sig []byte) error
	CutOff(ctx context.Context, session, id string) error
}

// AgentosdPasskeys is Passkeys over agentosd's passkey ops on localui.sock.
type AgentosdPasskeys struct{ Owner Owner }

func (a AgentosdPasskeys) List(ctx context.Context, session string) (localapi.PasskeyList, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var out localapi.PasskeyList
	err := a.Owner.Call(ctx, localapi.OpPasskeys, localapi.Auth{Token: session}, &out)
	return out, err
}

func (a AgentosdPasskeys) Begin(ctx context.Context, session string, point []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var out localapi.PasskeyBegun
	err := a.Owner.Call(ctx, localapi.OpPasskeyBegin, localapi.PasskeyBegin{Token: session, Point: point}, &out)
	return out.Challenge, err
}

func (a AgentosdPasskeys) Finish(ctx context.Context, session string, authData, clientData, sig []byte) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	return a.Owner.Call(ctx, localapi.OpPasskeyFinish, localapi.PasskeyFinish{Token: session,
		AuthenticatorData: authData, ClientDataJSON: clientData, Signature: sig}, nil)
}

func (a AgentosdPasskeys) CutOff(ctx context.Context, session, id string) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	return a.Owner.Call(ctx, localapi.OpPasskeyCutOff, localapi.PasskeyCutOff{Token: session, ID: id}, nil)
}

// AnchorReply is the page's answer to cutting off a hardware key (#2740
// item 2, REC-3).
const AnchorReply = "That is one of your hardware keys. A hardware key is replaced only through recovery, with your Owner Card. To stop a lost phone, cut off the phone's passkey instead."

// passkeyText is the owner's wording for each refusal; none carries a
// value, and anything else reads as agentosd not answering.
func passkeyText(err error) string {
	var r Refused
	errors.As(err, &r)
	switch string(r) {
	case localapi.ErrPasskeyAnchor:
		return AnchorReply
	case localapi.ErrPasskeyNotAnchor:
		return "That tap was a phone passkey's. Only one of your hardware keys can add a passkey. Start again and tap a hardware key when asked."
	case localapi.ErrPasskeyBadAssertion:
		return "That tap didn't match. Start again, and tap one of your hardware keys when asked."
	case localapi.ErrPasskeyRefused:
		return "I couldn't add that passkey. A passkey you cut off can't come back: make a new one on the phone and start again."
	case localapi.ErrPasskeyStale:
		return "That took too long, or this page is out of date. Start again."
	case localapi.ErrPasskeySetup:
		return "Finish setup first."
	case localapi.ErrLimited:
		return "Too many tries. Wait a minute, then start again."
	case localapi.ErrUnauthorized:
		return "Your sign-in ended. Sign in again, then start again."
	}
	return "I couldn't reach the part of me that keeps your passkeys. Try again in a minute."
}

// passkeyJS is the passkey page's one script, pinned by its hash in the
// page's CSP (L6). It runs the two WebAuthn ceremonies and nothing else:
// create() for the phone's new ES256 passkey, whose public point it puts
// in the begin form, then get() on a hardware key over the challenge
// agentosd returned, whose answer it puts in the finish form. It talks
// only to this page's own forms, holds no secret, and shows only fixed
// words.
const passkeyJS = `(function () {
  var el = function (id) { return document.getElementById(id); };
  var say = function (t) { var m = el("pk-msg"); if (m) m.textContent = t; };
  var b64 = function (b) { b = new Uint8Array(b); var s = ""; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); };
  var unb64 = function (s) { return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); };
  var rnd = function (n) { var a = new Uint8Array(n); crypto.getRandomValues(a); return a; };
  var add = el("pk-add"), tap = el("pk-tap");
  if (!window.PublicKeyCredential || !navigator.credentials) {
    if (add || tap) say("This browser can't use passkeys.");
    return;
  }
  if (add) add.addEventListener("click", function () {
    var f = el("pk-begin");
    navigator.credentials.create({ publicKey: {
      rp: { id: f.dataset.rp, name: "agentOS" },
      user: { id: rnd(16), name: "agentOS owner", displayName: "agentOS owner" },
      challenge: rnd(32),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      attestation: "none"
    } }).then(function (c) {
      var r = c.response;
      if (r.getPublicKeyAlgorithm() !== -7) { say("That passkey isn't one I can use. Try again."); return; }
      var spki = new Uint8Array(r.getPublicKey());
      f.elements.point.value = b64(spki.slice(spki.length - 65));
      f.submit();
    }, function () { say("No passkey was made. Try again."); });
  });
  if (tap) tap.addEventListener("click", function () {
    var f = el("pk-finish");
    navigator.credentials.get({ publicKey: {
      challenge: unb64(f.dataset.challenge), rpId: f.dataset.rp,
      allowCredentials: [], userVerification: "required"
    } }).then(function (c) {
      var r = c.response;
      f.elements.ad.value = b64(r.authenticatorData);
      f.elements.cd.value = b64(r.clientDataJSON);
      f.elements.sig.value = b64(r.signature);
      f.submit();
    }, function () { say("No hardware key answered. Try again."); });
  });
})();`

// passkeyCSP is pageCSP plus the hash of passkeyJS, the only script the
// passkey page runs.
var passkeyCSP = func() string {
	h := sha256.Sum256([]byte(passkeyJS))
	return cspWith(base64.StdEncoding.EncodeToString(h[:]))
}()

// passkeysView is the passkey page in one of its steps: the list, the
// hardware key's tap, or the cut-off confirm.
type passkeysView struct {
	RP   string
	List localapi.PasskeyList
	// Step is "", "tap" or "confirm".
	Step string
	// Challenge is the tap's challenge, base64.
	Challenge string
	Confirm   localapi.Passkey
	Err, Done string
}

// formBytes is form field v as bytes: base64, 1 to max bytes.
func formBytes(v string, max int) ([]byte, bool) {
	if v == "" || len(v) > (max+2)/3*4 {
		return nil, false
	}
	b, err := base64.StdEncoding.DecodeString(v)
	return b, err == nil && len(b) > 0 && len(b) <= max
}

// passkeysPage serves /passkeys/ behind sign-in (CH-7), only with an RP ID
// (agentos-localui -passkey-rp-id): the owner's keys, adding a phone
// passkey, and cutting one off. GET only shows; every step that reaches
// agentosd is a same-origin form post.
func (s *Server) passkeysPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", passkeyCSP)
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	tok := cookieToken(r)
	v := passkeysView{RP: s.cfg.PasskeyRPID}
	list := func() {
		l, err := s.cfg.Passkeys.List(ctx, tok)
		if err != nil {
			v.Err = passkeyText(err)
		}
		v.List = l
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		list()
		s.render(w, "passkeys", v)
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
		point, ok := formBytes(f.Get("point"), localapi.PasskeyPoint)
		if !ok || len(point) != localapi.PasskeyPoint {
			v.Err = "That passkey isn't one I can use. Try again."
			break
		}
		c, err := s.cfg.Passkeys.Begin(ctx, tok, point)
		if err != nil {
			v.Err = passkeyText(err)
			break
		}
		v.Step, v.Challenge = "tap", base64.StdEncoding.EncodeToString(c)
		s.render(w, "passkeys", v)
		return
	case "finish":
		ad, ok1 := formBytes(f.Get("ad"), localapi.MaxPasskeyAssertion)
		cd, ok2 := formBytes(f.Get("cd"), localapi.MaxPasskeyAssertion)
		sig, ok3 := formBytes(f.Get("sig"), localapi.MaxPasskeyAssertion)
		if !ok1 || !ok2 || !ok3 {
			v.Err = passkeyText(Refused(localapi.ErrPasskeyBadAssertion))
			break
		}
		if err := s.cfg.Passkeys.Finish(ctx, tok, ad, cd, sig); err != nil {
			v.Err = passkeyText(err)
			break
		}
		v.Done = "Your phone's passkey is added. It works from now on."
	case "confirm", "cutoff":
		id := f.Get("id")
		list()
		k, ok := findPasskey(v.List, id)
		if !ok {
			v.Err = passkeyText(Refused(localapi.ErrPasskeyStale))
			break
		}
		if f.Get("step") == "confirm" {
			v.Step, v.Confirm = "confirm", k
			s.render(w, "passkeys", v)
			return
		}
		if err := s.cfg.Passkeys.CutOff(ctx, tok, id); err != nil {
			v.Err = passkeyText(err)
			break
		}
		v.Done = "That passkey is cut off for good. Anything it approved before stays as it was."
	default:
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	err := v.Err
	list()
	if err != "" {
		v.Err = err
	}
	s.render(w, "passkeys", v)
}

// findPasskey is the live key id names in l: a hardware key or a phone
// passkey, never one cut off already.
func findPasskey(l localapi.PasskeyList, id string) (localapi.Passkey, bool) {
	if id == "" {
		return localapi.Passkey{}, false
	}
	for _, k := range append(append([]localapi.Passkey{}, l.Anchors...), l.Enrolled...) {
		if k.ID == id {
			return k, true
		}
	}
	return localapi.Passkey{}, false
}

// algName is a key's algorithm as the page shows it.
func algName(alg string) string {
	switch alg {
	case "es256":
		return "ES256"
	case "ed25519":
		return "Ed25519"
	}
	return "unknown"
}

func init() {
	tmpl.Funcs(template.FuncMap{"passkeyjs": func() template.JS { return template.JS(passkeyJS) }, "algname": algName})
	template.Must(tmpl.Parse(`{{define "passkeys"}}{{template "head" ""}}
<h1>Passkeys</h1>
{{with .Err}}<p class="err">{{.}}</p>{{end}}{{with .Done}}<p class="ok">{{.}}</p>{{end}}
<p class="err" id="pk-msg"></p>
{{if eq .Step "tap"}}
<p>Now tap one of your hardware keys. It signs to add the new passkey; nothing is added until it does.</p>
<form method="post" action="/passkeys/" id="pk-finish" data-rp="{{.RP}}" data-challenge="{{.Challenge}}"><input type="hidden" name="step" value="finish"><input type="hidden" name="ad"><input type="hidden" name="cd"><input type="hidden" name="sig"></form>
<p><button type="button" id="pk-tap">Tap a hardware key</button></p>
<p><a href="/passkeys/">Cancel</a></p>
{{else if eq .Step "confirm"}}
<p>Cut off key <strong>{{.Confirm.Fingerprint}}</strong> ({{algname .Confirm.Alg}})? It is cut off for good: it can't approve anything again, and can't be added back.</p>
<form method="post" action="/passkeys/"><input type="hidden" name="step" value="cutoff"><input type="hidden" name="id" value="{{.Confirm.ID}}"><button>Cut off</button></form>
<p><a href="/passkeys/">Cancel</a></p>
{{else}}
<h2>Hardware keys</h2>
{{range .List.Anchors}}<p><strong>{{.Fingerprint}}</strong> <span class="muted">{{algname .Alg}}</span></p>
<form method="post" action="/passkeys/"><input type="hidden" name="step" value="confirm"><input type="hidden" name="id" value="{{.ID}}"><button>Cut off</button></form>{{else}}<p class="muted">None listed.</p>{{end}}
<h2>Phone passkeys</h2>
{{range .List.Enrolled}}<p><strong>{{.Fingerprint}}</strong> <span class="muted">{{algname .Alg}}, added with hardware key {{.By}}</span></p>
<form method="post" action="/passkeys/"><input type="hidden" name="step" value="confirm"><input type="hidden" name="id" value="{{.ID}}"><button>Cut off</button></form>{{else}}<p class="muted">None yet.</p>{{end}}
{{with .List.CutOff}}<h2>Cut off</h2>{{range .}}<p class="muted">{{.Fingerprint}} ({{algname .Alg}})</p>{{end}}{{end}}
<h2>Add a phone passkey</h2>
<p>On the phone you want to add, make a passkey here, then tap one of your hardware keys to approve it.</p>
<form method="post" action="/passkeys/" id="pk-begin" data-rp="{{.RP}}"><input type="hidden" name="step" value="begin"><input type="hidden" name="point"></form>
<p><button type="button" id="pk-add">Add a phone passkey</button></p>
{{end}}
<script>{{passkeyjs}}</script>
{{template "foot"}}{{end}}`))
}
