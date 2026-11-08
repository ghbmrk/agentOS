package localui

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// Forget is the Forget page's ops (LOG-4, KRN-forget c, #3414; D-284):
// agentosd looks a name up and answers what it holds under it by count
// and kind, then erases exactly that on one of the owner's passkeys'
// taps over it. session is the phone's session token, which agentosd
// checks. A refusal is a Refused with one of localapi.EraseCodes.
type Forget interface {
	ForgetFind(ctx context.Context, session, name string) (localapi.EraseFound, error)
	ForgetConfirm(ctx context.Context, session, handle string, authData, clientData, sig []byte) (string, error)
}

// The erase ops are agentosd's, on the same socket as its passkey ops,
// whose page name the tap is on: AgentosdPasskeys serves both.
func (a AgentosdPasskeys) ForgetFind(ctx context.Context, session, name string) (localapi.EraseFound, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var out localapi.EraseFound
	err := a.Owner.Call(ctx, localapi.OpEraseFind, localapi.EraseFind{Token: session, Name: name}, &out)
	return out, err
}

// ForgetConfirm's call is not bounded by callTimeout: the confirm returns
// only after every agent that read the erased content went back (D-169),
// and the page's own request bounds the wait.
func (a AgentosdPasskeys) ForgetConfirm(ctx context.Context, session, handle string, authData, clientData, sig []byte) (string, error) {
	var out localapi.Text
	err := a.Owner.Call(ctx, localapi.OpEraseConfirm, localapi.EraseConfirm{Token: session, Handle: handle,
		AuthenticatorData: authData, ClientDataJSON: clientData, Signature: sig}, &out)
	return out.Text, err
}

// ForgetTapAgainText is the tap step's answer when the tap was not one of
// the owner's passkeys over this list: the find still stands, so the owner
// taps again.
const ForgetTapAgainText = "That tap didn't match one of your passkeys, so nothing was forgotten. Tap again with your passkey."

// ForgetUnknownText answers a confirm that went out but got no refusal
// back (a timeout, a dropped socket): it may have erased.
const ForgetUnknownText = "I can't tell yet whether those were forgotten. Look the name up again to see what I still keep."

// forgetRefusedBefore reports whether err is one of agentosd's refusals,
// each given before anything is erased (localapi.EraseCodes and the
// session and argument checks).
func forgetRefusedBefore(err error) bool {
	var r Refused
	if !errors.As(err, &r) {
		return false
	}
	switch string(r) {
	case localapi.ErrEraseBadAssertion, localapi.ErrEraseStale, localapi.ErrEraseUnavailable,
		localapi.ErrBadArgs, localapi.ErrLimited, localapi.ErrUnauthorized:
		return true
	}
	return false
}

// forgetText is the owner's wording for each refusal; none carries a
// value, and anything else reads as agentosd not answering. Each says
// that nothing was forgotten.
func forgetText(err error) string {
	var r Refused
	errors.As(err, &r)
	switch string(r) {
	case localapi.ErrEraseBadAssertion:
		return ForgetTapAgainText
	case localapi.ErrEraseStale:
		return "That look-up expired or was already used, so nothing was forgotten. Look the name up again."
	case localapi.ErrBadArgs:
		return "Type a shorter name of letters, digits, spaces or plain punctuation, then look it up."
	case localapi.ErrLimited:
		return "Too many look-ups. Wait a minute, then try again."
	case localapi.ErrUnauthorized:
		return "Your sign-in ended, so nothing was forgotten. Sign in again, then look the name up again."
	}
	return "I couldn't reach the part of me that keeps your things, so nothing was forgotten. Try again in a minute."
}

// forgetView is the Forget page in one of its steps: the name form, or a
// passkey's tap over what was found.
type forgetView struct {
	RP string
	// Step is "" or "tap".
	Step string
	Name string
	// Found is agentosd's readback, shown unchanged.
	Found  string
	Handle string
	// Challenge is the tap's challenge, base64.
	Challenge string
	// Tok binds the tap step's fields to the phone (forgetToken).
	Tok       string
	Err, Done string
}

// forgetToken binds a tap step's handle, challenge, name and readback, as
// agentosd returned them, to the signed-in phone, so a wrong tap's retry
// shows only what this UI was given, never what the form made up (the
// passkey page's rule, #3239 item 2). Its input is kept apart from
// passkeyToken's and formToken's.
func (s *Server) forgetToken(sess string, v forgetView) string {
	m := hmac.New(sha256.New, s.formKey)
	m.Write([]byte("forget"))
	for _, p := range []string{sess, v.Handle, v.Challenge, v.Name, v.Found} {
		m.Write(binary.AppendUvarint(nil, uint64(len(p))))
		m.Write([]byte(p))
	}
	return hex.EncodeToString(m.Sum(nil))
}

// forgetPage serves /forget/ behind sign-in (CH-7): type a name, see what
// I hold under it by count and kind (agentosd's words), and forget exactly
// that on a passkey's tap. GET only shows; every step that reaches
// agentosd is a same-origin form post. Its one script is the passkey
// page's (passkeyJS), whose get() runs the tap.
func (s *Server) forgetPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", passkeyCSP)
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	v := forgetView{RP: s.cfg.PasskeyRPID}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		s.render(w, "forget", v)
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
	// The confirm waits for the agents to go back (D-169), so its bound
	// is the page's longest.
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	tok := cookieToken(r)
	f := r.PostForm
	switch f.Get("step") {
	case "find":
		v.Name = strings.TrimSpace(f.Get("name"))
		found, err := s.cfg.Forget.ForgetFind(ctx, tok, v.Name)
		if err != nil {
			v.Err = forgetText(err)
			break
		}
		v.Found = found.Text
		if found.Handle != "" && len(found.Challenge) == localapi.PasskeyChallenge {
			v.Step, v.Handle, v.Challenge = "tap", found.Handle, base64.StdEncoding.EncodeToString(found.Challenge)
			v.Tok = s.forgetToken(tok, v)
		}
	case "confirm":
		handle := f.Get("handle")
		ad, ok1 := formBytes(f.Get("ad"), localapi.MaxPasskeyAssertion)
		cd, ok2 := formBytes(f.Get("cd"), localapi.MaxPasskeyAssertion)
		sig, ok3 := formBytes(f.Get("sig"), localapi.MaxPasskeyAssertion)
		var err error = Refused(localapi.ErrEraseBadAssertion)
		if ok1 && ok2 && ok3 {
			var text string
			text, err = s.cfg.Forget.ForgetConfirm(ctx, tok, handle, ad, cd, sig)
			v.Done = text
		}
		// A tap that did not match stays on the tap step with the same
		// find, which the form carries back: only as this UI gave it to
		// this phone (forgetToken), never as the form made it up.
		back := forgetView{RP: v.RP, Step: "tap", Handle: handle, Challenge: f.Get("ch"), Name: f.Get("name"), Found: f.Get("found")}
		var ref Refused
		if errors.As(err, &ref) && string(ref) == localapi.ErrEraseBadAssertion &&
			hmac.Equal([]byte(f.Get("tok")), []byte(s.forgetToken(tok, back))) {
			back.Tok, back.Err = f.Get("tok"), ForgetTapAgainText
			v = back
			break
		}
		if err != nil {
			v.Done, v.Err = "", forgetText(err)
			if !forgetRefusedBefore(err) {
				// The confirm went out and no refusal came back: agentosd
				// may have erased, since its confirm runs to the end on its
				// own (D-169).
				v.Err = ForgetUnknownText
			}
		}
	default:
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	s.render(w, "forget", v)
}

func init() {
	// passkeyjs is passkeys.go's too; files init in name order, so each
	// page that runs the tap adds it.
	tmpl.Funcs(template.FuncMap{"passkeyjs": func() template.JS { return template.JS(passkeyJS) }})
	template.Must(tmpl.Parse(`{{define "forget"}}{{template "head" ""}}
<h1>Forget</h1>
{{with .Err}}<p class="err">{{.}}</p>{{end}}{{with .Done}}<p class="ok">{{.}}</p>{{end}}
<p class="err" id="pk-msg"></p>
{{if eq .Step "tap"}}
<p>{{.Found}}</p>
<p>Your passkey confirms forgetting exactly these. Forgetting cannot be undone.</p>
<form method="post" action="/forget/" id="pk-finish" data-rp="{{.RP}}" data-challenge="{{.Challenge}}" data-any="1"><input type="hidden" name="step" value="confirm"><input type="hidden" name="handle" value="{{.Handle}}"><input type="hidden" name="ch" value="{{.Challenge}}"><input type="hidden" name="name" value="{{.Name}}"><input type="hidden" name="found" value="{{.Found}}"><input type="hidden" name="tok" value="{{.Tok}}"><input type="hidden" name="ad"><input type="hidden" name="cd"><input type="hidden" name="sig"></form>
<p><button type="button" id="pk-tap">Tap your passkey to forget them</button></p>
<p><a href="/forget/">Cancel</a></p>
{{else}}
{{with .Found}}<p>{{.}}</p>{{end}}
<p>Type a name, such as a person's. I show what I hold under it, and forget it when you confirm with your passkey.</p>
<form method="post" action="/forget/"><input type="hidden" name="step" value="find">
<label>Name<input type="text" name="name" maxlength="256" required value="{{.Name}}"></label>
<p><button>Look it up</button></p></form>
{{end}}
<script>{{passkeyjs}}</script>
{{template "foot"}}{{end}}`))
}
