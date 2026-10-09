package localui

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// The Update source page (OSS-10, GR26): the owner brings a root file from
// a source they trust (a fork, or the project's own to switch back), sees
// what following it means, names it and asks. The ask is a tier-4 request
// agentosd confirms only from this page, approved on the Approvals page
// with a code; nothing changes until then (WF3).

// followView is the Update source page.
type followView struct {
	// Sum is the root shown, with Tok binding the ask form to it.
	Sum           *rootView
	Tok, Msg, Err string
	MaxName       int
}

type rootView struct {
	Version int64
	Expires string
	Digest  string
	// Print is the short fingerprint the approval card shows
	// (grants.FollowPrint).
	Print string
	// Project: the root has the project's own keys, so the form offers
	// only switching back, with no name (WF1).
	Project bool
	Roles   []roleView
	RootIDs []string
	Odd     bool
}

type roleView struct {
	Does       string
	Need, Have int
}

// followRoles are the roles shown, with what their keys do.
var followRoles = []struct{ role, does string }{
	{"root", "To change these keys"},
	{"targets", "To sign software"},
	{"snapshot", "To vouch for the list of software"},
	{"timestamp", "To vouch the list is current"},
}

// The page's own words for a refused root (OSS-10w L3: only the coarse
// cause agentosd names).
const (
	rootExpiredText    = "This root file has expired by this box's clock. Ask the source for its current root file."
	rootSignaturesText = "This root file isn't signed by enough of its own keys, so the box can't trust it."
	rootThresholdText  = "This root file lets too few keys sign. This box needs at least two keys to agree for each change."
	rootUnreadText     = "The box can't use this root file. Check it's the root.json the source gave you, or ask the source's maintainers for theirs."
	rootTooBigText     = "That file is too big to be a root file. Make sure you chose the source's root.json."
	rootTooManyText    = "That is too many root files. Choose the newest root file, and for switching back, the project's root files after the one this box last trusted."
	followOffText      = "This box can't change where its updates come from. Nothing was changed."
	followStale        = "This page is out of date. Choose the root file again."
	followUnreachable  = "The box isn't answering right now. Nothing was asked. Reload to try again."
	followNoName       = "Give this source a name first. The box's texts use it to say where updates come from."
	followReservedName = "Choose another name. Only switching back may be called " + reservedName + "."
)

// reservedName starts only the switch back's line (grants.ReservedFollowName;
// security 323-1). The page refuses it before asking, and the gate again.
const reservedName = "the AgentOS project"

// followPrint is grants.FollowPrint: the digest's first 8 hex characters in
// two groups of 4, as the approval card shows them.
func followPrint(digest string) string {
	if len(digest) < 8 {
		return ""
	}
	return digest[:4] + "-" + digest[4:8]
}

// follow serves the Update source page behind sign-in (CH-7).
func (s *Server) follow(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if s.getOwner() == nil {
		http.Redirect(w, r, "/status", http.StatusSeeOther)
		return
	}
	tok := cookieToken(r)
	sess := tokenKey(tok)
	v := followView{MaxName: localapi.MaxFollowName / 4}
	unauth := false
	if r.Method == http.MethodPost {
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			unauth = s.showRoot(w, r, tok, sess, &v)
		} else {
			unauth = s.askFollow(r, w, tok, sess, &v)
		}
	}
	if unauth {
		http.Redirect(w, r, "/unlock?next=/follow/", http.StatusSeeOther)
		return
	}
	s.render(w, "follow", v)
}

// showRoot reads the brought files and shows agentosd's summary of the
// newest: the others go with it as the chain a switch back across the
// project's key rotations walks (OSS-10w-r). It reports a session agentosd
// no longer knows.
func (s *Server) showRoot(w http.ResponseWriter, r *http.Request, tok, sess string, v *followView) bool {
	r.Body = http.MaxBytesReader(w, r.Body, (localapi.MaxRootChain+1)*localapi.MaxRoot+64<<10)
	mr, err := r.MultipartReader()
	if err != nil {
		v.Err = rootUnreadText
		return false
	}
	var files [][]byte
	var bad error
	for {
		p, err := mr.NextPart()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				bad = err
			}
			break
		}
		if p.FormName() != "root" {
			continue
		}
		if len(files) == localapi.MaxRootChain+1 {
			v.Err = rootTooManyText
			return false
		}
		b, err := io.ReadAll(io.LimitReader(p, localapi.MaxRoot+1))
		switch {
		case err != nil:
			bad = err
		case len(b) > localapi.MaxRoot:
			v.Err = rootTooBigText
			return false
		case len(b) > 0:
			files = append(files, b)
		}
		if bad != nil {
			break
		}
	}
	switch {
	case bad != nil:
		v.Err = rootUnreadText
		return false
	case len(files) == 0:
		v.Err = "Choose the source's root file first."
		return false
	}
	root, chain := newestRoot(files)
	var sum localapi.RootSummary
	err = s.call(r.Context(), localapi.OpFollowRoot, localapi.FollowRoot{Token: tok, Root: root, Chain: chain}, &sum)
	switch {
	case refused(err, localapi.ErrUnauthorized):
		return true
	case refused(err, localapi.ErrFailed):
		v.Err = followOffText
		return false
	case err != nil:
		v.Err = followUnreachable
		return false
	}
	if sum.Refusal != "" {
		v.Err = refusedRootText(sum.Reason)
		return false
	}
	v.Sum, v.Tok = s.rootView(sum), s.followToken(sess, sum.Digest, sum.Project)
	return false
}

// newestRoot picks the file with the highest root version (the first, on
// a tie or when none reads) as the root; the rest, in the order brought,
// are its chain. Only agentosd verifies them.
func newestRoot(files [][]byte) (root []byte, chain [][]byte) {
	best, top := 0, int64(-1)
	for i, b := range files {
		var m struct {
			Signed struct {
				Version int64 `json:"version"`
			} `json:"signed"`
		}
		if json.Unmarshal(b, &m) == nil && m.Signed.Version > top {
			best, top = i, m.Signed.Version
		}
	}
	for i, b := range files {
		if i != best {
			chain = append(chain, b)
		}
	}
	return files[best], chain
}

func refusedRootText(reason string) string {
	switch reason {
	case localapi.RootExpired:
		return rootExpiredText
	case localapi.RootSignatures:
		return rootSignaturesText
	case localapi.RootThreshold:
		return rootThresholdText
	}
	return rootUnreadText
}

func (s *Server) rootView(sum localapi.RootSummary) *rootView {
	rv := &rootView{Version: sum.Version, Digest: sum.Digest, Print: followPrint(sum.Digest), Project: sum.Project}
	if !sum.Expires.IsZero() {
		rv.Expires = sum.Expires.UTC().Format("2 January 2006")
	}
	for _, fr := range followRoles {
		if n := len(sum.Keys[fr.role]); n > 0 {
			rv.Roles = append(rv.Roles, roleView{Does: fr.does, Need: sum.Thresholds[fr.role], Have: n})
		}
	}
	for _, id := range sum.Keys["root"] {
		shown, odd := showField(id)
		rv.RootIDs = append(rv.RootIDs, shown)
		rv.Odd = rv.Odd || odd
	}
	return rv
}

// askFollow asks agentosd to follow the shown root under the owner's name
// for it. It reports a session agentosd no longer knows.
func (s *Server) askFollow(r *http.Request, w http.ResponseWriter, tok, sess string, v *followView) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		v.Err = followStale
		return false
	}
	get := func(k string) string {
		if x := r.PostForm[k]; len(x) == 1 {
			return x[0]
		}
		return ""
	}
	digest, name, project := get("digest"), get("name"), get("project") == "1"
	// Bound to this phone's sign-in, the root it was shown and whether
	// that root was offered as switching back, as the Approvals form is
	// (Security D1). Switching back carries no name (WF1).
	if get("step") != "ask" || len(digest) != localapi.DigestLen ||
		!hmac.Equal([]byte(get("tok")), []byte(s.followToken(sess, digest, project))) || project && name != "" {
		v.Err = followStale
		return false
	}
	switch {
	case !project && name == "":
		v.Err = followNoName
		return false
	case strings.HasPrefix(strings.ToLower(name), strings.ToLower(reservedName)):
		v.Err = followReservedName
		return false
	case len(name) > localapi.MaxFollowName:
		v.Err = fmt.Sprintf("Use a name of at most %d characters.", localapi.MaxFollowName/4)
		return false
	}
	var t localapi.Text
	err := s.call(r.Context(), localapi.OpFollow, localapi.Follow{Token: tok, Name: name, Digest: digest}, &t)
	var rf Refused
	switch {
	case refused(err, localapi.ErrUnauthorized):
		return true
	case refused(err, localapi.ErrFailed):
		v.Err = followOffText
	case errors.As(err, &rf):
		v.Err = followStale
	case err != nil:
		v.Err = followUnreachable
	case strings.HasPrefix(t.Text, "Not asked"):
		// The box refused it (daemon.FollowRefused and its kin).
		v.Err = t.Text
	default:
		v.Msg = t.Text
	}
	return false
}

// followToken binds the ask form to the signed-in phone, the shown root's
// digest and whether it was offered as switching back; its label keeps it
// apart from an Approvals form token.
func (s *Server) followToken(sess, digest string, project bool) string {
	m := hmac.New(sha256.New, s.formKey)
	fmt.Fprintf(m, "follow\x00%s\x00%s\x00%t", sess, digest, project)
	return hex.EncodeToString(m.Sum(nil))
}
