package browser

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/childproc"
)

// MaxLine bounds one driver reply.
const MaxLine = 8 << 20

// Bounds on a reply's other fields.
const (
	maxTitle     = 1024
	maxErrDetail = 4096
	maxRefused   = 16
)

// MaxDownloadScan bounds how much of a downloaded file the gate reads to scan;
// a larger file is withheld rather than passed unscanned.
const MaxDownloadScan = 50 << 20

// Config starts one executor: one account, one driver process.
type Config struct {
	// Driver is the sandboxed driver's argv; the gate appends
	// --origins <declared...> --workspace <dir>.
	Driver []string
	// Origins are the account's declared origins (CRED-10).
	Origins []string
	// Workspace is the only directory the driver writes to (screenshots,
	// downloads). Created 0700 if missing.
	Workspace string
	// Scrub removes the vault's exact secret values from every output.
	Scrub Scrubber
	// Timeout bounds one driver reply; 0 means 60s. A driver that misses it
	// is stopped.
	Timeout time.Duration
	// Env is the driver's whole environment beyond PATH, HOME and LANG; the
	// broker's own environment is never inherited. Each key must be on
	// childproc's allowlist, or Start refuses the configuration.
	Env []string
	// StateLinks are the recipe's own state-changing link patterns: URL
	// path prefixes on the declared origins. They add to the defaults
	// (ADP-14-get).
	StateLinks []string
	// LoggedOut declares that the clerk supplies this account's sessions
	// no identity: no cookies, password or card. Only then are clicks,
	// typing and selects free (G9, D-147). Left false, identity is unknown
	// and the gate fails closed.
	LoggedOut bool
	// TokenParams are the recipe's session and anti-forgery token query
	// parameters. Their values are left out of an approval's print, so a
	// rotated token is the same submit (CLK-3).
	TokenParams []string
}

// Result is everything an agent can see from one request. Fields the driver
// sends that are not here are dropped.
type Result struct {
	OK                 bool     `json:"ok"`
	Error              string   `json:"error,omitempty"`
	Detail             string   `json:"detail,omitempty"`
	URL                string   `json:"url,omitempty"`
	Title              string   `json:"title,omitempty"`
	Snapshot           string   `json:"snapshot,omitempty"`
	Truncated          bool     `json:"truncated,omitempty"`
	Redactions         int      `json:"redactions,omitempty"`
	PasswordFields     int      `json:"password_fields,omitempty"`
	Path               string   `json:"path,omitempty"`
	Bytes              int64    `json:"bytes,omitempty"`
	RefusedNavigations []string `json:"refused_navigations,omitempty"`
	// To names what an action waiting for approval reaches (error
	// "approval_required"): the role, quoted name and target of the ref, or
	// the URL of a navigate, after the output filter.
	To string `json:"to,omitempty"`
	// Approval is what the owner would approve for it (CLK-3).
	Approval *Approval `json:"approval,omitempty"`
	// Covered is the STATUS line for a submit a task's approval covered,
	// once sent: the site, the control's label and the time (CLK-3).
	Covered string `json:"covered,omitempty"`
}

// Gate is one running executor behind the protocol gate.
type Gate struct {
	cfg     Config
	origins Origins
	filter  filter
	ws      string
	links   stateLinks
	// secret keys approval prints; it never leaves the gate.
	secret []byte
	tokens map[string]bool

	mu      sync.Mutex
	cmd     *childproc.Cmd
	stdin   io.WriteCloser
	lines   chan []byte
	stopped bool
	// refs is what the last snapshot the driver returned showed, per ref.
	refs map[string]link
	// shown is the same refs as the agent saw them, read from the snapshot
	// after omission and the output filter: what an approval shows.
	shown map[string]link
	// page is the URL of the page the refs were read from.
	page string
	// typed is what the agent typed, per ref, on the page the driver
	// named in its reply (G10).
	typed map[string]typedField
	// said is the text the agent put on pages, by type or in a URL it
	// navigated to, kept on every page (G10, #2245).
	said []string
	// lost is set once typed or said overflows maxTyped. From then on
	// every snapshot with an omitted field is withheld: forgetting agent
	// text would let its echo answer a guess (PR #2273 security delta).
	lost bool
	// sent is every approval print this gate has sent: each at most once.
	sent map[string]bool
}

// cover is a task approval as the clerk read it from the log: the site it
// covers and the held request the owner gave it over (CLK-3).
type cover struct{ site, first string }

// Start launches the driver for one account.
func Start(ctx context.Context, cfg Config) (*Gate, error) {
	origins, err := NewOrigins(cfg.Origins)
	if err != nil {
		return nil, err
	}
	links, err := newStateLinks(cfg.StateLinks, origins)
	if err != nil {
		return nil, err
	}
	if len(cfg.Driver) == 0 {
		return nil, errors.New("browser: no driver")
	}
	ws, err := filepath.Abs(cfg.Workspace)
	if err != nil || cfg.Workspace == "" {
		return nil, errors.New("browser: no workspace")
	}
	if err := os.MkdirAll(ws, 0o700); err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	tokens := map[string]bool{}
	for _, t := range cfg.TokenParams {
		tokens[t] = true
	}
	args := append(append([]string{}, cfg.Driver[1:]...), "--origins")
	args = append(append(args, cfg.Origins...), "--workspace", ws)
	env := childproc.NewEnv(append([]string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + ws, "LANG=C.UTF-8"}, cfg.Env...)...)
	// No Stderr: driver diagnostics may quote page text; never relayed.
	cmd := childproc.Command(ctx, env, childproc.Options{Dir: ws, SysProcAttr: &syscall.SysProcAttr{Setpgid: true}}, cfg.Driver[0], args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	g := &Gate{cfg: cfg, origins: origins, filter: filter{scrub: cfg.Scrub}, ws: ws, links: links,
		secret: secret, tokens: tokens, sent: map[string]bool{},
		cmd: cmd, stdin: stdin, lines: make(chan []byte)}
	go g.read(stdout)
	return g, nil
}

func (g *Gate) read(r io.Reader) {
	defer close(g.lines)
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := readLine(br)
		if err != nil {
			return
		}
		g.lines <- line
	}
}

func readLine(br *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		chunk, err := br.ReadSlice('\n')
		out = append(out, chunk...)
		if len(out) > MaxLine {
			return nil, errors.New("reply too long")
		}
		if err == nil {
			return out, nil
		}
		if err != bufio.ErrBufferFull {
			return nil, err
		}
	}
}

// Close stops the driver and everything it started.
func (g *Gate) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stop()
	return nil
}

func (g *Gate) stop() {
	if g.stopped {
		return
	}
	g.stopped = true
	g.stdin.Close()
	if pid := g.cmd.Pid(); pid > 0 {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
	go func() {
		for range g.lines {
		}
	}()
	_ = g.cmd.Wait()
}

var stoppedResult = Result{Error: "stopped", Detail: "the browser executor is not running"}

// do runs one request line and returns what the agent may see. Only the
// clerk calls it. An action that needs the owner's approval is refused
// unsent (approval_required): no recipe covers any page yet, so it needs
// the owner's approval of the exact request (CLK-3), which the result's
// Approval describes and submit then sends. effect reports an action that
// may change state at the site (judgeClosed), sent only because the
// session is logged out; lost reports that the executor stopped after it
// was written, so whether it acted is unknown (KRN-8).
func (g *Gate) do(ctx context.Context, raw []byte) (res Result, effect, lost bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	req, l, effect, need, refused := g.judge(raw)
	if refused != nil {
		return *refused, false, false
	}
	if need {
		a := g.approval(req, l)
		return Result{Error: "approval_required", To: strings.TrimSuffix(a.To, " · "+a.Print), Approval: &a,
			Detail: "this action may change state at the site and needs the owner's approval of this exact request; nothing was sent"}, false, false
	}
	out := g.forward(ctx, req)
	return out, effect, effect && g.stopped
}

// submit sends raw, an action the owner approved as print reaching to,
// only if the gate would still ask for that very approval now (CLK-3,
// CLK-2), and at most once per print. With tc, the owner approved the task
// rather than this print: the gate sends it only where asksAgain finds no
// reason to ask, and the result carries its approval for the log. written
// reports that it reached the driver; lost that the executor stopped after
// it was written (KRN-8).
func (g *Gate) submit(ctx context.Context, raw []byte, to, print string, retry bool, tc *cover) (res Result, written, lost bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	req, l, _, need, refused := g.judge(raw)
	switch {
	case refused != nil:
		return *refused, false, false
	case !need:
		return Result{Error: "not_a_submit", Detail: "this action needs no approval; send it as a read"}, false, false
	}
	a := g.approval(req, l)
	if a.Print != print || a.To != to {
		return Result{Error: "changed", Detail: "the page or the request differs from what the owner approved; nothing was sent"}, false, false
	}
	if tc != nil {
		if why := g.asksAgain(req, l, a, *tc); why != "" {
			return Result{Error: "approval_required", To: strings.TrimSuffix(a.To, " · "+a.Print), Approval: &a,
				Detail: why + "; it needs the owner's approval of this exact request; nothing was sent"}, false, false
		}
	}
	if g.sent[print] && !retry {
		return Result{Error: "already_sent", Detail: "this approved request was sent already; nothing was sent"}, false, false
	}
	g.sent[print] = true
	out := g.forward(ctx, req)
	if tc != nil {
		out.Approval = &a
	}
	return out, true, g.stopped
}

// asksAgain is why a task's approval tc does not cover req, which reaches
// l and the gate would approve as a, or "" if it does (CLK-3 "What asks
// again"). The held request the owner approved is covered on its site.
// Another task's approval never reaches here: the clerk reads only the
// approval of the task its key serves (kernel.TaskApproved). A readable
// value over a limit is the key's to refuse (clerk.Verify). The clerk
// fills no credential or card and refuses any step claiming a flow label
// (C4), so no fill or private entry can follow the approval yet.
func (g *Gate) asksAgain(req Request, l link, a Approval, tc cover) string {
	switch {
	case a.Site != tc.site:
		return "it is on another site than the task's approval"
	case a.Print == tc.first:
		return ""
	case g.secretScreen(req, l):
		return "it is on a screen that may reveal or create a secret (VRB-1)"
	}
	return ""
}

// secretScreen reports whether req, reaching l, is on a screen that may
// reveal or create a secret (VRB-1), read from what the gate itself saw: a
// secret word in the page's URL, the control's name or target, or the name
// of any field on the page ("Password", "Backup codes"). Pages have no
// recipe that says otherwise, so a match asks again. A field's value is
// not a sign: the gate counts every untyped value as a possible password
// (G10), and a prefilled address would make every checkout one.
func (g *Gate) secretScreen(req Request, l link) bool {
	texts := []string{g.page, l.name, l.target, req.URL}
	for _, r := range g.refs {
		if fieldRoles[r.role] {
			texts = append(texts, r.name)
		}
	}
	return secretText(texts...)
}

// reask answers a post whose print the page no longer yields: the
// approval the gate would ask for now, so the owner can approve again, or
// why it asks for none (a stopped executor, an action that needs none).
// Nothing is sent.
func (g *Gate) reask(raw []byte) Result {
	g.mu.Lock()
	defer g.mu.Unlock()
	req, l, _, need, refused := g.judge(raw)
	switch {
	case refused != nil:
		return *refused
	case !need:
		return Result{Error: "not_a_submit", Detail: "this action needs no approval; send it as a read"}
	}
	a := g.approval(req, l)
	return Result{Error: "changed", To: strings.TrimSuffix(a.To, " · "+a.Print), Approval: &a,
		Detail: "the page, the request or the browser itself changed since the owner approved; this is what approval would cover now; nothing was sent"}
}

// print is the approval print the gate would ask for raw now, "" if it
// would ask for none.
func (g *Gate) print(raw []byte) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	req, l, _, need, refused := g.judge(raw)
	if refused != nil || !need {
		return ""
	}
	return g.approval(req, l).Print
}

// siteOf is the site raw reaches now (Approval.Site), "" if the gate would
// ask no approval for it: the site whose task approval the clerk reads.
func (g *Gate) siteOf(raw []byte) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	req, l, _, need, refused := g.judge(raw)
	if refused != nil || !need {
		return ""
	}
	return g.approval(req, l).Site
}

// small bounds every field of res but the snapshot and the approval,
// which their makers bound. logged applies it to every result, so a logged
// result is bounded (MaxDetail).
func small(res Result) Result {
	res.Title, res.Detail, res.URL = capText(res.Title, maxTitle), capText(res.Detail, maxErrDetail), capText(res.URL, MaxURL)
	res.Error, res.To, res.Path = capText(res.Error, maxTitle), capText(res.To, MaxURL+maxLabel), capText(res.Path, maxTitle)
	if len(res.RefusedNavigations) > maxRefused {
		res.RefusedNavigations = res.RefusedNavigations[:maxRefused]
	}
	for i := range res.RefusedNavigations {
		res.RefusedNavigations[i] = capText(res.RefusedNavigations[i], maxTitle)
	}
	return res
}

// judge parses raw and judges it: what it reaches, whether it may change
// state at the site (effect, judgeClosed) and whether it needs the owner's
// approval here (need: effect, or under D-147 judgeLoggedOut's answer). A
// request it refuses was not sent.
func (g *Gate) judge(raw []byte) (req Request, l link, effect, need bool, refused *Result) {
	if g.stopped {
		stopped := stoppedResult
		return req, l, false, false, &stopped
	}
	req, err := Parse(raw)
	if err != nil {
		d, _ := g.filter.text(err.Error())
		return req, l, false, false, &Result{Error: "protocol", Detail: capText(d, maxErrDetail)}
	}
	if req.Verb == "navigate" && !g.origins.Declared(req.URL) {
		return req, l, false, false, &Result{Error: "off_origin", Detail: "not a declared origin; use an uncredentialed context"}
	}
	l, effect, refused = g.judgeClosed(req)
	need = effect
	if refused == nil && g.cfg.LoggedOut {
		l, need, refused = g.judgeLoggedOut(req)
	}
	return req, l, effect, need, refused
}

// forward sends a request the gate has allowed, recording what the agent
// put on pages.
func (g *Gate) forward(ctx context.Context, req Request) Result {
	switch req.Verb {
	case "type":
		g.say(req.Text)
	case "navigate":
		g.say(urlWords(req.URL)...)
	}
	out := g.send(ctx, req)
	if req.Verb == "type" && out.OK {
		g.remember(req, out.URL)
	}
	return out
}

// mayAct reports whether raw may have changed state at the site, judged
// without the refs: with no record of what Do judged, as after a restart,
// any line naming a ref may have acted (KRN-8).
func (g *Gate) mayAct(raw []byte) bool {
	req, err := Parse(raw)
	if err != nil {
		return false
	}
	switch req.Verb {
	case "snapshot", "screenshot":
		return false
	case "type":
		return req.Submit
	case "navigate":
		return g.links.match(req.URL)
	}
	return true
}

// judgeClosed reports what req reaches and whether it may change state at
// the site, failing closed: only a snapshot, a screenshot, typing without
// submit, a click that focuses a text field, and a navigate or a link
// followed to another http(s) page G9 does not match can not. A button, a
// select or a submit shows the gate no request, so on an account the owner
// may be signed in to it may act whatever its name. Logged out it can harm
// the owner only through a URL that acts or carries a token
// (judgeLoggedOut, D-147).
func (g *Gate) judgeClosed(req Request) (link, bool, *Result) {
	switch req.Verb {
	case "snapshot", "screenshot":
		return link{}, false, nil
	case "type":
		return g.refs[req.Ref], req.Submit, nil
	case "navigate":
		return link{target: req.URL}, g.links.match(req.URL), nil
	case "click", "download":
		l, ok := g.refs[req.Ref]
		if !ok {
			return link{}, false, &Result{Error: "unknown_ref", Detail: "ref not in the last snapshot; take a new snapshot"}
		}
		if req.Verb == "click" && fieldRoles[l.role] {
			return l, false, nil
		}
		return l, l.role != "link" || !leaves(l.target, g.page) || l.acts(g.links), nil
	}
	return g.refs[req.Ref], true, nil
}

// leaves reports whether following target loads another http(s) page. A
// javascript: href, or a fragment of the page itself ("#", "#pay"), loads
// nothing: the click runs the site's own script, which may submit.
func leaves(target, page string) bool {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return false
	}
	p, err := url.Parse(page)
	if err != nil {
		return true
	}
	u.Fragment, u.RawFragment, p.Fragment, p.RawFragment = "", "", "", ""
	return u.String() != p.String()
}

// judgeLoggedOut is judge for a session holding no identity of the owner's.
func (g *Gate) judgeLoggedOut(req Request) (link, bool, *Result) {
	switch req.Verb {
	case "navigate":
		return link{target: req.URL}, g.links.match(req.URL), nil
	case "click", "download":
		l, ok := g.refs[req.Ref]
		if !ok {
			return link{}, false, &Result{Error: "unknown_ref", Detail: "ref not in the last snapshot; take a new snapshot"}
		}
		return l, l.target != "" && g.links.match(l.target), nil
	}
	return g.refs[req.Ref], false, nil
}

type typedField struct{ text, url string }

// maxTyped bounds what the gate remembers of the agent's typing: typed
// refs, and texts it put on pages.
const maxTyped = 1024

// say records text the agent put on pages, before the reply that can
// echo it is filtered.
func (g *Gate) say(texts ...string) {
	for _, t := range texts {
		if t == "" {
			continue
		}
		if len(g.said) >= maxTyped {
			g.lost = true
			return
		}
		g.said = append(g.said, t)
	}
}

// urlWords is the text a page most often echoes from a URL the agent
// chose: its query values and fragment, decoded. Path segments and query
// keys name pages ("account", "login") and would withhold most of them,
// so they are left out (G10).
func urlWords(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var w []string
	for _, vs := range u.Query() {
		w = append(w, vs...)
	}
	return append(w, u.Fragment)
}

func (g *Gate) remember(req Request, url string) {
	if g.typed == nil {
		g.typed = map[string]typedField{}
	}
	if _, ok := g.typed[req.Ref]; !ok && len(g.typed) >= maxTyped {
		g.lost = true
		return
	}
	g.typed[req.Ref] = typedField{text: req.Text, url: url}
}

// omit derives the password refs from the snapshot itself, not from the
// driver (K14, G10), and omits their values (CRED-4). A typed ref whose
// field shows other text is forgotten (#2245). It returns the snapshot and
// the number of fields omitted.
func (g *Gate) omit(snapshot, url string) (string, int) {
	typed := map[string]string{}
	for ref, f := range g.typed {
		if f.url == url {
			typed[ref] = f.text
		}
	}
	refs, stale := entryRefs(snapshot, typed)
	for ref := range stale {
		delete(g.typed, ref)
		delete(typed, ref)
	}
	keep := map[string]bool{}
	for ref := range typed {
		keep[ref] = !refs[ref]
	}
	if g.lost && len(refs) > 0 {
		return withheldMark, len(refs)
	}
	return omitValues(snapshot, refs, keep, g.said), len(refs)
}

// send forwards a request the gate has allowed.
func (g *Gate) send(ctx context.Context, req Request) Result {
	if req.Verb == "screenshot" {
		// CRED-10: a screenshot of a page with a match is withheld. The gate
		// looks at the page itself first, with the vault's values too.
		snap, ok := g.roundtrip(ctx, Request{Verb: "snapshot"})
		if !ok {
			return snap
		}
		if !snap.OK || snap.Redactions > 0 {
			return Result{Error: "withheld", Detail: "page shows a value the detector matched (CRED-10)",
				RefusedNavigations: snap.RefusedNavigations}
		}
		// CRED-4: pixels cannot be omitted, so a page with a field value the
		// agent did not type is not shot at all (#2245).
		if snap.PasswordFields > 0 {
			return Result{Error: "withheld", Detail: "page shows a field value you did not type (CRED-4)",
				RefusedNavigations: snap.RefusedNavigations}
		}
	}
	res, ok := g.roundtrip(ctx, req)
	if !ok || !res.OK {
		return res
	}
	switch req.Verb {
	case "download":
		return g.scanFile(res, "downloaded file")
	case "screenshot":
		if res = g.scanFile(res, "screenshot"); !res.OK {
			return res
		}
		// The page may have changed between the first look and the shot.
		snap, ok := g.roundtrip(ctx, Request{Verb: "snapshot"})
		if !ok || !snap.OK || snap.Redactions > 0 || snap.PasswordFields > 0 {
			_ = os.Remove(filepath.Join(g.ws, res.Path))
			if !ok {
				return snap
			}
			if snap.OK && snap.Redactions == 0 {
				return Result{Error: "withheld", Detail: "page showed a field value you did not type during the screenshot (CRED-4)",
					RefusedNavigations: append(res.RefusedNavigations, snap.RefusedNavigations...)}
			}
			return Result{Error: "withheld", Detail: "page showed a value the detector matched during the screenshot (CRED-10)",
				RefusedNavigations: append(res.RefusedNavigations, snap.RefusedNavigations...)}
		}
	}
	return res
}

// roundtrip sends one canonical request and filters the reply. ok is false
// when the executor was stopped.
func (g *Gate) roundtrip(ctx context.Context, req Request) (Result, bool) {
	if _, err := g.stdin.Write(append(req.Encode(), '\n')); err != nil {
		g.stop()
		return stoppedResult, false
	}
	t := time.NewTimer(g.cfg.Timeout)
	defer t.Stop()
	var line []byte
	select {
	case l, open := <-g.lines:
		if !open {
			g.stop()
			return stoppedResult, false
		}
		line = l
	case <-t.C:
		g.stop()
		return Result{Error: "timeout", Detail: "the browser did not answer in time; executor stopped"}, false
	case <-ctx.Done():
		g.stop()
		return Result{Error: "timeout", Detail: "request cancelled; executor stopped"}, false
	}
	var res Result
	if err := json.Unmarshal(line, &res); err != nil {
		g.stop()
		return Result{Error: "driver", Detail: "malformed executor reply; executor stopped"}, false
	}
	if res.Snapshot != "" {
		// Read before filtering: a redaction must not hide a link's target.
		g.refs, g.page = parseRefs(res.Snapshot, res.URL), res.URL
	}
	read := res.Snapshot != ""
	// The driver's count is not trusted: the gate reports its own.
	res.Snapshot, res.PasswordFields = g.omit(res.Snapshot, res.URL)
	out, ok := g.post(req.Verb, res)
	if read {
		g.shown = parseRefs(out.Snapshot, res.URL)
	}
	return out, ok
}

var errCode = regexp.MustCompile(`^[A-Za-z_]{1,40}$`)

// post filters one driver reply (CRED-10) and enforces confinement.
func (g *Gate) post(verb string, res Result) (Result, bool) {
	if (res.OK && res.URL == "") || (res.URL != "" && res.URL != "about:blank" && !g.origins.Declared(res.URL)) {
		// The driver should never end a verb off its origins; if it did,
		// confinement failed and nothing from that page is relayed. An ok
		// reply must name its page, or confinement cannot be checked.
		g.stop()
		return Result{Error: "confinement", Detail: "the executor left its declared origins and was stopped"}, false
	}
	if res.Error != "" && !errCode.MatchString(res.Error) {
		res.Error = "driver"
	}
	if res.Redactions < 0 {
		res.Redactions = 0
	}
	n := 0
	for _, s := range []*string{&res.Detail, &res.URL, &res.Title, &res.Snapshot, &res.Error} {
		var k int
		*s, k = g.filter.text(*s)
		n += k
	}
	for i := range res.RefusedNavigations {
		var k int
		res.RefusedNavigations[i], k = g.filter.text(res.RefusedNavigations[i])
		n += k
	}
	res.Redactions += n
	// The snapshot is bounded as the log holds it, JSON-escaped.
	for n := len(js(res.Snapshot)); len(res.Snapshot) > MaxSnapshot || n > MaxSnapshot; n = len(js(res.Snapshot)) {
		cut := min(MaxSnapshot, len(res.Snapshot)*MaxSnapshot/n)
		for cut > 0 && !utf8.RuneStart(res.Snapshot[cut]) {
			cut--
		}
		res.Snapshot, res.Truncated = res.Snapshot[:cut], true
	}
	if res.Truncated {
		res.Snapshot += "\n[snapshot truncated]"
	}
	if res.Path != "" {
		p := filepath.Join(g.ws, filepath.Base(res.Path))
		if verb != "screenshot" && verb != "download" {
			return Result{Error: "driver", Detail: "executor named an output file for " + verb}, true
		}
		// A site names its downloads, so the name is output like any other.
		if _, k := g.filter.text(res.Path); k > 0 {
			if res.Path == filepath.Base(res.Path) {
				_ = os.Remove(p)
			}
			return Result{Error: "withheld", Detail: "output file name contains a value the detector matched (CRED-10)",
				URL: res.URL, Title: res.Title, RefusedNavigations: res.RefusedNavigations}, true
		}
		size, err := g.checkPath(res.Path)
		if err != nil {
			return Result{Error: "driver", Detail: "executor named an invalid output file"}, true
		}
		res.Bytes = size
	} else {
		res.Bytes = 0
	}
	return res, true
}

// checkPath accepts only a flat name of a regular, singly linked file
// directly in the workspace.
func (g *Gate) checkPath(name string) (int64, error) {
	if name != filepath.Base(name) || strings.ContainsAny(name, `/\`) || strings.HasPrefix(name, ".") || len(name) > 128 {
		return 0, fmt.Errorf("bad name")
	}
	fi, err := os.Lstat(filepath.Join(g.ws, name))
	if err != nil || !singleRegular(fi) {
		return 0, fmt.Errorf("not a regular file")
	}
	return fi.Size(), nil
}

// singleRegular refuses symlinks and hard links: a hard link can name a file
// outside the workspace.
func singleRegular(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return fi.Mode().IsRegular() && ok && st.Nlink == 1
}

// scanFile withholds and removes an output file (screenshot or download) whose
// bytes carry a vault value or a detector match. Images and binary formats are
// scanned as bytes only (K6).
func (g *Gate) scanFile(res Result, what string) Result {
	p := filepath.Join(g.ws, res.Path)
	withhold := func(why string) Result {
		_ = os.Remove(p)
		return Result{Error: "withheld", Detail: what + " " + why, URL: res.URL, Title: res.Title,
			RefusedNavigations: res.RefusedNavigations}
	}
	if res.Path == "" {
		return withhold("missing")
	}
	if res.Bytes > MaxDownloadScan {
		return withhold("too large to scan")
	}
	// Read through a descriptor that cannot follow a symlink swapped in since
	// checkPath, and check that descriptor's file again.
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return withhold("unreadable")
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !singleRegular(fi) || fi.Size() > MaxDownloadScan {
		return withhold("unreadable")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxDownloadScan+1))
	if err != nil || len(b) > MaxDownloadScan {
		return withhold("unreadable")
	}
	if _, k := g.filter.text(strings.ToValidUTF8(string(b), "\uFFFD")); k > 0 {
		return withhold("contains a value the detector matched (CRED-10)")
	}
	res.Bytes = int64(len(b))
	return res
}
