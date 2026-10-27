package localui

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"html"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: BAK-1, BAK-2, CH-7

// fakeBackupOps is agentosd's passkey ops and backup ops on one socket,
// as AgentosdPasskeys serves them.
type fakeBackupOps struct {
	*fakePasskeys
	choice  localapi.BackupChoice
	begun   []localapi.BackupPlace
	added   []localapi.BackupAdd
	removed []string
	err     error // every op but Backups answers it
}

func (f *fakeBackupOps) Backups(context.Context, string) (localapi.BackupChoice, error) {
	return f.choice, nil
}

func (f *fakeBackupOps) BackupBegin(_ context.Context, _ string, p localapi.BackupPlace) (localapi.BackupBegun, error) {
	f.begun = append(f.begun, p)
	return localapi.BackupBegun{N: 3, Challenge: []byte("0123456789abcdef0123456789abcdef")}, f.err
}

func (f *fakeBackupOps) BackupAdd(_ context.Context, _ string, p localapi.BackupPlace, n int, ad, cd, sig []byte) error {
	f.added = append(f.added, localapi.BackupAdd{Place: p, N: n, AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig})
	return f.err
}

func (f *fakeBackupOps) BackupRemove(_ context.Context, _, name string) error {
	f.removed = append(f.removed, name)
	return f.err
}

// backupRig is a set-up box whose passkey ops also serve the backup ops.
func backupRig(t *testing.T) (*rig, *fakeBackupOps) {
	t.Helper()
	r := newRig(t)
	fb := &fakeBackupOps{fakePasskeys: &fakePasskeys{}, choice: localapi.BackupChoice{
		Lines:    []string{"Backups: only one place holds them, so one fire or theft can take all; add a second."},
		Places:   []localapi.BackupPlace{{Name: "drive2", Kind: "dir", Locator: "/media/drive2/agentos", Newest: 1_800_000_000_000}},
		Wipeable: []string{"drive2"}}}
	s, err := New(Config{Page: testPage(), Hooks: r.hooks, SetupSecret: r.card.SetupSecret, Store: &MemStore{},
		Defaults: "spend cap $20 a day; payments need approval.", Passkeys: fb, PasskeyRPID: DefaultPageName,
		Now: r.clock, Rand: rand.New(rand.NewSource(9))})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = s
	r.runSetup()
	r.startChannel(modem.NewCarrier().Line(boxNum))
	return r, fb
}

// The page is served only when agentosd's passkey ops also serve the
// backup ops, behind sign-in, and never without the passkey page's name.
func TestBackupPageNeedsThePasskeyOps(t *testing.T) {
	r, _ := passkeyRig(t)
	r.signIn()
	if w := r.do("GET", "/backups/", nil); w.Code != http.StatusNotFound {
		t.Fatalf("backups page with passkey ops alone: %d", w.Code)
	}
	if _, err := New(Config{Page: testPage(), Backups: &fakeBackupOps{fakePasskeys: &fakePasskeys{}}}); err == nil {
		t.Fatal("a Backups page without the passkey page's name")
	}
	var _ Backups = AgentosdPasskeys{}
	b, _ := backupRig(t)
	if w := b.do("GET", "/backups/", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("backups page before sign-in: %d", w.Code)
	}
	b.signIn()
	if !strings.Contains(b.get("/home"), "/backups/") {
		t.Fatal("home does not link the Backups page")
	}
}

// The choice page shows the notice, names each place that keeps no old
// copies, and lists each place with its newest checked backup (BAK-2).
func TestBackupPageShowsTheNoticeAndNamesWipeablePlaces(t *testing.T) {
	r, fb := backupRig(t)
	r.signIn()
	p := html.UnescapeString(r.get("/backups/"))
	for _, want := range []string{fb.choice.Lines[0], "a hacked box could wipe them: <strong>drive2</strong>",
		"/media/drive2/agentos", "keeps no old copies", "newest checked backup " + backupDay(1_800_000_000_000),
		`name="step" value="remove"`, `name="step" value="begin"`} {
		if !strings.Contains(p, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	fb.choice = localapi.BackupChoice{Lines: []string{"Backups: none, so I hold the only copy of your data; add a drive on the Backups page."}, NoKey: true}
	p = html.UnescapeString(r.get("/backups/"))
	for _, want := range []string{fb.choice.Lines[0], "No backup: I hold the only copy", "no backup key yet"} {
		if !strings.Contains(p, want) {
			t.Errorf("empty page lacks %q", want)
		}
	}
}

// The status page carries the notice's lines, and links the Backups page
// only to a signed-in phone.
func TestStatusPageShowsTheBackupNotice(t *testing.T) {
	line := "Backups: none, so I hold the only copy of your data; add a drive on the Backups page."
	srv := newRig(t).srv
	for _, signedIn := range []bool{false, true} {
		w := httptest.NewRecorder()
		srv.render(w, "status", statusView{HasOwner: true, Owner: localapi.Status{Backups: []string{line}}, SignedIn: signedIn, Backups: true})
		p := html.UnescapeString(w.Body.String())
		if !strings.Contains(p, line) || strings.Contains(p, `href="/backups/"`) != signedIn {
			t.Fatalf("signed in %v:\n%s", signedIn, p)
		}
	}
	w := httptest.NewRecorder()
	srv.render(w, "status", statusView{HasOwner: true})
	if strings.Contains(w.Body.String(), "Backups") {
		t.Fatal("a notice with no lines")
	}
}

// Adding: the place goes to agentosd, the tap step shows exactly what the
// hardware key signs and carries the challenge, the count and the place
// back, and the tap's answer goes to agentosd as sent.
func TestBackupPageAddsOnAHardwareKeyTap(t *testing.T) {
	r, fb := backupRig(t)
	if w := r.post("/backups/", url.Values{"step": {"begin"}}); w.Code != http.StatusSeeOther || len(fb.begun) != 0 {
		t.Fatalf("a post without sign-in: %d", w.Code)
	}
	r.signIn()
	place := url.Values{"step": {"begin"}, "name": {"drive3"}, "locator": {" /media/drive3/agentos "}, "append": {"1"}}
	p := html.UnescapeString(r.post("/backups/", place).Body.String())
	want := localapi.BackupPlace{Name: "drive3", Kind: "dir", Locator: "/media/drive3/agentos", AppendOnly: true}
	if len(fb.begun) != 1 || fb.begun[0] != want {
		t.Fatalf("begun %+v", fb.begun)
	}
	ch := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	for _, s := range []string{`id="pk-finish"`, `data-rp="` + DefaultPageName + `"`, `data-challenge="` + ch + `"`, `id="pk-tap"`,
		"Name: <strong>drive3</strong>", "/media/drive3/agentos", "Keeps old copies: <strong>yes</strong>",
		`name="n" value="3"`, `name="append" value="1"`, `name="step" value="add"`} {
		if !strings.Contains(p, s) {
			t.Errorf("tap step lacks %q", s)
		}
	}
	enc := base64.StdEncoding.EncodeToString
	add := url.Values{"step": {"add"}, "name": {"drive3"}, "locator": {"/media/drive3/agentos"}, "append": {"1"}, "n": {"3"}, "ch": {ch},
		"ad": {enc([]byte("ad"))}, "cd": {enc([]byte("cd"))}, "sig": {enc([]byte("sig"))}}
	// A phone passkey's tap stays on the tap step, to tap again.
	fb.err = Refused(localapi.ErrBackupNotAnchor)
	p = html.UnescapeString(r.post("/backups/", add).Body.String())
	if len(fb.added) != 1 || !strings.Contains(p, BackupTapAgainText) || !strings.Contains(p, `data-challenge="`+ch+`"`) {
		t.Fatalf("wrong tap:\n%s", p)
	}
	fb.err = nil
	p = r.post("/backups/", add).Body.String()
	a := fb.added[1]
	if a.Place != want || a.N != 3 || string(a.Signature) != "sig" || string(a.AuthenticatorData) != "ad" || !strings.Contains(p, "Added.") {
		t.Fatalf("added %+v\n%s", a, p)
	}
	// An assertion past its bound, or no count, never reaches agentosd.
	bad := url.Values{}
	for k, v := range add {
		bad[k] = v
	}
	bad.Set("sig", enc(make([]byte, localapi.MaxPasskeyAssertion+1)))
	r.post("/backups/", bad)
	bad.Set("sig", enc([]byte("sig")))
	bad.Set("n", "")
	r.post("/backups/", bad)
	if len(fb.added) != 2 {
		t.Fatal("an unbounded frame reached agentosd")
	}
	// A cross-origin add is refused before anything runs.
	w := r.do("POST", "/backups/", add, func(q *http.Request) {
		q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		q.Header.Set("Origin", "http://evil.example")
	})
	if w.Code != http.StatusForbidden || len(fb.added) != 2 {
		t.Fatalf("a cross-origin add: %d", w.Code)
	}
}

// Stopping a place needs no tap; every refusal shows fixed words.
func TestBackupPageRemovesAndWordsEachRefusal(t *testing.T) {
	r, fb := backupRig(t)
	r.signIn()
	p := r.post("/backups/", url.Values{"step": {"remove"}, "name": {"drive2"}}).Body.String()
	if len(fb.removed) != 1 || fb.removed[0] != "drive2" || !strings.Contains(p, "Stopped.") {
		t.Fatalf("removed %v\n%s", fb.removed, p)
	}
	seen := map[string]bool{}
	for _, c := range append(append([]string{}, localapi.BackupCodes...), "kernel: a backup destination needs your hardware key's signature") {
		fb.err = Refused(c)
		p = html.UnescapeString(r.post("/backups/", url.Values{"step": {"remove"}, "name": {"drive2"}}).Body.String())
		txt := backupText(Refused(c))
		if !strings.Contains(p, txt) || strings.Contains(p, "kernel:") {
			t.Fatalf("%s:\n%s", c, p)
		}
		seen[txt] = true
	}
	if len(seen) != len(localapi.BackupCodes) {
		t.Fatalf("%d texts for %d codes and one stranger", len(seen), len(localapi.BackupCodes))
	}
}

// The page's one script is the passkey page's, admitted by its CSP hash.
func TestBackupScriptMatchesItsCSPHash(t *testing.T) {
	r, _ := backupRig(t)
	r.signIn()
	for _, w := range []*httptest.ResponseRecorder{r.do("GET", "/backups/", nil),
		r.post("/backups/", url.Values{"step": {"begin"}, "name": {"d"}, "locator": {"/m"}})} {
		page := w.Body.String()
		m := regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindAllStringSubmatch(page, -1)
		if len(m) != 1 || m[0][1] != passkeyJS {
			t.Fatalf("scripts: %d", len(m))
		}
		h := sha256.Sum256([]byte(m[0][1]))
		if csp := w.Header().Get("Content-Security-Policy"); csp != cspWith(base64.StdEncoding.EncodeToString(h[:])) {
			t.Fatalf("CSP %q", csp)
		}
	}
}
