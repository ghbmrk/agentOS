package localui

// REQ: CH-21

import (
	"encoding/base32"
	"html"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/owner"
)

// namedHooks is fakeHooks with FinishNamed, recording the names setup
// finished with.
type namedHooks struct {
	*fakeHooks
	mu    sync.Mutex
	names []Names
}

func (n *namedHooks) FinishNamed(owner string, names Names) error {
	n.mu.Lock()
	n.names = append(n.names, names)
	n.mu.Unlock()
	return n.Finish(owner)
}

func newNamedRig(t *testing.T) (*rig, *namedHooks) {
	r := newRig(t)
	h := &namedHooks{fakeHooks: r.hooks}
	r.via = h
	r.srv = r.open(&MemStore{})
	return r, h
}

var (
	boxNameRe   = regexp.MustCompile(`name="name" value="([^"]*)"`)
	ownerNameRe = regexp.MustCompile(`name="owner_name" value="([^"]*)"`)
	cardFNRe    = regexp.MustCompile(`\r\nFN:([^\r]*)\r\n`)
)

// pair texts PAIR from the phone's sms: link, so this phone continues setup.
func (r *rig) pair() {
	r.t.Helper()
	r.hooks.progress.Online = true
	m := regexp.MustCompile(`body=PAIR%20([A-Z2-9]{8})"`).FindStringSubmatch(html.UnescapeString(r.get("/setup")))
	if m == nil {
		r.t.Fatal("no pairing link")
	}
	if _, ok := r.srv.OfferText(ownerNum, "PAIR "+m[1]); !ok {
		r.t.Fatal("pairing refused")
	}
}

// names is the names form's values on the setup page, and the contact
// card's name.
func (r *rig) names() (box, owner, card string) {
	r.t.Helper()
	p := html.UnescapeString(r.get("/setup"))
	if m := boxNameRe.FindStringSubmatch(p); m != nil {
		box = m[1]
	}
	if m := ownerNameRe.FindStringSubmatch(p); m != nil {
		owner = m[1]
	}
	if m := cardFNRe.FindStringSubmatch(r.get("/box.vcf")); m != nil {
		card = m[1]
	}
	return box, owner, card
}

// TestSetupSuggestsTheBoxName: the screen after pairing offers a made-up
// full name, which is the contact card's name too, and kept unless the
// owner types another (SPEC CH-21, §12.1). Finish hands it to agentosd.
func TestSetupSuggestsTheBoxName(t *testing.T) {
	r, h := newNamedRig(t)
	r.pair()
	box, owner, card := r.names()
	if strings.Count(box, " ") != 1 || owner != "" || card != box {
		t.Fatalf("suggested %q, owner %q, card %q", box, owner, card)
	}
	if !strings.Contains(r.get("/setup"), `href="/box.vcf"`) {
		t.Error("no contact card on the names screen")
	}
	// A reload offers the same name: it is kept, not drawn again.
	if again, _, _ := r.names(); again != box {
		t.Errorf("reload suggested %q, then %q", box, again)
	}
	r.runSetupAfterPairing()
	if len(h.names) != 1 || h.names[0] != (Names{Box: box}) {
		t.Errorf("finished with %+v, want the suggestion %q", h.names, box)
	}
}

// TestSetupOwnerTypesTheNames: the owner overwrites the suggestion and
// fills in their own name; the name check refuses a bad one and the owner's
// own name, and changes nothing (SPEC CH-21).
func TestSetupOwnerTypesTheNames(t *testing.T) {
	r, h := newNamedRig(t)
	r.pair()
	suggested, _, _ := r.names()
	for _, c := range []struct{ name, owner, want string }{
		{"R2D2", "", "1 to 32 letters"},
		{"Help", "", "control words"},
		{"Agent Os", "", `"agentOS"`},
		{"mark  JONES", "Mark Jones", "your own name"},
		{"Dave Smith", "Mark 2", "Your name is up to 32"},
		{"Dave Smith", strings.Repeat("a", 33), "Your name is up to 32"},
	} {
		r.post("/setup/name", url.Values{"name": {c.name}, "owner_name": {c.owner}})
		if e := html.UnescapeString(r.setupErr()); !strings.Contains(e, c.want) {
			t.Errorf("name %q owner %q: error %q, want %q", c.name, c.owner, e, c.want)
		}
		if box, owner, _ := r.names(); box != suggested || owner != "" {
			t.Errorf("a refused name changed the names to %q, %q", box, owner)
		}
	}
	r.post("/setup/name", url.Values{"name": {"  Zoë   O'Neil "}, "owner_name": {" Mark  Jones "}})
	if e := r.setupErr(); e != "" {
		t.Fatalf("good names refused: %q", e)
	}
	if box, owner, card := r.names(); box != "Zoë O'Neil" || owner != "Mark Jones" || card != box {
		t.Fatalf("names %q, %q, card %q", box, owner, card)
	}
	r.runSetupAfterPairing()
	if len(h.names) != 1 || h.names[0] != (Names{Box: "Zoë O'Neil", Owner: "Mark Jones"}) {
		t.Errorf("finished with %+v", h.names)
	}
}

// TestOnlyThePairedPhoneNamesTheBox: before pairing any phone on the Wi-Fi
// may run setup's steps, but none may name the box; after it, only the
// phone that paired may (CH-7, CH-21).
func TestOnlyThePairedPhoneNamesTheBox(t *testing.T) {
	r, _ := newNamedRig(t)
	r.hooks.progress.Online = true
	r.post("/setup/name", url.Values{"name": {"Eve Spoof"}})
	if r.srv.setup.st.Name != "" {
		t.Fatalf("named before pairing: %q", r.srv.setup.st.Name)
	}
	r.pair()
	suggested, _, _ := r.names()
	r.asOther(func() {
		if w := r.post("/setup/name", url.Values{"name": {"Eve Spoof"}, "owner_name": {"Eve"}}); w.Code != http.StatusSeeOther {
			t.Errorf("other phone's post: %d", w.Code)
		}
	})
	if box, owner, card := r.names(); box != suggested || owner != "" || card != suggested {
		t.Errorf("another phone renamed the box: %q, %q, card %q", box, owner, card)
	}
}

// TestRestartDropsTheNames: starting setup over forgets the names, so the
// next pairing is offered a fresh suggestion and nothing of the last
// owner's.
func TestRestartDropsTheNames(t *testing.T) {
	r, _ := newNamedRig(t)
	r.pair()
	r.post("/setup/name", url.Values{"name": {"Zoë O'Neil"}, "owner_name": {"Mark Jones"}})
	r.post("/setup/restart", url.Values{})
	if st := r.srv.setup.st; st.Owner != "" || st.Name != "" || st.OwnerName != "" {
		t.Fatalf("after restart: %+v", st)
	}
	r.pair()
	if box, owner, _ := r.names(); box == "" || box == "Zoë O'Neil" || owner != "" {
		t.Errorf("after restart the names are %q, %q", box, owner)
	}
}

// TestSetupWithoutNamedFinish: Hooks without FinishNamed finish as before.
func TestSetupWithoutNamedFinish(t *testing.T) {
	r := newRig(t)
	r.runSetup()
	if r.hooks.finished != ownerNum {
		t.Fatalf("finished %q", r.hooks.finished)
	}
}

// runSetupAfterPairing walks the steps after pairing to the end, as
// runSetup does.
func (r *rig) runSetupAfterPairing() {
	t := r.t
	t.Helper()
	// The names screen is the codes step, so its key was shown already:
	// ask for a new one.
	r.post("/setup/codes", url.Values{"new": {"1"}})
	p := html.UnescapeString(r.get("/setup"))
	m := regexp.MustCompile(`otpauth://totp/AgentOS:AgentOS\?secret=([A-Z2-7]+)&`).FindStringSubmatch(p)
	if m == nil {
		t.Fatalf("no otpauth link: %s", p)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(m[1])
	if err != nil {
		t.Fatal(err)
	}
	r.post("/setup/codes", url.Values{"code": {owner.TOTP(seed, r.clock())}})
	r.post("/setup/recovery", url.Values{"stored": {"1"}})
	r.post("/setup/host", url.Values{})
	r.hooks.mu.Lock()
	r.hooks.progress = Progress{Phase: "ready", Updated: true, Online: true}
	r.hooks.mu.Unlock()
	r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}, "private": {"1"}})
	if r.hooks.finished != ownerNum {
		t.Fatalf("setup did not finish: %q", r.setupErr())
	}
}

// viaAgentosdNamed is viaAgentosd whose finish carries the names, through
// CardFinish as deployed (cmd/agentos-localui).
type viaAgentosdNamed struct {
	viaAgentosd
	c CardFinish
}

func (v viaAgentosdNamed) FinishNamed(n string, names Names) error {
	if err := v.c.FinishNamed(n, names); err != nil {
		return err
	}
	return v.fakeHooks.Finish(n)
}

// TestSetupNamesReachAgentosd: the names go over localui.sock in finish,
// and agentosd's setup checks and records them for the owner channel.
func TestSetupNamesReachAgentosd(t *testing.T) {
	r := newRig(t)
	rec := filepath.Join(t.TempDir(), "setup.json")
	s := localsrv.NewSetup(localsrv.SetupConfig{Record: localsrv.FileRecord{Path: rec}, Enroll: vaultEnroller{r.hooks},
		Progress: func() localapi.SetupProgress { p := r.hooks.Progress(); return localapi.SetupProgress(p) },
		Finished: func(string) {}, Now: r.clock})
	a := AgentosdSetup{Owner: InProcess(s.Ops())}
	r.via = viaAgentosdNamed{viaAgentosd{r.hooks, a}, CardFinish{AgentosdSetup: a}}
	r.srv = r.open(&MemStore{})
	r.pair()
	r.post("/setup/name", url.Values{"name": {"Zoë O'Neil"}, "owner_name": {"Mark Jones"}})
	r.runSetupAfterPairing()
	got, err := localsrv.FileRecord{Path: rec}.Load()
	if err != nil || !got.Finished || got.Name != "Zoë O'Neil" || got.OwnerName != "Mark Jones" {
		t.Fatalf("agentosd recorded %+v, %v", got, err)
	}
}
