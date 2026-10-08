package localui

import (
	"context"
	"encoding/base32"
	"errors"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/owner"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// REQ: ARC-2, CH-10, ONB-3, ONB-6, CRED-8, CH-7

// toCodes pairs this phone by text and opens the codes step.
func (r *rig) toCodes() string {
	r.t.Helper()
	r.hooks.mu.Lock()
	r.hooks.progress.Online = true
	r.hooks.mu.Unlock()
	code := regexp.MustCompile(`PAIR%20([A-Z2-9]{8})`).FindStringSubmatch(html.UnescapeString(r.get("/setup")))[1]
	r.srv.OfferText(ownerNum, "PAIR "+code)
	return html.UnescapeString(r.get("/setup"))
}

var secretRe = regexp.MustCompile(`secret=([A-Z2-7]+)&`)

// K17, CRED-8: the page asks the vault for each key and keeps none. A
// shown key stays the one asked for until the phone asks for a new one,
// so a typo needs no new scan; only the newest key confirms.
func TestTheCodesStepAsksTheVaultAndHoldsNoSeed(t *testing.T) {
	for _, f := range reflect.VisibleFields(reflect.TypeOf(setup{})) {
		if f.Type == reflect.TypeOf([]byte(nil)) {
			t.Fatalf("setup holds bytes in %s", f.Name)
		}
	}
	r := newRig(t)
	page := r.toCodes()
	m := secretRe.FindStringSubmatch(page)
	if m == nil || r.hooks.enrolls != 1 {
		t.Fatalf("no key from the vault (%d): %s", r.hooks.enrolls, page)
	}
	r.post("/setup/codes", url.Values{"code": {"000000"}})
	page = r.get("/setup")
	if !strings.Contains(page, "did not match") || strings.Contains(page, "secret=") || !strings.Contains(page, "Show a new key") {
		t.Fatalf("after a wrong code: %s", page)
	}
	r.post("/setup/codes", url.Values{"new": {"1"}})
	n := secretRe.FindStringSubmatch(html.UnescapeString(r.get("/setup")))
	if n == nil || n[1] == m[1] || r.hooks.enrolls != 2 {
		t.Fatalf("no new key (%d)", r.hooks.enrolls)
	}
	old := decodeSecret(t, m[1])
	r.post("/setup/codes", url.Values{"code": {owner.TOTP(old, r.clock())}})
	if r.srv.setup.st.Codes || !strings.Contains(r.setupErr(), "did not match") {
		t.Fatal("a replaced key confirmed")
	}
	r.post("/setup/codes", url.Values{"code": {owner.TOTP(decodeSecret(t, n[1]), r.clock())}})
	if !r.srv.setup.st.Codes || r.hooks.seed == nil {
		t.Fatal("the newest key did not confirm")
	}
}

// K17: a vault that already holds a sealed seed shows none; setup says so
// and continues, and the page's word alone does not skip the step.
func TestASealedVaultSkipsTheKey(t *testing.T) {
	r := newRig(t)
	r.post("/setup/codes", url.Values{"enrolled": {"1"}}) // before pairing
	page := r.toCodes()
	if r.srv.setup.st.Codes || strings.Contains(page, "already set up") {
		t.Fatal("codes skipped without the vault")
	}
	r.post("/setup/codes", url.Values{"enrolled": {"1"}})
	if r.srv.setup.st.Codes {
		t.Fatal("codes skipped while the vault waits for a code")
	}
	r.hooks.mu.Lock()
	r.hooks.seed, r.hooks.pending = []byte("sealed-canary-seed-0"), nil
	r.hooks.mu.Unlock()
	r.post("/setup/codes", url.Values{"new": {"1"}})
	page = r.get("/setup")
	if !strings.Contains(page, "already set up") || strings.Contains(page, "secret=") {
		t.Fatalf("sealed vault: %s", page)
	}
	r.post("/setup/codes", url.Values{"enrolled": {"1"}})
	if !r.srv.setup.st.Codes {
		t.Fatal("sealed vault did not continue")
	}
}

func decodeSecret(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b32.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// vaultEnroller is the fake vault as agentosd's Enroller sees it.
type vaultEnroller struct{ f *fakeHooks }

func (v vaultEnroller) Enroll() (string, error) {
	l, err := v.f.EnrollCode()
	return l, vaultSentinel(err)
}

func (v vaultEnroller) ConfirmEnroll(code string) (bool, error) {
	ok, err := v.f.ConfirmCode(code)
	return ok, vaultSentinel(err)
}

func vaultSentinel(err error) error {
	switch {
	case errors.Is(err, ErrCodesEnrolled):
		return localsrv.EnrollClosed
	case errors.Is(err, ErrNoCodeEnrollment):
		return localsrv.EnrollNone
	}
	return err
}

// viaAgentosd is the rig's hooks with enrollment, finish and the setup
// marker served by agentosd's setup ops (localsrv.Setup), as deployed.
type viaAgentosd struct {
	*fakeHooks
	a AgentosdSetup
}

func (v viaAgentosd) EnrollCode() (string, error)        { return v.a.EnrollCode() }
func (v viaAgentosd) ConfirmCode(c string) (bool, error) { return v.a.ConfirmCode(c) }
func (v viaAgentosd) AlreadySetUp() bool                 { return v.a.AlreadySetUp() }

// Finish records finish with agentosd, then has the fake start the owner
// channel, as agentosd's Finished does.
func (v viaAgentosd) Finish(n string) error {
	if err := v.a.Finish(n); err != nil {
		return err
	}
	return v.fakeHooks.Finish(n)
}

// Security L6, ARC-2: the page's setup goes through agentosd, which
// records finish only after it saw the vault confirm a code, then refuses
// every setup op for good: a page restarted with its state lost stays
// closed.
func TestSetupFinishesThroughAgentosdAndClosesForGood(t *testing.T) {
	r := newRig(t)
	rec := filepath.Join(t.TempDir(), "setup.json")
	var owners []string
	open := func() *localsrv.Setup {
		return localsrv.NewSetup(localsrv.SetupConfig{Record: localsrv.FileRecord{Path: rec}, Enroll: vaultEnroller{r.hooks},
			Progress: func() localapi.SetupProgress { p := r.hooks.Progress(); return localapi.SetupProgress(p) },
			Finished: func(o string) { owners = append(owners, o) }, Now: r.clock})
	}
	sock := InProcess(open().Ops())
	r.via = viaAgentosd{r.hooks, AgentosdSetup{sock}}
	r.srv = r.open(&MemStore{})
	r.runSetup()
	if !r.srv.setup.done() || len(owners) != 1 || owners[0] != ownerNum {
		t.Fatalf("done %v, agentosd recorded %v", r.srv.setup.done(), owners)
	}
	b, err := os.ReadFile(rec)
	if err != nil || strings.Contains(string(b), secretOf(r.hooks.seed)) {
		t.Fatalf("record %v: %s", err, b)
	}
	for _, s := range []namedOwner{{"live", sock}, {"restarted", InProcess(open().Ops())}} {
		a := AgentosdSetup{s.o}
		if !a.AlreadySetUp() {
			t.Errorf("%s: setup open", s.name)
		}
		if _, err := a.EnrollCode(); !refused(err, localapi.ErrSetupClosed) {
			t.Errorf("%s: enroll %v", s.name, err)
		}
		if err := a.Finish("+15550000002"); !refused(err, localapi.ErrSetupClosed) {
			t.Errorf("%s: finish %v", s.name, err)
		}
		r.via = viaAgentosd{r.hooks, a}
		r.srv = r.open(&MemStore{})
		if loc := r.do("GET", "/setup", nil).Header().Get("Location"); loc != "/status" {
			t.Errorf("%s: a page with no state reopened setup", s.name)
		}
	}
}

type namedOwner struct {
	name string
	o    Owner
}

func secretOf(seed []byte) string { return b32.EncodeToString(seed) }

// A page started before agentosd waits for it rather than reading its
// silence as setup closed.
func TestThePageWaitsForAgentosd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := (AgentosdSetup{Socket{Path: filepath.Join(t.TempDir(), "none.sock")}}).Wait(ctx, time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait %v", err)
	}
	closed := InProcess{localapi.OpSetupProgress: nil}
	if err := (AgentosdSetup{closed}).Wait(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("a refusal is an answer: %v", err)
	}
}
