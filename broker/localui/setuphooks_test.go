package localui

import (
	"context"
	crand "crypto/rand"
	"encoding/base32"
	"errors"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
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

// ONB-3, CRED-8 (P2-2w c2 r1): through agentosd, a vault whose enrollment
// setup never opened makes the codes step say the box cannot finish setup;
// it offers no Continue, no key and no "already set up". A vault that
// stops answering for setup after the codes step makes finish say the
// same, not "Try again".
func TestAVaultThatCannotFinishSetupSaysSo(t *testing.T) {
	via := func(r *rig) {
		s := localsrv.NewSetup(localsrv.SetupConfig{Record: localsrv.FileRecord{Path: filepath.Join(t.TempDir(), "setup.json")},
			Enroll:   vaultEnroller{r.hooks},
			Progress: func() localapi.SetupProgress { p := r.hooks.Progress(); return localapi.SetupProgress(p) },
			Finished: func(string) {}, Now: r.clock})
		r.via = viaAgentosd{r.hooks, AgentosdSetup{InProcess(s.Ops())}}
		r.srv = r.open(&MemStore{})
	}
	r := newRig(t)
	via(r)
	r.hooks.mu.Lock()
	r.hooks.unavailable = true
	r.hooks.mu.Unlock()
	page := r.toCodes()
	if !strings.Contains(page, cannotFinish) || strings.Contains(page, "already set up") ||
		strings.Contains(page, `name="enrolled"`) || strings.Contains(page, "secret=") {
		t.Fatalf("codes step on a vault never opened: %s", page)
	}
	for _, f := range []url.Values{{"enrolled": {"1"}}, {"code": {"123456"}}} {
		r.post("/setup/codes", f)
		if r.srv.setup.st.Codes || r.setupErr() != cannotFinish {
			t.Fatalf("%v: codes %v, said %q", f, r.srv.setup.st.Codes, r.setupErr())
		}
	}

	r = newRig(t)
	via(r)
	r.runSetupToAI()
	r.hooks.mu.Lock()
	r.hooks.unavailable = true
	r.hooks.mu.Unlock()
	r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}, "private": {"1"}})
	if r.srv.setup.done() || r.hooks.finished != "" || r.setupErr() != cannotFinish {
		t.Fatalf("finish on a vault not open: done %v, said %q", r.srv.setup.done(), r.setupErr())
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

// SealEnroll: the fake vault seals at confirm, so only its seal counts.
func (v vaultEnroller) SealEnroll() error {
	v.f.mu.Lock()
	defer v.f.mu.Unlock()
	if v.f.unavailable {
		return localsrv.EnrollNotOpen
	}
	if v.f.seed == nil {
		return localsrv.EnrollNone
	}
	return nil
}

func vaultSentinel(err error) error {
	switch {
	case errors.Is(err, ErrCodesEnrolled):
		return localsrv.EnrollClosed
	case errors.Is(err, ErrNoCodeEnrollment):
		return localsrv.EnrollNone
	case errors.Is(err, ErrCodesUnavailable):
		return localsrv.EnrollNotOpen
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

// k17Vault is the vault's enrollment as egress K17 runs it since L3 on
// #367: a confirmation waits for finish's seal, and a new seed voids it.
type k17Vault struct {
	mu                       sync.Mutex
	now                      func() time.Time
	pending, confirmed, seed []byte
}

func (v *k17Vault) Enroll() (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seed != nil {
		return "", localsrv.EnrollClosed
	}
	v.pending, v.confirmed = make([]byte, 20), nil
	if _, err := crand.Read(v.pending); err != nil {
		return "", err
	}
	return "otpauth://totp/AgentOS:AgentOS?secret=" + secretOf(v.pending) + "&issuer=AgentOS&algorithm=SHA1&digits=6&period=30", nil
}

func (v *k17Vault) ConfirmEnroll(code string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	switch {
	case v.seed != nil:
		return false, localsrv.EnrollClosed
	case v.pending == nil:
		return false, localsrv.EnrollNone
	case code != owner.TOTP(v.pending, v.now()):
		return false, nil
	}
	v.confirmed, v.pending = v.pending, nil
	return true, nil
}

func (v *k17Vault) SealEnroll() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	switch {
	case v.seed != nil:
		return localsrv.EnrollClosed
	case v.confirmed == nil || v.pending != nil:
		return localsrv.EnrollNone
	}
	v.seed = v.confirmed
	return nil
}

// L3 on #367, CRED-8, ONB-6: a phone that paired and confirmed, then lost
// setup to a restart with the card's secret, does not keep the code
// generator: the restarted pairing's seed is the one finish seals, and
// finish waits for it to be confirmed.
func TestARestartedSetupSealsTheNewPairingsSeed(t *testing.T) {
	r := newRig(t)
	vault := &k17Vault{now: r.clock}
	sock := InProcess(localsrv.NewSetup(localsrv.SetupConfig{Record: localsrv.FileRecord{Path: filepath.Join(t.TempDir(), "setup.json")},
		Enroll: vault, Now: r.clock}).Ops())
	agentosd := AgentosdSetup{sock}
	r.via = viaAgentosd{r.hooks, agentosd}
	r.srv = r.open(&MemStore{})
	pair := func(num string) []byte {
		code := regexp.MustCompile(`PAIR%20([A-Z2-9]{8})`).FindStringSubmatch(html.UnescapeString(r.get("/setup")))[1]
		r.srv.OfferText(num, "PAIR "+code)
		m := secretRe.FindStringSubmatch(html.UnescapeString(r.get("/setup")))
		if m == nil {
			t.Fatalf("%s: no key", num)
		}
		return decodeSecret(t, m[1])
	}
	r.hooks.mu.Lock()
	r.hooks.progress.Online = true
	r.hooks.mu.Unlock()
	seedA := pair(ownerNum)
	r.post("/setup/codes", url.Values{"code": {owner.TOTP(seedA, r.clock())}})
	if !r.srv.setup.st.Codes || vault.seed != nil {
		t.Fatalf("A's confirmation: codes %v, sealed %v", r.srv.setup.st.Codes, vault.seed != nil)
	}
	r.asOther(func() {
		r.get("/setup")
		r.post("/setup/restart", url.Values{"secret": {r.card.SetupSecret}})
	})
	if r.srv.setup.st.Owner != "" || r.srv.setup.st.Codes {
		t.Fatal("restart refused")
	}
	const numB = "+15550000002"
	seedB := pair(numB)
	if string(seedB) == string(seedA) {
		t.Fatal("the restarted pairing was shown A's key")
	}
	if err := agentosd.Finish(numB); !refused(err, localapi.ErrNotEnrolled) {
		t.Fatalf("finish before B confirmed: %v", err)
	}
	r.post("/setup/codes", url.Values{"code": {owner.TOTP(seedB, r.clock())}})
	r.post("/setup/recovery", url.Values{"stored": {"1"}})
	r.post("/setup/host", url.Values{})
	r.hooks.mu.Lock()
	r.hooks.progress = Progress{Phase: "ready", Updated: true, Online: true}
	r.hooks.mu.Unlock()
	r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}, "private": {"1"}})
	if !r.srv.setup.done() || r.hooks.finished != numB {
		t.Fatalf("done %v, finished %q", r.srv.setup.done(), r.hooks.finished)
	}
	if string(vault.seed) != string(seedB) {
		t.Fatal("the box holds a generator other than B's")
	}
	if owner.TOTP(seedA, r.clock()) == owner.TOTP(vault.seed, r.clock()) {
		t.Fatal("A's code verifies against the sealed seed")
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
