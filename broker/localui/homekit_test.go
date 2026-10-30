package localui

// REQ: DEV-3, DEV-8, DEV-10, CH-3, CH-6

import (
	"context"
	"html"
	"math/rand"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modem"
)

// fakeHomeKit is agentosd's HomeKit ops: it records each change and
// refuses a tier-4 step whose approval code is not "123456", and a pairing
// step whose HomeKit code is not the canary 111-22-333.
type fakeHomeKit struct {
	list    localapi.HomeKitList
	changes []localapi.HomeKitChange
	reset   bool
}

func (f *fakeHomeKit) HomeKit(context.Context, string) (localapi.HomeKitList, error) {
	return f.list, nil
}

func (f *fakeHomeKit) HomeKitChange(_ context.Context, c localapi.HomeKitChange) (localapi.HomeKitDone, error) {
	if localapi.HomeKitTier4(c.Step) && c.Code != "123456" {
		return localapi.HomeKitDone{}, Refused(localapi.ErrHomeKitApproval)
	}
	if (c.Step == localapi.HomeKitConnect || c.Step == localapi.HomeKitRepin) && c.HomeKitCode != "111-22-333" {
		return localapi.HomeKitDone{}, Refused(localapi.ErrHomeKitCode)
	}
	f.changes = append(f.changes, c)
	return localapi.HomeKitDone{Reset: f.reset}, nil
}

func homekitRig(t *testing.T) (*rig, *fakeHomeKit) {
	t.Helper()
	r := newRig(t)
	fh := &fakeHomeKit{list: localapi.HomeKitList{
		Lines:   []string{"homekit hall: thermostat, key a1b2c3d4, open"},
		Devices: []localapi.HomeKitDevice{{Name: "hall", Type: "thermostat", Key: "a1b2c3d4", State: "open"}},
		Listed:  []localapi.HomeKitListed{{Device: "enf-dev-7", Addr: "192.168.1.51:51826", Unpaired: true}, {Device: "enf-dev-8", Addr: "192.168.1.52:51826"}},
	}}
	s, err := New(Config{Page: testPage(), Hooks: r.hooks, SetupSecret: r.card.SetupSecret, Store: &MemStore{},
		Defaults: "spend cap $20 a day; payments need approval.", HomeKit: fh,
		Now: r.clock, Rand: rand.New(rand.NewSource(9))})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = s
	r.runSetup()
	r.startChannel(modem.NewCarrier().Line(boxNum))
	return r, fh
}

// The page is behind sign-in, and lists the STATUS lines, the paired
// thermostats by type and key, and the listed accessories by the
// enforcer's device ID; only an unpaired one offers connect.
func TestHomeKitPageLists(t *testing.T) {
	var _ HomeKit = AgentosdHomeKit{}
	r, fh := homekitRig(t)
	if w := r.do("GET", "/homekit/", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("homekit page before sign-in: %d", w.Code)
	}
	if w := r.post("/homekit/", url.Values{"step": {"disconnect"}, "name": {"hall"}, "confirm": {"1"}}); w.Code != http.StatusSeeOther || len(fh.changes) != 0 {
		t.Fatalf("a post without sign-in: %d", w.Code)
	}
	r.signIn()
	p := html.UnescapeString(r.get("/homekit/"))
	for _, want := range []string{"homekit hall: thermostat", "<strong>hall</strong>: thermostat, key starts <strong class=\"mono\">a1b2c3d4</strong>",
		"HomeKit accessory <strong class=\"mono\">enf-dev-7</strong>", "enf-dev-8</strong> at <span class=\"mono\">192.168.1.52:51826</span>: paired with something else"} {
		if !strings.Contains(p, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Count(p, `name="step" value="connect"`) != 1 {
		t.Error("a paired accessory offers connect")
	}
	r.post("/homekit/", url.Values{"step": {"connect"}, "device": {"enf-dev-8"}, "name": {"den"}, "homekit_code": {"11122333"}, "code": {"123456"}})
	if len(fh.changes) != 0 {
		t.Fatal("a connect to a paired accessory went to agentosd")
	}
}

// Connect takes the HomeKit code, then the approval code, in one confirm
// step; neither is written back into the page, and a wrong one of either
// stays on the confirm step with both fields empty.
func TestHomeKitConnectTakesCodeThenApproval(t *testing.T) {
	r, fh := homekitRig(t)
	r.signIn()
	step := url.Values{"step": {"connect"}, "device": {"enf-dev-7"}, "name": {"den"}}
	p := r.post("/homekit/", step).Body.String()
	hk, ap := strings.Index(p, `name="homekit_code"`), strings.Index(p, `name="code"`)
	if len(fh.changes) != 0 || hk < 0 || ap < 0 || hk > ap {
		t.Fatalf("no confirm step taking the HomeKit code, then the approval code:\n%s", p)
	}
	with := func(hkc, code string) string {
		v := url.Values{}
		for k, x := range step {
			v[k] = x
		}
		v.Set("homekit_code", hkc)
		v.Set("code", code)
		return r.post("/homekit/", v).Body.String()
	}
	for _, c := range []struct{ hk, code, text string }{
		{"111-22-333", "000000", "approval code didn't work"},
		{"999-99-999", "123456", "refused that HomeKit code"},
		{"1112233", "123456", "8 digits"},
	} {
		p := html.UnescapeString(with(c.hk, c.code))
		if len(fh.changes) != 0 || !strings.Contains(p, c.text) || !strings.Contains(p, `name="homekit_code"`) || strings.Contains(p, c.hk) {
			t.Fatalf("%+v:\n%s", c, p)
		}
	}
	p = html.UnescapeString(with("111 22 333", "123456"))
	if len(fh.changes) != 1 || fh.changes[0].HomeKitCode != "111-22-333" || fh.changes[0].Name != "den" || fh.changes[0].Device != "enf-dev-7" || fh.changes[0].Token == "" {
		t.Fatalf("changes: %+v", fh.changes)
	}
	if strings.Contains(p, "111-22-333") || strings.Contains(p, "111 22 333") {
		t.Fatal("the HomeKit code was written back into the page")
	}
	// Re-pin takes the same two codes, and a listed, unpaired accessory.
	if r.post("/homekit/", url.Values{"step": {"repin"}, "name": {"hall"}, "device": {"enf-dev-8"}, "homekit_code": {"11122333"}, "code": {"123456"}}); len(fh.changes) != 1 {
		t.Fatal("a re-pin to a paired accessory went to agentosd")
	}
	r.post("/homekit/", url.Values{"step": {"repin"}, "name": {"hall"}, "device": {"enf-dev-7"}, "homekit_code": {"11122333"}, "code": {"123456"}})
	if len(fh.changes) != 2 || fh.changes[1].Step != "repin" {
		t.Fatalf("changes: %+v", fh.changes)
	}
}

// Bounds take the approval code; a range outside 0 to 40 °C or a mode
// characteristic is refused before agentosd.
func TestHomeKitBoundsTakeApproval(t *testing.T) {
	r, fh := homekitRig(t)
	r.signIn()
	p := html.UnescapeString(r.post("/homekit/", url.Values{"step": {"bounds"}, "name": {"hall"}, "char": {"35"}, "min": {"18"}, "max": {"23"}}).Body.String())
	if len(fh.changes) != 0 || !strings.Contains(p, "Inside <strong>18–23 °C</strong> I may set the target temperature") || strings.Contains(p, `name="homekit_code"`) {
		t.Fatalf("no confirm step:\n%s", p)
	}
	for _, bad := range []url.Values{
		{"step": {"bounds"}, "name": {"hall"}, "char": {"33"}, "min": {"0"}, "max": {"3"}, "code": {"123456"}},
		{"step": {"bounds"}, "name": {"hall"}, "char": {"35"}, "min": {"23"}, "max": {"18"}, "code": {"123456"}},
		{"step": {"bounds"}, "name": {"hall"}, "char": {"35"}, "min": {"18"}, "max": {"90"}, "code": {"123456"}},
		{"step": {"bounds"}, "name": {"den"}, "char": {"35"}, "min": {"18"}, "max": {"23"}, "code": {"123456"}},
	} {
		if r.post("/homekit/", bad); len(fh.changes) != 0 {
			t.Fatalf("%v went to agentosd", bad)
		}
	}
	r.post("/homekit/", url.Values{"step": {"bounds"}, "name": {"hall"}, "char": {"35"}, "min": {"18"}, "max": {"23"}, "code": {"123456"}})
	if len(fh.changes) != 1 || fh.changes[0].Min != 18 || fh.changes[0].Max != 23 || fh.changes[0].Char != "35" {
		t.Fatalf("changes: %+v", fh.changes)
	}
}

// Disconnect needs no code but asks once more, and says when the
// thermostat keeps the pairing until it is reset.
func TestHomeKitDisconnectConfirms(t *testing.T) {
	r, fh := homekitRig(t)
	r.signIn()
	p := html.UnescapeString(r.post("/homekit/", url.Values{"step": {"disconnect"}, "name": {"hall"}}).Body.String())
	if len(fh.changes) != 0 || !strings.Contains(p, "I remove my pairing from the thermostat") || strings.Contains(p, `name="code"`) {
		t.Fatal("disconnect did not ask once more")
	}
	fh.reset = true
	p = html.UnescapeString(r.post("/homekit/", url.Values{"step": {"disconnect"}, "name": {"hall"}, "confirm": {"1"}}).Body.String())
	if len(fh.changes) != 1 || fh.changes[0].Step != "disconnect" || !strings.Contains(p, "reset HomeKit on it") {
		t.Fatalf("changes: %+v\n%s", fh.changes, p)
	}
}

// DEV-8, DEV-10: the page's types carry no text an accessory sent, so a
// thermostat is named by the owner's name, its type and its key, and a
// listed accessory by the enforcer's device ID.
func TestHomeKitPageShowsNoDeviceName(t *testing.T) {
	fields := func(v any) []string {
		var out []string
		for _, f := range reflect.VisibleFields(reflect.TypeOf(v)) {
			out = append(out, f.Name)
		}
		return out
	}
	if got := fields(localapi.HomeKitDevice{}); !reflect.DeepEqual(got, []string{"Name", "Type", "Key", "State", "Bounds"}) {
		t.Fatalf("HomeKitDevice fields: %v", got)
	}
	if got := fields(localapi.HomeKitListed{}); !reflect.DeepEqual(got, []string{"Device", "Addr", "Unpaired"}) {
		t.Fatalf("HomeKitListed fields: %v", got)
	}
	r, _ := homekitRig(t)
	r.signIn()
	p := html.UnescapeString(r.get("/homekit/"))
	if !strings.Contains(p, "thermostat, key starts") || !strings.Contains(p, "HomeKit accessory <strong class=\"mono\">enf-dev-7") {
		t.Fatalf("page:\n%s", p)
	}
}
