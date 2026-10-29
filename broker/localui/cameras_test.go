package localui

// REQ: DEV-7, DEV-10, CH-3

import (
	"context"
	"html"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modem"
)

// fakeCameras is agentosd's camera ops: it records each change and
// refuses a tier-4 step whose code is not "123456".
type fakeCameras struct {
	list    localapi.CameraList
	changes []localapi.CameraChange
}

func (f *fakeCameras) Cameras(context.Context, string) (localapi.CameraList, error) {
	return f.list, nil
}

func (f *fakeCameras) CameraChange(_ context.Context, c localapi.CameraChange) error {
	if localapi.CameraTier4(c.Step) && c.Code != "123456" {
		return Refused(localapi.ErrCameraCode)
	}
	f.changes = append(f.changes, c)
	return nil
}

const camKey = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

func cameraRig(t *testing.T) (*rig, *fakeCameras) {
	t.Helper()
	r := newRig(t)
	fc := &fakeCameras{list: localapi.CameraList{
		Lines:   []string{"camera porch: capture off"},
		Cameras: []localapi.Camera{{ID: "porch", Addr: "192.168.1.60:8443", Capture: "off"}},
		Listed: []localapi.CameraNode{{Addr: "192.168.1.61:8443", Key: camKey,
			Video: localapi.Shape{Width: 640, Height: 480}}},
	}}
	s, err := New(Config{Page: testPage(), Hooks: r.hooks, SetupSecret: r.card.SetupSecret, Store: &MemStore{},
		Defaults: "spend cap $20 a day; payments need approval.", Cameras: fc,
		Now: r.clock, Rand: rand.New(rand.NewSource(9))})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = s
	r.runSetup()
	r.startChannel(modem.NewCarrier().Line(boxNum))
	return r, fc
}

// The page is behind sign-in, and lists the STATUS lines, the cameras
// and the listed nodes with the key's first 8 characters only.
func TestCamerasPageLists(t *testing.T) {
	var _ Cameras = AgentosdCameras{}
	r, fc := cameraRig(t)
	if w := r.do("GET", "/cameras/", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("cameras page before sign-in: %d", w.Code)
	}
	if w := r.post("/cameras/", url.Values{"step": {"disconnect"}, "id": {"porch"}, "confirm": {"1"}}); w.Code != http.StatusSeeOther || len(fc.changes) != 0 {
		t.Fatalf("a post without sign-in: %d", w.Code)
	}
	r.signIn()
	p := html.UnescapeString(r.get("/cameras/"))
	for _, want := range []string{"camera porch: capture off", "192.168.1.60:8443", "key starts <strong class=\"mono\">a1b2c3d4</strong>"} {
		if !strings.Contains(p, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(p, camKey) {
		t.Error("the page shows the whole fingerprint, so the label check proves nothing")
	}
}

// A tier-4 step (here, capture on) shows a confirm step that states the
// mode and the consent notice, and goes to agentosd only with the code;
// a wrong code stays on the confirm step.
func TestCamerasCaptureNeedsTheCode(t *testing.T) {
	r, fc := cameraRig(t)
	r.signIn()
	p := html.UnescapeString(r.post("/cameras/", url.Values{"step": {"capture"}, "id": {"porch"}, "capture": {"continuous"}}).Body.String())
	if len(fc.changes) != 0 || !strings.Contains(p, "Capture <strong>continuous</strong>") ||
		!strings.Contains(p, "may need their consent under your local law") || !strings.Contains(p, `name="code"`) {
		t.Fatalf("no confirm step:\n%s", p)
	}
	p = html.UnescapeString(r.post("/cameras/", url.Values{"step": {"capture"}, "id": {"porch"}, "capture": {"continuous"}, "code": {"000000"}}).Body.String())
	if len(fc.changes) != 0 || !strings.Contains(p, "approval code didn't work") || !strings.Contains(p, `name="code"`) {
		t.Fatalf("a wrong code:\n%s", p)
	}
	r.post("/cameras/", url.Values{"step": {"capture"}, "id": {"porch"}, "capture": {"continuous"}, "code": {"123456"}})
	if len(fc.changes) != 1 || fc.changes[0].Capture != "continuous" || fc.changes[0].Token == "" {
		t.Fatalf("changes: %+v", fc.changes)
	}
	if r.post("/cameras/", url.Values{"step": {"capture"}, "id": {"porch"}, "capture": {"always"}, "code": {"123456"}}); len(fc.changes) != 1 {
		t.Fatal("an unknown mode went to agentosd")
	}
}

// Connect takes a listed node only when the owner types the first 8
// characters of its key from the case label, and connects with capture
// off; a wrong label is refused before agentosd.
func TestCamerasConnectChecksTheLabel(t *testing.T) {
	r, fc := cameraRig(t)
	r.signIn()
	bad := url.Values{"step": {"connect"}, "addr": {"192.168.1.61:8443"}, "id": {"garden"}, "label": {"a1b2c3d5"}, "code": {"123456"}}
	if p := r.post("/cameras/", bad).Body.String(); len(fc.changes) != 0 || !strings.Contains(html.UnescapeString(p), "doesn't match") {
		t.Fatal("a wrong label was taken")
	}
	good := url.Values{"step": {"connect"}, "addr": {"192.168.1.61:8443"}, "id": {"garden"}, "label": {"A1B2C3D4"}, "code": {"123456"}}
	r.post("/cameras/", good)
	if len(fc.changes) != 1 || fc.changes[0].Node.Key != camKey || fc.changes[0].Capture != "off" || fc.changes[0].Node.Video.Width != 640 {
		t.Fatalf("changes: %+v", fc.changes)
	}
}

// Disconnect needs no code but asks once more.
func TestCamerasDisconnectConfirms(t *testing.T) {
	r, fc := cameraRig(t)
	r.signIn()
	p := html.UnescapeString(r.post("/cameras/", url.Values{"step": {"disconnect"}, "id": {"porch"}}).Body.String())
	if len(fc.changes) != 0 || !strings.Contains(p, "erase its key and every recording") {
		t.Fatal("disconnect did not ask once more")
	}
	r.post("/cameras/", url.Values{"step": {"disconnect"}, "id": {"porch"}, "confirm": {"1"}})
	if len(fc.changes) != 1 || fc.changes[0].Step != "disconnect" {
		t.Fatalf("changes: %+v", fc.changes)
	}
}

// L3 point 2 on 0658b8c: re-pin, like connect, takes the listed node only
// when the owner types the first 8 characters of its key, and carries the
// node's address with its key.
func TestCamerasRepinChecksTheLabel(t *testing.T) {
	r, fc := cameraRig(t)
	r.signIn()
	bad := url.Values{"step": {"repin"}, "addr": {"192.168.1.61:8443"}, "id": {"porch"}, "label": {"a1b2c3d5"}, "code": {"123456"}}
	if p := r.post("/cameras/", bad).Body.String(); len(fc.changes) != 0 || !strings.Contains(html.UnescapeString(p), "doesn't match") {
		t.Fatal("a wrong label was taken")
	}
	good := url.Values{"step": {"repin"}, "addr": {"192.168.1.61:8443"}, "id": {"porch"}, "label": {"a1b2c3d4"}, "code": {"123456"}}
	r.post("/cameras/", good)
	if len(fc.changes) != 1 || fc.changes[0].Node.Key != camKey || fc.changes[0].Node.Addr != "192.168.1.61:8443" {
		t.Fatalf("changes: %+v", fc.changes)
	}
}
