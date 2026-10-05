package localui

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"
	"io"
	"math"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"rsc.io/qr"

	"github.com/ghbmrk/agentos/broker/card"
)

// REQ: CRED-8, HW-5a, CH-6, CH-7, ONB-1

// fakeVault stands in for the vault process's unlock socket, with the
// same rules as cmd/agentos-egress: the passphrase makes the unlock
// pending and returns a ticket; the code, with that ticket, opens it;
// three wrong codes discard it.
type fakeVault struct {
	mu      sync.Mutex
	pass    string
	code    string
	state   string
	ticket  string
	expires time.Time
	pin     bool
	wantPIN string
	left    int
	down    bool
	// calls records what reached the socket.
	unlocks  []string
	confirms []string
	pins     []string
}

func newFakeVault(pass string) *fakeVault {
	return &fakeVault{pass: card.NormalizePassphrase(pass), code: "123456", state: "locked", left: 3}
}

func (f *fakeVault) Status(ctx context.Context) (VaultStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return VaultStatus{}, errors.New("dial unix: connection refused")
	}
	return f.status(), nil
}

func (f *fakeVault) status() VaultStatus {
	st := VaultStatus{State: f.state, PIN: f.pin && f.state == "locked"}
	if f.state == "pending" {
		st.Expires = f.expires
	}
	return st
}

func (f *fakeVault) Unlock(ctx context.Context, pass string) (VaultStatus, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unlocks = append(f.unlocks, pass)
	if f.state != "locked" {
		return VaultStatus{}, "", &VaultError{409, "an unlock is already in progress or the vault is open"}
	}
	if card.NormalizePassphrase(pass) != f.pass {
		return VaultStatus{}, "", &VaultError{403, "the passphrase does not open this vault"}
	}
	f.state, f.ticket, f.expires = "pending", "tkt-"+strings.Repeat("a", 16), time.Date(2026, 10, 5, 9, 15, 0, 0, time.UTC)
	return f.status(), f.ticket, nil
}

func (f *fakeVault) Confirm(ctx context.Context, ticket, code string) (VaultStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.confirms = append(f.confirms, ticket+"/"+code)
	if f.state != "pending" || ticket != f.ticket {
		return VaultStatus{}, &VaultError{409, "no unlock is waiting for a code"}
	}
	if code != f.code {
		f.left--
		if f.left == 0 {
			f.state, f.ticket = "locked", ""
			return VaultStatus{}, &VaultError{429, "Too many wrong codes. Unlock again after Tue 09:00."}
		}
		if f.left == 1 {
			return VaultStatus{}, &VaultError{403, "wrong code; 1 try left"}
		}
		return VaultStatus{}, &VaultError{403, "wrong code; 2 tries left"}
	}
	f.state, f.ticket = "open", ""
	return f.status(), nil
}

func (f *fakeVault) UnlockPIN(ctx context.Context, pin string) (VaultStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pins = append(f.pins, pin)
	if !f.pin || f.state != "locked" {
		return VaultStatus{}, &VaultError{409, "no boot PIN is awaited"}
	}
	if pin != f.wantPIN {
		return VaultStatus{}, &VaultError{403, "wrong PIN"}
	}
	f.state, f.pin = "open", false
	return f.status(), nil
}

// vaultRig is a set-up box whose local UI serves the vault unlock page.
func vaultRig(t *testing.T) (*rig, *fakeVault) {
	t.Helper()
	r := newRig(t)
	fv := newFakeVault(r.card.VaultPassphrase)
	s, err := New(Config{AP: testAP(), Hooks: r.hooks, SetupSecret: r.card.SetupSecret, Store: &MemStore{},
		Vault: fv, Now: r.clock, Rand: rand.New(rand.NewSource(9))})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = s
	return r, fv
}

// upload posts the passphrase form as a phone does: multipart, with a
// photo and/or typed words.
func (r *rig) upload(photo []byte, typed string) *httpResult {
	r.t.Helper()
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	mw.WriteField("step", "passphrase")
	if photo != nil {
		fw, _ := mw.CreateFormFile("photo", "IMG_0001.jpg")
		fw.Write(photo)
	}
	mw.WriteField("passphrase", typed)
	mw.Close()
	w := r.doBody("POST", "/unlock/vault", &b, mw.FormDataContentType())
	return &httpResult{w.Code, w.Body.String(), w.Header().Get("Location")}
}

type httpResult struct {
	Code     int
	Body     string
	Location string
}

func (r *rig) doBody(method, path string, body io.Reader, ctype string) *httptest.ResponseRecorder {
	r.t.Helper()
	return r.do(method, path, nil, func(req *http.Request) {
		req.Body = io.NopCloser(body)
		req.ContentLength = -1
		req.Header.Set("Content-Type", ctype)
	})
}

// cardPhoto renders the card's two QR codes side by side on a grey desk,
// tilted and scaled, with uneven light and sensor noise, as a JPEG at
// phone quality: the photo the owner takes.
func cardPhoto(t *testing.T, payloads ...string) []byte {
	t.Helper()
	const W, H = 2400, 1800
	img := image.NewRGBA(image.Rect(0, 0, W, H))
	draw.Draw(img, img.Bounds(), &image.Uniform{color.RGBA{120, 118, 112, 255}}, image.Point{}, draw.Src)
	// The card: a white rectangle holding the codes.
	cardW, cardH := 1500, 900
	cardImg := image.NewRGBA(image.Rect(0, 0, cardW, cardH))
	draw.Draw(cardImg, cardImg.Bounds(), image.White, image.Point{}, draw.Src)
	for i, p := range payloads {
		c, err := qr.Encode(p, qr.M)
		if err != nil {
			t.Fatal(err)
		}
		mod := 560 / (c.Size + 8)
		ox, oy := 80+i*720, 120
		for y := 0; y < c.Size; y++ {
			for x := 0; x < c.Size; x++ {
				if c.Black(x, y) {
					draw.Draw(cardImg, image.Rect(ox+(x+4)*mod, oy+(y+4)*mod, ox+(x+5)*mod, oy+(y+5)*mod), image.Black, image.Point{}, draw.Src)
				}
			}
		}
	}
	// Place the card rotated by 6 degrees, nearest neighbour.
	rng := rand.New(rand.NewSource(3))
	a := 6 * math.Pi / 180
	cx, cy := float64(W)/2, float64(H)/2
	for y := 0; y < H; y++ {
		for x := 0; x < W; x++ {
			dx, dy := float64(x)-cx, float64(y)-cy
			sx := dx*math.Cos(a) + dy*math.Sin(a) + float64(cardW)/2
			sy := -dx*math.Sin(a) + dy*math.Cos(a) + float64(cardH)/2
			var v float64
			if sx >= 0 && sy >= 0 && int(sx) < cardW && int(sy) < cardH {
				v = float64(cardImg.RGBAAt(int(sx), int(sy)).R)
			} else {
				v = float64(img.RGBAAt(x, y).R)
			}
			// Light falls off to one side; the sensor adds noise.
			v = v*(0.75+0.25*float64(x)/W) + rng.NormFloat64()*10
			g := uint8(math.Max(0, math.Min(255, v)))
			img.SetRGBA(x, y, color.RGBA{g, g, uint8(math.Max(0, float64(g)-6)), 255})
		}
	}
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, &jpeg.Options{Quality: 80}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// qrPNG renders one QR code at eight pixels a module with its quiet zone,
// in colour, as a screenshot.
func qrPNG(t *testing.T, payload string) []byte {
	t.Helper()
	c, err := qr.Encode(payload, qr.M)
	if err != nil {
		t.Fatal(err)
	}
	const mod = 8
	n := (c.Size + 8) * mod
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			v := color.RGBA{255, 255, 255, 255}
			if c.Black(x/mod-4, y/mod-4) {
				v = color.RGBA{10, 10, 30, 255}
			}
			img.SetRGBA(x, y, v)
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestScanPassphraseFromCardPhoto(t *testing.T) {
	c, err := card.Generate(rand.New(rand.NewSource(7)))
	if err != nil {
		t.Fatal(err)
	}
	wifi := card.WiFiQR(c.WiFiName, c.WiFiPassword)
	// The whole card: the Wi-Fi code is skipped, the passphrase found.
	got, err := ScanPassphrase(cardPhoto(t, wifi, c.VaultPassphrase))
	if err != nil || got != c.VaultPassphrase {
		t.Fatalf("scan: %q %v", got, err)
	}
	// A screenshot of the card's code (PNG, not a camera JPEG).
	if got, err := ScanPassphrase(qrPNG(t, c.VaultPassphrase)); err != nil || got != c.VaultPassphrase {
		t.Fatalf("screenshot: %q %v", got, err)
	}
	// Only the Wi-Fi code in the frame: say so.
	if _, err := ScanPassphrase(cardPhoto(t, wifi)); !errors.Is(err, ErrWiFiQR) {
		t.Fatalf("Wi-Fi only: %v", err)
	}
	// No code at all.
	if _, err := ScanPassphrase(cardPhoto(t)); !errors.Is(err, ErrNoQR) {
		t.Fatalf("blank card: %v", err)
	}
	// Some other code, such as a code-generator link, is never taken.
	if _, err := ScanPassphrase(cardPhoto(t, "otpauth://totp/AgentOS?secret=AAAA")); !errors.Is(err, ErrNoQR) {
		t.Fatalf("otpauth: %v", err)
	}
	if _, err := ScanPassphrase([]byte("not a photo")); !errors.Is(err, ErrNotPhoto) {
		t.Fatalf("garbage: %v", err)
	}
}

// A photo whose header claims more pixels than the bound is refused before
// it is decoded, so one upload cannot exhaust the box's memory.
func TestScanRefusesOversizedPhotos(t *testing.T) {
	var b bytes.Buffer
	png.Encode(&b, image.NewGray(image.Rect(0, 0, 1, 1)))
	hdr := append([]byte(nil), b.Bytes()...)
	// Rewrite the IHDR width and height (bytes 16-23) to 10000 x 10000
	// and fix its checksum; DecodeConfig reads only the header.
	binary.BigEndian.PutUint32(hdr[16:], 10000)
	binary.BigEndian.PutUint32(hdr[20:], 10000)
	binary.BigEndian.PutUint32(hdr[29:], crc32.ChecksumIEEE(hdr[12:29]))
	if cfg, _, err := image.DecodeConfig(bytes.NewReader(hdr)); err != nil || cfg.Width != 10000 {
		t.Fatalf("fixture: %v %v", cfg, err)
	}
	if _, err := ScanPassphrase(hdr); !errors.Is(err, ErrPhotoSize) {
		t.Fatalf("oversized: %v", err)
	}
}

// TestVaultUnlockByPhotoThenCode is the unknown-host unlock on the local
// page (CRED-8): open without sign-in (CH-7), the HW-5a warning at the
// point of use, the passphrase scanned from a photo of the card, then the
// code-generator code. Only the phone that sent the passphrase can answer
// with the code, and the passphrase is never shown back.
func TestVaultUnlockByPhotoThenCode(t *testing.T) {
	r, fv := vaultRig(t)
	page := r.get("/unlock/vault")
	if !strings.Contains(page, "If this drive was out of your hands, unlock it only on your trusted PC.") {
		t.Fatalf("no HW-5a warning:\n%s", page)
	}
	if !strings.Contains(page, `enctype="multipart/form-data"`) || !strings.Contains(page, `type="file"`) || !strings.Contains(page, `accept="image/*"`) {
		t.Fatalf("no photo upload:\n%s", page)
	}
	// The sign-in page links here.
	if !strings.Contains(r.get("/unlock"), `href="/unlock/vault"`) {
		t.Fatal("sign-in page does not link the vault unlock")
	}

	wifi := card.WiFiQR(r.card.WiFiName, r.card.WiFiPassword)
	res := r.upload(cardPhoto(t, wifi, r.card.VaultPassphrase), "")
	if res.Code != http.StatusSeeOther || res.Location != "/unlock/vault" {
		t.Fatalf("passphrase post: %d %s\n%s", res.Code, res.Location, res.Body)
	}
	if len(fv.unlocks) != 1 || fv.unlocks[0] != r.card.VaultPassphrase {
		t.Fatalf("vault got %q", fv.unlocks)
	}
	page = r.get("/unlock/vault")
	if !strings.Contains(page, `name="code"`) || !strings.Contains(page, "09:15") {
		t.Fatalf("no code form after the passphrase:\n%s", page)
	}

	// Another phone on the Wi-Fi sees that an unlock waits, and cannot
	// answer it.
	other := &rig{t: t, srv: r.srv, ip: "10.42.0.77:40000"}
	other.jar, _ = cookiejar.New(nil)
	op := other.get("/unlock/vault")
	if strings.Contains(op, `name="code"`) || !strings.Contains(op, "another phone") {
		t.Fatalf("other phone:\n%s", op)
	}
	w := other.post("/unlock/vault", url.Values{"step": {"code"}, "code": {"123456"}})
	if len(fv.confirms) != 0 || !strings.Contains(w.Body.String(), "another phone") {
		t.Fatalf("other phone answered the unlock: %v\n%s", fv.confirms, w.Body)
	}

	// A wrong code: tries left, the form stays.
	w = r.post("/unlock/vault", url.Values{"step": {"code"}, "code": {"000000"}})
	if !strings.Contains(w.Body.String(), "Wrong code; 2 tries left.") || !strings.Contains(w.Body.String(), `name="code"`) {
		t.Fatalf("wrong code:\n%s", w.Body)
	}
	w = r.post("/unlock/vault", url.Values{"step": {"code"}, "code": {" 123456 "}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("right code: %d\n%s", w.Code, w.Body)
	}
	page = r.get("/unlock/vault")
	if !strings.Contains(page, "The box is unlocked.") || !strings.Contains(page, `href="/unlock"`) {
		t.Fatalf("open page:\n%s", page)
	}
	for _, b := range r.seen {
		if strings.Contains(b, r.card.VaultPassphrase) {
			t.Fatal("a page showed the passphrase")
		}
		if strings.Contains(strings.ToLower(b), "<script") {
			t.Fatal("a page carries script (ONB-1)")
		}
	}
}

// Typing the words is the fallback (CRED-8); typed words win over a photo.
func TestVaultUnlockByTypedWords(t *testing.T) {
	r, fv := vaultRig(t)
	// The photo holds only the Wi-Fi code; the typed words are used.
	res := r.upload(cardPhoto(t, card.WiFiQR(r.card.WiFiName, r.card.WiFiPassword)), "  "+strings.ToUpper(r.card.VaultPassphrase)+" ")
	if res.Code != http.StatusSeeOther || len(fv.unlocks) != 1 {
		t.Fatalf("typed: %d %v\n%s", res.Code, fv.unlocks, res.Body)
	}
	if card.NormalizePassphrase(fv.unlocks[0]) != card.NormalizePassphrase(r.card.VaultPassphrase) {
		t.Fatalf("vault got %q", fv.unlocks[0])
	}
}

// Each refusal is one plain line, and nothing typed is put back in the
// page.
func TestVaultUnlockRefusals(t *testing.T) {
	r, fv := vaultRig(t)
	wifi := card.WiFiQR(r.card.WiFiName, r.card.WiFiPassword)
	cases := []struct {
		photo []byte
		typed string
		want  string
	}{
		{nil, "", "Take a photo of the passphrase code, or type the words."},
		{cardPhoto(t, wifi), "", "That is the Wi-Fi code."},
		{cardPhoto(t), "", "No QR code found in that photo."},
		{[]byte("GIF89a not really"), "", "The box cannot read that file."},
		{nil, "wrong words entirely here now please", "Those words do not open this box."},
	}
	for _, c := range cases {
		res := r.upload(c.photo, c.typed)
		if res.Code != http.StatusOK || !strings.Contains(res.Body, c.want) {
			t.Fatalf("%q: %d\n%s", c.want, res.Code, res.Body)
		}
		if c.typed != "" && strings.Contains(res.Body, c.typed) {
			t.Fatal("typed words echoed")
		}
	}
	if len(fv.unlocks) != 1 {
		t.Fatalf("only the typed attempt reaches the vault: %q", fv.unlocks)
	}

	// Three wrong codes: the vault process discards the key and the page
	// says when to try again; the phone's ticket is forgotten.
	r.upload(nil, r.card.VaultPassphrase)
	var body string
	for i := 0; i < 3; i++ {
		body = r.post("/unlock/vault", url.Values{"step": {"code"}, "code": {"000000"}}).Body.String()
	}
	if !strings.Contains(body, "Unlock again after Tue 09:00.") {
		t.Fatalf("lockout:\n%s", body)
	}
	if page := r.get("/unlock/vault"); strings.Contains(page, `name="code"`) {
		t.Fatalf("code form after lockout:\n%s", page)
	}
}

// The upload is read in memory, never spooled to a temporary file, so a
// photo of the passphrase never reaches the drive (CRED-8).
func TestVaultPhotoNeverTouchesTheDrive(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	r, _ := vaultRig(t)
	// Larger than any in-memory threshold multipart parsing uses.
	big := append(cardPhoto(t, r.card.VaultPassphrase), make([]byte, 12<<20)...)
	r.upload(big, "")
	ents, err := os.ReadDir(tmp)
	if err != nil || len(ents) != 0 {
		t.Fatalf("temporary files: %v %v", ents, err)
	}
	// Above the bound: refused without reading it all.
	res := r.upload(make([]byte, MaxPhotoBytes+1024), "")
	if !strings.Contains(res.Body, "too large") {
		t.Fatalf("oversized upload:\n%s", res.Body)
	}
}

// A trusted PC with a boot PIN (CRED-8, P2-4b) asks for it on the same
// page; the card still works.
func TestVaultBootPIN(t *testing.T) {
	r, fv := vaultRig(t)
	fv.pin, fv.wantPIN = true, "4711"
	page := r.get("/unlock/vault")
	if !strings.Contains(page, `name="pin"`) || !strings.Contains(page, `type="file"`) {
		t.Fatalf("PIN page:\n%s", page)
	}
	w := r.post("/unlock/vault", url.Values{"step": {"pin"}, "pin": {"0000"}})
	if !strings.Contains(w.Body.String(), "Wrong PIN.") || strings.Contains(w.Body.String(), "0000") {
		t.Fatalf("wrong PIN:\n%s", w.Body)
	}
	w = r.post("/unlock/vault", url.Values{"step": {"pin"}, "pin": {"4711"}})
	if w.Code != http.StatusSeeOther || !strings.Contains(r.get("/unlock/vault"), "The box is unlocked.") {
		t.Fatalf("PIN: %d %v", w.Code, fv.pins)
	}
	// Without a PIN awaited, no PIN form.
	r2, _ := vaultRig(t)
	if strings.Contains(r2.get("/unlock/vault"), `name="pin"`) {
		t.Fatal("PIN form on an unknown host")
	}
}

// The vault process down: the page says so and reloads itself.
func TestVaultNotAnswering(t *testing.T) {
	r, fv := vaultRig(t)
	fv.down = true
	page := r.get("/unlock/vault")
	if !strings.Contains(page, "not answering") || !strings.Contains(page, `http-equiv="refresh"`) {
		t.Fatalf("down:\n%s", page)
	}
}

// A post from another site never reaches the vault (CH-7, ONB-5).
func TestVaultUnlockRefusesCrossSitePosts(t *testing.T) {
	r, fv := vaultRig(t)
	w := r.do("POST", "/unlock/vault", url.Values{"step": {"passphrase"}, "passphrase": {r.card.VaultPassphrase}}, func(req *http.Request) {
		req.Header.Set("Origin", "http://evil.example")
	})
	if w.Code != http.StatusForbidden || len(fv.unlocks) != 0 {
		t.Fatalf("cross-site: %d %v", w.Code, fv.unlocks)
	}
}
