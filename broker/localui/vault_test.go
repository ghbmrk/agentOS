package localui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"html"
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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"rsc.io/qr"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
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
	// boot is a changed boot path on a trusted PC (P2-4b): "", "updated",
	// "secure_boot" or "other".
	boot  string
	keeps []bool
	// interrupted: a passphrase change is staged, so a wrong passphrase
	// gets the vault process's interrupted line; unfinished: the
	// passphrase opened beside a change that never took (P2-4g).
	interrupted, unfinished bool
	// n numbers tickets; confirmed is the ticket of the confirmed unlock.
	n         int
	confirmed string
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
	if f.boot != "" && f.state != "open" {
		st.BootChanged, st.Updated, st.SecureBoot = true, f.boot == "updated", f.boot == "secure_boot"
	}
	if f.state == "pending" {
		st.Expires = f.expires
	}
	st.ChangeUnfinished = f.unfinished && f.state != "locked"
	return st
}

func (f *fakeVault) Unlock(ctx context.Context, pass string) (VaultStatus, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unlocks = append(f.unlocks, pass)
	if f.state == "open" {
		return VaultStatus{}, "", &VaultError{409, "an unlock is already in progress or the vault is open"}
	}
	if card.NormalizePassphrase(pass) != f.pass {
		if f.interrupted {
			return VaultStatus{}, "", &VaultError{403, "a passphrase change was interrupted; try your new passphrase"}
		}
		return VaultStatus{}, "", &VaultError{403, "the passphrase does not open this vault"}
	}
	// A new correct passphrase supersedes a pending unlock (P2-4f).
	f.n++
	f.state, f.ticket, f.expires = "pending", fmt.Sprintf("tkt-%016d", f.n), time.Date(2099, 10, 5, 9, 15, 0, 0, time.UTC) // far future: the unlock cookie carries this expiry, and the client drops expired cookies by the wall clock
	return f.status(), f.ticket, nil
}

func (f *fakeVault) Confirm(ctx context.Context, ticket, code string, keep bool) (VaultStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keeps = append(f.keeps, keep)
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
	f.state, f.confirmed, f.ticket = "open", f.ticket, ""
	st := f.status()
	st.KeptTrusted = keep && f.boot != ""
	return st, nil
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
// photo and/or typed words. It waits out the attempt gap first, as a
// person would.
func (r *rig) upload(photo []byte, typed string) *httpResult {
	r.t.Helper()
	r.advance(VaultTryGap)
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
func qrPNG(t testing.TB, payload string) []byte {
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
	if strings.Contains(op, `name="code"`) || !strings.Contains(op, "another phone or a closed page") {
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
		if strings.Count(strings.ToLower(b), "<script") > strings.Count(b, "<script>"+shrinkJS+"</script>") {
			t.Fatal("a page carries script other than the photo shrink (ONB-1)")
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
	r.advance(VaultTryGap)
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
	if !strings.Contains(page, "still starting") || !strings.Contains(page, `http-equiv="refresh"`) {
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

// A trusted PC that started a boot path the box never approved (P2-4b)
// falls back to the card. The page says why, and offers "Keep this PC
// trusted", never ticked by default, since the cause hints come from the
// drive (#42 T6); the owner ticks it.
func TestVaultChangedBootPath(t *testing.T) {
	cases := []struct {
		boot, notice string
		ticked       bool // the owner ticks the box
	}{
		{"updated", "Box updated. Unlock once with your passphrase and a code; this PC stays trusted after that.", true},
		{"secure_boot", "Secure Boot settings on this PC changed. If you updated firmware, unlock with your card to keep this PC trusted.", false},
		{"other", "This PC started the box in a way it hasn&#39;t before. If you didn&#39;t change anything, the drive may have been tampered with. Unlock only if you&#39;re sure.", false},
	}
	for _, c := range cases {
		r, fv := vaultRig(t)
		fv.boot = c.boot
		if page := r.get("/unlock/vault"); !strings.Contains(page, c.notice) {
			t.Fatalf("%s notice:\n%s", c.boot, page)
		}
		r.upload(nil, r.card.VaultPassphrase)
		page := r.get("/unlock/vault")
		if !strings.Contains(page, `name="keep"`) || strings.Contains(page, `value="1" checked`) {
			t.Fatalf("%s checkbox:\n%s", c.boot, page)
		}
		form := url.Values{"step": {"code"}, "code": {"123456"}}
		if c.ticked {
			form.Set("keep", "1")
		}
		r.post("/unlock/vault", form)
		if len(fv.keeps) != 1 || fv.keeps[0] != c.ticked {
			t.Fatalf("%s keep sent: %v", c.boot, fv.keeps)
		}
		if strings.Contains(r.get("/unlock/vault"), "This PC stays trusted.") != c.ticked {
			t.Fatalf("%s kept notice", c.boot)
		}
	}
	// An unknown host has no checkbox.
	r, _ := vaultRig(t)
	r.upload(nil, r.card.VaultPassphrase)
	if strings.Contains(r.get("/unlock/vault"), `name="keep"`) {
		t.Fatal("keep-trusted offered on an unknown host")
	}
}

// The vault process does not count wrong passphrases, and its attempts
// share one slot, so the page bounds attempts per phone and on the Wi-Fi
// as a whole; refused attempts never reach the vault (#50 security B1).
func TestVaultAttemptBudget(t *testing.T) {
	r, fv := vaultRig(t)
	post := func(ip string) string {
		r.ip = ip
		var b bytes.Buffer
		mw := multipart.NewWriter(&b)
		mw.WriteField("step", "passphrase")
		mw.WriteField("passphrase", "wrong words entirely here now please")
		mw.Close()
		return r.doBody("POST", "/unlock/vault", &b, mw.FormDataContentType()).Body.String()
	}
	post("10.42.0.30:1000")
	if body := post("10.42.0.30:1001"); !strings.Contains(body, "Wait a few seconds") || len(fv.unlocks) != 1 {
		t.Fatalf("inside the gap: %d\n%s", len(fv.unlocks), body)
	}
	for i := 1; i < VaultTriesPerHour; i++ {
		r.advance(VaultTryGap)
		post("10.42.0.30:1000")
	}
	r.advance(VaultTryGap)
	if body := post("10.42.0.30:1000"); !strings.Contains(body, "Too many tries from this phone. Try again after 10:00.") {
		t.Fatalf("per phone:\n%s", body)
	}
	if len(fv.unlocks) != VaultTriesPerHour {
		t.Fatalf("vault saw %d", len(fv.unlocks))
	}
	// Rotating addresses meets the Wi-Fi-wide bound.
	for i := 0; len(fv.unlocks) < VaultTriesAllPerHour; i++ {
		post("10.42.0." + strconv.Itoa(40+i) + ":1000")
	}
	if body := post("10.42.0.200:1000"); !strings.Contains(body, "Too many tries on the box&#39;s Wi-Fi.") || len(fv.unlocks) != VaultTriesAllPerHour {
		t.Fatalf("Wi-Fi bound: %d\n%s", len(fv.unlocks), body)
	}
	// An hour on, the owner's phone is admitted again.
	r.advance(time.Hour)
	post("10.42.0.23:1000")
	if len(fv.unlocks) != VaultTriesAllPerHour+1 {
		t.Fatal("budget did not recover")
	}
}

// Parallel uploads cannot each hold a photo: while one is read, another is
// refused before its body is read (#50 security B2).
func TestVaultOneUploadAtATime(t *testing.T) {
	r, fv := vaultRig(t)
	r.srv.scanning <- struct{}{} // an upload in progress
	res := r.upload(cardPhoto(t, r.card.VaultPassphrase), "")
	<-r.srv.scanning
	if !strings.Contains(res.Body, "reading another photo") || len(fv.unlocks) != 0 {
		t.Fatalf("second upload: %v\n%s", fv.unlocks, res.Body)
	}
}

// A 16-bit PNG decodes to 8 bytes a pixel, so it is refused, and a non-JPEG
// photo has a lower pixel bound (#50 security B2).
func TestScanRefusesCostlyPNGs(t *testing.T) {
	var b bytes.Buffer
	png.Encode(&b, image.NewRGBA64(image.Rect(0, 0, 64, 64)))
	if _, err := ScanPassphrase(b.Bytes()); !errors.Is(err, ErrNotPhoto) {
		t.Fatalf("16-bit PNG: %v", err)
	}
	b.Reset()
	png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 1, 1)))
	hdr := append([]byte(nil), b.Bytes()...)
	binary.BigEndian.PutUint32(hdr[16:], 6000) // 6000 x 5000 = 30 MP
	binary.BigEndian.PutUint32(hdr[20:], 5000)
	binary.BigEndian.PutUint32(hdr[29:], crc32.ChecksumIEEE(hdr[12:29]))
	if _, err := ScanPassphrase(hdr); !errors.Is(err, ErrPhotoSize) {
		t.Fatalf("30 MP PNG: %v", err)
	}
}

// A decoder panic on a hostile file is an unreadable photo, not a crash.
func TestScanSafeRecovers(t *testing.T) {
	// A JPEG header with absurd tables exercises the decoders; whatever
	// they do, scanSafe returns.
	for _, b := range [][]byte{nil, {0xff, 0xd8, 0xff}, []byte("\x89PNG\r\n\x1a\n")} {
		if _, err := scanSafe(b); err == nil {
			t.Fatalf("%q decoded", b)
		}
	}
}

// FuzzScanPassphrase: no input makes the scan panic or hang.
func FuzzScanPassphrase(f *testing.F) {
	var b bytes.Buffer
	png.Encode(&b, image.NewGray(image.Rect(0, 0, 8, 8)))
	f.Add(b.Bytes())
	f.Add([]byte{0xff, 0xd8, 0xff, 0xe0})
	f.Add(qrPNG(f, "correct horse battery staple wing duck tree"))
	f.Fuzz(func(t *testing.T, photo []byte) {
		ScanPassphrase(photo)
	})
}

// A progressive JPEG keeps every coefficient until the end, so it has a
// lower pixel bound than a camera's baseline JPEG (#50 L3 F1).
func TestScanBoundsProgressiveJPEG(t *testing.T) {
	var b bytes.Buffer
	jpeg.Encode(&b, image.NewGray(image.Rect(0, 0, 8, 8)), nil)
	sof := bytes.Index(b.Bytes(), []byte{0xff, 0xc0})
	if sof < 0 {
		t.Fatal("no SOF0")
	}
	sized := func(w, h int, marker byte) []byte {
		j := append([]byte(nil), b.Bytes()...)
		j[sof+1] = marker
		binary.BigEndian.PutUint16(j[sof+5:], uint16(h))
		binary.BigEndian.PutUint16(j[sof+7:], uint16(w))
		return j
	}
	// 20 MP: a baseline header passes the bounds (and then fails to
	// decode, being a stub); a progressive one is refused before decoding.
	if _, err := ScanPassphrase(sized(5000, 4000, 0xc0)); errors.Is(err, ErrPhotoSize) {
		t.Fatalf("baseline 20 MP: %v", err)
	}
	if _, err := ScanPassphrase(sized(5000, 4000, 0xc2)); !errors.Is(err, ErrPhotoSize) {
		t.Fatalf("progressive 20 MP: %v", err)
	}
	// Above 24 MP, any JPEG is refused.
	if _, err := ScanPassphrase(sized(6000, 5000, 0xc0)); !errors.Is(err, ErrPhotoSize) {
		t.Fatalf("baseline 30 MP: %v", err)
	}
	// A segment whose length has bit 1 of its low byte set must not hide
	// the real frame header behind a fake SOF0 (#50 L3 re-review, F1).
	prog := sized(5000, 4000, 0xc2)
	fake := append([]byte{0xff, 0xd8, 0xff, 0xef, 0x00, 0x06, 0x00, 0x00, 0xff, 0xc0}, prog[2:]...)
	if _, err := ScanPassphrase(fake); !errors.Is(err, ErrPhotoSize) {
		t.Fatalf("progressive 20 MP behind a fake SOF0: %v", err)
	}
	// Every segment length walks to the next marker.
	for n := 2; n < 600; n++ {
		j := []byte{0xff, 0xd8, 0xff, 0xe1, byte(n >> 8), byte(n)}
		j = append(j, make([]byte, n-2)...)
		j = append(j, 0xff, 0xc2, 0, 8, 8, 0, 8, 0, 8, 1)
		for k := 6; k < 4+n; k++ {
			j[k] = 0xc0 // a stray SOF0 marker byte inside the segment
		}
		if !progressiveJPEG(j) {
			t.Fatalf("segment length %d: progressive frame missed", n)
		}
	}
}

// A photo spends an attempt before it is read, even one with no code in
// it, so scans cannot be repeated outside the budget (#50 L3 F2).
func TestVaultPhotoSpendsAnAttempt(t *testing.T) {
	r, _ := vaultRig(t)
	blank := cardPhoto(t)
	send := func() string {
		var b bytes.Buffer
		mw := multipart.NewWriter(&b)
		mw.WriteField("step", "passphrase")
		fw, _ := mw.CreateFormFile("photo", "IMG.jpg")
		fw.Write(blank)
		mw.Close()
		return r.doBody("POST", "/unlock/vault", &b, mw.FormDataContentType()).Body.String()
	}
	if body := send(); !strings.Contains(body, "No QR code found") {
		t.Fatalf("first photo:\n%s", body)
	}
	if body := send(); !strings.Contains(body, "Wait a few seconds") {
		t.Fatalf("second photo inside the gap was scanned:\n%s", body)
	}
}

// proofVerifier is the vault process's verify socket for the owner
// channel: it redeems the confirmed unlock's ticket once (P2-4f).
type proofVerifier struct {
	fv     *fakeVault
	mu     sync.Mutex
	proofs []string
	refuse bool
}

func (p *proofVerifier) VerifyTOTP(code string, after int64, counted bool) (int64, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.proofs = append(p.proofs, code)
	p.fv.mu.Lock()
	defer p.fv.mu.Unlock()
	if p.refuse || p.fv.confirmed == "" || code != owner.UnlockProofPrefix+p.fv.confirmed {
		return 0, false, nil
	}
	p.fv.confirmed = ""
	return after + 1, true, nil
}

func (r *rig) channelWith(v owner.Verifier) {
	r.t.Helper()
	ch, err := owner.New(owner.Config{Owner: ownerNum, Modem: modem.NewCarrier().Line(boxNum), Engine: r.eng, Store: &owner.MemStore{},
		Verifier: v, Now: r.clock, Location: time.UTC})
	if err != nil {
		r.t.Fatal(err)
	}
	r.ch = ch
	r.srv.SetOwner(r.page(ch))
}

// UX-50-1, P2-4f: the code that unlocks the box also signs the phone in
// and unlocks chat by text. The local UI presents the confirmed ticket to
// the owner channel, which has the vault process check it; the local UI
// never signs a phone in without that check.
func TestVaultUnlockSignsThePhoneIn(t *testing.T) {
	r, fv := vaultRig(t)
	pv := &proofVerifier{fv: fv}
	r.channelWith(pv)
	r.upload(nil, r.card.VaultPassphrase)
	ticket := fv.ticket
	r.post("/unlock/vault", url.Values{"step": {"code"}, "code": {"123456"}})
	page := r.get("/unlock/vault")
	if !strings.Contains(page, "This phone is signed in, and chat by text is unlocked.") {
		t.Fatalf("open page:\n%s", page)
	}
	if len(pv.proofs) != 1 || pv.proofs[0] != owner.UnlockProofPrefix+ticket {
		t.Fatalf("proofs: %q", pv.proofs)
	}
	if w := r.do("GET", "/home", nil); w.Code != http.StatusOK {
		t.Fatal("phone not signed in")
	}
	if st := r.ch.LocalStatus(); st.Challenged || st.LowLocked {
		t.Fatalf("chat not unlocked: %+v", st)
	}
	// Another phone is not signed in by it.
	other := &rig{t: t, srv: r.srv, ip: "10.42.0.77:40000"}
	other.jar, _ = cookiejar.New(nil)
	if strings.Contains(other.get("/unlock/vault"), "This phone is signed in") {
		t.Fatal("other phone shown as signed in")
	}
}

// When the owner channel refuses the proof, the phone is not signed in and
// the page offers sign-in with the next code.
func TestVaultUnlockSignInRefused(t *testing.T) {
	r, fv := vaultRig(t)
	r.channelWith(&proofVerifier{fv: fv, refuse: true})
	r.upload(nil, r.card.VaultPassphrase)
	r.post("/unlock/vault", url.Values{"step": {"code"}, "code": {"123456"}})
	page := r.get("/unlock/vault")
	if strings.Contains(page, "This phone is signed in") || !strings.Contains(page, `<a href="/unlock">sign in</a>`) {
		t.Fatalf("open page:\n%s", page)
	}
}

// PU1, P2-4f: a phone that finds an unlock waiting elsewhere can start
// over with the card; the new unlock is then this phone's.
func TestVaultStartOverOnAnotherPhone(t *testing.T) {
	r, fv := vaultRig(t)
	r.upload(nil, r.card.VaultPassphrase)
	other := &rig{t: t, srv: r.srv, ip: "10.42.0.77:40000", now: r.clock()}
	other.jar, _ = cookiejar.New(nil)
	page := other.get("/unlock/vault")
	if !strings.Contains(page, "Start over on this phone") || !strings.Contains(page, "This cancels the unlock waiting on the other phone.") || !strings.Contains(page, `name="photo"`) {
		t.Fatalf("other phone:\n%s", page)
	}
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	mw.WriteField("step", "passphrase")
	mw.WriteField("passphrase", r.card.VaultPassphrase)
	mw.Close()
	if w := other.doBody("POST", "/unlock/vault", &b, mw.FormDataContentType()); w.Code != http.StatusSeeOther {
		t.Fatalf("start over: %d\n%s", w.Code, w.Body)
	}
	if !strings.Contains(other.get("/unlock/vault"), `name="code"`) {
		t.Fatal("new unlock is not the other phone's")
	}
	if strings.Contains(r.get("/unlock/vault"), `name="code"`) {
		t.Fatal("first phone still holds the unlock")
	}
	other.post("/unlock/vault", url.Values{"step": {"code"}, "code": {"123456"}})
	if fv.state != "open" {
		t.Fatalf("state %s", fv.state)
	}
}

// The vault page's one script shrinks a large photo on the phone (#50
// arbitrator). The CSP allows it by hash and nothing else; it reaches
// nothing outside the page; the form works without it; and no other page
// may run script.
func TestVaultShrinkScript(t *testing.T) {
	if MaxProgressivePixels != 12e6 {
		t.Fatal("shrinkJS's max must equal MaxProgressivePixels")
	}
	r, _ := vaultRig(t)
	w := r.do("GET", "/unlock/vault", nil)
	page := w.Body.String()
	m := regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindAllStringSubmatch(page, -1)
	if len(m) != 1 {
		t.Fatalf("scripts: %d\n%s", len(m), page)
	}
	h := sha256.Sum256([]byte(m[0][1]))
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.HasSuffix(csp, "; script-src 'sha256-"+base64.StdEncoding.EncodeToString(h[:])+"'") || !strings.HasPrefix(csp, pageCSP) {
		t.Fatalf("CSP %q does not allow exactly the page's script", csp)
	}
	for _, bad := range []string{"fetch", "XMLHttpRequest", "http", "src", "eval", "Function(", "submit", "innerHTML", "cookie"} {
		if strings.Contains(m[0][1], bad) {
			t.Fatalf("shrink script uses %q", bad)
		}
	}
	if !strings.Contains(page, `<form method="post" action="/unlock/vault" enctype="multipart/form-data">`) || !strings.Contains(page, `<input type="file" name="photo" id="photo" accept="image/*">`) {
		t.Fatal("photo form needs the script")
	}
	if csp := r.do("GET", "/status", nil).Header().Get("Content-Security-Policy"); csp != pageCSP || strings.Contains(csp, "script-src") {
		t.Fatalf("status CSP %q", csp)
	}
}

// A phone holding the pending unlock's cookie is exempt from the
// Wi-Fi-wide budget (#50 arbitrator); its own limits still apply.
func TestVaultBudgetExemptsThePendingPhone(t *testing.T) {
	r, fv := vaultRig(t)
	r.upload(nil, r.card.VaultPassphrase)
	if fv.state != "pending" {
		t.Fatalf("state %q", fv.state)
	}
	// Other addresses use up the Wi-Fi-wide budget.
	for i := 0; i < VaultTriesAllPerHour; i++ {
		o := &rig{t: t, srv: r.srv, ip: fmt.Sprintf("10.42.0.%d:40000", 100+i), now: r.clock()}
		o.jar, _ = cookiejar.New(nil)
		o.post("/unlock/vault", url.Values{"step": {"pin"}, "pin": {"0000"}})
	}
	o := &rig{t: t, srv: r.srv, ip: "10.42.0.250:5000"}
	o.jar, _ = cookiejar.New(nil)
	if b := o.post("/unlock/vault", url.Values{"step": {"pin"}, "pin": {"0000"}}).Body.String(); !strings.Contains(b, "Too many tries on the box") {
		t.Fatalf("budget not spent:\n%s", b)
	}
	// The owner's phone, holding the cookie, still gets a try.
	r.advance(VaultTryGap)
	if b := r.post("/unlock/vault", url.Values{"step": {"pin"}, "pin": {"0000"}}).Body.String(); strings.Contains(b, "Too many tries") {
		t.Fatalf("pending phone starved:\n%s", b)
	}
}

// A typed code is never the vault unlock's sign-in proof; only the vault
// page presents one, right after the confirm (#65 L3 follow-up 1).
func TestTypedCodeIsNeverAnUnlockProof(t *testing.T) {
	r, fv := vaultRig(t)
	pv := &proofVerifier{fv: fv}
	r.channelWith(pv)
	w := r.post("/unlock", url.Values{"code": {owner.UnlockProofPrefix + "tkt-0000000000000001"}})
	if len(pv.proofs) != 0 {
		t.Fatalf("typed proof reached the owner channel: %q", pv.proofs)
	}
	if !strings.Contains(w.Body.String(), html.EscapeString(wrongCodeText)) {
		t.Fatalf("typed proof:\n%s", w.Body)
	}
}

// P2-4g (UX lens on #63): after an interrupted passphrase change the page
// says so in fixed words, instead of the plain wrong-passphrase line, and
// once the old passphrase opened beside a change that never took, it asks
// the owner to change it again, on the code step and once unlocked.
func TestVaultInterruptedPassphraseChange(t *testing.T) {
	r, fv := vaultRig(t)
	fv.interrupted = true
	res := r.upload(nil, "not the words")
	if !strings.Contains(res.Body, "A passphrase change was interrupted. Try your new passphrase, or your old one if that fails.") ||
		strings.Contains(res.Body, "Those words do not open this box") {
		t.Fatalf("interrupted change:\n%s", res.Body)
	}

	fv.interrupted, fv.unfinished = false, true
	const line = "Your passphrase change did not finish, so your old passphrase still works. Change it again the same way you started it."
	if page := r.get("/unlock/vault"); strings.Contains(page, line) {
		t.Fatalf("shown while locked:\n%s", page)
	}
	if res := r.upload(nil, r.card.VaultPassphrase); res.Code != http.StatusSeeOther {
		t.Fatalf("passphrase: %d\n%s", res.Code, res.Body)
	}
	if page := r.get("/unlock/vault"); !strings.Contains(page, line) || !strings.Contains(page, `name="code"`) {
		t.Fatalf("code step:\n%s", page)
	}
	if w := r.post("/unlock/vault", url.Values{"step": {"code"}, "code": {"123456"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("code: %d\n%s", w.Code, w.Body)
	}
	if page := r.get("/unlock/vault"); !strings.Contains(page, line) || !strings.Contains(page, "The box is unlocked.") {
		t.Fatalf("open page:\n%s", page)
	}
	// Another phone on the Wi-Fi learns nothing: the line would tell it
	// the old passphrase still opens the box (M1, security R1 on #93).
	other := &rig{t: t, srv: r.srv, ip: "10.42.0.77:40000"}
	other.jar, _ = cookiejar.New(nil)
	if page := other.get("/unlock/vault"); strings.Contains(page, line) || !strings.Contains(page, "The box is unlocked.") {
		t.Fatalf("other phone:\n%s", page)
	}
}
