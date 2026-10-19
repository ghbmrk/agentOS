package checker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/checker/checkersock"
)

// REQ: CH-4, CH-10, ARC-1

// totp computes the owner's code-generator code at t (RFC 6238, SHA-1,
// 30 s, 6 digits), as the owner's phone does.
func totp(seed []byte, t time.Time) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/30))
	m := hmac.New(sha1.New, seed)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

func syntheticSeed(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newChecker(t *testing.T, clk *clock) (*Checker, string) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "checker.json")
	c, err := New(Config{StatePath: state, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	return c, state
}

func act(t *testing.T, body string) string {
	return Act("bank-login", "bank.example", "POST", "/v1/pay", []byte(body))
}

// Nothing verifies before the seed is handed: no seed, no approval.
func TestNoSeedVerifiesNothing(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c, _ := newChecker(t, clk)
	_, ok, err := c.Verify("123456", 0, true, []string{act(t, "{}")})
	if ok || !errors.Is(err, ErrNoSeed) {
		t.Fatalf("ok %v err %v", ok, err)
	}
	if c.Redeem(act(t, "{}")) {
		t.Fatal("redeemed an act nothing approved")
	}
}

// A code-generator code approves the acts it was given, each once, and
// only those (CH-4, CH-10). The step is spent: the same code never
// approves again.
func TestVerifiedCodeApprovesEachActOnce(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c, _ := newChecker(t, clk)
	seed := syntheticSeed(t)
	c.Hand(seed)
	a1, a2, other := act(t, `{"n":1}`), act(t, `{"n":2}`), act(t, `{"n":3}`)
	step, ok, err := c.Verify(totp(seed, clk.now()), 0, true, []string{a1, a2})
	if err != nil || !ok || step != clk.now().Unix()/30 {
		t.Fatalf("step %d ok %v err %v", step, ok, err)
	}
	if c.Redeem(other) {
		t.Fatal("an act outside the batch was approved")
	}
	if !c.Redeem(a1) || !c.Redeem(a2) {
		t.Fatal("approved acts were not redeemable")
	}
	if c.Redeem(a1) {
		t.Fatal("an approval was redeemed twice")
	}
	if _, ok, _ := c.Verify(totp(seed, clk.now()), 0, true, []string{other}); ok {
		t.Fatal("a spent step verified again")
	}
	if c.Redeem(other) {
		t.Fatal("a spent code approved an act")
	}
}

// A wrong code approves nothing, and wrong codes pause checks per bucket
// once the window's limit is reached, the way the vault process does.
func TestWrongCodesApproveNothingAndPause(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c, _ := newChecker(t, clk)
	seed := syntheticSeed(t)
	c.Hand(seed)
	a := act(t, "{}")
	wrong := "000000"
	if wrong == totp(seed, clk.now()) {
		wrong = "000001"
	}
	for i := 0; i < MaxWrongCounted; i++ {
		if _, ok, err := c.Verify(wrong, 0, true, []string{a}); ok || err != nil {
			t.Fatalf("try %d: ok %v err %v", i, ok, err)
		}
	}
	var p *PausedError
	if _, ok, err := c.Verify(totp(seed, clk.now()), 0, true, []string{a}); ok || !errors.As(err, &p) {
		t.Fatalf("not paused: ok %v err %v", ok, err)
	}
	if c.Redeem(a) {
		t.Fatal("a paused check approved an act")
	}
	// The silent bucket is apart: a flood of counted codes does not stop it.
	if _, ok, err := c.Verify(totp(seed, clk.now()), 0, false, []string{a}); !ok || err != nil {
		t.Fatalf("silent check: ok %v err %v", ok, err)
	}
	clk.add(VerifyWindow + time.Second)
	if _, _, err := c.Verify(wrong, 0, true, nil); err != nil {
		t.Fatalf("still paused after the window: %v", err)
	}
}

// An approval lasts as long as a CH-10 code: one not redeemed within
// ApprovalTTL is gone.
func TestApprovalExpires(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c, _ := newChecker(t, clk)
	seed := syntheticSeed(t)
	c.Hand(seed)
	a := act(t, "{}")
	if _, ok, err := c.Verify(totp(seed, clk.now()), 0, true, []string{a}); !ok || err != nil {
		t.Fatalf("ok %v err %v", ok, err)
	}
	clk.add(ApprovalTTL + time.Second)
	if c.Redeem(a) {
		t.Fatal("an expired approval was redeemed")
	}
}

// The spent step is on disk before the answer: a restarted checker never
// accepts it again, and approvals do not survive the restart.
func TestSpentStepSurvivesRestart(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c, state := newChecker(t, clk)
	seed := syntheticSeed(t)
	c.Hand(seed)
	a := act(t, "{}")
	code := totp(seed, clk.now())
	if _, ok, err := c.Verify(code, 0, true, []string{a}); !ok || err != nil {
		t.Fatalf("ok %v err %v", ok, err)
	}
	again, err := New(Config{StatePath: state, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	again.Hand(seed)
	if again.Redeem(a) {
		t.Fatal("an approval survived the restart")
	}
	if _, ok, _ := again.Verify(code, 0, true, []string{a}); ok {
		t.Fatal("a spent step verified after a restart")
	}
	raw, err := os.ReadFile(state)
	if err != nil || bytes.Contains(raw, seed) {
		t.Fatalf("state file: %v, holds seed %v", err, bytes.Contains(raw, seed))
	}
}

// after is honoured: a step at or before the channel's last one never
// verifies (O6).
func TestVerifyHonoursAfter(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c, _ := newChecker(t, clk)
	seed := syntheticSeed(t)
	c.Hand(seed)
	if _, ok, _ := c.Verify(totp(seed, clk.now()), clk.now().Unix()/30, true, nil); ok {
		t.Fatal("a step at after verified")
	}
}

// Act binds every part of the request the holder sends, and the account
// whose login sends it (CH-10).
func TestActBindsTheWholeRequest(t *testing.T) {
	base := Act("bank-login", "bank.example", "POST", "/v1/pay", []byte(`{"to":"a"}`))
	for name, a := range map[string]string{
		"host":    Act("bank-login", "bank2.example", "POST", "/v1/pay", []byte(`{"to":"a"}`)),
		"method":  Act("bank-login", "bank.example", "PUT", "/v1/pay", []byte(`{"to":"a"}`)),
		"path":    Act("bank-login", "bank.example", "POST", "/v1/pay2", []byte(`{"to":"a"}`)),
		"body":    Act("bank-login", "bank.example", "POST", "/v1/pay", []byte(`{"to":"b"}`)),
		"split":   Act("bank-login", "bank.example", "POST/v1", "/pay", []byte(`{"to":"a"}`)),
		"account": Act("bank-login-b", "bank.example", "POST", "/v1/pay", []byte(`{"to":"a"}`)),
	} {
		if a == base {
			t.Errorf("%s does not change the act", name)
		}
	}
}

// The three sockets serve their closed sets: the hand socket never reads
// the seed back, the verify socket never redeems, and the redeem socket
// never verifies (ARC-1).
func TestHandlersServeClosedSets(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c, _ := newChecker(t, clk)
	seed := syntheticSeed(t)

	hand := httptest.NewServer(c.handHandler())
	defer hand.Close()
	put, _ := http.NewRequest("PUT", hand.URL+"/secret", bytes.NewReader(seed))
	if resp, err := http.DefaultClient.Do(put); err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("hand: %v %v", resp, err)
	}
	if resp, err := http.Get(hand.URL + "/state"); err != nil {
		t.Fatal(err)
	} else {
		var st struct{ Held bool }
		json.NewDecoder(resp.Body).Decode(&st)
		resp.Body.Close()
		if !st.Held {
			t.Fatal("state does not report the seed")
		}
	}
	for _, p := range []string{"/secret", "/seed", "/verify", "/redeem"} {
		resp, err := http.Get(hand.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		b.ReadFrom(resp.Body)
		resp.Body.Close()
		if resp.StatusCode < 400 || bytes.Contains(b.Bytes(), seed) {
			t.Errorf("hand GET %s: %d", p, resp.StatusCode)
		}
	}

	verify := httptest.NewServer(c.verifyHandler())
	defer verify.Close()
	redeem := httptest.NewServer(c.redeemHandler())
	defer redeem.Close()
	a := act(t, "{}")
	post := func(url string, v any) *http.Response {
		b, _ := json.Marshal(v)
		resp, err := http.Post(url, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if resp := post(redeem.URL+"/verify", checkersock.VerifyRequest{Code: totp(seed, clk.now()), Counted: true, Acts: []string{a}}); resp.StatusCode < 400 {
		t.Fatal("the redeem socket verified a code")
	}
	if resp := post(verify.URL+"/redeem", redeemReq{Act: a}); resp.StatusCode < 400 {
		t.Fatal("the verify socket redeemed")
	}
	resp := post(verify.URL+"/verify", checkersock.VerifyRequest{Code: totp(seed, clk.now()), Counted: true, Acts: []string{a}})
	var vr checkersock.VerifyResponse
	json.NewDecoder(resp.Body).Decode(&vr)
	if resp.StatusCode != http.StatusOK || !vr.OK {
		t.Fatalf("verify: %d %+v", resp.StatusCode, vr)
	}
	if resp := post(redeem.URL+"/redeem", redeemReq{Act: a}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("redeem: %d", resp.StatusCode)
	}
	if resp := post(redeem.URL+"/redeem", redeemReq{Act: a}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("second redeem: %d", resp.StatusCode)
	}
}

// Over real unix sockets: only the declared peer uid reaches each socket,
// and the holder's client redeems through its socket.
func TestServeOverSockets(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c, _ := newChecker(t, clk)
	seed := syntheticSeed(t)
	c.Hand(seed)
	dir, err := os.MkdirTemp("", "chk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	me := os.Getuid()
	lns := map[string]net.Listener{}
	for _, name := range []string{HandSocket, VerifySocket, RedeemSocket} {
		ln, err := Listen(filepath.Join(dir, name), me)
		if err != nil {
			t.Fatal(err)
		}
		lns[name] = ln
	}
	go c.Serve(lns[HandSocket], lns[VerifySocket], lns[RedeemSocket])
	a := act(t, "{}")
	red := Redeemer(filepath.Join(dir, RedeemSocket))
	if ok, err := red(context.Background(), a); ok || err != nil {
		t.Fatalf("redeemed before any code: %v %v", ok, err)
	}
	vc := checkersock.VerifyClient(filepath.Join(dir, VerifySocket))
	if _, ok, err := vc.VerifyTOTP(totp(seed, clk.now()), 0, true, a); !ok || err != nil {
		t.Fatalf("verify: %v %v", ok, err)
	}
	if ok, err := red(context.Background(), a); !ok || err != nil {
		t.Fatalf("redeem: %v %v", ok, err)
	}
	if ok, _ := red(context.Background(), a); ok {
		t.Fatal("redeemed twice")
	}
	// A socket declared for another uid closes this caller unread.
	other, err := Listen(filepath.Join(dir, "other.sock"), me+4242)
	if err != nil {
		t.Fatal(err)
	}
	go (&http.Server{Handler: c.redeemHandler()}).Serve(other)
	if _, err := Redeemer(filepath.Join(dir, "other.sock"))(context.Background(), a); err == nil {
		t.Fatal("a socket for another uid answered")
	}
}

// The broker's client reports the checker's refusals as their errors, and
// a malformed or oversized batch approves nothing.
func TestClientReportsRefusals(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c, _ := newChecker(t, clk)
	dir, err := os.MkdirTemp("", "chk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	ln, err := Listen(filepath.Join(dir, VerifySocket), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	go (&http.Server{Handler: c.verifyHandler()}).Serve(ln)
	vc := checkersock.VerifyClient(filepath.Join(dir, VerifySocket))
	if _, ok, err := vc.VerifyTOTP("123456", 0, true); ok || !errors.Is(err, ErrNoSeed) {
		t.Fatalf("no seed: ok %v err %v", ok, err)
	}
	seed := syntheticSeed(t)
	c.Hand(seed)
	if _, ok, err := vc.VerifyTOTP(totp(seed, clk.now()), 0, true, "not-an-act"); ok || err == nil {
		t.Fatalf("malformed act: ok %v err %v", ok, err)
	}
	many := make([]string, MaxActs+1)
	for i := range many {
		many[i] = act(t, fmt.Sprint(i))
	}
	if _, ok, err := vc.VerifyTOTP(totp(seed, clk.now()), 0, true, many...); ok || err == nil {
		t.Fatalf("oversized batch: ok %v err %v", ok, err)
	}
	if c.Redeem(many[0]) {
		t.Fatal("a refused batch approved an act")
	}
	for i := 0; i < MaxWrongCounted; i++ {
		vc.VerifyTOTP("x", 0, true)
	}
	var p *PausedError
	if _, _, err := vc.VerifyTOTP(totp(seed, clk.now()), 0, true); !errors.As(err, &p) || !p.Until.After(clk.now()) {
		t.Fatalf("paused: %v", err)
	}
}

// The holder's client reports approval only on 204: a 403 is no approval,
// and any other answer (a 200, a 400, a 500, a redirect) is an error, so
// the holder refuses rather than reading a broken checker as a yes (CH-10).
func TestRedeemerTrustsOnly204(t *testing.T) {
	dir, err := os.MkdirTemp("", "chk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	a := act(t, "{}")
	for _, status := range []int{200, 201, 202, 302, 400, 404, 500, 503} {
		path := filepath.Join(dir, fmt.Sprintf("r%d.sock", status))
		ln, err := Listen(path, os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })}
		go srv.Serve(ln)
		ok, err := Redeemer(path)(context.Background(), a)
		srv.Close()
		if ok || err == nil {
			t.Errorf("redeem answered %d: approved %v, err %v", status, ok, err)
		}
	}
}

// The unlock step takes the seed back at a lock: the checker then holds no
// seed, verifies nothing, and an approval it gave before the lock can no
// longer be redeemed (CRED-1, CH-10).
func TestHandSocketDropTakesTheSeedBack(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c, _ := newChecker(t, clk)
	seed := syntheticSeed(t)
	c.Hand(seed)
	a := act(t, "{}")
	if _, ok, err := c.Verify(totp(seed, clk.now()), 0, true, []string{a}); !ok || err != nil {
		t.Fatalf("verify: %v %v", ok, err)
	}
	hand := httptest.NewServer(c.handHandler())
	defer hand.Close()
	del, _ := http.NewRequest("DELETE", hand.URL+"/secret", nil)
	if resp, err := http.DefaultClient.Do(del); err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("drop: %v %v", resp, err)
	}
	if c.Held() {
		t.Fatal("the checker still holds the seed after a drop")
	}
	if c.Redeem(a) {
		t.Fatal("an approval made before the lock was redeemed after it")
	}
	clk.add(30 * time.Second)
	if _, _, err := c.Verify(totp(seed, clk.now()), 0, true, nil); !errors.Is(err, ErrNoSeed) {
		t.Fatalf("verify after drop: %v", err)
	}
}

// The unlock step checks its code on the hand socket, so the step it spends
// and the broker's are one store (CH-4): a code spent there is refused on
// the verify socket. The hand socket approves no acts.
func TestHandSocketVerifiesOnTheOneStore(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c, _ := newChecker(t, clk)
	seed := syntheticSeed(t)
	c.Hand(seed)
	hand := httptest.NewServer(c.handHandler())
	defer hand.Close()
	verify := httptest.NewServer(c.verifyHandler())
	defer verify.Close()
	post := func(url string, v any) (*http.Response, checkersock.VerifyResponse) {
		b, _ := json.Marshal(v)
		resp, err := http.Post(url, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		var vr checkersock.VerifyResponse
		json.NewDecoder(resp.Body).Decode(&vr)
		resp.Body.Close()
		return resp, vr
	}
	code := totp(seed, clk.now())
	if resp, _ := post(hand.URL+"/verify", checkersock.VerifyRequest{Code: code, Counted: true, Acts: []string{act(t, "{}")}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("the hand socket took acts: %d", resp.StatusCode)
	}
	resp, vr := post(hand.URL+"/verify", checkersock.VerifyRequest{Code: code, Counted: true})
	if resp.StatusCode != http.StatusOK || !vr.OK || vr.Step != clk.now().Unix()/30 {
		t.Fatalf("hand verify: %d %+v", resp.StatusCode, vr)
	}
	if _, vr := post(verify.URL+"/verify", checkersock.VerifyRequest{Code: code, Counted: true}); vr.OK {
		t.Fatal("the verify socket took a step the unlock step spent")
	}
}
