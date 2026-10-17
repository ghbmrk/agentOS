package netjoin

// REQ: ONB-3, ONB-1, CRED-1, DEV-2, CH-7

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/sockets"
)

// canary is a synthetic PSK (never a real password); test 6 looks for it
// everywhere but the request the fake receives.
const canary = "CANARY-netjoin-7f3a9c"

const home = "Home Net"

// call is one NM call the fake saw.
type call struct {
	Method string
	Path   string
}

// fakeNM records every call and answers from a scripted state. Before
// each ActiveConnections read, tick (if set) moves the state on.
type fakeNM struct {
	mu       sync.Mutex
	calls    []call
	sent     []Settings
	conns    map[string]bool // saved connection paths with UUID
	active   []string
	uuid     map[string]string
	state    map[string]uint32
	reads    int
	tick     func(f *fakeNM, read int)
	writeErr error
	getErr   error
	listErr  error
	block    chan struct{}
	entered  chan struct{}
}

func newFake() *fakeNM {
	return &fakeNM{conns: map[string]bool{}, uuid: map[string]string{}, state: map[string]uint32{}}
}

func (f *fakeNM) rec(m, p string) {
	f.mu.Lock()
	f.calls = append(f.calls, call{m, p})
	f.mu.Unlock()
}

func (f *fakeNM) GetConnectionByUuid(_ context.Context, uuid string) (string, error) {
	f.rec("GetConnectionByUuid", "/org/freedesktop/NetworkManager/Settings")
	if f.entered != nil {
		close(f.entered)
		<-f.block
	}
	if f.getErr != nil {
		return "", f.getErr
	}
	if uuid != UUID {
		return "", fmt.Errorf("fake: asked for uuid %q", uuid)
	}
	for p := range f.conns {
		return p, nil
	}
	return "", ErrNoConnection
}

func (f *fakeNM) AddConnection2(_ context.Context, s Settings) (string, error) {
	f.rec("AddConnection2", "/org/freedesktop/NetworkManager/Settings")
	f.sent = append(f.sent, s)
	if f.writeErr != nil {
		return "", f.writeErr
	}
	p := "/org/freedesktop/NetworkManager/Settings/7"
	f.conns[p] = true
	return p, nil
}

func (f *fakeNM) Update2(_ context.Context, path string, s Settings) error {
	f.rec("Update2", path)
	f.sent = append(f.sent, s)
	return f.writeErr
}

func (f *fakeNM) ActiveConnections(context.Context) ([]string, error) {
	f.rec("ActiveConnections", "/org/freedesktop/NetworkManager")
	if f.tick != nil {
		f.tick(f, f.reads)
	}
	f.reads++
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]string(nil), f.active...), nil
}

func (f *fakeNM) ActiveUUID(_ context.Context, p string) (string, error) {
	f.rec("ActiveUUID", p)
	u, ok := f.uuid[p]
	if !ok {
		return "", errors.New("fake: no such object")
	}
	return u, nil
}

func (f *fakeNM) ActiveState(_ context.Context, p string) (uint32, error) {
	f.rec("ActiveState", p)
	s, ok := f.state[p]
	if !ok {
		return 0, errors.New("fake: no such object")
	}
	return s, nil
}

func (f *fakeNM) appear(p, uuid string, st uint32) {
	f.active = append(f.active, p)
	f.uuid[p], f.state[p] = uuid, st
}

func (f *fakeNM) vanish(p string) {
	for i, q := range f.active {
		if q == p {
			f.active = append(f.active[:i], f.active[i+1:]...)
			break
		}
	}
	delete(f.uuid, p)
	delete(f.state, p)
}

// fakeClock makes the wait run out without real time passing.
type fakeClock struct {
	t     time.Time
	slept time.Duration
}

func (c *fakeClock) now() time.Time { return c.t }
func (c *fakeClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.t = c.t.Add(d)
	c.slept += d
	return nil
}

// The tests' station and access point interfaces (S-R4): a station
// distinct from the one interface agentos-ap may serve on.
const (
	station = "wlan1"
	apIface = "wlan0"
)

func joiner(f *fakeNM) (*Joiner, *fakeClock) {
	j := NewJoiner(f, station, []string{apIface})
	c := &fakeClock{t: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)}
	j.now, j.sleep = c.now, c.sleep
	return j, c
}

// Test 2: every edge of L8.5, checked before any NetworkManager call.
func TestBoundsAreCheckedBeforeAnyCall(t *testing.T) {
	hex64 := strings.Repeat("0123456789abcDEF", 4)
	cases := []struct {
		name, ssid, psk string
		ok              bool
	}{
		{"ssid 0 bytes", "", "password", false},
		{"ssid 1 byte", "a", "password", true},
		{"ssid 32 bytes", strings.Repeat("s", 32), "password", true},
		{"ssid 33 bytes", strings.Repeat("s", 33), "password", false},
		{"ssid 32 bytes multibyte", strings.Repeat("é", 16), "password", true},
		{"ssid 34 bytes multibyte", strings.Repeat("é", 17), "password", false},
		{"psk 7", home, "1234567", false},
		{"psk 8", home, "12345678", true},
		{"psk 63", home, strings.Repeat("p", 63), true},
		{"psk 64 non-hex", home, strings.Repeat("p", 64), false},
		{"psk 64 hex", home, hex64, true},
		{"psk 64 hex but one", home, hex64[:63] + "g", false},
		{"psk 65 hex", home, hex64 + "0", false},
		{"psk with newline", home, "pass\nword", false},
		{"psk with tab", home, "pass\tword", false},
		{"psk with NUL", home, "pass\x00word", false},
		{"psk with DEL", home, "pass\x7fword", false},
		{"psk non-ASCII", home, "pässword", false},
		{"psk with space and symbols", home, "p a s s ~!", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if Valid(c.ssid, c.psk) != c.ok {
				t.Fatalf("Valid = %v, want %v", !c.ok, c.ok)
			}
			f := newFake()
			j, _ := joiner(f)
			got := j.Join(context.Background(), c.ssid, c.psk)
			if !c.ok {
				if got != Refused || len(f.calls) != 0 {
					t.Fatalf("answer %q after %d calls, want refused after none", got, len(f.calls))
				}
				return
			}
			if got == Refused || len(f.calls) == 0 {
				t.Fatalf("a valid request was refused: %q", got)
			}
		})
	}
}

// want is L8.4's list, written out here rather than taken from the code.
func want(ssid, psk string) Settings {
	return Settings{
		"connection": {
			"type": "802-11-wireless", "id": "agentos-home",
			"uuid": "8907ba39-4053-4e84-9cbf-931587303e08", "autoconnect": true,
			"interface-name": station,
		},
		"802-11-wireless":          {"mode": "infrastructure", "ssid": []byte(ssid), "hidden": false},
		"802-11-wireless-security": {"key-mgmt": "wpa-psk", "psk": psk, "psk-flags": uint32(0)},
		"ipv4":                     {"method": "auto"},
		"ipv6":                     {"method": "auto"},
	}
}

func sameSettings(t *testing.T, got, want Settings) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("settings have %d groups, want %d", len(got), len(want))
	}
	for g, props := range want {
		if len(got[g]) != len(props) {
			t.Fatalf("%s has %d keys, want %d", g, len(got[g]), len(props))
		}
		for k, v := range props {
			gv, ok := got[g][k]
			if !ok || !reflect.DeepEqual(gv, v) || reflect.TypeOf(gv) != reflect.TypeOf(v) {
				t.Fatalf("%s.%s differs from L8.4", g, k)
			}
		}
	}
}

// S-R4 (#1428): the join never takes an interface agentos_ap may hold.
// With no station, a malformed one, lo, one agentos-ap may run the access
// point on, or no access point interface known, Join answers failed (setup
// says to use Ethernet) before any NetworkManager call, so nothing is
// written and nothing can autoconnect.
func TestJoinRefusesTheAccessPointInterface(t *testing.T) {
	cases := []struct {
		name, station string
		ap            []string
	}{
		{"no station", "", []string{apIface}},
		{"station is the access point", apIface, []string{apIface}},
		{"station is a second access point radio", "wlan2", []string{apIface, "wlan2"}},
		{"no access point interface known", station, nil},
		{"an empty access point interface", station, []string{""}},
		{"a malformed access point interface", station, []string{"wlan 0"}},
		{"lo", "lo", []string{apIface}},
		{"dot", ".", []string{apIface}},
		{"dot dot", "..", []string{apIface}},
		{"too long", "wlan0123456789ab", []string{apIface}},
		{"a space", "wlan 1", []string{apIface}},
		{"a slash", "wlan/1", []string{apIface}},
		{"a NUL", "wlan\x001", []string{apIface}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			j := NewJoiner(f, c.station, c.ap)
			if got := j.Join(context.Background(), home, canary); got != Failed {
				t.Fatalf("answered %q, want failed", got)
			}
			if len(f.calls) != 0 || len(f.sent) != 0 {
				t.Fatalf("a refused join reached NetworkManager: %v", f.calls)
			}
		})
	}
	// A request that fails Valid is still refused first.
	if got := NewJoiner(newFake(), "", nil).Join(context.Background(), "", canary); got != Refused {
		t.Fatalf("invalid request answered %q, want refused", got)
	}
}

// S-R4: the connection names its one interface, so NetworkManager never
// activates it on another device, the access point's included, at the
// join or at any later autoconnect.
func TestTheConnectionIsPinnedToTheStation(t *testing.T) {
	if got := ConnectionSettings(home, canary, station)["connection"]["interface-name"]; got != station {
		t.Fatalf("interface-name = %v, want %q", got, station)
	}
	f := newFake()
	j, _ := joiner(f)
	j.Join(context.Background(), home, canary)
	if len(f.sent) != 1 || f.sent[0]["connection"]["interface-name"] != station {
		t.Fatalf("the written connection is not pinned to %s", station)
	}
}

// Test 3: create by the fixed UUID, then update on that path only; the
// settings are exactly L8.4's; no other method is ever called.
func TestFirstJoinCreatesThenUpdatesTheOneConnection(t *testing.T) {
	f := newFake()
	j, _ := joiner(f)
	if got := j.Join(context.Background(), home, canary); got != Saved {
		t.Fatalf("first join answered %q", got)
	}
	if got := j.Join(context.Background(), "Other", "another-password"); got != Saved {
		t.Fatalf("second join answered %q", got)
	}
	var writes []call
	allowed := map[string]bool{"GetConnectionByUuid": true, "AddConnection2": true, "Update2": true,
		"ActiveConnections": true, "ActiveUUID": true, "ActiveState": true}
	for _, c := range f.calls {
		if !allowed[c.Method] {
			t.Fatalf("called %s", c.Method)
		}
		switch c.Method {
		case "GetConnectionByUuid", "AddConnection2", "Update2":
			writes = append(writes, c)
		}
	}
	wantWrites := []call{
		{"GetConnectionByUuid", "/org/freedesktop/NetworkManager/Settings"},
		{"AddConnection2", "/org/freedesktop/NetworkManager/Settings"},
		{"GetConnectionByUuid", "/org/freedesktop/NetworkManager/Settings"},
		{"Update2", "/org/freedesktop/NetworkManager/Settings/7"},
	}
	if !reflect.DeepEqual(writes, wantWrites) {
		t.Fatalf("writes %v, want %v", writes, wantWrites)
	}
	sameSettings(t, f.sent[0], want(home, canary))
	sameSettings(t, f.sent[1], want("Other", "another-password"))
}

// Test 4: one fake-state test per answer code.
func TestEachAnswerCode(t *testing.T) {
	const ac = "/org/freedesktop/NetworkManager/ActiveConnection/3"
	const other = "/org/freedesktop/NetworkManager/ActiveConnection/1"
	cases := []struct {
		name  string
		setup func(f *fakeNM)
		want  Code
	}{
		{"joined", func(f *fakeNM) {
			f.appear(other, "access-point-uuid", StateActivated)
			f.tick = func(f *fakeNM, n int) {
				switch n {
				case 2:
					f.appear(ac, UUID, 1)
				case 4:
					f.state[ac] = StateActivated
				}
			}
		}, Joined},
		{"not joined: deactivated", func(f *fakeNM) {
			f.tick = func(f *fakeNM, n int) {
				switch n {
				case 2:
					f.appear(ac, UUID, 1)
				case 3:
					f.state[ac] = 3
				case 4:
					f.state[ac] = StateDeactivated
				}
			}
		}, NotJoined},
		{"not joined: went away", func(f *fakeNM) {
			f.tick = func(f *fakeNM, n int) {
				switch n {
				case 2:
					f.appear(ac, UUID, 1)
				case 3:
					f.vanish(ac)
				}
			}
		}, NotJoined},
		{"saved: none appears", func(f *fakeNM) {
			f.appear(other, "access-point-uuid", StateActivated)
		}, Saved},
		{"saved: already active before the write", func(f *fakeNM) {
			f.conns["/org/freedesktop/NetworkManager/Settings/7"] = true
			f.appear(ac, UUID, StateActivated)
		}, Saved},
		{"failed: the write", func(f *fakeNM) {
			f.writeErr = errors.New("org.freedesktop.NetworkManager.PermissionDenied")
		}, Failed},
		{"failed: the update", func(f *fakeNM) {
			f.conns["/org/freedesktop/NetworkManager/Settings/7"] = true
			f.writeErr = errors.New("org.freedesktop.NetworkManager.PermissionDenied")
		}, Failed},
		{"failed: the lookup", func(f *fakeNM) {
			f.getErr = errors.New("org.freedesktop.DBus.Error.NoReply")
		}, Failed},
		{"failed: reading the active connections", func(f *fakeNM) {
			f.tick = func(f *fakeNM, n int) {
				if n == 1 {
					f.listErr = errors.New("org.freedesktop.DBus.Error.NoReply")
				}
			}
		}, Failed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			c.setup(f)
			j, _ := joiner(f)
			if got := j.Join(context.Background(), home, canary); got != c.want {
				t.Fatalf("answered %q, want %q", got, c.want)
			}
		})
	}
	f := newFake()
	j, _ := joiner(f)
	if got := j.Join(context.Background(), "", canary); got != Refused {
		t.Fatalf("refused case answered %q", got)
	}
}

// Test 4: the fixed wait runs out on a fake clock, at Wait (at most 40s).
func TestTheWaitRunsOutAsSaved(t *testing.T) {
	if Wait > 40*time.Second || Wait >= CallTimeout {
		t.Fatalf("Wait %v must be at most 40s and under CallTimeout %v", Wait, CallTimeout)
	}
	f := newFake()
	j, c := joiner(f)
	if got := j.Join(context.Background(), home, canary); got != Saved {
		t.Fatalf("answered %q", got)
	}
	if c.slept < Wait || c.slept > Wait+poll {
		t.Fatalf("waited %v, want %v", c.slept, Wait)
	}
	// A caller that goes away ends the wait as saved: the write is done.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	j2 := NewJoiner(newFake(), station, []string{apIface})
	j2.sleep = sleep
	if got := j2.Join(ctx, home, canary); got != Saved {
		t.Fatalf("cancelled join answered %q", got)
	}
}

// Test 4: busy while another join runs.
func TestASecondJoinWhileOneRunsIsBusy(t *testing.T) {
	f := newFake()
	f.block, f.entered = make(chan struct{}), make(chan struct{})
	j, _ := joiner(f)
	done := make(chan Code)
	go func() { done <- j.Join(context.Background(), home, canary) }()
	<-f.entered
	f.mu.Lock()
	n := len(f.calls)
	f.mu.Unlock()
	if got := j.Join(context.Background(), home, canary); got != Busy {
		t.Fatalf("second join answered %q", got)
	}
	f.mu.Lock()
	m := len(f.calls)
	f.mu.Unlock()
	if m != n {
		t.Fatalf("a busy join made %d calls", m-n)
	}
	close(f.block)
	if got := <-done; got != Saved {
		t.Fatalf("first join answered %q", got)
	}
}

// serve starts the helper's socket for uid, as main does.
func serve(t *testing.T, j *Joiner, uid int) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "run")
	s := &sockets.Server{Dir: dir}
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx, Endpoint(j, NewScanner(newScan()), uid)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); s.Wait() })
	return filepath.Join(dir, Socket)
}

// raw sends one request line and reads the answer. The server frees a
// connection's slot only after its handler returns, which can be just after
// the client has read the answer, so a refusal for too many connections
// right after an earlier request is retried for up to a second.
func raw(t *testing.T, path string, line []byte) sockets.Response {
	t.Helper()
	for range 100 {
		if r := raw1(t, path, line); r.Error != string(sockets.ErrTooMany) {
			return r
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the socket stayed full")
	return sockets.Response{}
}

func raw1(t *testing.T, path string, line []byte) sockets.Response {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	go c.Write(append(line, '\n'))
	b, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	var r sockets.Response
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func answer(t *testing.T, r sockets.Response) Code {
	t.Helper()
	var a Answer
	if !r.OK || json.Unmarshal(r.Result, &a) != nil {
		t.Fatalf("not an answer: %+v", r)
	}
	return a.Code
}

// Test 1: only agentosd's uid is served, and that before any read; odd
// requests get fixed codes and no D-Bus call.
func TestTheSocketServesAgentosdOnly(t *testing.T) {
	good := []byte(`{"op":"join","args":{"ssid":"Home Net","psk":"` + canary + `"}}`)

	f := newFake()
	j, _ := joiner(f)
	path := serve(t, j, os.Getuid()+1)
	if r := raw(t, path, good); r.OK || r.Error != string(sockets.ErrPeer) {
		t.Fatalf("another uid was served: %+v", r)
	}
	if len(f.calls) != 0 {
		t.Fatalf("another uid's request reached NetworkManager: %v", f.calls)
	}

	f = newFake()
	j, _ = joiner(f)
	path = serve(t, j, os.Getuid())
	for _, c := range []struct {
		name string
		line []byte
		err  sockets.Code
		code Code
	}{
		{"oversized", append(append([]byte(`{"op":"join","args":{"ssid":"`), bytes.Repeat([]byte("x"), sockets.MaxRequest)...), `"}}`...), sockets.ErrTooLarge, ""},
		{"malformed", []byte(`{"op":"join","args":`), sockets.ErrMalformed, ""},
		{"unknown op", []byte(`{"op":"delete","args":{}}`), sockets.ErrUnknownOp, ""},
		{"no args", []byte(`{"op":"join"}`), "", Refused},
		{"extra field", []byte(`{"op":"join","args":{"ssid":"Home Net","psk":"password","dns":"192.0.2.1"}}`), "", Refused},
		{"wrong type", []byte(`{"op":"join","args":{"ssid":"Home Net","psk":12345678}}`), "", Refused},
		{"array args", []byte(`{"op":"join","args":["Home Net","password"]}`), "", Refused},
	} {
		r := raw(t, path, c.line)
		if c.err != "" {
			if r.OK || r.Error != string(c.err) {
				t.Fatalf("%s: %+v, want %q", c.name, r, c.err)
			}
		} else if got := answer(t, r); got != c.code {
			t.Fatalf("%s: answered %q, want %q", c.name, got, c.code)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("a refused request reached NetworkManager: %v", f.calls)
	}
	if got := answer(t, raw(t, path, good)); got != Saved {
		t.Fatalf("agentosd's request answered %q", got)
	}
}

// Client round trip, and its errors for a missing helper or a bad answer.
func TestClientAsksTheHelper(t *testing.T) {
	f := newFake()
	f.tick = func(f *fakeNM, n int) {
		if n == 1 {
			f.appear("/a/1", UUID, StateActivated)
		}
	}
	j, _ := joiner(f)
	path := serve(t, j, os.Getuid())
	code, err := Client{Path: path}.Join(context.Background(), home, canary)
	if err != nil || code != Joined {
		t.Fatalf("Join = %q, %v", code, err)
	}
	if _, err := (Client{Path: filepath.Join(t.TempDir(), "none.sock")}).Join(context.Background(), home, canary); err == nil {
		t.Fatal("a missing helper gave no error")
	}
	for _, reply := range []string{`{"ok":true,"result":{"code":"rebooted"}}`, `{"ok":false,"error":"request failed"}`, `not json`} {
		p := fakeHelper(t, reply)
		if code, err := (Client{Path: p}).Join(context.Background(), home, canary); err == nil {
			t.Fatalf("reply %s gave code %q", reply, code)
		} else if strings.Contains(err.Error(), canary) {
			t.Fatal("an error carries the password")
		}
	}
}

// fakeHelper answers every connection with reply.
func fakeHelper(t *testing.T, reply string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "h.sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			bufio.NewReader(c).ReadBytes('\n')
			c.Write([]byte(reply + "\n"))
			c.Close()
		}
	}()
	return p
}

// Test 6: the canary PSK reaches the fake's request and nothing else:
// no log line, no formatted request, no error.
func TestThePasswordIsNeverLoggedOrFormatted(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	r := Request{SSID: home, PSK: canary}
	for _, s := range []string{fmt.Sprint(r), fmt.Sprintf("%v %+v %#v %s", r, r, r, r), fmt.Sprint(&r)} {
		if strings.Contains(s, canary) {
			t.Fatalf("formatting the request shows the password: %s", s)
		}
	}
	f := newFake()
	f.writeErr = errors.New("org.freedesktop.NetworkManager.PermissionDenied")
	j, _ := joiner(f)
	path := serve(t, j, os.Getuid())
	code, err := Client{Path: path}.Join(context.Background(), home, canary)
	if err != nil || code != Failed {
		t.Fatalf("Join = %q, %v", code, err)
	}
	if strings.Contains(logs.String(), canary) {
		t.Fatal("a log line carries the password")
	}
	if len(f.sent) != 1 || f.sent[0]["802-11-wireless-security"]["psk"] != canary {
		t.Fatal("the password did not reach the fake's request")
	}
}
