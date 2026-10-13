package localsrv

import (
	"bytes"
	"errors"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: ONB-3, CRED-1

// A synthetic home Wi-Fi password: no network uses it.
const canaryPSK = "CANARY-localsrv-psk-31d"

// P2-2w c3: setup's join op hands the network to the helper and answers
// success or the one fixed refusal; the password reaches the helper only.
func TestJoinHandsTheNetworkToTheHelper(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	r := newSetupRig(t)
	if err := r.call(localapi.OpSetupJoin, localapi.Join{SSID: "home", Password: canaryPSK}, nil); err != nil {
		t.Fatal(err)
	}
	if len(r.joins) != 1 || r.joins[0] != [2]string{"home", canaryPSK} {
		t.Fatalf("helper got %d joins", len(r.joins))
	}
	r.joinErr = errors.New("helper: not_joined " + canaryPSK)
	err := r.call(localapi.OpSetupJoin, localapi.Join{SSID: "home", Password: canaryPSK}, nil)
	if code(err) != localapi.ErrNotJoined {
		t.Fatalf("a failed join answered %v", err)
	}
	if strings.Contains(err.Error(), canaryPSK) {
		t.Fatal("the helper's error reached the page")
	}
	// No helper configured: the same refusal.
	r.s.cfg.Join = nil
	if err := r.call(localapi.OpSetupJoin, localapi.Join{SSID: "home", Password: canaryPSK}, nil); code(err) != localapi.ErrNotJoined {
		t.Fatalf("no helper answered %v", err)
	}
	b, _ := os.ReadFile(r.path)
	if strings.Contains(string(b), canaryPSK) || strings.Contains(logs.String(), canaryPSK) {
		t.Fatal("the password was recorded or logged")
	}
}

// Security L8.8: agentosd checks the shape only, before the helper is
// called; an extra field is refused.
func TestJoinShapeIsCheckedBeforeTheHelper(t *testing.T) {
	r := newSetupRig(t)
	for _, j := range []any{
		localapi.Join{SSID: "", Password: canaryPSK},
		localapi.Join{SSID: strings.Repeat("s", localapi.MaxSSID+1), Password: canaryPSK},
		localapi.Join{SSID: "home", Password: strings.Repeat("p", localapi.MinPassword-1)},
		localapi.Join{SSID: "home", Password: strings.Repeat("p", localapi.MaxPassword+1)},
		map[string]string{"ssid": "home", "password": canaryPSK, "id": "x"},
		[]string{"home", canaryPSK},
	} {
		if err := r.call(localapi.OpSetupJoin, j, nil); code(err) != localapi.ErrBadArgs {
			t.Errorf("%v: %v", j, err)
		}
	}
	for _, j := range []localapi.Join{
		{SSID: strings.Repeat("s", localapi.MaxSSID), Password: strings.Repeat("p", localapi.MinPassword)},
		{SSID: "s", Password: strings.Repeat("p", localapi.MaxPassword)},
	} {
		r.now = r.now.Add(time.Minute)
		if err := r.call(localapi.OpSetupJoin, j, nil); err != nil {
			t.Errorf("edge %d/%d: %v", len(j.SSID), len(j.Password), err)
		}
	}
	if len(r.joins) != 2 {
		t.Fatalf("helper called %d times, want the 2 edges", len(r.joins))
	}
}

// Security L6.4: at most JoinsPerMinute tries a minute, counted before
// the helper is called, so a page cannot churn NetworkManager's store.
func TestJoinsAreBounded(t *testing.T) {
	r := newSetupRig(t)
	r.joinErr = errors.New("not joined")
	for i := 0; i < JoinsPerMinute; i++ {
		if err := r.call(localapi.OpSetupJoin, localapi.Join{SSID: "home", Password: canaryPSK}, nil); code(err) != localapi.ErrNotJoined {
			t.Fatal(i, err)
		}
	}
	if err := r.call(localapi.OpSetupJoin, localapi.Join{SSID: "home", Password: canaryPSK}, nil); code(err) != localapi.ErrLimited {
		t.Fatalf("7th try: %v", err)
	}
	if len(r.joins) != JoinsPerMinute {
		t.Fatalf("helper called %d times", len(r.joins))
	}
	r.now = r.now.Add(time.Minute)
	r.joinErr = nil
	if err := r.call(localapi.OpSetupJoin, localapi.Join{SSID: "home", Password: canaryPSK}, nil); err != nil {
		t.Fatal(err)
	}
}
