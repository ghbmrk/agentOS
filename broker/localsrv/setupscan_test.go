package localsrv

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: ONB-3, CRED-1

// scanRig is a setupRig whose Setup also lists networks.
func scanRig(t *testing.T, scan func(context.Context) ([]string, error)) *setupRig {
	r := newSetupRig(t)
	cfg := r.s.cfg
	cfg.Networks = scan
	r.s = NewSetup(cfg)
	return r
}

// P2-2w c4b: page_setup_networks answers the helper's list; with no
// helper, or an error, an empty one.
func TestNetworksAnswersTheHelpersList(t *testing.T) {
	calls := 0
	r := scanRig(t, func(context.Context) ([]string, error) {
		calls++
		return []string{"Neighbor", "Home Net"}, nil
	})
	var n localapi.Networks
	if err := r.call(localapi.OpSetupNetworks, nil, &n); err != nil || !reflect.DeepEqual(n.SSIDs, []string{"Neighbor", "Home Net"}) {
		t.Fatalf("networks %v %q", err, n.SSIDs)
	}
	if err := r.call(localapi.OpSetupNetworks, struct{}{}, &n); err != nil || calls != 2 {
		t.Fatalf("{} args: %v, %d calls", err, calls)
	}
	if err := r.call(localapi.OpSetupNetworks, map[string]string{"ssid": "x"}, nil); code(err) != localapi.ErrBadArgs || calls != 2 {
		t.Fatalf("extra args: %v, %d calls", err, calls)
	}

	for name, scan := range map[string]func(context.Context) ([]string, error){
		"no helper": nil,
		"an error":  func(context.Context) ([]string, error) { return []string{"stale"}, errors.New("no helper") },
	} {
		r := scanRig(t, scan)
		var n localapi.Networks
		if err := r.call(localapi.OpSetupNetworks, nil, &n); err != nil || n.SSIDs == nil || len(n.SSIDs) != 0 {
			t.Fatalf("%s: %v %q", name, err, n.SSIDs)
		}
	}

	many := make([]string, localapi.MaxNetworks+3)
	for i := range many {
		many[i] = fmt.Sprintf("n%d", i)
	}
	r = scanRig(t, func(context.Context) ([]string, error) { return many, nil })
	if err := r.call(localapi.OpSetupNetworks, nil, &n); err != nil || len(n.SSIDs) != localapi.MaxNetworks {
		t.Fatalf("too many: %v, %d", err, len(n.SSIDs))
	}
}

// At most ScansPerMinute scans reach the helper; past that the list is
// empty until the minute passes.
func TestNetworksAreBounded(t *testing.T) {
	calls := 0
	r := scanRig(t, func(context.Context) ([]string, error) { calls++; return []string{"Home Net"}, nil })
	var n localapi.Networks
	for i := range ScansPerMinute {
		if err := r.call(localapi.OpSetupNetworks, nil, &n); err != nil || len(n.SSIDs) != 1 {
			t.Fatalf("scan %d: %v %q", i, err, n.SSIDs)
		}
	}
	if err := r.call(localapi.OpSetupNetworks, nil, &n); err != nil || len(n.SSIDs) != 0 || calls != ScansPerMinute {
		t.Fatalf("over the limit: %v %q, %d calls", err, n.SSIDs, calls)
	}
	r.now = r.now.Add(61e9)
	if err := r.call(localapi.OpSetupNetworks, nil, &n); err != nil || len(n.SSIDs) != 1 {
		t.Fatalf("after a minute: %v %q", err, n.SSIDs)
	}
}

// Security L6: once finish is recorded the op is refused before the
// helper is asked.
func TestNetworksCloseWithSetup(t *testing.T) {
	calls := 0
	r := scanRig(t, func(context.Context) ([]string, error) { calls++; return nil, nil })
	r.enrollAndConfirm()
	if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.call(localapi.OpSetupNetworks, nil, nil); code(err) != localapi.ErrSetupClosed || calls != 0 {
		t.Fatalf("after finish: %v, %d calls", err, calls)
	}
}
