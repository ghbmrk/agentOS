package pacingfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
)

func manifestImage(t *testing.T, path string, limit int, latency int64) []byte {
	t.Helper()
	b, err := json.Marshal(ProvisionedManifest{Version: 1, Ledger: path, RequestsPerHour: limit, MaxStoreLatencyMillis: latency})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// REQ: CH-15, CH-11, OP-1
func TestProvisionedManifestRejectsDigestAndNoncanonicalInputs(t *testing.T) {
	valid := manifestImage(t, "/synthetic/private/ledger", 2, 1000)
	pin := sha256.Sum256(valid)
	for _, b := range [][]byte{nil, []byte("null"), append(append([]byte{}, valid...), '\n'), []byte(`{"version":1,"version":1,"ledger":"/synthetic/private/ledger","requests_per_hour":2,"max_store_latency_ms":1000}`), []byte(`{"version":1,"ledger":"/synthetic/private/ledger","requests_per_hour":2,"max_store_latency_ms":1000,"require_existing":false}`), []byte(`{"ledger":"/synthetic/private/ledger","version":1,"requests_per_hour":2,"max_store_latency_ms":1000}`)} {
		ownPin := sha256.Sum256(b)
		if m, err := ReadProvisionedManifest(bytes.NewReader(b), ownPin); m != nil || err != ErrManifest {
			t.Fatal("noncanonical image accepted", err)
		}
	}
	if m, err := ReadProvisionedManifest(bytes.NewReader(valid), [32]byte{}); m != nil || err != ErrManifest {
		t.Fatal("missing trusted digest accepted", err)
	}
	changed := append([]byte{}, valid...)
	changed[len(changed)-2] = '1'
	if m, err := ReadProvisionedManifest(bytes.NewReader(changed), pin); m != nil || err != ErrManifest {
		t.Fatal("changed bytes accepted", err)
	}
	if m, err := ReadProvisionedManifest(bytes.NewReader(valid), pin); m == nil || err != nil {
		t.Fatal("valid pinned manifest refused", err)
	}
}

// REQ: CH-15, CH-11, RES-1
func TestProvisionedManifestRefusesInvalidPolicyAndLedgerSettings(t *testing.T) {
	for _, path := range []string{"", "ledger", "/", "/synthetic/../ledger", "/synthetic/ledger.lock", "/synthetic/ledger.tmp", "/synthetic/ledger\x00"} {
		b := manifestImage(t, path, 2, 1000)
		if m, err := ReadProvisionedManifest(bytes.NewReader(b), sha256.Sum256(b)); m != nil || err != ErrManifest {
			t.Fatal("unsafe path accepted", path, err)
		}
	}
	for _, limit := range []int{-1, 0, 4097} {
		b := manifestImage(t, "/synthetic/ledger", limit, 1000)
		if m, err := ReadProvisionedManifest(bytes.NewReader(b), sha256.Sum256(b)); m != nil || err != ErrManifest {
			t.Fatal("bad allowance", limit, err)
		}
	}
	for _, latency := range []int64{-1, 0, 300001} {
		b := manifestImage(t, "/synthetic/ledger", 2, latency)
		if m, err := ReadProvisionedManifest(bytes.NewReader(b), sha256.Sum256(b)); m != nil || err != ErrManifest {
			t.Fatal("bad threshold", latency, err)
		}
	}
	b := []byte(`{"version":2,"ledger":"/synthetic/ledger","requests_per_hour":2,"max_store_latency_ms":1000}`)
	if m, err := ReadProvisionedManifest(bytes.NewReader(b), sha256.Sum256(b)); m != nil || err != ErrManifest {
		t.Fatal("unknown version accepted", err)
	}
}

type manifestProbe struct {
	read int
	err  error
}

func (r *manifestProbe) Read(b []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	for i := range b {
		b[i] = 'x'
	}
	r.read += len(b)
	return len(b), nil
}

// REQ: RES-1, CH-11
func TestProvisionedManifestReaderCapsConsumptionAndSanitizesErrors(t *testing.T) {
	r := &manifestProbe{}
	if m, err := ReadProvisionedManifest(r, sha256.Sum256([]byte("synthetic"))); m != nil || err != ErrManifest || r.read != MaxManifestBytes+1 {
		t.Fatal("unbounded input", r.read, err)
	}
	private := errors.New("synthetic private manifest canary")
	if m, err := ReadProvisionedManifest(&manifestProbe{err: private}, sha256.Sum256([]byte("synthetic"))); m != nil || err != ErrManifest || strings.Contains(err.Error(), "canary") {
		t.Fatal("private read error", err)
	}
	if m, err := ReadProvisionedManifest(nil, sha256.Sum256([]byte("synthetic"))); m != nil || err != ErrManifest {
		t.Fatal("nil reader accepted", err)
	}
	untouched := &manifestProbe{}
	if _, err := ReadProvisionedManifest(untouched, [32]byte{}); err != ErrManifest || untouched.read != 0 {
		t.Fatal("missing pin still read untrusted source")
	}
}

// REQ: CH-15, CH-11
func TestProvisionedManifestRejectsCompetingOptionsBeforeAnyStartup(t *testing.T) {
	b := manifestImage(t, "/synthetic/private/ledger", 2, 1000)
	m, err := ReadProvisionedManifest(bytes.NewReader(b), sha256.Sum256(b))
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []grants.Config{{}, {Now: time.Now, RequestsPerHour: 2}, {Now: time.Now, PacingRequireExisting: true}, {Now: time.Now, PacingMaxStoreLatency: time.Second}, {Now: time.Now, PacingStore: Store{Path: "/synthetic/private/ledger"}}} {
		var slot StartupSlot
		if p, err := m.Start(&slot, cfg); p != nil || err != ErrManifest {
			t.Fatal("ambiguous config launched", err)
		}
	}
	var zero ManifestSettings
	var slot StartupSlot
	if p, err := zero.Start(&slot, grants.Config{Now: time.Now}); p != nil || err != ErrManifest {
		t.Fatal("zero settings launched", err)
	}
	if p, err := m.Start(nil, grants.Config{Now: time.Now}); p != nil || err != ErrManifest {
		t.Fatal("missing owner slot accepted", err)
	}
}

var _ io.Reader = (*manifestProbe)(nil)

// REQ: RES-1, CH-15
func TestProvisionedManifestExactInputAndPolicyBoundaries(t *testing.T) {
	base := manifestImage(t, "/", 4096, 300000)
	ledger := "/" + strings.Repeat("x", MaxManifestBytes-len(base))
	exact := manifestImage(t, ledger, 4096, 300000)
	if len(exact) != MaxManifestBytes {
		t.Fatal("fixture size", len(exact))
	}
	if m, err := ReadProvisionedManifest(bytes.NewReader(exact), sha256.Sum256(exact)); m == nil || err != nil {
		t.Fatal("exact bounded image refused", err)
	}
	overflow := append(append([]byte{}, exact...), ' ')
	if m, err := ReadProvisionedManifest(bytes.NewReader(overflow), sha256.Sum256(overflow)); m != nil || err != ErrManifest {
		t.Fatal("overflow image accepted", err)
	}
	low := manifestImage(t, "/synthetic/ledger", 1, 1)
	if m, err := ReadProvisionedManifest(bytes.NewReader(low), sha256.Sum256(low)); m == nil || err != nil {
		t.Fatal("minimum explicit policy refused", err)
	}
}
