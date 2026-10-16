package apnet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/durable"
)

// REQ: CH-12, REC-4, ARC-1

func writeNet(t *testing.T, path, password string) {
	t.Helper()
	m, err := Network{SSID: Prefix + "ABCD", Password: password}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := durable.WriteFile(path, m, 0o600); err != nil {
		t.Fatal(err)
	}
}

// #1525: consecutive Up failures are counted per version of the card's
// network file, a rewrite starts again at one, and a served network
// clears the count. The record names the file's version, never its
// password, and is root-only.
func TestUpFailuresCountPerNetworkVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ap-net.json")
	if f, err := ReadUpFailures(path); err != nil || f.Count != 0 {
		t.Fatalf("none yet: %+v %v", f, err)
	}
	writeNet(t, path, "ABCD-EFGH-JKLM-NPQR")
	var first UpFailures
	for i := 1; i <= 3; i++ {
		f, err := RecordUpFailure(path)
		if err != nil || f.Count != i || f.Network == "" {
			t.Fatalf("failure %d: %+v %v", i, f, err)
		}
		first = f
	}
	if f, err := ReadUpFailures(path); err != nil || f != first {
		t.Fatalf("read back: %+v %v", f, err)
	}
	fi, err := os.Stat(UpFailuresPath(path))
	if err != nil || fi.Mode().Perm() != 0o600 || filepath.Dir(UpFailuresPath(path)) != filepath.Dir(path) {
		t.Fatalf("record file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(UpFailuresPath(path)); strings.Contains(string(b), "ABCD-EFGH") {
		t.Fatal("the record holds the password")
	}

	writeNet(t, path, "STUV-WXYZ-2345-6789")
	f, err := RecordUpFailure(path)
	if err != nil || f.Count != 1 || f.Network == first.Network {
		t.Fatalf("a rewritten network: %+v %v", f, err)
	}
	if err := ClearUpFailures(path); err != nil {
		t.Fatal(err)
	}
	if err := ClearUpFailures(path); err != nil {
		t.Fatalf("clearing twice: %v", err)
	}
	if f, err := ReadUpFailures(path); err != nil || f.Count != 0 {
		t.Fatalf("cleared: %+v %v", f, err)
	}
}

// A record that does not parse, or is oversized, is an error, not a
// count; a missing network file records nothing.
func TestUpFailuresRecordIsCareful(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ap-net.json")
	if _, err := RecordUpFailure(path); err == nil {
		t.Fatal("recorded a failure with no network file")
	}
	os.WriteFile(UpFailuresPath(path), []byte("{"), 0o600)
	if _, err := ReadUpFailures(path); err == nil {
		t.Fatal("read a malformed record")
	}
	os.WriteFile(UpFailuresPath(path), []byte(`{"network":"`+strings.Repeat("x", maxUpFailures)+`","count":9}`), 0o600)
	if _, err := ReadUpFailures(path); err == nil {
		t.Fatal("read an oversized record")
	}
}
