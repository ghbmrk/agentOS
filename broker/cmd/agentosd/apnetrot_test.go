package main

// REQ: REC-4, CH-7, ARC-1

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/apnet"
	"github.com/ghbmrk/agentos/broker/durable"
)

// Synthetic card networks, the shape card.Generate makes.
var (
	cardNet    = apnet.Network{SSID: "AgentOS-AB2C", Password: "ABCD-EFGH-JKLM-NP23"}
	rotatedNet = apnet.Network{SSID: "AgentOS-AB2C", Password: "QRST-UVWX-YZ23-4567"}
)

func writeAPNet(t *testing.T, n apnet.Network) string {
	t.Helper()
	b, err := n.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "ap-net.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// permit is the vault process's hold as a taker: each queued network is
// given once, then nothing (modelroute.ErrNoRotatedWiFi's case).
func permit(ns ...apnet.Network) func() (apnet.Network, error) {
	return func() (apnet.Network, error) {
		if len(ns) == 0 {
			return apnet.Network{}, errors.New("no rotated Wi-Fi network is waiting")
		}
		n := ns[0]
		ns = ns[1:]
		return n, nil
	}
}

func readAPNet(t *testing.T, p string) apnet.Network {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	n, err := apnet.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestARotatedWiFiNetworkReplacesTheCardsOwnRootOnly(t *testing.T) {
	p := writeAPNet(t, cardNet)
	if err := rotateAPNet(p, permit(rotatedNet))(); err != nil {
		t.Fatal(err)
	}
	if readAPNet(t, p) != rotatedNet {
		t.Fatal("file holds another network")
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

// #1522: a session alone cannot change ap-net.json: with no Wi-Fi commit
// behind it there is nothing to take, and one commit permits one write.
func TestARotatedWiFiNetworkNeedsTheVaultsOneShotPermit(t *testing.T) {
	p := writeAPNet(t, cardNet)
	before, _ := os.ReadFile(p)
	if rotateAPNet(p, permit())() == nil {
		t.Fatal("written with no commit")
	}
	if after, _ := os.ReadFile(p); !bytes.Equal(before, after) {
		t.Fatal("file changed with no commit")
	}
	hook := rotateAPNet(p, permit(rotatedNet))
	if err := hook(); err != nil {
		t.Fatal(err)
	}
	// Put the card's own back by hand, as if another write had raced:
	// the hook must not write again inside the window.
	b, _ := cardNet.Marshal()
	os.WriteFile(p, b, 0o600)
	if hook() == nil || readAPNet(t, p) != cardNet {
		t.Fatal("a second write inside the window")
	}
}

func TestARotatedWiFiNetworkIsRefusedUnlessItRotatesTheCardsOwn(t *testing.T) {
	for name, n := range map[string]apnet.Network{
		"another name":     {SSID: "AgentOS-ZZ99", Password: "QRST-UVWX-YZ23-4567"},
		"not a card shape": {SSID: "AgentOS-AB2C", Password: "short"},
		"injection":        {SSID: "AgentOS-AB2C", Password: "QRST-UVWX-YZ23-456\n"},
	} {
		p := writeAPNet(t, cardNet)
		before, _ := os.ReadFile(p)
		err := rotateAPNet(p, permit(n))()
		if err == nil {
			t.Fatalf("%s: written", name)
		}
		if strings.Contains(err.Error(), "QRST") || strings.Contains(err.Error(), "ABCD") {
			t.Fatalf("%s: error names a password: %v", name, err)
		}
		if after, _ := os.ReadFile(p); !bytes.Equal(before, after) {
			t.Fatalf("%s: file changed", name)
		}
	}

	missing := filepath.Join(t.TempDir(), "ap-net.json")
	if rotateAPNet(missing, permit(rotatedNet))() == nil {
		t.Fatal("wrote a rotation before setup wrote the first network")
	}
	if _, err := os.Lstat(missing); err == nil {
		t.Fatal("created the file")
	}
	if rotateAPNet("", permit(rotatedNet)) != nil || rotateAPNet(missing, nil) != nil {
		t.Fatal("no path or no taker still serves the op")
	}
}

// #1523, #1524: the write is durable's, and a directory sync that fails
// after the rename put the network on the air, so it reports success.
func TestARotatedWiFiNetworkIsWrittenDurably(t *testing.T) {
	if reflect.ValueOf(writeAPNetFile).Pointer() != reflect.ValueOf(durable.WriteFile).Pointer() {
		t.Fatal("ap-net.json is not written through durable.WriteFile")
	}
	p := writeAPNet(t, cardNet)
	defer func(w func(string, []byte, os.FileMode) error) { writeAPNetFile = w }(writeAPNetFile)
	calls := 0
	writeAPNetFile = func(path string, data []byte, perm os.FileMode) error {
		calls++
		if err := durable.WriteFile(path, data, perm); err != nil {
			return err
		}
		return fmt.Errorf("%w: synthetic", durable.ErrDirSync)
	}
	if err := rotateAPNet(p, permit(rotatedNet))(); err != nil || calls != 1 {
		t.Fatalf("dir sync after the rename: %v (%d writes)", err, calls)
	}
	if readAPNet(t, p) != rotatedNet {
		t.Fatal("not written")
	}
	writeAPNetFile = func(string, []byte, os.FileMode) error { return errors.New("synthetic: read-only") }
	if rotateAPNet(p, permit(cardNet))() == nil {
		t.Fatal("a failed write reported success")
	}
}

// #1524: the socket main serves rotates only with both the file and the
// vault process's verify socket, and takes the network over the socket.
func TestThePageSocketTakesTheNetworkFromTheVaultProcess(t *testing.T) {
	p := writeAPNet(t, cardNet)
	sock := filepath.Join(t.TempDir(), "verify.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	given := 0
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/rotate/wifi" || given > 0 {
			http.Error(w, "gone", http.StatusGone)
			return
		}
		given++
		fmt.Fprintf(w, `{"ssid":%q,"password":%q}`, rotatedNet.SSID, rotatedNet.Password)
	}))
	srv.Listener = l
	srv.Start()
	defer srv.Close()

	if pageSocket(os.Getuid(), os.Getgid(), "", sock).RotateAPNet != nil || pageSocket(os.Getuid(), os.Getgid(), p, "").RotateAPNet != nil {
		t.Fatal("served without the file or the verify socket")
	}
	ps := pageSocket(os.Getuid(), os.Getgid(), p, sock)
	if ps.UID != os.Getuid() || ps.GID == nil || *ps.GID != os.Getgid() || ps.RotateAPNet == nil {
		t.Fatalf("page socket: %+v", ps)
	}
	if err := ps.RotateAPNet(); err != nil {
		t.Fatal(err)
	}
	if readAPNet(t, p) != rotatedNet {
		t.Fatal("not the vault's network")
	}
	if ps.RotateAPNet() == nil {
		t.Fatal("a second write with no second commit")
	}
}
