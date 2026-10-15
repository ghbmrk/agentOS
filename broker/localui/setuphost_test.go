package localui

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: CRED-9, CH-12, ONB-6

// fakeRoot writes the DMI names and meminfo HostInfo reads under a root.
func fakeRoot(t *testing.T, vendor, product, meminfo string) string {
	t.Helper()
	root := t.TempDir()
	for name, v := range map[string]string{"sys/class/dmi/id/sys_vendor": vendor, "sys/class/dmi/id/product_name": product, "proc/meminfo": meminfo} {
		if v == "" {
			continue
		}
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const memTotal8 = "MemTotal:        7990124 kB\nMemFree:          123456 kB\n"

// §8.1's pairing reply names the PC and its RAM: "I'm running on [host,
// RAM]". The names come from the PC's firmware (DMI), the RAM from the
// kernel, rounded up to whole GB.
func TestHostInfoNamesThePCAndItsRAM(t *testing.T) {
	for _, c := range []struct{ vendor, product, mem, want string }{
		{"GEEKOM\n", "Air12\n", memTotal8, "GEEKOM Air12, 8 GB"},
		{"GEEKOM", "GEEKOM Air12", memTotal8, "GEEKOM Air12, 8 GB"},
		{"Intel(R) Client Systems", "NUC13ANHi5", "MemTotal: 32617000 kB\n", "NUC13ANHi5, 32 GB"},
		{"Intel(R) Client Systems", "NUC13ANHi5", "MemTotal: 8000000 kB\n", "Intel(R) Client Systems NUC13ANHi5, 8 GB"},
		{"Not Specified", "System Version", "MemTotal: 16000000 kB\n", "a PC with 16 GB"},
		{"Very Long Vendor Name Incorporated Worldwide", "", "MemTotal: 66000000 kB\n", "Very Long Vendor Name Incorporate, 63 GB"},
		{"To Be Filled By O.E.M.", "Default string", memTotal8, "a PC with 8 GB"},
		{"", "", memTotal8, "a PC with 8 GB"},
		{"GEEKOM", "Air12", "", "GEEKOM Air12"},
		{"GEEKOM", "Air12", "MemTotal: lots\n", "GEEKOM Air12"},
		{"", "", "", ""},
		{"Very Long Vendor Name Incorporated Worldwide", "Model 9000 Ultra Max Pro", memTotal8, "Model 9000 Ultra Max Pro, 8 GB"},
		{"", "An Exceedingly Long Product Name For A Mini PC", "MemTotal: 130000000 kB\n", "An Exceedingly Long Product Name, 124 GB"},
		// Firmware text is not trusted: the reply keeps no link or domain.
		{"", "http://evil.example/x", memTotal8, "http://evil.example/x, 8 GB"},
		{"-", "(.)", "", "- (.)"},
	} {
		got := AgentosdSetup{Root: fakeRoot(t, c.vendor, c.product, c.mem)}.HostInfo()
		if got != c.want {
			t.Errorf("%q %q: %q, want %q", c.vendor, c.product, got, c.want)
		}
		// The whole name and RAM reach the pairing reply, uncut.
		if got != "" && !strings.ContainsAny(got, ".:/") && !strings.Contains(pairedText(got), got) {
			t.Errorf("cut from the pairing reply: %q", pairedText(got))
		}
		// agentosd sends the reply (localapi.SetupText); a refused one
		// would silently leave the owner unpaired.
		if !localapi.SetupText(pairedText(got)) {
			t.Errorf("agentosd refuses the pairing reply %q", pairedText(got))
		}
	}
}

// Every character gsmSafe keeps, leading or inside the PC's name, still
// gives a pairing reply agentosd sends (localapi.SetupText): pairedText
// and SetupText's host class must agree, or the owner is silently left
// unpaired.
func TestPairedTextPassesSetupTextForEveryKeptCharacter(t *testing.T) {
	names := []string{",Foo", "+Foo", "'Foo", "A+B's PC", "A,B", "Foo, 8 GB", "Mark's PC", "+'-,() Foo"}
	for _, c := range " ,.-+()/:'" {
		names = append(names, string(c)+"Foo", "A"+string(c)+"B", "Foo"+string(c))
	}
	for _, name := range names {
		got := pairedText(name)
		if !localapi.SetupText(got) {
			t.Errorf("%q: agentosd refuses the pairing reply %q", name, got)
		}
		// A kept character inside the name reaches the reply.
		if inner := strings.TrimLeft(name, " ,()+'-"); !strings.ContainsAny(inner, ".:/") && strings.TrimSpace(inner) != "" && !strings.Contains(got, strings.TrimSpace(inner)) {
			t.Errorf("%q: cut from the pairing reply %q", name, got)
		}
	}
}

// fakeTrust is the vault process's setup host step.
type fakeTrust struct {
	got []bool
	err error
}

func (f *fakeTrust) SetupTrust(_ context.Context, trusted bool) (string, error) {
	f.got = append(f.got, trusted)
	return "Test PC", f.err
}

// The host step saves through the vault process; a page with no vault
// process wired cannot, and says so as any failed save.
func TestTrustHostGoesToTheVaultProcess(t *testing.T) {
	if err := (AgentosdSetup{}).TrustHost(true); err == nil {
		t.Fatal("trusted with no vault process")
	}
	f := &fakeTrust{}
	a := AgentosdSetup{Vault: f}
	if a.TrustHost(true) != nil || a.TrustHost(false) != nil || len(f.got) != 2 || !f.got[0] || f.got[1] {
		t.Fatalf("calls %v", f.got)
	}
	f.err = errors.New("vault: down")
	if a.TrustHost(true) == nil {
		t.Fatal("a refusal was taken as saved")
	}
}

// A PC without a TPM cannot be trusted: the page says why and how to go
// on, in words (CH-12), and "This is not my PC" then continues.
func TestHostStepWithoutATrustChip(t *testing.T) {
	r := newRig(t)
	r.hooks.trustErr = ErrNoTrustChip
	r.runSetupToHost()
	r.post("/setup/host", url.Values{})
	msg := r.setupErr()
	if !strings.Contains(msg, "This is not my PC") || strings.Contains(msg, "Try again") || strings.Contains(msg, "TPM") {
		t.Fatalf("no-chip text: %q", msg)
	}
	ch12(t, msg)
	r.hooks.trustErr = nil
	r.post("/setup/host", url.Values{"not_mine": {"1"}})
	if r.setupErr() != "" || r.hooks.trusted == nil || *r.hooks.trusted {
		t.Fatalf("not mine did not continue: %q", r.setupErr())
	}
}

// UnlockClient.SetupTrust is POST /setup/host on the unlock socket; the
// vault process's no_tpm answer is ErrNoTrustChip, any other refusal a
// VaultError.
func TestSetupTrustOverTheUnlockSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "unlock.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var reply func(w http.ResponseWriter, trusted bool)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Trusted *bool `json:"trusted"`
		}
		if r.Method != http.MethodPost || r.URL.Path != "/setup/host" || json.NewDecoder(r.Body).Decode(&req) != nil || req.Trusted == nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		reply(w, *req.Trusted)
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	c := NewUnlockClient(sock)
	ctx := context.Background()

	reply = func(w http.ResponseWriter, trusted bool) {
		if trusted {
			w.Write([]byte(`{"host":"Test PC"}`))
		} else {
			w.Write([]byte(`{"host":""}`))
		}
	}
	if name, err := c.SetupTrust(ctx, true); err != nil || name != "Test PC" {
		t.Fatalf("trust: %q %v", name, err)
	}
	if _, err := c.SetupTrust(ctx, false); err != nil {
		t.Fatalf("not mine: %v", err)
	}
	reply = func(w http.ResponseWriter, _ bool) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":"this PC has no TPM, so it cannot be a trusted host","no_tpm":true}`))
	}
	if _, err := c.SetupTrust(ctx, true); !errors.Is(err, ErrNoTrustChip) {
		t.Fatalf("no TPM: %v", err)
	}
	reply = func(w http.ResponseWriter, _ bool) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":"no code generator was confirmed since the last enrollment"}`))
	}
	var ve *VaultError
	if _, err := c.SetupTrust(ctx, true); !errors.As(err, &ve) || ve.Status != http.StatusConflict || errors.Is(err, ErrNoTrustChip) {
		t.Fatalf("refusal: %v", err)
	}
}
