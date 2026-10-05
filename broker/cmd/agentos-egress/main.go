// Command agentos-egress is the vault process (P2-4). It alone holds the
// unlocked vault and runs the credentialed egress proxy behind every agent
// machine's model route; agentosd forwards that route here and links
// neither the vault nor the proxy (vault V2).
//
//	agentos-egress init     create a sealed vault: passphrase slot and code-generator seed
//	agentos-egress serve    hold the vault; serve the model, verify and unlock sockets
//	agentos-egress unlock   unknown-host unlock from a terminal: passphrase, then code
//	agentos-egress put      store a provider API key in the open vault
//
// It runs as its own uid. The vault and keys files are readable by it only;
// the model and verify sockets admit the broker's uid only, and the unlock
// socket the local UI's uid only.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/vault"
)

const (
	defaultVault = "/var/lib/agentos-egress/vault"
	defaultKeys  = "/var/lib/agentos-egress/vault.keys"
	defaultState = "/var/lib/agentos-egress/unlock.json"
	defaultRun   = "/run/agentos-egress"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal("usage: agentos-egress init|serve|unlock|put [flags]")
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = initCmd(args, os.Stdout)
	case "serve":
		err = serveCmd(args)
	case "unlock":
		err = unlockCmd(args, os.Stdin, os.Stdout)
	case "put":
		err = putCmd(args, os.Stdin)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		log.Fatal(err)
	}
}

// grants collects -grant machine=adapter,adapter flags (egress E5).
type grants map[string][]string

func (g grants) String() string { return "" }
func (g grants) Set(v string) error {
	m, list, ok := strings.Cut(v, "=")
	if !ok || !machineRE.MatchString(m) || list == "" {
		return errors.New("want machine=adapter[,adapter]")
	}
	g[m] = append(g[m], strings.Split(list, ",")...)
	return nil
}

// adapters are the built-in relays. Their credentials are vault entries of
// kind api_key named after the adapter.
func adapters() []egress.Adapter {
	return []egress.Adapter{egress.OpenAI("openai"), egress.Anthropic("anthropic")}
}

// newProxy builds the proxy over an open vault. tr is nil outside tests.
func newProxy(v *vault.Vault, g map[string][]string, tr http.RoundTripper) (*egress.Proxy, error) {
	return egress.New(egress.Config{
		Adapters:  adapters(),
		Grants:    g,
		Vault:     apiKeysOnly{v},
		Transport: tr,
		// Each request's auditor and label come from the broker
		// (HandlerFor); this one only satisfies New.
		Audit: noAudit{},
	})
}

type noAudit struct{}

func (noAudit) Egress(egress.Event) {}

func serveCmd(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	vaultPath := fs.String("vault", defaultVault, "sealed vault file")
	keysPath := fs.String("keys", defaultKeys, "key slots file")
	statePath := fs.String("state", defaultState, "unlock state: wrong codes and last code step (CH-18)")
	run := fs.String("run", defaultRun, "socket directory (created 0711)")
	brokerUID := fs.Int("broker-uid", -1, "uid of agentosd, the only peer on the model socket")
	unlockUID := fs.Int("unlock-uid", -1, "uid of the local UI, the only peer on the unlock socket")
	ttl := fs.Duration("code-ttl", owner.DefaultCodeTTL, "how long a decrypted vault waits for its approval code")
	g := grants{}
	fs.Var(g, "grant", "machine=adapter[,adapter] (repeatable)")
	fs.Parse(args)
	self := os.Getuid()
	if *brokerUID < 0 || *brokerUID == self {
		return errors.New("-broker-uid must name agentosd's own uid, distinct from this process's")
	}
	if *unlockUID < 0 || *unlockUID == *brokerUID {
		return errors.New("-unlock-uid must name the local UI's uid, distinct from agentosd's")
	}
	c, err := newCustody(&custody{
		open: func(p string) (*vault.Vault, error) {
			return vault.OpenSealed(*vaultPath, *keysPath, vault.Passphrase(p))
		},
		build:     func(v *vault.Vault) (*egress.Proxy, error) { return newProxy(v, g, nil) },
		ttl:       *ttl,
		now:       time.Now,
		notify:    func(s string) { log.Print(s) },
		statePath: *statePath,
	})
	if err != nil {
		return err
	}
	// Fail at start on a bad grant rather than at the first unlock.
	if _, err := egress.New(egress.Config{Adapters: adapters(), Grants: g, Vault: emptyVault{}, Audit: noAudit{}}); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srvs, err := serve(*run, c, *brokerUID, *unlockUID)
	if err != nil {
		return err
	}
	log.Printf("vault process up, vault locked; sockets in %s", *run)
	<-ctx.Done()
	for _, s := range srvs {
		s.Close()
	}
	c.lock()
	return nil
}

type emptyVault struct{}

func (emptyVault) Secret(string) (vault.Secret, bool) { return vault.Secret{}, false }
func (emptyVault) Redactor() (*vault.Redactor, error) { return vault.NewRedactor(nil), nil }

// serve opens the model, verify and unlock sockets in dir and serves them
// until closed. The model and verify sockets admit the broker's uid only.
func serve(dir string, c *custody, brokerUID, unlockUID int) ([]*http.Server, error) {
	if err := runDir(dir); err != nil {
		return nil, err
	}
	socks := []struct {
		name string
		uid  int
		h    http.Handler
	}{
		{ModelSocket, brokerUID, modelHandler(c)},
		{VerifySocket, brokerUID, verifyHandler(c)},
		{UnlockSocket, unlockUID, unlockHandler(c)},
	}
	var lns []net.Listener
	for _, s := range socks {
		ln, err := listen(dir, s.name, s.uid)
		if err != nil {
			for _, l := range lns {
				l.Close()
			}
			return nil, err
		}
		lns = append(lns, ln)
	}
	var srvs []*http.Server
	for i, s := range socks {
		srv := newServer(s.h)
		go srv.Serve(lns[i])
		srvs = append(srvs, srv)
	}
	return srvs, nil
}

// initCmd creates a sealed vault: a generated passphrase (100 bits) in the
// passphrase slot and a fresh code-generator seed inside the vault. It
// prints both once, as the Owner Card does (P2-2 prints the real card).
func initCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	vaultPath := fs.String("vault", defaultVault, "sealed vault file to create")
	keysPath := fs.String("keys", defaultKeys, "key slots file to create")
	fs.Parse(args)
	pass, err := newPassphrase()
	if err != nil {
		return err
	}
	seed := make([]byte, 20)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*vaultPath), 0o700); err != nil {
		return err
	}
	if err := sealNew(*vaultPath, *keysPath, pass, seed); err != nil {
		return err
	}
	secret := b32().EncodeToString(seed)
	fmt.Fprintf(out, "Vault passphrase: %s\n", pass)
	fmt.Fprintf(out, "Code generator:   otpauth://totp/AgentOS?secret=%s&issuer=AgentOS\n", secret)
	fmt.Fprintln(out, "Keep both offline. They are shown once.")
	return nil
}

// sealNew builds the vault and keys under temporary names, stores the seed,
// and only then renames them into place, keys last: the keys file is what
// makes a vault openable, so a crash leaves either nothing usable or a
// complete vault. A vault file without its keys file can never be opened,
// so init reports it for removal rather than leaving the owner stuck.
func sealNew(vaultPath, keysPath, pass string, seed []byte) error {
	if _, err := os.Lstat(keysPath); err == nil {
		return fmt.Errorf("%s already exists; this box already has a vault", keysPath)
	}
	if _, err := os.Lstat(vaultPath); err == nil {
		return fmt.Errorf("%s exists without its keys file (an earlier init did not finish); it cannot be opened: remove it and run init again", vaultPath)
	}
	vt, kt := vaultPath+".init", keysPath+".init"
	os.Remove(vt)
	os.Remove(kt)
	v, err := vault.CreateSealed(vt, kt, vault.Passphrase(pass))
	if err != nil {
		return err
	}
	err = v.Put(SeedName, vault.KindTOTPSeed, seed)
	v.Close()
	if err == nil {
		err = os.Rename(vt, vaultPath)
	}
	if err == nil {
		err = os.Rename(kt, keysPath)
	}
	if err != nil {
		os.Remove(vt)
		os.Remove(kt)
		return err
	}
	return syncDir(filepath.Dir(keysPath))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	serr := d.Sync()
	if err := d.Close(); serr == nil {
		serr = err
	}
	return serr
}

func b32() *base32.Encoding { return base32.StdEncoding.WithPadding(base32.NoPadding) }

// newPassphrase returns 100 random bits as five groups of four base32
// characters.
func newPassphrase() (string, error) {
	b := make([]byte, 13)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	s := strings.ToLower(base32.StdEncoding.EncodeToString(b))[:20]
	return strings.Join([]string{s[0:4], s[4:8], s[8:12], s[12:16], s[16:20]}, " "), nil
}

// unixClient talks HTTP to a socket in the run directory.
func unixClient(path string) *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
}

func post(c *http.Client, path string, body any) (map[string]any, int, error) {
	raw, _ := json.Marshal(body)
	u := url.URL{Scheme: "http", Host: "agentos-egress", Path: path}
	resp, err := c.Post(u.String(), "application/json", strings.NewReader(string(raw)))
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out := map[string]any{}
	json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out)
	return out, resp.StatusCode, nil
}

// unlockCmd reads the passphrase, then the approval code, from in.
func unlockCmd(args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("unlock", flag.ExitOnError)
	run := fs.String("run", defaultRun, "socket directory")
	fs.Parse(args)
	c := unixClient(filepath.Join(*run, UnlockSocket))
	r := bufio.NewReader(in)
	fmt.Fprint(out, "Vault passphrase: ")
	pass, _ := r.ReadString('\n')
	res, code, err := post(c, "/unlock", map[string]string{"passphrase": strings.TrimSpace(pass)})
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("unlock: %v", res["error"])
	}
	ticket, _ := res["ticket"].(string)
	for {
		fmt.Fprintf(out, "Code-generator code (6 digits, due by %v): ", res["expires"])
		otp, rerr := r.ReadString('\n')
		var cres map[string]any
		cres, code, err = post(c, "/confirm", map[string]string{"ticket": ticket, "code": strings.TrimSpace(otp)})
		if err != nil {
			return err
		}
		if code == http.StatusOK {
			break
		}
		// A wrong code leaves the unlock pending until it expires or
		// the cap is reached; anything else ends it.
		msg, _ := cres["error"].(string)
		if code != http.StatusForbidden || rerr != nil || !(strings.HasPrefix(msg, "wrong code") || strings.HasPrefix(msg, "that code is for another time")) {
			return fmt.Errorf("confirm: %s", msg)
		}
		fmt.Fprintln(out, msg)
	}
	fmt.Fprintln(out, "Vault unlocked.")
	return nil
}

// putCmd reads a provider API key from in and stores it under -name.
func putCmd(args []string, in io.Reader) error {
	fs := flag.NewFlagSet("put", flag.ExitOnError)
	run := fs.String("run", defaultRun, "socket directory")
	name := fs.String("name", "", "credential name: an adapter name such as openai or anthropic")
	fs.Parse(args)
	val, _ := bufio.NewReader(io.LimitReader(in, maxUnlockBody)).ReadString('\n')
	res, code, err := post(unixClient(filepath.Join(*run, UnlockSocket)), "/credential", map[string]string{"name": *name, "value": strings.TrimSpace(val)})
	if err != nil {
		return err
	}
	if code != http.StatusNoContent {
		return fmt.Errorf("put: %v", res["error"])
	}
	return nil
}
