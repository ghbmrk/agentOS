// Command agentos-egress is the vault process (P2-4). It alone holds the
// unlocked vault and runs the credentialed egress proxy behind every agent
// machine's model route; agentosd forwards that route here and links
// neither the vault nor the proxy (vault V2).
//
//	agentos-egress init     create a sealed vault: passphrase slot and code-generator seed
//	agentos-egress serve    hold the vault; serve the model, verify and unlock sockets
//	agentos-egress unlock   unknown-host unlock from a terminal: passphrase, then code
//	                        (or the boot PIN, on a trusted host that has one)
//	agentos-egress put      store a provider API key in the open vault
//	agentos-egress trust    make this PC a trusted host (code; optional boot PIN)
//	agentos-egress untrust  remove a trusted host (code)
//	agentos-egress hosts    list the trusted hosts
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
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/route"
	"github.com/ghbmrk/agentos/broker/vault"
)

const (
	defaultVault = "/var/lib/agentos-egress/vault"
	defaultKeys  = "/var/lib/agentos-egress/vault.keys"
	defaultTPM   = "/dev/tpmrm0"
	// defaultPCRs measure the Type #1 boot path of S7's host stack: PCR 4
	// the boot loader and kernel, 7 the Secure Boot state (db, dbx;
	// arbitrator, #42), 9 the initrd, 12 the kernel command line, which
	// carries the /usr root hash (HW-5a).
	defaultPCRs = "4,7,9,12"
	defaultRun  = "/run/agentos-egress"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal("usage: agentos-egress init|serve|unlock|put|trust|untrust|hosts [flags]")
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
	case "trust":
		err = trustCmd(args, os.Stdin, os.Stdout)
	case "untrust":
		err = untrustCmd(args, os.Stdin)
	case "hosts":
		err = hostsCmd(args, os.Stdout)
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

// newRouter builds the model router (P2-7) over the grants. Its egress
// handler, label, and auditor are given per call (modelHandler).
func newRouter(rule route.Rule, g map[string][]string, privateOK map[string]bool) (*route.Router, error) {
	return route.New(route.Config{
		Providers: []route.Provider{route.OpenAI(), route.Anthropic()},
		Rule:      rule,
		Granted: func(machine, provider string) bool {
			for _, a := range g[machine] {
				if a == provider {
					return true
				}
			}
			return false
		},
		PrivateOK: privateOK,
		Upstream: func(string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "model egress unavailable", http.StatusServiceUnavailable)
			})
		},
		// Decisions carry no content; failovers are logged for the
		// operator. Denials and usage go back to the broker per call.
		Audit: func(d route.Decision) {
			if d.Outcome == route.Failover {
				log.Printf("model route %s: %s failed over (HTTP %d)", d.Machine, d.Route, d.Status)
			}
		},
		// No modem before P2-3: the owner text is a log line for now.
		CredentialRejected: func(provider string) {
			log.Printf("provider %s rejected the vault's API key; replace it with put", provider)
		},
	})
}

// readPrices reads the evaluation price table; an empty path is an empty
// table, which refuses every evaluation route.
func readPrices(path string) (prices, error) {
	ps := prices{}
	if path == "" {
		return ps, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &ps); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for k, p := range ps {
		if p.Input < 0 || p.Output < 0 {
			return nil, fmt.Errorf("%s: %s has a negative price", path, k)
		}
	}
	return ps, nil
}

// readRule reads a routing rule: a JSON object from task class to routes
// in preference order, e.g. {"default":[{"provider":"anthropic","model":"..."}]}.
func readRule(path string) (route.Rule, error) {
	if path == "" {
		return nil, errors.New("-rule is required: a JSON file mapping task classes to routes")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rule route.Rule
	if err := json.Unmarshal(raw, &rule); err != nil {
		return nil, fmt.Errorf("rule %s: %w", path, err)
	}
	return rule, nil
}

type noAudit struct{}

func (noAudit) Egress(egress.Event) {}

func serveCmd(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	vaultPath := fs.String("vault", defaultVault, "sealed vault file")
	keysPath := fs.String("keys", defaultKeys, "key slots file")
	statePath := fs.String("state", "", "unlock state: wrong codes and last code step (CH-18); default unlock.json beside the keys")
	run := fs.String("run", defaultRun, "socket directory (created 0711)")
	brokerUID := fs.Int("broker-uid", -1, "uid of agentosd, the only peer on the model socket")
	unlockUID := fs.Int("unlock-uid", -1, "uid of the local UI, the only peer on the unlock socket")
	ttl := fs.Duration("code-ttl", owner.DefaultCodeTTL, "how long a decrypted vault waits for its approval code")
	g := grants{}
	fs.Var(g, "grant", "machine=adapter[,adapter] (repeatable)")
	rulePath := fs.String("rule", "", "routing rule: JSON task class -> routes (P2-7); adoptions may only reorder its routes")
	routingPath := fs.String("routing-state", "", "the adopted routing rule, kept across restarts (W3); default routing.json beside the keys")
	pricesPath := fs.String("prices", "", "model price table for evaluation routes: JSON \"provider/model\" -> {input, output} per million tokens; empty refuses every evaluation route")
	evalFrom := fs.String("eval-from", "", "the agent machine whose model grants replay machines use (LOOP-5); empty (the default) gives replay no model access")
	privateOK := fs.String("private-ok", "", "providers the owner allowed for private data, comma-separated (CAP-9)")
	tpmPath := fs.String("tpm", defaultTPM, "this PC's TPM (trusted host, CRED-8); absent means every boot is an unknown host")
	polPath := fs.String("pcr-policy", "", "approved boot paths: signed PCR policies (HW-5a); default vault.pcrpolicy beside the keys")
	pcrList := fs.String("pcrs", defaultPCRs, "PCRs a trusted host's boot path is measured into (SHA-256 bank)")
	fs.Parse(args)
	pcrs, err := parsePCRs(*pcrList)
	if err != nil {
		return err
	}
	rule, err := readRule(*rulePath)
	if err != nil {
		return err
	}
	pok := map[string]bool{}
	for _, p := range strings.Split(*privateOK, ",") {
		if p = strings.TrimSpace(p); p != "" {
			pok[p] = true
		}
	}
	if *routingPath == "" {
		*routingPath = filepath.Join(filepath.Dir(*keysPath), "routing.json")
	}
	base := rule
	if rule, err = startRule(base, *routingPath); err != nil {
		log.Printf("routing: starting from -rule: %v", err)
	}
	rt, err := newRouter(rule, g, pok)
	if err != nil {
		return err
	}
	var ev *evalRoute
	if *evalFrom != "" {
		ps, err := readPrices(*pricesPath)
		if err != nil {
			return err
		}
		ev = &evalRoute{From: *evalFrom, Grants: g[*evalFrom], PrivateOK: pok, Active: rule, Prices: ps}
	}
	for m := range g {
		if strings.HasPrefix(m, modelroute.EvalPrefix) {
			return fmt.Errorf("-grant %s: replay machines take -eval-from's grants, never their own", m)
		}
	}
	self := os.Getuid()
	if *brokerUID < 0 || *brokerUID == self {
		return errors.New("-broker-uid must name agentosd's own uid, distinct from this process's")
	}
	if *unlockUID < 0 || *unlockUID == *brokerUID {
		return errors.New("-unlock-uid must name the local UI's uid, distinct from agentosd's")
	}
	if *statePath == "" {
		*statePath = statePathFor(*keysPath)
	}
	if *polPath == "" {
		*polPath = filepath.Join(filepath.Dir(*keysPath), "vault.pcrpolicy")
	}
	c, err := newCustody(&custody{
		keysPath: *keysPath,
		open: func(p string) (*vault.Vault, error) {
			return vault.OpenSealed(*vaultPath, *keysPath, vault.Passphrase(p))
		},
		build:     func(v *vault.Vault) (*egress.Proxy, error) { return newProxy(v, g, nil) },
		ttl:       *ttl,
		now:       time.Now,
		notify:    func(s string) { log.Print(s) },
		statePath: *statePath,
		host:      newTPMHost(*tpmPath, *vaultPath, *keysPath, *polPath, pcrs),
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
	ro := &routing{base: base, rt: rt, ev: ev, path: *routingPath}
	srvs, err := serve(*run, c, rt, ev, ro, *brokerUID, *unlockUID)
	if err != nil {
		return err
	}
	c.bootTrusted()
	ph, _ := c.status()
	log.Printf("vault process up, vault %s; sockets in %s", ph, *run)
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
func serve(dir string, c *custody, rt *route.Router, ev *evalRoute, ro *routing, brokerUID, unlockUID int) ([]*http.Server, error) {
	if ro == nil {
		ro = &routing{base: rt.Rule(), rt: rt, ev: ev}
	}
	if err := runDir(dir); err != nil {
		return nil, err
	}
	socks := []struct {
		name string
		uid  int
		h    http.Handler
	}{
		{ModelSocket, brokerUID, modelHandler(c, rt, ev)},
		{RoutingSocket, brokerUID, ro.handler()},
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
	statePath := fs.String("state", "", "unlock state to create; default unlock.json beside the keys")
	fs.Parse(args)
	if *statePath == "" {
		*statePath = statePathFor(*keysPath)
	}
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
	// The unlock state goes in place before the keys make the vault
	// openable, so serve can require it (newCustody).
	if _, err := os.Lstat(*keysPath); err == nil {
		return fmt.Errorf("%s already exists; this box already has a vault", *keysPath)
	}
	if err := writeFileAtomic(*statePath, []byte("{}")); err != nil {
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

// statePathFor is the default unlock state file, beside the keys file.
func statePathFor(keysPath string) string {
	return filepath.Join(filepath.Dir(keysPath), "unlock.json")
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
	st, _, err := get(c, "/status")
	if err == nil && st["pin"] == true {
		fmt.Fprint(out, "Boot PIN for this trusted PC: ")
		pin, _ := r.ReadString('\n')
		res, code, err := post(c, "/unlock-pin", map[string]string{"pin": strings.TrimSpace(pin)})
		if err != nil {
			return err
		}
		if code != http.StatusOK {
			return fmt.Errorf("unlock: %v", res["error"])
		}
		fmt.Fprintln(out, "Vault unlocked.")
		return nil
	}
	keep := false
	if err == nil && st["boot_changed"] == true {
		if st["secure_boot"] == true {
			fmt.Fprintln(out, "Secure Boot settings on this PC changed. If you updated firmware, unlock with your card to keep this PC trusted.")
		} else if st["updated"] == true {
			fmt.Fprintln(out, "Box updated. Unlock once with your passphrase and a code; this PC stays trusted after that.")
		} else {
			fmt.Fprintln(out, "This PC started the box in a way it hasn't before. If you didn't change anything, the drive may have been tampered with. Unlock only if you're sure.")
		}
		// Never ticked by default: updated and secure_boot come from
		// files on the drive, not from a verified release's measured
		// boot, so a tampered boot path must not become trusted unless
		// the owner says so. (A release the updater verified has its
		// policy signed before the reboot, and never gets here.)
		fmt.Fprint(out, "Keep this PC trusted? [y/N] ")
		ans, _ := r.ReadString('\n')
		ans = strings.ToLower(strings.TrimSpace(ans))
		keep = ans == "y" || ans == "yes"
	}
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
		cres, code, err = post(c, "/confirm", map[string]any{"ticket": ticket, "code": strings.TrimSpace(otp), "keep_trusted": keep})
		if err != nil {
			return err
		}
		if code == http.StatusOK {
			if keep && cres["kept_trusted"] != true {
				fmt.Fprintln(out, "Could not keep this PC trusted; trust it again with: agentos-egress trust")
			}
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

func get(c *http.Client, path string) (map[string]any, int, error) {
	u := url.URL{Scheme: "http", Host: "agentos-egress", Path: path}
	resp, err := c.Get(u.String())
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out := map[string]any{}
	json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out)
	return out, resp.StatusCode, nil
}

// trustCmd makes this PC a trusted host (CRED-9): it reads a
// code-generator code and, with -pin, then the boot PIN, from in.
func trustCmd(args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("trust", flag.ExitOnError)
	run := fs.String("run", defaultRun, "socket directory")
	withPIN := fs.Bool("pin", false, "also require a boot PIN on this PC (no unattended restart)")
	fs.Parse(args)
	r := bufio.NewReader(io.LimitReader(in, maxUnlockBody))
	fmt.Fprint(out, "Code-generator code: ")
	code, _ := r.ReadString('\n')
	var pin string
	if *withPIN {
		fmt.Fprintln(out, "With a PIN, the box won't restart by itself after a power cut until you enter the PIN.")
		fmt.Fprintln(out, "This also locks this PC's TPM reset to the box until you turn the PIN off.")
		fmt.Fprint(out, "New boot PIN: ")
		pin, _ = r.ReadString('\n')
		pin = strings.TrimSpace(pin)
		if pin == "" {
			return errors.New("trust: -pin needs a PIN")
		}
	}
	res, status, err := post(unixClient(filepath.Join(*run, UnlockSocket)), "/trust", map[string]string{"code": strings.TrimSpace(code), "pin": pin})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("trust: %v", res["error"])
	}
	fmt.Fprintf(out, "%v is now a trusted host.\n", res["host"])
	return nil
}

// untrustCmd removes the trusted host -id (from hosts), reading a
// code-generator code from in.
func untrustCmd(args []string, in io.Reader) error {
	fs := flag.NewFlagSet("untrust", flag.ExitOnError)
	run := fs.String("run", defaultRun, "socket directory")
	id := fs.String("id", "", "host id, as hosts prints it")
	fs.Parse(args)
	code, _ := bufio.NewReader(io.LimitReader(in, maxUnlockBody)).ReadString('\n')
	res, status, err := post(unixClient(filepath.Join(*run, UnlockSocket)), "/untrust", map[string]string{"code": strings.TrimSpace(code), "id": *id})
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return fmt.Errorf("untrust: %v", res["error"])
	}
	return nil
}

// hostsCmd lists the trusted hosts.
func hostsCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("hosts", flag.ExitOnError)
	run := fs.String("run", defaultRun, "socket directory")
	fs.Parse(args)
	res, status, err := get(unixClient(filepath.Join(*run, UnlockSocket)), "/hosts")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("hosts: %v", res["error"])
	}
	hosts, _ := res["hosts"].([]any)
	if len(hosts) == 0 {
		fmt.Fprintln(out, "No trusted hosts: every boot needs the vault passphrase and a code.")
	}
	for _, h := range hosts {
		m, _ := h.(map[string]any)
		line := fmt.Sprintf("%v", m["label"])
		if m["this"] == true {
			line += "  (this PC)"
		}
		if m["pin"] == true {
			line += "  (boot PIN)"
		}
		fmt.Fprintf(out, "%s\n    id %v\n", line, m["id"])
	}
	return nil
}
