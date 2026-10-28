package inbox

import (
	_ "embed"
	"errors"
	"fmt"
	"strings"
)

// The shipped provider tables (MAIL-world-a): VRB-2's provider table, and
// per mailbox provider its authserv-id and security senders, which the
// alert guard needs. They ship in the binary, so the clerk takes none of
// them from the main side (D-154).

//go:embed providers.txt
var providersTxt []byte

// Providers is a parsed provider tables file (providers.txt's form).
type Providers struct {
	esp      []string
	authServ map[string]string   // key to authserv-id
	security map[string][]string // key to security senders
}

// Shipped is the binary's own tables. A bad line panics at init, so no
// test binary of this package starts with one.
var Shipped = mustProviders(providersTxt)

func mustProviders(b []byte) *Providers {
	p, err := ParseProviders(b)
	if err != nil {
		panic(err)
	}
	return p
}

// ParseProviders reads a tables file: blank lines and # comments aside,
// each line is "esp <domain>", "authserv <key> <id>" or
// "security <key> <address-or-domain>", ending with "-- <source>". Keys and
// domains are kept in A-labels; a key repeated on authserv lines is an
// error.
func ParseProviders(b []byte) (*Providers, error) {
	p := &Providers{authServ: map[string]string{}, security: map[string][]string{}}
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		bad := func(why string) error { return fmt.Errorf("inbox: providers line %d: %s", i+1, why) }
		entry, source, ok := strings.Cut(line, " -- ")
		if !ok || strings.TrimSpace(source) == "" {
			return nil, bad("no source")
		}
		f := strings.Fields(entry)
		switch {
		case len(f) == 2 && f[0] == "esp":
			d := alabel(f[1])
			if d == "" || !strings.Contains(d, ".") {
				return nil, bad("not a domain")
			}
			p.esp = append(p.esp, d)
		case len(f) == 3 && f[0] == "authserv":
			k := providerKey(f[1])
			if k == "" || f[2] == "" {
				return nil, bad("bad key")
			}
			if _, dup := p.authServ[k]; dup {
				return nil, bad("repeated key")
			}
			p.authServ[k] = f[2]
		case len(f) == 3 && f[0] == "security":
			k := providerKey(f[1])
			if k == "" || !strings.Contains(f[2], ".") {
				return nil, bad("bad key or sender")
			}
			p.security[k] = append(p.security[k], strings.ToLower(f[2]))
		default:
			return nil, bad("not an esp, authserv or security line")
		}
	}
	for k := range p.security {
		if _, ok := p.authServ[k]; !ok {
			return nil, errors.New("inbox: providers: security senders for " + k + " with no authserv line")
		}
	}
	return p, nil
}

// providerKey is a key in A-labels: an API name (one label) or a host
// suffix.
func providerKey(k string) string { return alabel(k) }

// Table is VRB-2's provider table.
func (p *Providers) Table() []string { return append([]string(nil), p.esp...) }

// For is the authserv-id and security senders of the provider serving an
// account: by its API when api is set (an exact key with no dot), else by
// its IMAP host, whose A-label form must be a key with a dot or end with
// "." and one, so evilgmail.com never matches gmail.com. The longest key
// that matches wins. An unknown provider gets "" and none, so the alert
// guard is off for it.
func (p *Providers) For(api, host string) (authServ string, security []string) {
	key := ""
	if api != "" {
		if a := providerKey(api); a != "" && !strings.Contains(a, ".") {
			if _, ok := p.authServ[a]; ok {
				key = a
			}
		}
	} else if h := alabel(host); h != "" {
		for k := range p.authServ {
			if strings.Contains(k, ".") && (h == k || strings.HasSuffix(h, "."+k)) && len(k) > len(key) {
				key = k
			}
		}
	}
	if key == "" {
		return "", nil
	}
	return p.authServ[key], append([]string(nil), p.security[key]...)
}
