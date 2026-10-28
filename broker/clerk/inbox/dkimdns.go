package inbox

import (
	"context"
	"encoding/base64"
	"strings"
	"sync"
	"time"
)

// The mail clerk's own key lookups (MAIL-world-a, D-154 rule 5): DKIM key
// records come from the clerk's own DNS queries, through the process's
// netguard resolver, never from the main side.

// Lookup bounds. A name past a bound is not looked up, so its signatures
// fail (dkim-none or dkim-fail): fail closed. Vars for tests.
var (
	dkimPerMail       = 2                // names looked up per mail
	dkimPerRead       = 400              // names looked up per read
	dkimLookupWait    = 5 * time.Second  // one lookup
	dkimReadWait      = 30 * time.Second // every lookup of one read
	dkimMaxTXT        = 8 << 10          // TXT bytes kept per name
	dkimLookupsAtOnce = 8                // lookups in flight at once
)

// TXTResolver is the part of *net.Resolver LookupDKIM uses.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// KeyNames is the names a read's mails look up: each mail's first
// dkimPerMail names (DKIMNames), each once across the read.
func KeyNames(raws [][]byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range raws {
		ns := DKIMNames(raw)
		if len(ns) > dkimPerMail {
			ns = ns[:dkimPerMail]
		}
		for _, n := range ns {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out
}

// LookupDKIM looks up each of names (DKIMNames' form) as a rooted name
// through r, so no search list applies, and returns the p= of each name
// whose answer holds exactly one usable key record (keyRecord), keyed by the
// name as given: the map VerifyDKIM reads. Only the first dkimPerRead valid
// names are looked up; a name over 253 bytes or with a bad label is not. A
// failed lookup leaves its name absent and is not retried.
func LookupDKIM(ctx context.Context, r TXTResolver, names []string) map[string]string {
	ctx, cancel := context.WithTimeout(ctx, dkimReadWait)
	defer cancel()
	var todo []string
	for _, n := range names {
		if len(todo) == dkimPerRead {
			break
		}
		if dnsName(n) && !contains(todo, n) {
			todo = append(todo, n)
		}
	}
	out := map[string]string{}
	var mu sync.Mutex
	work := make(chan string)
	var wg sync.WaitGroup
	for range min(dkimLookupsAtOnce, len(todo)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range work {
				if p, ok := lookupOne(ctx, r, n); ok {
					mu.Lock()
					out[n] = p
					mu.Unlock()
				}
			}
		}()
	}
feed:
	for _, n := range todo {
		select {
		case work <- n:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()
	return out
}

// lookupOne is one name's lookup under the per-lookup bound.
func lookupOne(ctx context.Context, r TXTResolver, name string) (string, bool) {
	if ctx.Err() != nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(ctx, dkimLookupWait)
	defer cancel()
	type answer struct {
		txt []string
		err error
	}
	got := make(chan answer, 1)
	go func() {
		txt, err := r.LookupTXT(ctx, name+".")
		got <- answer{txt, err}
	}()
	var a answer
	select {
	case a = <-got:
	case <-ctx.Done():
		return "", false // a resolver that ignores its context does not hold the read
	}
	if a.err != nil {
		return "", false
	}
	size := 0
	for _, t := range a.txt {
		size += len(t)
	}
	if size > dkimMaxTXT {
		return "", false
	}
	return keyRecord(a.txt)
}

// dnsName reports whether n is at most 253 bytes of labels of 1 to 63
// letters, digits, hyphens or underscores (a selector or _domainkey).
func dnsName(n string) bool {
	if n == "" || len(n) > 253 {
		return false
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > 63 {
			return false
		}
		for _, c := range []byte(l) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// keyRecord is the p= of the one DKIM key record among txt, each one TXT
// record's strings joined (as net.Resolver gives them). It is kept only when
// exactly one record parses as a key record, and that record has v=DKIM1
// first if any v=, k=rsa if any k=, sha256 among any h=, email or * among
// any s=, no y flag in t= (RFC 6376 section 3.6.1: a test key counts as
// unsigned), and a non-empty base64 p= (an empty one is revoked).
func keyRecord(txt []string) (string, bool) {
	var recs [][][2]string
	for _, t := range txt {
		if tags, ok := keyTags(t); ok {
			recs = append(recs, tags)
		}
	}
	if len(recs) != 1 {
		return "", false
	}
	var p string
	for i, kv := range recs[0] {
		k, v := kv[0], kv[1]
		switch k {
		case "v":
			if i != 0 || v != "DKIM1" {
				return "", false
			}
		case "k":
			if v != "rsa" {
				return "", false
			}
		case "h":
			if !listHas(v, "sha256") {
				return "", false
			}
		case "s":
			if !listHas(v, "email") && !listHas(v, "*") {
				return "", false
			}
		case "t":
			if listHas(v, "y") {
				return "", false
			}
		case "p":
			p = v
		}
	}
	if p == "" {
		return "", false
	}
	if _, err := base64.StdEncoding.DecodeString(p); err != nil {
		return "", false
	}
	return p, true
}

// keyTags parses a key record's tag list (RFC 6376 section 3.2), in order,
// with all whitespace removed from each value: ok only when every part is
// tag=value, no tag repeats, and a p= tag is present.
func keyTags(rec string) ([][2]string, bool) {
	var out [][2]string
	hasP := false
	for _, part := range strings.Split(rec, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, false
		}
		for _, kv := range out {
			if kv[0] == k {
				return nil, false
			}
		}
		hasP = hasP || k == "p"
		out = append(out, [2]string{k, strings.Join(strings.Fields(v), "")})
	}
	return out, hasP
}

// listHas reports whether the colon-separated list v holds x.
func listHas(v, x string) bool {
	for _, e := range strings.Split(v, ":") {
		if e == x {
			return true
		}
	}
	return false
}
