package vault

// REQ: CRED-7, A14

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/recall"
)

// planLoginVault holds one plan-login entry, a JSON token set, and
// returns the vault and each credential field's canary by field name.
func planLoginVault(t *testing.T) (*Vault, map[string]string) {
	t.Helper()
	v, err := Create(filepath.Join(t.TempDir(), "vault"), bytes.Repeat([]byte{7}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	fields := map[string]string{}
	for _, f := range []string{"access_token", "refresh_token", "id_token"} {
		// No "sk-" prefix, so recall's own pattern scrubber does not
		// catch it and the vault redactor is what the tests see.
		fields[f] = strings.Replace(string(canary(t)), "sk-canary-", "plcanary", 1)
	}
	set := map[string]any{"account_id": "acct-x"}
	for f, c := range fields {
		set[f] = c
	}
	val, _ := json.Marshal(set)
	if err := v.Put("plan-login-codex", KindPlanLogin, val); err != nil {
		t.Fatal(err)
	}
	return v, fields
}

// A token echoed alone, outside its entry's JSON, is redacted by both
// redactors, verbatim and encoded (VAULT-REDACT, #1735).
func TestPlanLoginBareFieldIsRedacted(t *testing.T) {
	v, fields := planLoginVault(t)
	r, err := v.Redactor()
	if err != nil {
		t.Fatal(err)
	}
	h, err := v.HashRedactor()
	if err != nil {
		t.Fatal(err)
	}
	for f, c := range fields {
		for _, line := range []string{
			"refresh failed for token " + c + ": 401",
			"Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x:"+c)),
		} {
			for name, red := range map[string]func([]byte) []byte{"Redactor": r.Redact, "HashRedactor": h.Redact} {
				out := string(red([]byte(line)))
				if strings.Contains(out, c) || !strings.Contains(out, Placeholder) {
					t.Fatalf("%s left %s in %q", name, f, out)
				}
			}
		}
	}
	// Short fields are not patterns: the account ID is not redacted, so
	// ordinary text that happens to contain it survives.
	if out := string(r.Redact([]byte("account acct-x"))); out != "account acct-x" {
		t.Fatalf("short field redacted: %q", out)
	}
}

// A field split across two writes of a redacting stream is still caught.
func TestPlanLoginBareFieldIsRedactedInStream(t *testing.T) {
	v, fields := planLoginVault(t)
	r, _ := v.Redactor()
	c := fields["refresh_token"]
	var out bytes.Buffer
	w := r.Writer(&out)
	w.Write([]byte("log: " + c[:9]))
	w.Write([]byte(c[9:] + " end"))
	w.Close()
	if strings.Contains(out.String(), c) {
		t.Fatalf("stream left the token: %q", out.String())
	}
}

// Journal canary absence per field: a broker log line that echoes a bare
// token lands in the journal redacted, and stays so after replay.
func TestPlanLoginFieldAbsentFromJournal(t *testing.T) {
	v, fields := planLoginVault(t)
	r, _ := v.Redactor()
	red := func(s string) string { return string(r.Redact([]byte(s))) }
	st := &journal.MemStore{}
	e, err := journal.Open(st, nil, nil, red)
	if err != nil {
		t.Fatal(err)
	}
	for f, c := range fields {
		if err := e.RecordEgress(journal.EgressNote{Machine: "m1", Status: 401, Reason: f + " rejected: " + c}); err != nil {
			t.Fatal(err)
		}
	}
	e2, err := journal.Open(st, nil, nil, red)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, rec := range e2.Trail() {
		if rec.Egress == nil {
			continue
		}
		n++
		for f, c := range fields {
			if strings.Contains(rec.Egress.Reason, c) {
				t.Fatalf("journal holds %s: %q", f, rec.Egress.Reason)
			}
		}
	}
	if n != len(fields) {
		t.Fatalf("replayed %d egress records, want %d", n, len(fields))
	}
}

// Recall canary absence per field: text that echoes a bare token is
// stored redacted. Recall's own scrubber also drops high-entropy runs, so
// the test checks that the vault redactor, which runs first, took it.
func TestPlanLoginFieldAbsentFromRecall(t *testing.T) {
	v, fields := planLoginVault(t)
	r, _ := v.Redactor()
	ix, err := recall.Open(recall.NewMemDir(), recall.WithVaultRedactor(func(s string) string { return string(r.Redact([]byte(s))) }))
	if err != nil {
		t.Fatal(err)
	}
	for f, c := range fields {
		id, err := ix.Ingest(recall.Item{Source: recall.Source{Kind: "file", Ref: "/log/" + f}, Text: "codex said " + c})
		if err != nil {
			t.Fatal(err)
		}
		it, ok := ix.Get(id)
		if !ok {
			t.Fatalf("%s: item %s not found", f, id)
		}
		if strings.Contains(it.Text, c) || !strings.Contains(it.Text, Placeholder) {
			t.Fatalf("recall holds %s, or the vault redactor missed it: %q", f, it.Text)
		}
	}
}

// An identifier stored beside the tokens is not a pattern: #1747's Codex
// entry keeps account_id, a UUID, and the placeholder id_token it hands the
// CLI carries that ID in its base64url payload. Redacting the ID would splice
// the placeholder on every refresh and let a guest confirm a guessed ID.
func TestPlanLoginIdentifierIsNotRedacted(t *testing.T) {
	v, err := Create(filepath.Join(t.TempDir(), "vault"), bytes.Repeat([]byte{7}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	account := "0f8d6c2e-4b1a-4c7e-9a3d-5e2f1b7c8a90"
	tok := strings.Replace(string(canary(t)), "sk-canary-", "plcanary", 1)
	val, _ := json.Marshal(map[string]string{"access_token": tok, "refresh_token": tok + "r", "id_token": tok + "i", "account_id": account})
	if err := v.Put("plan-login-codex", KindPlanLogin, val); err != nil {
		t.Fatal(err)
	}
	r, _ := v.Redactor()
	h, _ := v.HashRedactor()
	// #1747's placeholderIDToken shape: header.payload.random, payload
	// holding the account ID under the provider's auth claim.
	enc := func(x any) string { b, _ := json.Marshal(x); return base64.RawURLEncoding.EncodeToString(b) }
	for exp := int64(1790000000); exp < 1790000016; exp++ {
		ph := enc(map[string]string{"alg": "none", "typ": "JWT"}) + "." +
			enc(map[string]any{"exp": exp, "https://api.openai.com/auth": map[string]string{"chatgpt_account_id": account}}) +
			".c2lnbmF0dXJlLXBsYWNlaG9sZGVy"
		for _, line := range []string{`{"id_token":"` + ph + `"}`, "account " + account} {
			for name, red := range map[string]func([]byte) []byte{"Redactor": r.Redact, "HashRedactor": h.Redact} {
				if out := string(red([]byte(line))); out != line {
					t.Fatalf("%s changed %q to %q", name, line, out)
				}
			}
		}
	}
	// The tokens beside it are still patterns.
	if out := string(r.Redact([]byte("x " + tok + "r"))); strings.Contains(out, tok) {
		t.Fatalf("token survived: %q", out)
	}
}
