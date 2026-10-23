package inbox

// REQ: CLK-9

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// contractGrant names the environment variable that holds a real test
// account's refresh grant, as the clerk seals it (refresh_token, client_id,
// client_secret), consented with gmail.modify only. It is set only by the
// scheduled contract run, outside CI's required checks (A22); without it the
// test is skipped.
const contractGrant = "AGENTOS_GMAIL_CONTRACT_GRANT"

// The fake's cases, against a real test account: the same calls, the same
// read-backs, and Gmail's own refusal of permanent deletion and settings
// changes under the box's grant (A22 Fences).
func TestGmailContractAgainstARealTestAccount(t *testing.T) {
	grant := os.Getenv(contractGrant)
	if grant == "" {
		t.Skip(contractGrant + " is not set: the contract runs on its schedule, not in CI")
	}
	box, err := OpenGmail(GmailBase, GmailToken, []byte(grant), netguard.New(netguard.Config{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var profile struct {
		Email string `json:"emailAddress"`
	}
	if _, err := box.call(ctx, gProfile, nil, &profile); err != nil || profile.Email == "" {
		t.Fatalf("profile: %v", err)
	}
	env := gmailEnv{box: box,
		// A mail to itself through the declared send, then read until it
		// is in the inbox.
		deliver: func(t *testing.T, raw string) {
			raw = strings.Replace(raw, "To: owner@example.test", "To: "+profile.Email, 1)
			if _, err := box.call(ctx, gSend, map[string]string{"raw": base64.RawURLEncoding.EncodeToString([]byte(raw))}, nil); err != nil {
				t.Fatalf("send: %v", err)
			}
			mid := messageID([]byte(raw))
			for range 20 {
				ms, err := box.Read(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, m := range ms {
					if messageID(m.Raw) == mid {
						return
					}
				}
				time.Sleep(3 * time.Second)
			}
			t.Fatal("the mail sent to the account did not arrive")
		},
		attempt: func(t *testing.T, method, path, body string) int {
			return attemptReal(t, grant, method, path, body)
		}}
	gmailContract(t, env)
}

// attemptReal makes a request outside the declaration with an access token
// redeemed from the same grant, so it has exactly the box's power.
func attemptReal(t *testing.T, grant, method, path, body string) int {
	t.Helper()
	var g map[string]string
	if err := json.Unmarshal([]byte(grant), &g); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"refresh_token"}}
	for k, v := range g {
		form.Set(k, v)
	}
	resp, err := http.PostForm(GmailToken, form)
	if err != nil {
		t.Fatal(err)
	}
	var tok struct {
		Access string `json:"access_token"`
	}
	err = json.NewDecoder(resp.Body).Decode(&tok)
	resp.Body.Close()
	if err != nil || tok.Access == "" {
		t.Fatalf("token: %d %v", resp.StatusCode, err)
	}
	req, err := http.NewRequest(method, GmailBase+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.Access)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}
