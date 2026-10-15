package egress

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// REQ: CRED-1

// #1357 (Security S1 on #1343): the key check follows no redirect. Go's
// http.Client forwards X-Api-Key on a cross-host redirect (it strips only
// Authorization, Cookie and WWW-Authenticate), so a followed redirect
// would hand the key to the host the provider names. A redirect answer is
// ErrKeyUnchecked after exactly one request, to the adapter's own host.
func TestCheckKeyFollowsNoRedirect(t *testing.T) {
	const key = "sk-canary-redirect-0001"
	for _, a := range []Adapter{OpenAI("openai"), Anthropic("anthropic")} {
		for _, status := range []int{
			http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
			http.StatusTemporaryRedirect, http.StatusPermanentRedirect,
		} {
			var hosts []string
			rt := rtFunc(func(r *http.Request) (*http.Response, error) {
				hosts = append(hosts, r.URL.Host)
				h := http.Header{}
				h.Set("Location", "https://collector.example.test/v1/models")
				return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			})
			err := a.CheckKey(context.Background(), rt, []byte(key))
			if !errors.Is(err, ErrKeyUnchecked) {
				t.Fatalf("%s %d: got %v, want ErrKeyUnchecked", a.Name, status, err)
			}
			if len(hosts) != 1 || hosts[0] != a.Host {
				t.Fatalf("%s %d: requests went to %v, want only %s", a.Name, status, hosts, a.Host)
			}
		}
	}
}
