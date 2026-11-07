package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-4, CH-10, ARC-1

func act(body string) string {
	return Act("bank-login", "bank.example", "POST", "/v1/pay", []byte(body))
}

func TestActBindsTheWholeRequest(t *testing.T) {
	base := Act("bank-login", "bank.example", "POST", "/v1/pay", []byte(`{"to":"a"}`))
	for name, a := range map[string]string{
		"host":    Act("bank-login", "bank2.example", "POST", "/v1/pay", []byte(`{"to":"a"}`)),
		"method":  Act("bank-login", "bank.example", "PUT", "/v1/pay", []byte(`{"to":"a"}`)),
		"path":    Act("bank-login", "bank.example", "POST", "/v1/pay2", []byte(`{"to":"a"}`)),
		"body":    Act("bank-login", "bank.example", "POST", "/v1/pay", []byte(`{"to":"b"}`)),
		"split":   Act("bank-login", "bank.example", "POST/v1", "/pay", []byte(`{"to":"a"}`)),
		"account": Act("bank-login-b", "bank.example", "POST", "/v1/pay", []byte(`{"to":"a"}`)),
	} {
		if a == base {
			t.Errorf("%s does not change the act", name)
		}
	}
}

// The holder's client reports approval only on 204 and refusal only on
// 403: any other answer (a 200, a 400, a 500, a redirect) is an error, so
// the holder refuses rather than reading a broken checker as a yes (CH-10).
// It sends the act and whether the request reveals a secret to POST
// /redeem.
func TestRedeemerTrustsOnly204(t *testing.T) {
	dir, err := os.MkdirTemp("", "chk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	a := act("{}")
	for _, status := range []int{200, 201, 202, 204, 302, 400, 403, 404, 500, 503} {
		path := filepath.Join(dir, fmt.Sprintf("r%d.sock", status))
		ln, err := sockets.ListenPeers(path, os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		var got RedeemRequest
		var where string
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			where = r.Method + " " + r.URL.Path
			json.NewDecoder(r.Body).Decode(&got)
			w.WriteHeader(status)
		})}
		go srv.Serve(ln)
		ok, err := Redeemer(path)(context.Background(), a, true)
		srv.Close()
		switch status {
		case 204:
			if !ok || err != nil {
				t.Errorf("redeem answered 204: approved %v, err %v", ok, err)
			}
		case 403:
			if ok || err != nil {
				t.Errorf("redeem answered 403: approved %v, err %v", ok, err)
			}
		default:
			if ok || err == nil {
				t.Errorf("redeem answered %d: approved %v, err %v", status, ok, err)
			}
		}
		if where != "POST /redeem" || got != (RedeemRequest{Act: a, Secret: true}) {
			t.Errorf("redeem sent %s %+v", where, got)
		}
	}
	if ok, err := Redeemer(filepath.Join(dir, "absent.sock"))(context.Background(), a, false); ok || err == nil {
		t.Errorf("no checker: approved %v, err %v", ok, err)
	}
}
