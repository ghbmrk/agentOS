// Command guest is the clean-room stand-in for cleanroom's integration
// test. It plays a hostile clean room: before building, it tries to reach
// everything a clean room must not see, and puts what it found in its
// result, so the test can check both the probes and the published output.
//
//	guest idle    write $CANARY to /work/canary (a private machine's data), then wait
//	guest build   probe $PROBES (paths) and $SOCKS (sockets), read the hint,
//	              submit a result holding the hint and the probe report, then wait
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const sock = "/run/agentos/broker.sock"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "idle" {
		os.MkdirAll("/work", 0o755)
		os.WriteFile("/work/canary", []byte(os.Getenv("CANARY")), 0o600)
		select {}
	}
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	var hint string
	for i := 0; i < 200; i++ { // the socket can lag the start
		if code, body := do(c, "GET", "/cleanroom/hint", nil); code == 200 {
			hint = body
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	var rep []string
	paths := append(strings.Split(os.Getenv("PROBES"), ":"), "/work/canary")
	for _, p := range paths {
		if p == "" {
			continue
		}
		b, err := os.ReadFile(p)
		switch {
		case err == nil:
			rep = append(rep, "read "+p+" READ "+string(b))
		case os.IsNotExist(err):
			rep = append(rep, "read "+p+" absent")
		default:
			rep = append(rep, "read "+p+" denied")
		}
	}
	for _, p := range strings.Split(os.Getenv("SOCKS"), ":") {
		if p == "" {
			continue
		}
		if conn, err := net.DialTimeout("unix", p, 2*time.Second); err == nil {
			conn.Close()
			rep = append(rep, "dial "+p+" CONNECTED")
		} else {
			rep = append(rep, "dial "+p+" refused")
		}
	}
	for _, p := range []string{"/mcp", "/owner/next", "/owner/reply"} {
		code, _ := do(c, "POST", p, []byte(`{}`))
		rep = append(rep, fmt.Sprintf("svc %s %d", p, code))
	}
	if err := os.WriteFile("/run/agentos/x", []byte("y"), 0o600); err == nil {
		rep = append(rep, "write /run/agentos WROTE")
	} else {
		rep = append(rep, "write /run/agentos refused")
	}
	if conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 2*time.Second); err == nil {
		conn.Close()
		rep = append(rep, "net tcp CONNECTED")
	} else {
		rep = append(rep, "net tcp refused")
	}
	res, _ := json.Marshal(map[string]any{
		"files":    map[string]string{"hint.json": hint, "report.txt": strings.Join(rep, "\n") + "\n"},
		"fixtures": map[string]int{"passed": 1},
	})
	for i := 0; i < 20; i++ {
		if code, _ := do(c, "POST", "/cleanroom/result", res); code == 200 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {}
}

func do(c *http.Client, method, path string, body []byte) (int, string) {
	req, _ := http.NewRequest(method, "http://broker"+path, bytes.NewReader(body))
	resp, err := c.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
