// Command agentos-guest-bridge runs inside an agent machine as its first
// process (PLAN P1-7). It is guest code: untrusted, replaceable by a root
// guest, and trusted by nothing in the broker (ARC-7). Its jobs:
//
//   - Start the guest runtime (argv after "--") with a fresh guest-local
//     gateway token, and reap orphaned processes, as PID 1 must.
//   - Serve 127.0.0.1:18080 inside the machine and pass every request to the
//     machine's broker socket (/run/agentos/broker.sock), because guests
//     such as OpenClaw speak HTTP to a URL, not to a Unix socket. Model
//     calls (/model/...) and broker tools (/mcp) go this way (ARC-6 (a), (b)).
//   - Serve the tree's compiled skills and procedures as MCP tools on
//     /skills/mcp (CAP-5, package skill). A skill runs here, in the guest,
//     and sends each step to the broker as an ordinary effect_request, so
//     it carries no authority the guest lacks.
//   - Keep the tree directory a copy of the box's adopted procedures,
//     skills and context, fetched with the broker tool managed_tree, which
//     answers only a private machine (W4, tree.go).
//   - Fetch owner messages from the broker (/owner/next), hand each to the
//     guest's own inbound API (OpenAI-compatible chat completions on the
//     gateway), and post the answer back (/owner/reply) (ARC-6 (c)).
//
// Usage: agentos-guest-bridge [flags] -- runtime args...
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/skill"
)

func main() {
	sock := flag.String("socket", "/run/agentos/broker.sock", "the machine's broker socket")
	listen := flag.String("listen", "127.0.0.1:18080", "where the guest reaches the broker")
	gateway := flag.String("gateway", "http://127.0.0.1:18789", "the guest's inbound API")
	model := flag.String("inbound-model", "openclaw", "model name the inbound API expects")
	tree := flag.String("tree", "/etc/agentos/tree", "the managed tree's skills and procedures (CAP-5)")
	treeEvery := flag.Duration("tree-sync", 30*time.Second, "how often to fetch the managed tree from the broker (W4); 0 never")
	flag.Parse()

	var b [24]byte
	rand.Read(b[:])
	token := hex.EncodeToString(b[:]) // guest-local: authenticates the bridge to the gateway, nothing else
	broker := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", *sock)
		},
	}}

	l, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	go http.Serve(l, routes(broker, *tree))

	var child *exec.Cmd
	if args := flag.Args(); len(args) > 0 {
		if child, err = startRuntime(args, token); err != nil {
			log.Fatal(err)
		}
	}
	go owner(broker, *gateway, *model, token)
	if *treeEvery > 0 {
		go syncTree(context.Background(), broker, *tree, *treeEvery)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		s := <-sig
		if child != nil {
			child.Process.Signal(s)
		}
	}()
	reap(child)
}

// runtimeVars are the variables the runtime gets from the bridge's own
// environment, by name: PATH (the OCI spec's) and each one
// guest/openclaw/launch.json sets. Anything else the bridge was given
// stays with it (P3-4b-3r-env).
var runtimeVars = []string{
	"PATH", "HOME",
	"OPENCLAW_CONFIG_PATH", "OPENCLAW_CONFIG_READONLY", "OPENCLAW_NO_AUTO_UPDATE",
	"OPENCLAW_DISABLE_BONJOUR", "OPENCLAW_CLAWHUB_URL", "DO_NOT_TRACK",
}

// startRuntime starts the guest runtime with runtimeVars and the gateway
// token as its whole environment.
func startRuntime(args []string, token string) (*exec.Cmd, error) {
	env := []string{"OPENCLAW_GATEWAY_TOKEN=" + token}
	for _, k := range runtimeVars {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	child := exec.Command(args[0], args[1:]...)
	child.Env = env
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	return child, child.Start()
}

// routes forwards the guest's requests to the broker and serves the
// tree's skills, whose steps go back to the broker's own effect_request.
func routes(broker *http.Client, tree string) http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(&url.URL{Scheme: "http", Host: "broker.localhost"})
			r.Out.Host = "broker.localhost"
		},
		Transport:     broker.Transport,
		FlushInterval: -1, // model streams flow through as they arrive
	}
	mux := http.NewServeMux()
	mux.Handle("/", rp)
	mux.Handle("/skills/mcp", &skill.Server{Dir: tree,
		Effects: &skill.MCPEffects{Client: broker, URL: "http://broker.localhost/mcp"}})
	return mux
}

// reap waits for every child, as PID 1 must, and exits with the runtime.
func reap(child *exec.Cmd) {
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, 0, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			if child == nil {
				select {} // nothing to run: just bridge
			}
			os.Exit(1)
		}
		if child != nil && pid == child.Process.Pid {
			log.Printf("runtime exited: %v", ws)
			os.Exit(ws.ExitStatus())
		}
	}
}

// owner moves owner messages from the broker into the guest and answers
// back. Failures wait and retry: an unanswered message is handed out again.
func owner(broker *http.Client, gateway, model, token string) {
	for {
		if err := ownerOnce(broker, gateway, model, token); err != nil {
			log.Printf("owner message: %v", err)
			time.Sleep(2 * time.Second)
		}
	}
}

func ownerOnce(broker *http.Client, gateway, model, token string) error {
	resp, err := broker.Get("http://broker.localhost/owner/next")
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("next: %s", resp.Status)
	}
	var msg struct{ ID, Text string }
	if err := json.Unmarshal(body, &msg); err != nil {
		return err
	}
	// The runtime may still be starting (OpenClaw takes about 27 s cold):
	// keep this message and retry, rather than wait out its lease.
	var answer string
	for wait := time.Second; ; wait = min(2*wait, 30*time.Second) {
		if answer, err = ask(gateway, model, token, msg.Text); err == nil {
			break
		}
		log.Printf("owner message %s: %v; retrying", msg.ID, err)
		time.Sleep(wait)
	}
	out, _ := json.Marshal(map[string]string{"id": msg.ID, "text": answer})
	resp, err = broker.Post("http://broker.localhost/owner/reply", "application/json", bytes.NewReader(out))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("reply: %s", resp.Status)
	}
	return nil
}

// ask sends one owner message to the guest's inbound API and returns its
// answer text.
func ask(gateway, model, token, text string) (string, error) {
	req, _ := json.Marshal(map[string]any{
		"model": model, "user": "owner",
		"messages": []map[string]string{{"role": "user", "content": text}},
	})
	r, _ := http.NewRequest("POST", gateway+"/v1/chat/completions", bytes.NewReader(req))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Minute}).Do(r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&out) != nil || len(out.Choices) == 0 {
		return "", fmt.Errorf("inbound API: %s", resp.Status)
	}
	return out.Choices[0].Message.Content, nil
}
