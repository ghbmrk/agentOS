package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/e2e/boxe2e/codexstub"
	"github.com/ghbmrk/agentos/broker/egress"
)

// agentSock is the agent machine's guest-plane socket: agentosd's
// -sockets directory, guests/, the -agent-machine id, guest.Socket.
const agentSock = "/run/agentos/guests/agent/broker.sock"

// taskBrief is the guest task's brief: synthetic, and plain text as
// provider_run requires.
const taskBrief = "agentos-e2e guest task: reply with one short line."

// The waits of the task: for the agent machine's socket after setup, and
// for one provider_run, which starts a worker and runs the plan's model.
// sockWait is a var only so a test can shorten it.
var sockWait = 3 * time.Minute

const runWait = 5 * time.Minute

// providerTask is the guest task on the Codex plan route, run as the agent
// machine's guest runs it: provider_run over the machine's own MCP socket
// (ASSUMPTIONS E12), twice. The first run is admitted as the plan's probe,
// with no usage reading yet; the second only once the first run's quota
// reading landed, so a second run refused as pool-at-reserve says it never
// did. Each run passes only when the tool answers without error, the
// answer carries codexstub.Answer, the whole result carries no issued token
// or other canary, and the stub saw a new model call and refused none. A
// box that offers no provider_run, or refuses the first run as unqualified,
// fails with the not-driven text naming the work item that serves it;
// every other outcome is FAIL.
func (d *driver) providerTask() error {
	if d.stub == nil {
		return errors.New("no plan stub")
	}
	sock := d.guestSock
	if sock == "" {
		sock = agentSock
	}
	err := until(sockWait, func() (bool, error) {
		_, err := os.Lstat(sock)
		return err == nil, err
	})
	if err != nil {
		return fmt.Errorf("agent machine's guest socket never appeared: %w; %s", err, agentDiag(d.stub.Tokens()))
	}
	c := &mcpClient{sock: sock, tokens: d.stub.Tokens}
	if _, err := c.call("initialize", map[string]any{"protocolVersion": "2025-06-18",
		"capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "box-e2e", "version": "1"}}); err != nil {
		return err
	}
	raw, err := c.call("tools/list", map[string]any{})
	if err != nil {
		return err
	}
	var list struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return fmt.Errorf("tools/list: %v", err)
	}
	offered := false
	for _, t := range list.Tools {
		offered = offered || t.Name == "provider_run"
	}
	if !offered {
		return errors.New(notDriven + " no provider_run offered to agent machine: no Codex worker image and agentosd has no -worker-image (#1721)")
	}
	for run := 1; run <= 2; run++ {
		if err := d.providerRun(c, run); err != nil {
			return err
		}
	}
	return nil
}

// providerRun is run number run of the guest task's provider_run.
func (d *driver) providerRun(c *mcpClient, run int) error {
	route := egress.Codex()
	before, refused := d.stub.Hits()["responses"], d.stub.Refused()
	w := d.watchRun()
	raw, err := c.call("tools/call", map[string]any{"name": "provider_run",
		"arguments": map[string]string{"provider": route.Provider, "brief": taskBrief, "task_class": "code"}})
	out := w.stop()
	if err != nil {
		return err
	}
	if leaks(raw, d.stub.Tokens()) {
		return fmt.Errorf("provider_run %d's result carried a provider token", run)
	}
	var res struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &res); err != nil || len(res.Content) == 0 {
		return fmt.Errorf("provider_run %d: unreadable result (%v)", run, err)
	}
	text := res.Content[0].Text
	if res.IsError {
		switch {
		case run == 1 && strings.HasPrefix(text, "provider_run: unqualified:"):
			return errors.New(notDriven + " provider_run refuses the Codex route as unqualified until its qualification record (#809) lands")
		case run > 1 && strings.HasPrefix(text, "provider_run: pool-at-reserve:"):
			return errors.New("the plan's usage reading never landed: provider_run 2 was refused as pool-at-reserve")
		}
		// The refusal is a closed reason only (CRED-5); what the run's
		// CLI wrote says why (#1701, ASSUMPTIONS E14).
		return fmt.Errorf("provider_run %d refused: %s; stub %v refused %d; %s", run, short(text),
			d.stub.Hits(), d.stub.Refused(), d.workerDiag("result", out))
	}
	hits := d.stub.Hits()["responses"]
	switch {
	case !strings.Contains(text, codexstub.Answer):
		return fmt.Errorf("provider_run %d's answer is not the model's: %s", run, short(text))
	case hits <= before:
		return fmt.Errorf("provider_run %d answered without a model call at the provider: stub %v", run, d.stub.Hits())
	case d.stub.Refused() != refused:
		return fmt.Errorf("the provider refused %d calls during provider_run %d: stub %v", d.stub.Refused()-refused, run, d.stub.Hits())
	}
	return nil
}

// leaks reports whether raw, a whole tools/call result, carries an issued
// token, or a canary other than the model's answer, anywhere: in its raw
// bytes or in any key or string it decodes to, every content item and
// field included. An id_token's header and payload carry no canary, so
// tokens must list every id_token issued.
func leaks(raw []byte, tokens []string) bool {
	texts := []string{string(raw)}
	var v any
	if json.Unmarshal(raw, &v) == nil {
		texts = strs(texts, v)
	}
	for _, s := range texts {
		// Answer itself starts with Canary; any other canary is a token.
		if strings.Contains(strings.ReplaceAll(s, codexstub.Answer, ""), codexstub.Canary) {
			return true
		}
		for _, t := range tokens {
			if t != "" && strings.Contains(s, t) {
				return true
			}
		}
	}
	return false
}

// strs appends every key and string in v to out.
func strs(out []string, v any) []string {
	switch v := v.(type) {
	case string:
		out = append(out, v)
	case []any:
		for _, e := range v {
			out = strs(out, e)
		}
	case map[string]any:
		for k, e := range v {
			out = strs(append(out, k), e)
		}
	}
	return out
}

// hasImage reports whether agentosd registers image name: an -image flag
// whose value is name=dir.
func (d *driver) hasImage(name string) (bool, error) {
	argv := d.agentosdArgv
	if argv == nil {
		argv = unitArgv
	}
	args, err := argv()
	if err != nil {
		return false, err
	}
	for i, a := range args {
		v, ok := strings.CutPrefix(strings.TrimLeft(a, "-"), "image=")
		if !ok && strings.TrimLeft(a, "-") == "image" && i+1 < len(args) {
			v, ok = args[i+1], true
		}
		if ok && strings.HasPrefix(v, name+"=") {
			return true, nil
		}
	}
	return false, nil
}

// unitArgv is agentosd's command line as its unit gives it, drop-ins
// included.
func unitArgv() ([]string, error) {
	out, err := command("systemctl", "show", "-p", "ExecStart", "--value", "agentosd.service").Output()
	if err != nil {
		return nil, fmt.Errorf("agentosd's command line: %w", err)
	}
	return execArgv(string(out))
}

// execArgv is the argv of a unit's ExecStart as systemctl show prints it.
func execArgv(show string) ([]string, error) {
	_, after, ok := strings.Cut(show, "argv[]=")
	if !ok {
		return nil, errors.New("agentosd's command line: no argv")
	}
	argv, _, _ := strings.Cut(after, " ;")
	return strings.Fields(argv), nil
}

// short is a guest-facing text cut to one short line for the console.
func short(s string) string {
	if s = oneLine(s); len(s) > logLineMax {
		s = s[:logLineMax]
	}
	return s
}

// agentDiag says why the agent machine has no socket: agentosd's journal
// lines about agent machines, cut short, with any issued token cut out.
func agentDiag(tokens []string) string {
	logs, _ := command("journalctl", "-b", "-o", "cat", "--no-pager", "-u", "agentosd.service").Output()
	var keep []string
	for _, l := range strings.Split(string(logs), "\n") {
		if strings.Contains(l, "agent machine") || strings.Contains(l, "worker tools") {
			keep = append(keep, l)
		}
	}
	return "diag: agentosd: " + redactLog(strings.Join(keep, "\n"), 6, append(tokens, codexstub.Canary)...)
}

// mcpClient speaks the guest plane's MCP (JSON-RPC 2.0 over POST /mcp) on
// a machine's unix socket, as the guest's MCP bridge does. tokens is the
// stub's issued set, cut out of every error the client quotes.
type mcpClient struct {
	sock   string
	id     int
	tokens func() []string
}

func (c *mcpClient) call(method string, params any) (json.RawMessage, error) {
	c.id++
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	hc := &http.Client{Timeout: runWait, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", c.sock)
		},
	}}
	resp, err := hc.Post("http://localhost/mcp", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s: %s", method, c.redact(err.Error()))
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %d %v", method, resp.StatusCode, err)
	}
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%s: unreadable answer", method)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("%s: error %d %s", method, out.Error.Code, c.redact(out.Error.Message))
	}
	return out.Result, nil
}

// redact is s cut to one short line with every issued token and canary
// cut out, as agentDiag cuts the journal (ASSUMPTIONS E8).
func (c *mcpClient) redact(s string) string {
	var tokens []string
	if c.tokens != nil {
		tokens = c.tokens()
	}
	return short(redactLog(oneLine(s), 1, append(tokens, codexstub.Canary)...))
}
