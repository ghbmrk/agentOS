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

// providerTask is one guest task on the Codex plan route, run as the agent
// machine's guest runs it: provider_run over the machine's own MCP socket
// (ASSUMPTIONS E12). It passes only when the tool answers without error,
// the answer carries codexstub.Answer and no issued token, and the stub
// saw a new model call and refused none. A box that offers no provider_run,
// or refuses it as unqualified, fails with the not-driven text naming the
// work item that serves it; every other outcome is FAIL.
func (d *driver) providerTask() error {
	if d.stub == nil {
		return errors.New("no plan stub")
	}
	sock := d.guestSock
	if sock == "" {
		sock = agentSock
	}
	err := until(sockWait, func() (bool, error) {
		_, err := os.Stat(sock)
		return err == nil, err
	})
	if err != nil {
		return fmt.Errorf("the agent machine's guest socket never appeared: %w; %s", err, agentDiag(d.stub.Tokens()))
	}
	c := &mcpClient{sock: sock}
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
		return errors.New(notDriven + " the agent machine is offered no provider_run: the box has no Codex worker image and agentosd no -worker-image (#1721)")
	}
	route := egress.Codex()
	before, refused := d.stub.Hits()["responses"], d.stub.Refused()
	raw, err = c.call("tools/call", map[string]any{"name": "provider_run",
		"arguments": map[string]string{"provider": route.Provider, "brief": taskBrief, "task_class": "code"}})
	if err != nil {
		return err
	}
	var res struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &res); err != nil || len(res.Content) == 0 {
		return fmt.Errorf("provider_run: unreadable result (%v)", err)
	}
	text := res.Content[0].Text
	// Answer itself starts with Canary; any other canary is an issued token.
	if strings.Contains(strings.ReplaceAll(text, codexstub.Answer, ""), codexstub.Canary) {
		return errors.New("provider_run's answer carried a provider token")
	}
	if res.IsError {
		if strings.HasPrefix(text, "provider_run: unqualified:") {
			return errors.New(notDriven + " provider_run refuses the Codex route as unqualified until its qualification record (#809) and the image's pinned version (#1877) land")
		}
		return errors.New("provider_run refused: " + short(text))
	}
	hits := d.stub.Hits()["responses"]
	switch {
	case !strings.Contains(text, codexstub.Answer):
		return errors.New("provider_run's answer is not the model's: " + short(text))
	case hits <= before:
		return fmt.Errorf("provider_run answered without a model call at the provider: stub %v", d.stub.Hits())
	case d.stub.Refused() != refused:
		return fmt.Errorf("the provider refused %d calls during the task: stub %v", d.stub.Refused()-refused, d.stub.Hits())
	}
	return nil
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
// a machine's unix socket, as the guest's MCP bridge does.
type mcpClient struct {
	sock string
	id   int
}

func (c *mcpClient) call(method string, params any) (json.RawMessage, error) {
	c.id++
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	hc := &http.Client{Timeout: runWait, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", c.sock)
		},
	}}
	resp, err := hc.Post("http://guest/mcp", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", method, err)
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
		return nil, fmt.Errorf("%s: error %d %s", method, out.Error.Code, short(out.Error.Message))
	}
	return out.Result, nil
}
