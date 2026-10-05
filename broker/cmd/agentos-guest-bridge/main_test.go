package main

// REQ: CAP-5

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/skill"
)

// CAP-5, K1: end to end through the bridge. The guest calls a skill on
// /skills/mcp; each step reaches the broker's /mcp effect_request over the
// machine's socket as an ordinary effect request, and every other path
// still goes to the broker unchanged.
func TestBridgeRunsSkillThroughBroker(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "b.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var paths []string
	var effects []skill.Effect
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		paths = append(paths, r.URL.Path)
		if r.URL.Path != "/mcp" {
			w.Write([]byte("ok"))
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Params struct {
				Name      string       `json:"name"`
				Arguments skill.Effect `json:"arguments"`
			} `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Params.Name != "effect_request" {
			t.Errorf("tool %q", req.Params.Name)
		}
		effects = append(effects, req.Params.Arguments)
		st, _ := json.Marshal(skill.State{RequestID: req.Params.Arguments.RequestID, State: skill.Succeeded})
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID,
			"result": map[string]any{"content": []map[string]string{{"type": "text", "text": string(st)}}}})
	})}
	go srv.Serve(l)
	defer srv.Close()

	tree := t.TempDir()
	sk := &skill.Skill{Version: skill.Version, Kind: skill.KindSkill, Runs: 3,
		Slots: []skill.Slot{{Name: "to", Type: skill.Email, Max: 64}},
		Steps: []skill.Step{
			{Account: "mail", Action: "draft.create", Params: map[string]skill.Node{"subject": {Lit: json.RawMessage(`"Weekly report"`)}, "to": {Slot: "to"}}},
			{Account: "mail", Action: "message.send", Recipients: []skill.Node{{Slot: "to"}}},
		}}
	sk.ID = "k" + sk.Shape() // the bridge offers a file only under its own shape
	os.MkdirAll(filepath.Join(tree, skill.SkillsNS), 0o755)
	os.WriteFile(filepath.Join(tree, sk.Path()), sk.Encode(), 0o644)

	broker := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	bridge := httptest.NewServer(routes(broker, tree))
	defer bridge.Close()

	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "skill_" + sk.ID, "arguments": map[string]any{"run_id": "r1", "to": "ann@example.test"}}})
	resp, err := http.Post(bridge.URL+"/skills/mcp", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Result struct {
			Content []struct{ Text string } `json:"content"`
		} `json:"result"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if len(out.Result.Content) != 1 || !strings.Contains(out.Result.Content[0].Text, `"done"`) {
		t.Fatalf("result %+v", out)
	}
	if r, err := http.Get(bridge.URL + "/v1/models"); err != nil || r.StatusCode != 200 {
		t.Fatalf("proxy: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(effects) != 2 || effects[1].RequestID != "skill-"+sk.ID+"-r1-2" || effects[1].Recipients[0] != "ann@example.test" {
		t.Fatalf("broker saw %+v", effects)
	}
	if paths[len(paths)-1] != "/v1/models" {
		t.Fatalf("paths %v", paths)
	}
}
