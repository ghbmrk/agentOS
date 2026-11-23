package skill

// REQ: CAP-5

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// noteBroker answers every plan with the given state text, isError flag and,
// after it, one note as its own content item, as the guest plane carries an
// untold step-snapshot note (guest/mcp.go, SR2-3s).
func noteBroker(text string, isErr bool, note string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID,
			"result": map[string]any{"content": []map[string]string{
				{"type": "text", "text": text}, {"type": "text", "text": note}}, "isError": isErr}})
	}))
}

// The text after the broker's first content item reaches the agent: the
// skill's tool result carries it as its own content item after the JSON
// result, which stays whole, whether the step succeeded or the broker
// refused it (#1568, SR2-3s).
func TestSkillCarriesBrokerNotes(t *testing.T) {
	const note = "note: the step snapshot was not saved"
	done, _ := json.Marshal(State{RequestID: "x", State: Succeeded})
	for _, tc := range []struct {
		name, text, status string
		isErr              bool
	}{
		{"succeeded", string(done), "done", false},
		{"refused", "plan refused", "stopped", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sk := report()
			os.MkdirAll(filepath.Join(dir, SkillsNS), 0o755)
			os.WriteFile(filepath.Join(dir, sk.Path()), sk.Encode(), 0o644)
			bs := noteBroker(tc.text, tc.isErr, note)
			defer bs.Close()
			srv := httptest.NewServer(&Server{Dir: dir, Effects: &MCPEffects{Client: bs.Client(), URL: bs.URL}})
			defer srv.Close()

			call := rpc(t, srv.URL, "tools/call", map[string]any{"name": "skill_" + sk.ID,
				"arguments": map[string]any{"run_id": "r1", "to": "bo@example.test", "week": 7}})
			content := call["result"].(map[string]any)["content"].([]any)
			var res Result
			if err := json.Unmarshal([]byte(content[0].(map[string]any)["text"].(string)), &res); err != nil || res.Status != tc.status {
				t.Fatalf("result %v", content[0])
			}
			want := 2 // one note per step run
			if tc.isErr {
				want = 1 // the run stops at the first step
			}
			if len(content) != 1+want {
				t.Fatalf("content %v: want the JSON result then %d notes", content, want)
			}
			for _, c := range content[1:] {
				if c.(map[string]any)["text"] != note {
					t.Fatalf("note %v", c)
				}
			}
		})
	}
}
