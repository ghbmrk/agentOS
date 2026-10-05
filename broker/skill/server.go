package skill

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
)

// Server is an MCP tool server (streamable HTTP, one JSON response per
// POST: the subset broker/guest serves) that offers each valid skill in
// Dir as a tool named skill_<id>, and runs it through Effects. It is guest
// code: agentos-guest-bridge serves it inside the agent machine, so it
// holds nothing the guest does not. Files that fail Decode are not offered.
type Server struct {
	Dir     string
	Effects Effects
}

// ToolPrefix starts every skill tool's name.
const ToolPrefix = "skill_"

const maxBody = 1 << 20

// List returns the valid skills in Dir (skills and procedures), sorted by
// ID.
func (s *Server) List() []*Skill {
	var out []*Skill
	for _, ns := range []string{SkillsNS, ProceduresNS} {
		ents, _ := os.ReadDir(filepath.Join(s.Dir, ns))
		for _, e := range ents {
			if sk := s.load(ns, strings.TrimSuffix(e.Name(), ".json")); sk != nil {
				out = append(out, sk)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// load reads and validates one file; nil when absent or invalid, or when
// its ID is not its file name.
func (s *Server) load(ns, id string) *Skill {
	if !idRE.MatchString(id) {
		return nil
	}
	f, err := os.Open(filepath.Join(s.Dir, ns, id+".json"))
	if err != nil {
		return nil
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxFile+1))
	if err != nil {
		return nil
	}
	sk, err := Decode(b)
	if err != nil || sk.ID != id || sk.Path() != ns+"/"+id+".json" {
		return nil
	}
	return sk
}

func (s *Server) find(id string) *Skill {
	if sk := s.load(SkillsNS, id); sk != nil {
		return sk
	}
	return s.load(ProceduresNS, id)
}

// Tool is a skill's MCP tool definition.
func Tool(sk *Skill) map[string]any {
	props := map[string]any{
		"run_id": map[string]any{"type": "string", "description": "A new id for this run (letters, digits, _; at most 32). Reuse it only to retry the same run."},
	}
	req := []string{"run_id"}
	for _, sl := range sk.Slots {
		p := map[string]any{}
		switch sl.Type {
		case Text:
			p["type"], p["maxLength"] = "string", sl.Max
		case Email:
			p["type"], p["format"], p["maxLength"] = "string", "email", sl.Max
		case Number:
			p["type"] = "number"
		case Bool:
			p["type"] = "boolean"
		case JSON:
			p["type"] = []string{"array", "object"}
		}
		props[sl.Name] = p
		req = append(req, sl.Name)
	}
	var steps []string
	for i, st := range sk.Steps {
		steps = append(steps, fmt.Sprintf("%d) %s on %s", i+1, st.Action, st.Account))
	}
	what := "A learned task"
	if sk.Kind == KindProcedure {
		what = "A recorded procedure"
	}
	return map[string]any{
		"name": ToolPrefix + sk.ID,
		"description": fmt.Sprintf("%s (from %d past runs the owner accepted): %s. "+
			"Each step is an ordinary effect request, checked and approved as usual. "+
			"It stops at the first step that does not succeed and returns the remaining steps for you to finish.",
			what, sk.Runs, strings.Join(steps, ", ")),
		"inputSchema": map[string]any{"type": "object", "properties": props, "required": req},
	}
}

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var req rpcReq
	if err := json.Unmarshal(body, &req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
		writeRPC(w, nil, nil, -32600, "invalid request")
		return
	}
	if len(req.ID) == 0 || string(req.ID) == "null" {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(req.Params, &p)
		v := "2025-06-18"
		for _, x := range []string{"2025-06-18", "2025-03-26", "2024-11-05"} {
			if x == p.ProtocolVersion {
				v = x
			}
		}
		writeRPC(w, req.ID, map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]string{"name": "agentos-skills", "version": "1"},
		}, 0, "")
	case "ping":
		writeRPC(w, req.ID, map[string]any{}, 0, "")
	case "tools/list":
		tools := []map[string]any{}
		for _, sk := range s.List() {
			tools = append(tools, Tool(sk))
		}
		writeRPC(w, req.ID, map[string]any{"tools": tools}, 0, "")
	case "tools/call":
		var call struct {
			Name      string                     `json:"name"`
			Arguments map[string]json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &call); err != nil {
			writeRPC(w, req.ID, nil, -32602, "bad params")
			return
		}
		id, ok := strings.CutPrefix(call.Name, ToolPrefix)
		sk := s.find(id)
		if !ok || sk == nil {
			writeRPC(w, req.ID, toolText("no such skill", true), 0, "")
			return
		}
		var runID string
		json.Unmarshal(call.Arguments["run_id"], &runID)
		args := map[string]json.RawMessage{}
		for k, v := range call.Arguments {
			if k != "run_id" {
				args[k] = v
			}
		}
		res := Run(r.Context(), sk, runID, args, s.Effects)
		b, _ := json.Marshal(res)
		writeRPC(w, req.ID, toolText(string(b), false), 0, "")
	default:
		writeRPC(w, req.ID, nil, -32601, "method not found")
	}
}

func toolText(text string, isErr bool) map[string]any {
	return map[string]any{"content": []map[string]string{{"type": "text", "text": text}}, "isError": isErr}
}

func writeRPC(w http.ResponseWriter, id json.RawMessage, result any, code int, msg string) {
	if id == nil {
		id = json.RawMessage("null")
	}
	out := map[string]any{"jsonrpc": "2.0", "id": id}
	if code != 0 {
		out["error"] = map[string]any{"code": code, "message": msg}
	} else {
		out["result"] = result
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// MCPEffects calls the broker's effect_request tool over MCP. URL is the
// broker's /mcp endpoint as the guest reaches it.
type MCPEffects struct {
	Client *http.Client
	URL    string
	seq    atomic.Int64
}

func (m *MCPEffects) Request(ctx context.Context, e Effect) (State, error) {
	args, _ := json.Marshal(e)
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": m.seq.Add(1), "method": "tools/call",
		"params": map[string]any{"name": "effect_request", "arguments": json.RawMessage(args)},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.URL, bytes.NewReader(body))
	if err != nil {
		return State{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	c := m.Client
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return State{}, err
	}
	defer resp.Body.Close()
	var out struct {
		Result *struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&out); err != nil {
		return State{}, fmt.Errorf("broker answer: %v", err)
	}
	switch {
	case out.Error != nil:
		return State{}, errors.New(out.Error.Message)
	case out.Result == nil || len(out.Result.Content) == 0:
		return State{}, errors.New("empty broker answer")
	case out.Result.IsError:
		return State{}, errors.New(out.Result.Content[0].Text)
	}
	var st State
	if err := json.Unmarshal([]byte(out.Result.Content[0].Text), &st); err != nil {
		return State{}, fmt.Errorf("broker answer: %v", err)
	}
	return st, nil
}
