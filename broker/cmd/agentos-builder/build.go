package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/skill/format"
)

const (
	defaultRounds    = 4
	defaultMaxTokens = 8000
	maxReply         = 1 << 20 // bytes of one broker or model reply read
)

// Brief is the job as the broker serves it on /brief (loopbuild Brief,
// restated: guest code links no broker package but the skill format).
type Brief struct {
	Signal string            `json:"signal"`
	Class  string            `json:"class"`
	Key    string            `json:"key"`
	Writes string            `json:"writes"`
	Steps  []json.RawMessage `json:"steps"`
	Cases  []json.RawMessage `json:"cases"`
	Limits struct {
		Files     int `json:"files"`
		FileBytes int `json:"file_bytes"`
		Bytes     int `json:"bytes"`
	} `json:"limits"`
}

type builder struct {
	hc        *http.Client
	model     string
	rounds    int
	maxTokens int
	logf      func(string, ...any)
}

// errStop ends the job without another round: the model route refused
// (the job's token cap, the share, or no route), or the broker ended it.
var errStop = errors.New("stopped")

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// run does one job: brief, rounds of model and check, then a candidate or
// /done.
func (b *builder) run(ctx context.Context) error {
	var br Brief
	raw, err := b.get(ctx, "/brief")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &br); err != nil {
		return fmt.Errorf("brief: %w", err)
	}
	msgs := []message{{Role: "system", Content: systemPrompt(br)}, {Role: "user", Content: string(raw)}}
	for i := 0; i < b.rounds && ctx.Err() == nil; i++ {
		reply, err := b.complete(ctx, msgs)
		if err != nil {
			b.giveUp(ctx)
			return err
		}
		msgs = append(msgs, message{Role: "assistant", Content: reply})
		files, err := prepare(br, reply)
		if err == nil {
			var accepted bool
			if accepted, err = b.submit(ctx, files); accepted {
				b.logf("builder: candidate of %d files accepted after %d rounds", len(files), i+1)
				return nil
			}
			if errors.Is(err, errStop) {
				return err
			}
		}
		b.logf("builder: round %d refused: %v", i+1, err)
		msgs = append(msgs, message{Role: "user", Content: "That candidate was refused: " + clip(err.Error(), 2000) +
			"\nFix it and answer again with only the JSON object."})
	}
	b.giveUp(ctx)
	return fmt.Errorf("no candidate after %d rounds", b.rounds)
}

// complete makes one model call and returns the first choice's text.
func (b *builder) complete(ctx context.Context, msgs []message) (string, error) {
	body, _ := json.Marshal(map[string]any{"model": b.model, "messages": msgs, "max_tokens": b.maxTokens, "temperature": 0})
	code, raw, err := b.post(ctx, "/model/v1/chat/completions", body)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("%w: model route answered %d: %s", errStop, code, clip(string(raw), 200))
	}
	var r struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &r); err != nil || len(r.Choices) == 0 {
		return "", fmt.Errorf("%w: model reply unreadable", errStop)
	}
	return r.Choices[0].Message.Content, nil
}

// submit posts a candidate. A 422 is a refusal the model may fix; any
// other failure ends the job.
func (b *builder) submit(ctx context.Context, files map[string]string) (bool, error) {
	body, _ := json.Marshal(map[string]any{"files": files})
	code, raw, err := b.post(ctx, "/candidate", body)
	switch {
	case err != nil:
		return false, fmt.Errorf("%w: %v", errStop, err)
	case code == http.StatusOK:
		return true, nil
	case code == http.StatusUnprocessableEntity:
		return false, errors.New(strings.TrimSpace(string(raw)))
	}
	return false, fmt.Errorf("%w: candidate answered %d", errStop, code)
}

// giveUp tells the broker there is nothing to submit, so the job ends now.
func (b *builder) giveUp(ctx context.Context) {
	if _, _, err := b.post(context.WithoutCancel(ctx), "/done", nil); err != nil {
		b.logf("builder: /done: %v", err)
	}
}

func (b *builder) get(ctx context.Context, p string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://broker"+p, nil)
	if err != nil {
		return nil, err
	}
	resp, err := b.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxReply))
	if err == nil && resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("%s answered %d", p, resp.StatusCode)
	}
	return raw, err
}

func (b *builder) post(ctx context.Context, p string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://broker"+p, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxReply))
	return resp.StatusCode, raw, err
}

// prepare is the image's toolchain: it takes the model's answer, a JSON
// object {"files": {path: content}}, and returns the files as the broker
// wants them, or why not. Skills and procedures are decoded leniently and
// re-encoded in the canonical form the runner accepts, then checked with
// the runner's own validator; a context rule is {"select": [source...]}.
// The broker checks everything again (loopbuild B4, change C6, C20).
func prepare(br Brief, reply string) (map[string]string, error) {
	var ans struct {
		Files map[string]json.RawMessage `json:"files"`
	}
	obj := jsonObject(reply)
	if obj == "" {
		return nil, errors.New(`the answer has no JSON object; answer {"files": {"<path>": <content>}}`)
	}
	if err := json.Unmarshal([]byte(obj), &ans); err != nil {
		return nil, fmt.Errorf("the answer is not valid JSON: %v", err)
	}
	if len(ans.Files) == 0 {
		return nil, errors.New("the answer has no files")
	}
	if br.Limits.Files > 0 && len(ans.Files) > br.Limits.Files {
		return nil, fmt.Errorf("%d files; at most %d", len(ans.Files), br.Limits.Files)
	}
	out := map[string]string{}
	total := 0
	for _, p := range sortedKeys(ans.Files) {
		if path.Clean(p) != p || path.IsAbs(p) || !strings.HasPrefix(p, br.Writes+"/") {
			return nil, fmt.Errorf("%s: write only clean paths under %s/", p, br.Writes)
		}
		p2, text, err := fileText(br.Writes, p, ans.Files[p])
		if err != nil {
			return nil, fmt.Errorf("%s: %v", p, err)
		}
		if _, dup := out[p2]; dup {
			return nil, fmt.Errorf("%s: another file has the same steps", p)
		}
		p = p2
		if !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
			return nil, fmt.Errorf("%s: not text", p)
		}
		if br.Limits.FileBytes > 0 && len(text) > br.Limits.FileBytes {
			return nil, fmt.Errorf("%s: %d bytes; at most %d", p, len(text), br.Limits.FileBytes)
		}
		total += len(text)
		out[p] = text
	}
	if br.Limits.Bytes > 0 && total > br.Limits.Bytes {
		return nil, fmt.Errorf("%d bytes in all; at most %d", total, br.Limits.Bytes)
	}
	return out, nil
}

// fileText is one file's path and content in the form its namespace
// takes. A skill's or procedure's ID is the hash of its own steps
// (format.Shape, P3-6e), so the toolchain names the file from them.
func fileText(ns, p string, raw json.RawMessage) (string, string, error) {
	switch ns {
	case format.SkillsNS, format.ProceduresNS:
		if path.Dir(p) != ns || !strings.HasSuffix(p, ".json") {
			return "", "", fmt.Errorf("a %s file is %s/<name>.json", ns, ns)
		}
		var s format.Skill
		if err := json.Unmarshal(unquote(raw), &s); err != nil {
			return "", "", fmt.Errorf("not a skill file: %v", err)
		}
		s.ID = idLetter(ns) + "000000000000"
		if err := s.Validate(); err != nil {
			return "", "", err
		}
		s.ID = idLetter(ns) + s.Shape()
		enc := s.Encode()
		if _, err := format.DecodeFile(s.Path(), enc); err != nil {
			return "", "", err
		}
		return s.Path(), string(enc), nil
	case "context":
		machine := strings.TrimSuffix(strings.TrimPrefix(p, "context/"), ".json")
		if machine == "" || strings.Contains(machine, "/") || !strings.HasSuffix(p, ".json") {
			return "", "", errors.New("a context rule is context/<machine>.json")
		}
		var r struct {
			Select []string `json:"select"`
		}
		dec := json.NewDecoder(bytes.NewReader(unquote(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil || len(r.Select) == 0 {
			return "", "", errors.New(`a context rule is {"select": ["<source>", ...]}`)
		}
		enc, _ := json.Marshal(r)
		return p, string(enc), nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return p, s, nil
	}
	return p, string(raw), nil
}

func idLetter(ns string) string {
	if ns == format.SkillsNS {
		return "k"
	}
	return "p"
}

// unquote takes content the model gave as a JSON string holding JSON.
func unquote(raw json.RawMessage) []byte {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []byte(s)
	}
	return raw
}

// jsonObject is the outermost JSON object in a model's answer, which may
// be wrapped in prose or a code fence.
func jsonObject(s string) string {
	i := strings.IndexByte(s, '{')
	j := strings.LastIndexByte(s, '}')
	if i < 0 || j < i {
		return ""
	}
	return s[i : j+1]
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}

// systemPrompt tells the model its job. The brief itself follows as the
// user message.
func systemPrompt(br Brief) string {
	var b strings.Builder
	fmt.Fprintf(&b, `You improve how a personal assistant box does one kind of task. The user message is a brief, as JSON:
- "signal" and "key": what went wrong or was costly (failure, correction, slow, expensive), and where.
- "steps": the journal intents behind it (account, action, state, params; free text is redacted).
- "cases": examples the owner judged, with their expected outcome.

Write a candidate change that would have done these tasks better. Write files only under %s/. Answer with one JSON object and nothing else:
{"files": {"<path>": <content>}}
At most %d files, %d bytes each, %d bytes in all.
`, br.Writes, br.Limits.Files, br.Limits.FileBytes, br.Limits.Bytes)
	switch br.Writes {
	case format.SkillsNS, format.ProceduresNS:
		kind := "skill"
		if br.Writes == format.ProceduresNS {
			kind = "procedure"
		}
		fmt.Fprintf(&b, `
Each file is %[1]s/<any name>.json (it is renamed after its steps) and its content is a JSON object:
{"version": 1, "kind": "%[2]s", "runs": <how many of the brief's tasks it covers, at least 1>,
 "slots": [{"name": "<lowercase_name>", "type": "text|email|number|bool|json", "max": <bytes, 1 to 16384>}],
 "steps": [{"account": "<account>", "action": "<action>",
            "params": {"<lowercase_key>": {"lit": <a JSON value>} or {"slot": "<slot name>"} or {"obj": {...}}},
            "recipients": [{"lit": "<address>"} or {"slot": "<slot name>"}]}]}
At most 32 steps and 32 slots; every slot is used; no step uses the account "broker" or an action starting "meta.".
`, br.Writes, kind)
		if kind == "procedure" {
			b.WriteString("A procedure takes every value as a slot: no literals.\n")
		}
	case "context":
		b.WriteString(`
Each file is context/<machine>.json and its content is {"select": ["<source>", ...]}: which of the sources the machine already receives it should see. Never name a new source.
`)
	}
	return b.String()
}
