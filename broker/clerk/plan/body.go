package plan

import (
	"fmt"
	"strings"
)

// The model call's request body (MIG-4-plan-login-b, PLN-5(a)). The clerk
// decodes it, holds it to the CLI's declared shape and sends its own
// re-encoding, so the provider parses exactly what was checked. It is the
// old core's checkResponses (egress/worker.go, measured on Codex CLI
// 0.162.1, #809), moved here.

// Body is a model call's declared shape: its top-level keys, its input
// items' types, a message's content part types, and the tools it may
// declare, all client-side, so the provider never runs a tool, keeps a
// response or fetches an address for the guest.
type Body struct {
	Keys, InputTypes, ContentTypes []string
	// ToolTypes are the tool types a call may declare, each one the CLI
	// runs itself (clientToolTypes).
	ToolTypes []string
	// Tools are the CLI's own tools, by namespace and name; any other
	// tool, a hosted one above all, is refused.
	Tools []Tool
	// Stream requires "stream": true, so the answer is the event stream
	// whose last event the clerk meters (#3128 Security 1): the guest does
	// not choose how its call is metered.
	Stream bool
}

// Tool is one declared tool. An empty Namespace is a tool outside any.
type Tool struct{ Namespace, Name, Type string }

// clientToolTypes are the only tool types a body may allow: the CLI runs
// them. A hosted type has the provider act for the guest.
var clientToolTypes = []string{"namespace", "function", "custom"}

// hostedKeys are top-level keys no body may declare: background runs,
// provider-held prompts and conversations, and server-side tool sources.
var hostedKeys = []string{"background", "prompt", "conversation", "previous_response_id", "web_search_options", "mcp_servers", "container"}

// urlKeys hold a content source by address; only an inline data: URL may
// sit under one.
var urlKeys = []string{"url", "image_url", "file_url", "document_url", "audio_url", "video_url", "server_url"}

// Body refusals, after DBody; each names a rule, never a value (CLK-4).
const (
	bodyJSON    = "json"    // not a single JSON object
	bodyKey     = "key"     // an undeclared top-level key
	bodyStore   = "store"   // store set to anything but false
	bodyStream  = "stream"  // a declared stream not set to true
	bodyMeta    = "meta"    // client_metadata not an object of strings
	bodyInput   = "input"   // an input item out of its declared types
	bodyContent = "content" // a content part out of its declared types
	bodyTool    = "tool"    // a tool undeclared, hosted or out of place
	bodyChoice  = "choice"  // tool_choice out of shape
	bodyRemote  = "remote"  // a content source by address
	bodyDepth   = "depth"   // nested too deep to check
)

const maxDepth = 32

func (b *Body) validate() error {
	if len(b.Keys) == 0 || len(b.InputTypes) == 0 || len(b.ContentTypes) == 0 {
		return fmt.Errorf("clerk: a model body declares its keys, input types and content types")
	}
	// store is forced off on every call, so it is declared (#3128 L3 2).
	if !contains(b.Keys, "store") {
		return fmt.Errorf("clerk: a model body declares store, which the clerk forces off")
	}
	if b.Stream && !contains(b.Keys, "stream") {
		return fmt.Errorf("clerk: a streamed body declares its stream key")
	}
	for _, k := range b.Keys {
		if contains(hostedKeys, k) {
			return fmt.Errorf("clerk: body key %q has the provider act for the guest", k)
		}
	}
	for _, t := range b.ToolTypes {
		if !contains(clientToolTypes, t) {
			return fmt.Errorf("clerk: tool type %q is not client-side", t)
		}
	}
	for _, t := range b.Tools {
		if t.Name == "" || t.Type == "namespace" || !contains(b.ToolTypes, t.Type) {
			return fmt.Errorf("clerk: tool %q is out of shape", t.Name)
		}
		if t.Namespace != "" && !contains(b.ToolTypes, "namespace") {
			return fmt.Errorf("clerk: tool %q sits in a namespace the body does not allow", t.Name)
		}
	}
	return nil
}

// check holds a model call to the declared shape and returns the clerk's
// own encoding of what it checked, or the rule it broke. Tools appear only
// where the CLI declares them (a top-level tools list, an additional_tools
// input item (#809), a namespace's nested tools); store is forced off; and
// remote content sources are refused.
func (b *Body) check(body []byte) ([]byte, string) {
	obj, err := strictObject(body)
	if err != nil {
		return nil, bodyJSON
	}
	for k, v := range obj {
		if !contains(b.Keys, k) {
			return nil, bodyKey
		}
		if k != "tools" && k != "input" {
			if r := noTools(v, 0); r != "" {
				return nil, r
			}
		}
	}
	if s, ok := obj["store"]; ok && s != false {
		return nil, bodyStore
	}
	obj["store"] = false
	if b.Stream && obj["stream"] != true {
		return nil, bodyStream
	}
	if m, ok := obj["client_metadata"]; ok {
		meta, ok := m.(map[string]any)
		if !ok {
			return nil, bodyMeta
		}
		for _, v := range meta {
			if _, text := v.(string); !text {
				return nil, bodyMeta
			}
		}
	}
	if t, ok := obj["tools"]; ok {
		if r := b.tools(t, ""); r != "" {
			return nil, r
		}
	}
	if in, ok := obj["input"]; ok {
		if r := b.input(in); r != "" {
			return nil, r
		}
	}
	if tc, ok := obj["tool_choice"]; ok {
		switch v := tc.(type) {
		case string:
			if v != "auto" && v != "none" && v != "required" {
				return nil, bodyChoice
			}
		case map[string]any:
			if t, _ := v["type"].(string); !contains(b.ToolTypes, t) {
				return nil, bodyChoice
			}
		default:
			return nil, bodyChoice
		}
	}
	if r := remote(obj, "", 0); r != "" {
		return nil, r
	}
	out, err := encodeJSON(obj)
	if err != nil {
		return nil, bodyJSON
	}
	return out, ""
}

// input holds each input item to a declared type. Only an additional_tools
// item carries tools, and a message's content parts (and a tool output's,
// when it is a list) are of declared types.
func (b *Body) input(v any) string {
	in, ok := v.([]any)
	if !ok {
		return bodyInput
	}
	for _, it := range in {
		item, ok := it.(map[string]any)
		if !ok {
			return bodyInput
		}
		t, _ := item["type"].(string)
		if !contains(b.InputTypes, t) {
			return bodyInput
		}
		for k, f := range item {
			switch {
			case k == "tools" && t == "additional_tools":
				if r := b.tools(f, ""); r != "" {
					return r
				}
			case k == "tools":
				return bodyTool
			case k == "content" || k == "output":
				if r := b.parts(f); r != "" {
					return r
				}
			default:
				if r := noTools(f, 0); r != "" {
					return r
				}
			}
		}
		if _, has := item["tools"]; t == "additional_tools" && !has {
			return bodyInput
		}
	}
	return ""
}

// parts allows text, or a list of parts of declared types.
func (b *Body) parts(v any) string {
	list, ok := v.([]any)
	if !ok {
		if _, text := v.(string); text {
			return ""
		}
		return bodyContent
	}
	for _, it := range list {
		part, ok := it.(map[string]any)
		if !ok {
			return bodyContent
		}
		if t, _ := part["type"].(string); !contains(b.ContentTypes, t) {
			return bodyContent
		}
		if r := noTools(part, 0); r != "" {
			return r
		}
	}
	return ""
}

// tools allows only declared tools: a declared namespace holding its
// declared tools, or a declared tool outside any namespace, each of its
// declared type. ns is the enclosing namespace.
func (b *Body) tools(v any, ns string) string {
	list, ok := v.([]any)
	if !ok {
		return bodyTool
	}
	for _, it := range list {
		tool, ok := it.(map[string]any)
		if !ok {
			return bodyTool
		}
		t, _ := tool["type"].(string)
		if !contains(b.ToolTypes, t) {
			return bodyTool
		}
		name, _ := tool["name"].(string)
		nested, has := tool["tools"]
		if t == "namespace" {
			if ns != "" || !has || !b.namespace(name) {
				return bodyTool
			}
			if r := b.tools(nested, name); r != "" {
				return r
			}
			continue
		}
		if has || !b.declared(ns, name, t) {
			return bodyTool
		}
	}
	return ""
}

func (b *Body) namespace(name string) bool {
	for _, t := range b.Tools {
		if name != "" && t.Namespace == name {
			return true
		}
	}
	return false
}

func (b *Body) declared(ns, name, typ string) bool {
	for _, t := range b.Tools {
		if t.Namespace == ns && t.Name == name && t.Type == typ {
			return true
		}
	}
	return false
}

// noTools refuses a tools key anywhere in v: tools are checked only where
// the CLI declares them.
func noTools(v any, depth int) string {
	if depth > maxDepth {
		return bodyDepth
	}
	switch x := v.(type) {
	case map[string]any:
		for k, f := range x {
			if k == "tools" {
				return bodyTool
			}
			if r := noTools(f, depth+1); r != "" {
				return r
			}
		}
	case []any:
		for _, f := range x {
			if r := noTools(f, depth+1); r != "" {
				return r
			}
		}
	}
	return ""
}

// remote refuses a content source given by address: a string under a
// urlKeys key that is not a data: URL. A function tool's JSON schema (its
// parameters) is the CLI's own declaration, not a fetch, so it is not
// looked inside; a parameters key anywhere else is (#3128 Security 3).
func remote(v any, key string, depth int) string {
	if depth > maxDepth {
		return bodyDepth
	}
	switch t := v.(type) {
	case map[string]any:
		for k, c := range t {
			if k == "parameters" && t["type"] == "function" {
				continue
			}
			if r := remote(c, k, depth+1); r != "" {
				return r
			}
		}
	case []any:
		for _, c := range t {
			if r := remote(c, key, depth+1); r != "" {
				return r
			}
		}
	case string:
		if contains(urlKeys, key) && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "data:") {
			return bodyRemote
		}
	}
	return ""
}
