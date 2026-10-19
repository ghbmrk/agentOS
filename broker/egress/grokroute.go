package egress

// Grok is the Grok CLI's plan route (#1378): xAI's official CLI, Grok
// Build, as read from the pinned CLI 1.0.62's own strings. Nothing here is
// measured yet (#809 measures it; ASSUMPTIONS.md lists each item), so every
// list is the narrowest the CLI's source supports and anything else fails
// by absence. The route carries run endpoints only: sign-in stays off until
// #809 captures the CLI's device flow, so a sign-in worker has no endpoint.
func Grok() PlanRoute {
	const run, auth = "cli-chat-proxy.grok.com", "auth.x.ai"
	return PlanRoute{
		Provider:     "grok",
		Origin:       "http://127.0.0.1:18433",
		AuthHost:     auth,
		RedirectPath: "/callback",
		DevicePage:   "/device",
		Endpoints: []PlanEndpoint{
			{Name: "responses", Host: run, Method: "POST", Path: "/v1/responses", Kind: KindResponses},
			{Name: "models", Host: run, Method: "GET", Path: "/v1/models", Kind: KindRead},
			{Name: "refresh", Host: auth, Method: "POST", Path: "/oauth2/token", Kind: KindRefresh},
		},
		// The CLI's own tools, all plain functions outside any namespace;
		// its web_search and web_fetch are left out, so a request carrying
		// them is refused rather than run by the provider for the worker.
		ToolTypes: []string{"function"},
		Tools: []DeclaredTool{
			{"", "read_file", "function"},
			{"", "write_file", "function"},
			{"", "search_replace", "function"},
			{"", "run_terminal_cmd", "function"},
			{"", "list_dir", "function"},
			{"", "grep", "function"},
			{"", "glob", "function"},
			{"", "todo_write", "function"},
		},
		BodyKeys: []string{
			"model", "instructions", "input", "tools", "tool_choice", "parallel_tool_calls",
			"reasoning", "store", "stream", "include", "text", "max_output_tokens",
		},
		InputTypes:   []string{"message", "reasoning", "function_call", "function_call_output"},
		ContentTypes: []string{"input_text", "output_text", "input_image"},
		Token: ResponseRule{Fields: []Field{
			{Name: "access_token", Kind: FieldCredential},
			{Name: "refresh_token", Kind: FieldCredential, Optional: true},
			{Name: "id_token", Kind: FieldCredential, Optional: true},
			{Name: "expires_in", Kind: FieldNumber, Optional: true},
			{Name: "token_type", Kind: FieldText, Pattern: `[Bb]earer`, Optional: true},
			{Name: "scope", Kind: FieldText, Pattern: `[a-z_.: ]{1,200}`, Optional: true},
		}},
		// No refresh failure reads as a refused login until #809 measures
		// the codes the CLI treats as a dead one: the OAuth default,
		// invalid_grant, is one a worker can provoke with another client_id.
		RefusedLogin:    nil,
		RequestHeaders:  []string{"Accept", "Content-Type", "User-Agent"},
		ResponseHeaders: []string{"Content-Type", "Retry-After", "X-Request-Id"},
	}
}
