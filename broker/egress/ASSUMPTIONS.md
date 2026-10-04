# Vault and credentialed egress: assumptions

Built for PLAN P1-3 against SPEC v0.12 (PR #15) on top of the broker
skeleton (PR #19). Covers `broker/vault` and `broker/egress`. Each row is a
reading of the spec, or a gap left for a later package, that a reviewer may
want to change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| V1 | The vault is one AES-256-GCM sealed file (stdlib only), names and values both sealed, replaced atomically, mode 0600. The 32-byte data key is supplied by the caller; wrapping it under TPM, passphrase, and recovery-key slots is P2-4. | CRED-1, CRED-8, DEP-1 | P2-4 supplies the key; the file format is versioned. |
| V2 | Only `egress` (and the daemon binary) may import `vault`; `vault/imports_test.go` enforces it. Inside the trusted broker process Go cannot hide memory, so custody rests on this import rule plus `Secret` formatting as a placeholder under every `fmt` verb, JSON, and text marshaling. | CRED-1, ARC-1 | Add an importer only with a reviewed reason. |
| V3 | Values shorter than 12 bytes are refused, so CRED-7 redaction cannot shred innocent text. Passwords for credentialed browsers (P2-6) may need a different redaction rule. | CRED-7 | P2-6. |
| V4 | Redaction matches each value verbatim and as base64 (four variants), hex (both cases), and URL escaping. A value embedded mid-way in a larger base64 blob is not caught; redaction is defense in depth, custody does not rely on it. Streams hold back at most the longest pattern minus one byte. | CRED-7 | Add encodings in `NewRedactor`. |
| E1 | Guest path is `/<adapter>/<upstream path>`. A request is forwarded only if the path is clean (no `.`/`..`/empty segments, nothing percent-escaped), has no query, and matches a declared operation's method and path template exactly. Everything else is denied with 403 and reported. No normalization: ambiguous means denied. | ADP-10 | Declared query parameters, and GraphQL/JSON-RPC body schemas, arrive with the first adapter that needs them. |
| E2 | Built-in relays declare inference only: OpenAI `POST /v1/chat/completions` and `POST /v1/responses`; Anthropic `POST /v1/messages`. Model listing, files, batches, key management, and billing are undeclared, so denied. | CRED-5, ADP-10 | Add an operation per qualified need. |
| E3 | Request headers are an allowlist (`Content-Type`, `Accept`, `User-Agent`, plus adapter-declared); credential-bearing names can never be declared. So a guest's own key, cookie, or org header is dropped, and the vault credential is the only one sent. `Accept-Encoding` is not forwarded, so the proxy redacts plain bytes. | CRED-5, A14 | Small: `baseRequestHeaders`. |
| E4 | Responses keep only allowlisted headers (`Location`, `Set-Cookie` never), redirects are returned rather than followed (the key is never re-sent elsewhere), and headers and body pass the redactor. | CRED-1, CRED-7 | Small: `baseResponseHeaders`. |
| E5 | Grants are a static machine → adapter table given at construction. The grant store and grant-change intents (OP-5) are a later package; the data-label (REV-5) check for uncredentialed egress is not here, since model access is ARC-6 (a) for any granted machine. | OP-5, REV-5 | Swap `Config.Grants` for a lookup. |
| E6 | Decisions go to an `Auditor` interface; events carry no header or body content. The journal has no record type for a non-intent event yet, so wiring denials into the journal is left to whoever wires the proxy into the daemon (P1-7 guest). | ADP-10 | Add a journal record type, or journal denials as denied intents. |
| E7 | Not wired into the daemon: the daemon is on the ARC-2 control path, which may not import a network client. The guest package (P1-7) serves `Proxy.Handler(machine)` on each machine's own listener, so identity comes from the listener (as in sockets, B8). | ARC-2, ARC-6 | — |
| E8 | OP-8 model-spend metering is not in this package. The proxy is the right place for it (it sees every call by machine); it needs token counting from the broker's own observation. | OP-8 | Follow-up package. |
