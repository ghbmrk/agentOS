# S10 result: personal-agent protocols (PACT, PAP)

**Answer: no.** As PACT 1.0 is specified, a single box cannot be its own personal-agent platform. A conforming Provider MUST verify every personal-agent JWT against an HTTPS `jwksUri` (PACT §3.1, §3.2). The spec has no way to carry or pin the key inside the token, and in delegation the OAuth `client_id` *is* that issuer URL (§5, §5.4). Taking part therefore needs an HTTPS origin, reachable by every Provider, that keeps serving the box's keys. SPEC §2 forbids a public domain or certificate, and a box behind a carrier NAT has no inbound reachability without one. PACT is **not adoptable as specified**, so the package stops here, per its brief. The Meta/Sierra Personal Agent Protocol has **no published spec** to test (§5).

The self-issued key itself is not the obstacle: PACT has no CA and no platform registry. Two smaller obstacles follow it: a Provider-assigned `audience` obtained out of band, and Provider-chosen allowlisting (§3). §6 states the protocol change that would remove all three. §7 states the one question for Mark.

Evidence labels follow SPEC.md: [Fact] established or verifiable · [Inference] reasoned, untested · [Risk] known open question.

## 1. Sources and reachability

| Source | Reached? | What was read |
|---|---|---|
| openpactprotocol.org | No: egress proxy, CONNECT 403 | — |
| github.com/openpactprotocol/openpactprotocol | Web 403; **`git clone` worked** | Commit `838c6bd1da9b` (2026-10-06, "deps: clear pnpm audit --prod (#39)"), Apache-2.0. Read: `docs/spec.md` (normative, "PACT **1.0**"), `docs/personal-agent.md`, `docs/provider.md`, the reference Provider's `auth/verifyPlatformJwt.ts`, `platforms/register.ts` and `delegation/`, `packages/protocol/src/delegation.ts` (receipt schema), `packages/client/src/delegation.ts` (`verifyReceipt`) |
| decagon.ai blog (PACT announcement) | No: egress blocked | — |
| sierra.ai blog (PAP announcement) | No: egress blocked | Secondary reports only, through web search |

Claims the coordinator relayed, checked against the PACT repository:

| Claim | Result |
|---|---|
| PACT is built on A2A and OAuth | [Fact] A2A 1.0 HTTP+JSON, plus RFC 8628 device code and RFC 8414 metadata. |
| Three parties: personal agent, business, host of the business agent | [Fact] The spec names four roles: Provider (host), Brand (business), personal agent, and User. |
| A2A Agent Card discovery, with scopes such as `orders:read` | [Fact] PACT §2.1 and §5.1. |
| Short-lived signed JWT | [Fact] PACT §3.2: `exp` at most 300 s after `iat`. |
| OAuth device-flow consent with the business | [Fact] PACT §5.3. |
| Short-lived delegation token binding customer, platform, business and scopes | [Fact] PACT §5.4: `sub`, `client_id`, `aud` (one Brand) and `scope`; lifetime SHOULD be 1 h or less; a refresh token is also issued. |
| Signed receipts | [Fact] PACT §5.6. Receipts are **mandatory** under delegation, not optional ("can return"). |
| "with Instinct" | Not found in the repository. Unverified. |

## 2. PACT in one page

- [Fact] **Discovery (§2.1).** The card sits at `https://{brandDomain}/.well-known/agent-card.json` or is redirected to the Provider. It is fetched without authentication. The personal agent never builds a card URL from a Brand ID.
- [Fact] **Identity (§3).** Every call except the card fetch carries `Authorization: Bearer <pa-jwt>`, signed ES256 or RS256 with:
  - `iss`: the registered issuer URL, matched exactly;
  - `sub`: stable, opaque and per User, with no personal data;
  - `aud`: a Provider-assigned audience;
  - `iat` and `exp`, with a lifetime of 300 s or less;
  - `jti`, optional. Providers need not track replay.

  The Provider keeps `issuer`, `jwksUri` (HTTPS) and `enabled`. "How these are exchanged is out of scope." Allowlisting is "the Provider's policy, not PACT's". An open Provider MAY find `jwksUri` through `{iss}/.well-known/openid-configuration`.
- [Fact] **Messages (§4).** Natural-language `message:send` carries one `contextId` per (personal agent, `sub`, Brand). A retried `messageId` returns the stored reply without re-running the Brand's agent.
- [Fact] **Delegation (§5, optional profile).** The flow is RFC 8628 with the personal agent as client, authenticated by its JWT on every call. The User logs in on the Brand's own page and approves scopes there. The personal agent "MUST NOT proxy, frame, or observe the login". The resulting delegation token is a Provider-signed JWT, sent in `X-A2A-User-Delegation` beside the personal-agent JWT. The Provider checks the signature, `aud`, `exp`, `client_id == pa iss` and that the grant is not revoked. When a scope is missing, the step-up response is a `TASK_STATE_AUTH_REQUIRED` task carrying a new link. Every delegated reply carries a receipt signed with the Provider's keys.
- [Fact] **Revocation.** PACT defines no revocation endpoint (no RFC 7009). The reference consent page says "Revoke access anytime in {brandName} settings".
- [Fact] **The reference Provider is stricter than the spec.** `register.ts` requires issuer and `jwksUri` to be HTTPS on the **same origin**. In production it rejects localhost, private, link-local and CGNAT addresses. `verifyPlatformJwt.ts` rejects any `iss` that is not registered and enabled.

## 3. The decision boundary

| Sub-question | PACT 1.0 | Source |
|---|---|---|
| Self-issued signing key? | **Yes.** No CA and no platform certificate. The personal agent generates its own key. | [Fact] §3, `personal-agent.md` step 1 |
| No registration with a platform registry? | **Not guaranteed.** PACT defines no registry, and allowlisting is the Provider's policy. The reference Provider requires per-Provider registration (self-service). Either way, the `audience` comes "from its documentation or onboarding process", once per Provider. | [Fact] §3.1, `personal-agent.md` step 2. [Inference] Early production Providers will allowlist known platforms, since an open Provider gains nothing from an unknown issuer. |
| No domain-hosted JWKS? | **No.** "Providers MUST verify the signature via `jwksUri`", and `jwksUri` is an "HTTPS URL of the personal agent's JWKS". There is no `jwk`/`x5c` header path and no key pinning. In delegation, `client_id` is the issuer URL, and the consent page shows the "personal agent's issuer origin". | [Fact] §3.1, §3.2, §5, §5.3 |

So conformance requires an HTTPS origin, reachable by every Provider, that keeps serving the box's keys. That is "a domain the box publishes", the brief's stop condition, and it collides with SPEC §2 (forbidden: a public domain or certificate). [Inference] Serving it from the box itself would also need inbound reachability through a carrier NAT, and that needs a relay or tunnel.

The Identity profile is not a way around this. Delegation (§5) requires Identity (§3). Identity alone (§3.3) only lets the Brand's agent verify the User "the way it does in a chat widget", which the existing browser path already reaches.

## 4. Ways around it, and why each fails or needs a ruling

| Option | What it is | Verdict |
|---|---|---|
| A. Owner key host | The box publishes its JWKS (public keys only) and an issuer URL on a static host under an account the owner already has (for example a personal pages site). The private key stays in the vault. | **Needs Mark's ruling (§7); not adopted.** [Inference] This should pass the reference Provider: HTTPS, same origin, public host; untested. For it: no secret leaves the box; the host is outside the control path; losing it costs PACT only (DEP-3). Against it: (1) anyone who controls that account can publish their own key and impersonate the owner's personal agent at Identity level; delegated actions still need the delegation token, which stays in the vault. (2) The host sees which Providers fetch the JWKS, which is surveillance metadata. (3) Key rotation needs a write credential to the host (vault) or a manual step by the owner. (4) Each Provider's audience and registration is still a manual onboarding step. (5) A Provider that allowlists platforms may still refuse. It also stretches §2's "public domain" to a subdomain the owner does not control. |
| B. Borrow a commercial platform's identity | A personal-agent platform signs on the box's behalf. | **Rejected.** A third party would hold or use the signing key, against ARC-1 and CRED-1, and would sit in the path of every business call. |
| C. Box serves its own JWKS | A domain plus a certificate, or a tunnel to the box. | **Rejected.** SPEC §2 forbids a public domain or certificate, and a relay. |
| D. Identity profile only | — | **Not a way around it.** It needs the same JWKS. |

## 5. Personal Agent Protocol (Meta and Sierra)

- [Fact] It was announced on 2026-10-06. Sierra's announcement is not reachable from here (egress blocked).
- [Inference, secondary reports only] **No spec is published.** A v0.1 is reported "due later in October". The design is described as OAuth-based, with a guest tier and then a signed-in grant of read or write access. The business chooses whether agents reach it through its website, its APIs (MCP, OpenAPI) or its own agent. Payments and finer-grained permissions are future extensions, and a reference implementation is promised.
- **The decision-boundary question cannot be answered until v0.1 is published.** The question to put to it is the same as §3: does the business verify the personal agent through a URL-hosted key, a platform registry, or a key carried in the request?

## 6. What PACT would have to change for a single box to take part

The smallest change that keeps PACT's security properties is a **self-certifying personal agent** option. [Inference] This is a proposal to send upstream (the repository has a spec-change issue template); it has not been sent.

1. **Key-bound issuer.** `iss` MAY be a JWK Thumbprint URI (RFC 9278 over RFC 7638). The JWT header carries the public key as `jwk`. The Provider verifies the signature with that key and checks that its thumbprint equals `iss`, with no `jwksUri` fetch. Everything else in §3.2 is unchanged. RFC 9449 (DPoP) already uses header-carried keys in OAuth.
2. **Rotation is a new identity.** Rotating the key changes `iss`, and grants are consented again. This keeps the option stateless. A signed continuity statement could come later.
3. **Audience on the card.** The Provider publishes its `audience` on the Agent Card, still opaque and still per Provider. An open Provider then needs no out-of-band onboarding.
4. **Consent display.** For a thumbprint issuer, the consent page shows a short fingerprint and a self-declared name labelled unverified, where it would otherwise show the issuer origin.
5. **Policy stays the Provider's.** The option makes taking part *possible*; each Provider still decides whether to accept unregistered issuers. [Inference] The `pa` field in the reference receipt schema is validated as a URL, and a thumbprint URN parses as one.

This keeps every PACT check: signature, `aud`, lifetime and `client_id == iss`. What it gives up is out-of-band vetting of the platform, which open Providers already give up.

## 7. Decisions needed

| For | Question | Recommendation |
|---|---|---|
| Mark (spec boundary) | Under SPEC §2, is a public-keys-only file on the owner's existing third-party account (option A) an Optional dependency, or a forbidden "public domain"? | **Hold; no ruling yet.** Nothing in the release needs PACT. Option A's value also depends on an open Provider that does not yet exist (§3). Revisit when the LATER.md trigger fires. |
| Mark (outward-facing) | Send the §6 proposal upstream as an issue on openpactprotocol/openpactprotocol? | **Yes, if Mark wants AgentOS to take part eventually.** It is the only route that needs no exception to §2. It is not sent from this session, because publishing is Mark's call. |

## 8. Design record if PACT is adopted later (threat model and SPEC v0.12 mapping)

Kept so a later package starts from here. None of it is built. All rows are [Inference] unless marked.

### 8.1 Threats

| Threat | PACT's own control | What remains | AgentOS control it would need |
|---|---|---|---|
| Token theft | The delegation token alone is useless: §5.5 needs a valid PA JWT whose `iss` equals `client_id` [Fact]. | The token is not bound to the key (no DPoP). Stealing both the token and the signing key is full use. A refresh token is long-lived. | The signing key, delegation token and refresh token stay in the vault only (CRED-1, ARC-1). The egress proxy **mints** a fresh PA JWT per request and injects both headers (ADP-10). Minting is a new kind of injection; today's proxy injects stored values (`broker/egress` E1–E3). CRED-7 redacts all three. |
| Confused deputy between businesses | The delegation token's `aud` is one Brand's interface URL [Fact]. | The PA JWT's `aud` is per **Provider**, so one JWT is valid for every Brand on that Provider for up to 300 s. The Provider's own audience string might collide with another Provider's. | Refuse to register the same audience for two Providers. Keep the PA JWT lifetime short (60 s or less) with a fresh `jti`. Bind each declared operation to one interface URL. |
| Scope escalation through the Agent Card | The personal agent "MUST request only ids on the card"; descriptions are free text [Fact]. | A scope's meaning is the Brand's claim, and the model choosing scopes reads untrusted text. | A scope maps to a verb by the owner's consent, never by its description (ADP-2). Any write-capable or unknown scope takes the strictest verb. Read-only scopes may run autonomously; a write scope is requested per intent, with owner approval. |
| Injection by the Brand's agent | — | Replies, card text, step-up messages and scope descriptions are model-written by a third party. | All of it is untrusted content with a REV-5 label, rendered as untrusted (CAP-3), never as instructions. The step-up link is texted only if its host matches the Brand domain the card was found from (as in CRED-5 W5). |
| Receipt forgery | Provider-signed JWS; `verifyReceipt` checks the signature and that the claims match the payload [Fact]. | A receipt is the Provider's own attestation. `argsHash` is optional, with no defined hash or canonical form. The receipt does **not** bind `messageId` or `contextId`, so the Provider can attach an older receipt from the same grant. | Treat a receipt as evidence the Provider asserted, not proof of the effect (OP-7). Check `grantId`, `user`, `pa`, `brand` and that `ts` falls in the request window. Keep the receipt with the intent (§9). |
| Replay | Lifetime is 300 s or less [Fact]. | Providers "need not track replay" [Fact]. | Fresh `jti` and short `exp`. An intent ID maps to `messageId`, so a retry is idempotent by §4.3 (OP-1). |

### 8.2 Mapping to SPEC v0.12

| SPEC ID | Fit | Note |
|---|---|---|
| CRED-1, ARC-1, CRED-7 | Fits | The signing key, delegation token and refresh token are vault values. Agent machines never see them. The egress process signs. |
| ADP-1, ADP-2 | Partial fit | A PACT adapter declares three operations: `message:send`, `device_authorization` and `token`. The effect of `message:send` is decided by the Brand's agent in natural language, so the verb is bounded only by the granted scopes. A message sent under any write scope is one irreversible intent. Under Identity only, the verb is `send` (disclosure). |
| ADP-10 | Fits, with an extension | Host and path templates are fixed by the interface URL. New: two headers, one of them minted per request, and an `A2A-Version` header on the adapter allowlist. |
| REV-2, §9 | Fits | Each `message:send` is a journaled intent with `messageId = intent id`. A receipt is evidence for `observed`. If no reply arrives, the intent stays `outcome_unknown` (OP-2). A retry with the same `messageId` is safe by PACT §4.3. Offline verification needs the Provider's JWKS cached at the time of the call, since keys rotate. |
| REV-5 | Fits | The card is fetched by an unmodified GET from a URL in public content (the Brand's domain). A card or Provider URL found in private content is a disclosure intent. Cross-host redirects are followed only from the Brand's domain. |
| §8.1 step 8, CH-19 | Fits | Consent reuses the texted device-code link path. `verification_uri_complete` embeds the `user_code`, so the link goes out only in the broker's fixed template, with the host check above. The owner signs in on their own phone, which PACT requires (no proxying or framing). It is never done in a credentialed browser. |
| Revocation | Gap in PACT | There is no endpoint. The box deletes its tokens (stopping its own use), names the Brand settings page where the owner can revoke (as in CRED-5 W9), and lists active grants on the page: Brand, scopes, expiry and `grant_id`, read from the token claims. |
| DEP-3, OP-9 | Fits | Losing a Brand's PACT support, or a Provider refusing the issuer, falls back to the credentialed browser or adapter path, with an OP-9 status line. |
| §2, DEP-2, ID-2 | **Fails** | See §3. |

## 9. Findings

| Class | Finding |
|---|---|
| later | Revisit S10 when PAP v0.1 is published, when PACT adds a self-certifying issuer (§6), or when a production Provider accepts open issuers. Added to LATER.md. |
| later | The §6 upstream proposal and the §7 ruling on option A, both Mark's to decide. Recorded here; no row needed until the trigger above. |

No blocker and no release finding: no code was written, and nothing on the release path depends on PACT.

## 10. Usage

One session on the strongest model, documentation only. No prototype was built, because the stop rule applied.
