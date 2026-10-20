# P2-2w c4e: setup's AI providers through the vault process

Board section: Backlog refill (2026-10-05); work item #1222. Split from P2-2w c4 (#1218, briefs/P2-2w-c4.md). Without it, the AI step on a deployed box lists no provider, so setup cannot finish (A1, ONB-3).

**Requirements:**
- CRED-5: a provider credential entered at setup is held only in the vault. It is entered on the Wi-Fi page and never by text. A plan login (device-code sign-in) is split out to c4e2, below.
- CAP-9: the owner's private-data answer for each provider is recorded at setup, and the router honours it.
- ONB-3: the AI step is a minimum-path step. Once one provider is connected, setup can finish.
- CRED-1: the key passes through agentosd and the page only as a call argument. It is never kept, logged or answered back.
- Binding conditions: Security L6 (setup closes for good after finish) and egress K17 (setup's vault ops run only while the vault's setup enrollment is open).

**Acceptance:** A1 (setup on hardware, with P2-1).
**Implementation risk:** tier A. **Needs:** P2-2w c4 (merged, #1218). **Gate:** lenses (security: strongest tier).

## Sizing

#1222 also names device-code sign-in. That flow needs the provider's official CLI in a worker (CAP-11, CRED-5). Codex is the default plan route and is broker-held (D-114, D-061); Claude has no plan route (D-140). It is a different mechanism from a vault-held key, so it is split into a release row:

- **c4e2, plan sign-in at setup.** The page's "Use my plan" starts the provider CLI's device-code login in a worker, shows "This code is from <provider>", and records the login in the custody mode the adapter declares. For Codex that is broker-held: sign-in runs in a fresh provider worker through #1014's declared sign-in endpoints and auth-host check, the first token response is swapped to placeholders and written to the vault entry (#1015), and the page records the owner's consent for the unconfirmed route first (CRED-5c). Claude appears only after the opt-in warning, with the user-driven flow #1380 builds. Until c4e2, providers report `device_code: false`, so the page never offers it.

## Scope (files)

- `broker/cmd/agentos-egress/`: a new `providers.go` and `providers_test.go`; `server.go` (verify socket dispatch); `custody.go` (`put`'s checks shared with setup's put); `main.go` (the router's late-bound private check); `builder_test.go` (the new `modelRouting` argument); `broker/egress/ASSUMPTIONS.md` (K23).
- `broker/route/route.go`, `route_test.go` (the rig passes the hook) and a new `route/privateallowed_test.go`, and `route/ASSUMPTIONS.md`: a `Config.PrivateAllowed` hook beside the static `PrivateOK` map.
- `broker/modelroute/`: a new `providers.go` and `providers_test.go` (the verify socket client).
- `broker/localapi/setup.go`: three ops added to `SetupOps` and their types; `localapi_test.go` (the op count). The vault's refusals map to the existing codes.
- `broker/localsrv/`: `setup.go` (a `Providers` field on `SetupConfig` and the three ops), a new `setupproviders.go` (the handlers) and a new `setupproviders_test.go`.
- `broker/cmd/agentosd/setup.go` (the enroller also serves providers), a new `setupproviders_test.go`, `capoff_test.go` (the OP-9 guard now asks a box past setup), and `ASSUMPTIONS.md`.
- `broker/localui/setuphooks.go` (the provider hooks only), a new `setupproviders_test.go`, and `ASSUMPTIONS.md` (L42); `pages.go` (the private-data box starts unticked, Security S-B1) and `localui_test.go` (its expectation).

## What to build

1. **Vault process.** On the verify socket (peer: agentosd), serve:
   - `GET /setup/providers`: each built-in adapter's ID and display name, whether an API key is held (`connected`), and the private-data answer;
   - `POST /setup/providers/key` `{provider, key}`: store the key under the adapter's credential name, with `put`'s rules (built-in adapter credential only, never over an entry of another kind);
   - `POST /setup/providers/private` `{provider, ok}`: write or delete a marker entry for that adapter.

   All three need the vault open and setup's enrollment open (K17's `closedLocked`). A sealed vault answers 410 and a vault never opened for setup answers 412, as `/enroll` does.
2. **Router.** `route.Config.PrivateAllowed func(provider) bool` is checked when `PrivateOK` is false. The vault process passes a check that is true only while the vault is open and holds that adapter's marker. A locked vault allows nothing private, which is the fail-closed side.
3. **Client.** `modelroute.Verifier` gets `SetupProviders`, `SetupAPIKey` and `SetupPrivateOK`, with the enroll errors.
4. **agentosd.** `localsrv.SetupConfig.Providers` serves `page_setup_providers`, `page_setup_api_key` and `page_setup_private_ok` while setup is open. API keys are bounded at 512 bytes and printable, and limited to 10 a minute. agentosd's enroller implements the interface over the verify socket.
5. **Page.** `AgentosdSetup.Providers`, `ConnectAPIKey` and `SetPrivateOK` call those ops. The private-data box starts unticked (CAP-9's default no). `StartDeviceCode` still answers `errNotServed`.

## Acceptance tests

1. Vault process:
   - locked: 503;
   - open in setup: list, key put and private mark work, and `connected` and `private_ok` follow them;
   - an unknown provider, or a name held by another kind: 400, and nothing is written;
   - sealed: 410; never opened: 412;
   - the list answer never carries the key.
2. Router: with `PrivateOK` empty, a private call routes only to a provider `PrivateAllowed` names; a nil hook keeps the old behaviour. The vault process's check is false while the vault is locked.
3. The client maps 503, 410 and 412 to `ErrVaultLocked`, `ErrEnrolled` and `ErrEnrollNotOpen`.
4. localsrv: the three ops answer `setup closed` after finish; a nil `Providers` lists none and refuses keys; a malformed key is `bad args` and never reaches the vault; the eleventh key in a minute is `limited`.
5. End to end over localui.sock: page hooks to `localsrv.Setup` to a provider fake (agentosd's enroller is tested against a fake verify socket, and the vault handler in the egress package). A connected provider lets `maybeFinish` proceed. `localapi.APIKey`'s `String` and `GoString` carry no key.

Run tests with `-race`.

## Out of scope

c4e2 above; checking a key against the provider before storing it; the eval route's static `PrivateOK`; changing a provider's answer after setup.

## Estimate

About 110k tokens for one session. The figure is a checkpoint, not a cap (docs/OPERATING.md §5).
