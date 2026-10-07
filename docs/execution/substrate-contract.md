# SUB-1: peer execution substrates (draft L1 proposal)

Execution substrates — user-authorized premise, implementation pending review

Governing premise supplied 2026-10-07

“AgentOS exposes structured tools, command execution, and qualified computer-use
environments as peer execution substrates. It selects the narrowest substrate
that preserves the required capability. Computer-use environments may operate
browsers and graphical applications headlessly, including consumer services
unavailable through equivalent structured interfaces. They inherit the same
authority, disclosure, resource, evidence, recovery, and bypass-resistance
contracts as every other executor.”

This premise governs these proposals. It does not assert that an existing spike,
image or service is qualified. This draft PR proposes the SPEC.md reconciliation; no runtime policy is enabled.
The exact normative diff remains subject to external L1 review and Mark approval.

Repository fit and required decision

ADP-3 already orders API/MCP, CLI/plugin, browser, desktop routes by capability,
health, grant and custody. CAP-2, CRED-4/10 and ADP-5 already cover logged-in browser
and graphical application executors. ARC-5 requires gVisor or virtualization,
not Linux namespaces alone. S5 is a protocol/fixture spike, not CRED-4b production
broker wiring; ADP-5 remains dependent on CRED-4b. Browser and desktop operation
must be admitted and measured on the floor independently of the agent runtime.

There is one direct conflict: CAP-11 says “Driving a provider's consumer website
or app is never a route.” CRED-5 also restricts consumer-plan login use to an
unmodified provider CLI. Under the supplied premise, a consumer inference UI
without an equivalent structured interface is a possible computer-use substrate.
It needs a separately declared and qualified executor; it cannot be enabled by
merely deleting CAP-11's sentence or using CRED-5's CLI exception for a browser.

Proposed L1 decision, outside the normative specification for batch review:
1. Preserve CAP-11 as the declaration for provider CLI workers.
2. Add a separate computer-use declaration for consumer inference UIs when no
   equivalent structured route meets the task. Explicitly reconcile CRED-5 with
   broker-owned browser custody under CRED-4 and any desktop qualification under
   ADP-5. The worker-held CLI exception grants no access to browser cookies.
3. Express the supplied premise across CAP-2, ADP-3/4/7, CAP-9/12 and the relevant
   CRED-5 language. Route identity and quota pools remain separate for each
   product; a UI route is never represented as a CLI or API route.
4. Extend acceptance cases A5/A6/A13/A14/A15 to cover the same operation and
   adversarial inputs across each qualified substrate, including consumer UIs.

Routing contract to freeze

Describe the business capability before choosing a substrate: operation, exact
account/recipients/visibility, required fidelity and evidence, reversibility,
data label, resource envelope and recovery properties. “Narrowest” means least
exposed execution capability that still satisfies this complete contract. A
cheap API that omits a required feature is not equivalent; a headless browser
can be the narrowest adequate route when that feature exists only in the UI.

Apply these filters before ordering: explicitly granted; qualified for operation
and version/profile; correct account custody and permitted data label; resource
admission and pool; healthy; recovery/evidence capability. Among equivalent
routes use the ADP-3 order. If their exposed capabilities cannot be ordered,
retain a declared default and require reviewed measurement before optimizing.
Return an unavailable/held reason when no admissible route exists. Task preferences
cannot add grants, change reversibility, or widen origins or disclosure.

An executor declaration needs: route ID, substrate, account reference (broker only),
operation-to-fixed-verb mappings, required capabilities, immutable image/version,
origins and auth/challenge origins, allowed protocol/actions, login custody,
label permission, resource/pool limits and observability confidence, recovery
strategy, result/evidence formats and retention, supported cancellation,
qualification bundle/hash and health/drift checks. Guest-visible resources omit
account identity and credentials. Reserve claims must match what is enforceable:
a UI-reported quota is untrusted/advisory until independently qualified.

Computer-use authority boundary

Authorize a business operation, not a free-form “use the account” session. Bind
its account, parameters, recipients, visibility and expected state transition to
the intent. The broker-owned executor enforces the reviewed adapter trajectory
and per-step preconditions; snapshot refs are bound to a page/session/generation
and expire on navigation or material state change. The model cannot supply an
arbitrary script, raw keyboard escape, URL token or inferred grant to extend it.

A click can send, buy, share, delete or reveal a secret. The S5 fixed verb list
alone does not identify those business effects. CRED-4b therefore needs the
adapter's fixed ADP-2 mapping plus predispatch OP-3 checks at each effect boundary.
An unknown or changed UI state holds the operation for repair; it does not
silently convert a read into an irreversible click. Automation's internal trusted
Playwright implementation may use JavaScript; model-supplied JavaScript stays
absent from the protocol. System chrome, developer tools, clipboard credentials,
OS launchers, and unrestricted file dialogs are outside agent authority.

Headless does not imply unattended authentication or bypass of a human check.
Owner sign-in and human challenges use the existing local live view where needed;
the executor resumes only with the already-authorized operation. Browser or app
content, screenshots, downloads, accessibility text, OCR and UI-service output
are untrusted data. They cannot become owner commands, approvals or grants.
Use structural account/origin isolation and gates; content classifiers are
additional signals, not the authority boundary. Credentials, secret-reveal pages
and screenshots obey CRED-1/6/7/10, including cookie/profile snapshot exclusions.

Recovery without equivalent structured receipts

Persist dispatch intent before the first step that may create an external effect.
A lost UI acknowledgment means outcome_unknown. Observe a stable service result,
receipt, draft/sent state or history through a qualified read path, bound to the
account and operation. Lack of a visible receipt is not proof nothing happened.
No new attempt or substrate failover repeats the effect until reconciliation
resolves it. When the service offers no safe reconciliation, hold and explain
the unknown outcome; capability preservation includes that limitation.

Keep approval, permission, observed execution result and goal quality separate.
Receipts contain operation identity, route/image/protocol version, observation
provenance, verified effect state, result hash, timestamps, resource attribution,
and recovery status. Screenshots are optional supporting artifacts after secret
checks, not sole proof of recipients or successful delivery. Owner/private content
stays private-derived, including images and saved UI sessions.

Reviewable sequence

SUB-A: approve the above reconciliation and declaration/selection contract.
SUB-B: run fixture qualification for API-equivalent, CLI-equivalent, UI-only,
       browser and kiosk operations against identical business-state oracles.
SUB-C: CRED-4b broker wiring with actual isolation/custody and effect gates, using
       S5's closed protocol; qualification precedes route advertisement.
SUB-D: Linux ADP-5 kiosk and a separately declared consumer inference UI fixture;
       live-account, current-provider and floor-host qualification remain later.
SUB-E: comparative A10 experiment including qualified computer-use task classes.

The dependent INT-A proposal supplies qualification-cases.json and substrate-workloads.json with
synthetic inputs, business-state oracles and failure decisions. They are test
specifications, not an executor implementation or evidence of qualification.

Exact reconciliation proposed in this draft

CAP-13 records the supplied premise. CRED-5 retains the CLI modes and scopes their
client restriction to CLI credentials while requiring broker-owned custody for
computer use. CAP-11 names consumer UI as a separate route; CAP-12 exposes its
kind without credentials. ADP-3 compares full capability and preserves gates.
CAP-9 holds when no equivalent route can continue instead of promising an API
fallback for a UI-only feature. OP-8 declares bounded run admission, no overage
and advisory UI quota for computer-use inference; no token count is invented.
These metering and fallback clauses need explicit independent L1 review along
with custody. The draft enables no executor, account, grant or runtime route.
