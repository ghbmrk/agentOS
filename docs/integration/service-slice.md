# INT-A: actual service fixture slice (design before implementation)

INT-A / INT-B / INT-C — concrete fixture runner contract

Only after external design approval should the proposed runner be implemented.
The runner should build the exact pinned binaries and image, then exercise the
production constructors and wire protocols below. Separate Linux identities are
required; substituting one UID or NoCgroups/NoQuota invalidates the corresponding
qualification cases, even if convenient unit fixtures still pass.

Service identities and interfaces

- agentosd: owns grants, journal, channel, guest plane and resource admission.
  Serves owner.sock with modem peer UID; localui.sock with local UI peer UID;
  guest sockets with machine attribution. Connects to model.sock, verify.sock,
  routing.sock on the vault process. No reusable vault secret in its environment.
- agentos-egress (the vault process; no separate agentos-vault binary): owns vault
  and serves model.sock/routing.sock/verify.sock to broker UID, unlock.sock to
  local UI UID, sign.sock/sms.sock to modem UID if configured. Reject same-UID or
  missing peer configurations as production does. Unlock via synthetic owner
  factors using the existing local API; never an allow-all verifier.
- agentos-modem: separate peer, only service allowed on owner.sock. Exercise the
  real inbound/outbox/sent/state bridge protocol; owner-message/raw message is
  explicitly a simulator bypass and cannot establish bridge authorization.
- agentos-localui: separate peer on localui.sock/unlock.sock. Use real ticket,
  session/token and tier-4 local confirmation. Unconfigured setup and finished
  setup are separate snapshots; test replay of a completed setup token.
- unmodified OpenClaw in its registered gVisor image and launch configuration,
  with real cgroups, project quota and disk reserve. Its model egress crosses the
  actual vault router; stub inference only on a fixture-declared destination.
- fake external service owns durable business receipts outside the AgentOS
  restart domain. It supports deliberately lost replies and read-only receipt
  lookup, keyed by account and semantic intent ID. It never returns an owner code.

Fixture operations

I-read: read a public synthetic report. No outbound mutation; exact report hash.
I-send: draft a report and send to one granted synthetic recipient after approval.
I-private: read a synthetic private note and refuse a public or ungranted route.
I-control: looping/offline inference, inbound flood, then authenticated STOP and
STATUS; no dispatch after STOP boundary and unresolved effects are reported.
I-ui-only: required export exists only in the browser fixture; choose admitted
computer use and apply the same disclosure, intent and receipt checks.

Use fixtures/qualification/workloads.json for business-state inputs and expected
outputs. Generate synthetic sign-in factors only inside fixture-owned state;
never echo credentials or approval values in reports. Freeze the model response
sequence/hash and fixture account seed. External effects use a deterministic
receipt identity, while inference/tool transcript inputs remain adversarial.

Fault hooks (runner-owned, absent from production defaults)

F0: authorization complete, before dispatch recheck -> revoke grant or label.
F1: dispatch journal persisted, before external service receives request.
F2: external receipt persisted, acknowledgment dropped; kill broker or executor.
F3: acknowledgment observed, before settlement/result persists.
F4: settlement persists, before result notification; restart owner channel.
F5: owner approval pending; restart and try stale code/session/token.
F6: vault locked, inference offline, saturation of guest and bridge input.
F7: UI target changed after snapshot, cross-origin redirect or challenge appears.

At F1 an operation may have crossed the service boundary; classification must
follow authoritative transport evidence, not merely the hook name. Faults whose
acknowledgment is ambiguous stay outcome_unknown. Invariant: duplicate external
effects = zero, including a switch to another execution substrate. Notification
duplication is tracked separately and does not establish effect duplication.

Named proposed tests and acceptance

TestINTActualServiceOwnerTask: authenticated channel -> guest -> gate -> adapter
-> observed result. Existing e2e tests supply components, not this complete proof.
TestINTPeerUIDMatrix: every listed socket, correct/wrong peer plus spoofed JSON
identity; the production SO_PEERCRED decision wins.
TestINTRecoveryBoundaryMatrix: every F0-F7, durable restart, same/different params
under same ID; receipt/effect counts and unresolved state asserted separately.
TestINTSTOPUnderPressure: inference, disk and channel stress; preserve control
resources. Measure latency; numeric gate remains unset until floor freeze.
TestINTQuotasAndDevices: production quota/cgroup/device policies exercised, not
only existence of configuration directives.
TestINTSubstrateFailoverUnknown: UI service may have acted; no repeat through API
or CLI until account reconciliation resolves the original intent.

Each row in fixtures/qualification/service-and-substrates.json carries requirement IDs, setup,
trigger, oracle and available evidence. Reviewers must curate full normative
coverage; named tests do not automatically qualify G2 or G4.

Image dependency checklist

Coordinate image #175 at 15139f34 with P2-4 vault/volume protection, P2-2w onboarding
and HOST-1a/1c. Add the vault service/socket/ACL and UID wiring on its own follow-up;
verify encrypted owner/machine/learn state, immutable executable/configuration
paths, vault unknown-host behavior, disk split/reserve and prjquota, delegated
cgroups, root-unit DevicePolicy/accelerator allowances, no host disk auto-mount,
no host RTC/firmware changes outside disclosures, and inactive setup after finish.
QEMU needs software TPM and Secure Boot, a second internal disk and a USB disk.
Cloud tests do not replace real N95/firmware/three-vendor boot sessions.

Exact prerequisites currently missing

No production gVisor image, delegated writable cgroup, project-quota fixture
volume or QEMU binary was provided to this session. Software TPM was made
available locally for component tests. The actual assembled runner has not been
implemented or qualified. The above artifacts let reviewers approve one concrete
package rather than discover its boundaries during implementation.
