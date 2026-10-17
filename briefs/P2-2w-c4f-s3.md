# P2-2w c4f s3: Sandbox the setup vault's root oneshot

Work item #1387 (lane:primary, class:release, tier A). Release finding on the setup services (image/ASSUMPTIONS.md I14).

**Requirements:**
- HW-10: the box sets itself up from the claim; the setup vault is made when the page records the claim.
- CRED-9: the vault and its keys are held only by the vault process; the root step that makes the setup vault gets no more reach than it needs.

**Acceptance tests:** `SetupServicesTest.test_the_setup_vault_s_oneshot_is_sandboxed` (tests/test_image.py) pins each sandbox line of `agentos-egress-setup.service`; the existing `test_the_setup_vault_is_made_when_the_page_records_the_claim` and `EgressSetupTest` still pass unchanged; the booted image's e2e (image.yml) still claims the box and pairs, which needs the path unit to make the setup vault and restart agentos-egress under the new sandbox (broker/e2e/boxe2e/ASSUMPTIONS.md E3).

**Implementation risk:** tier A. **Needs:** nothing open.

## Scope

- `image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-egress-setup.service`
- `tests/test_image.py`
- `image/ASSUMPTIONS.md` (row I14)
- this brief

## What to build

`agentos-egress-setup.service` runs `/usr/lib/agentos/egress-setup --restart` as root with no sandbox. It needs only: a lock and a temporary directory in `/run`; to search the vault's and the page's 0700 state directories; `setpriv` to the page's and the vault's users; `chown` of its temporary directory; the vault's state directory writable for `init -setup`; and `systemctl try-restart` over `/run/systemd/private`. Give it the sandbox those allow:

- `CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE`, no ambient capabilities, `NoNewPrivileges=yes`.
- `ProtectSystem=strict`, `ReadWritePaths=/run -/var/lib/agentos-egress` (`-`: the script exits 0 when the directory is missing, so the namespace must not fail first), `ProtectHome`, `PrivateTmp`, `PrivateDevices` (init -setup uses no TPM), `PrivateNetwork`, `RestrictAddressFamilies=AF_UNIX`.
- `ProtectKernelTunables/Modules/Logs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`, `SystemCallArchitectures=native`, `SystemCallFilter=@system-service` (it holds `@setuid` and `@chown`), `UMask=0077`, `ProtectProc=invisible`, `PrivateIPC`.
- Not `ProcSubset=pid`: the claim check reads `/proc/sys/kernel/random/boot_id`.

## Out of scope

The `+` ExecStartPre copy of egress-setup inside agentos-egress.service (runs outside that unit's namespace by design); the script itself.

## Estimate

~60k tokens.
