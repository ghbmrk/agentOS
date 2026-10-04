# Assurance gates: canary (A5) and dependency audit (A9)

Two permanent CI jobs in `.github/workflows/assurance.yml`, run on every PR, on
`main`, and daily with fresh canaries. Both are stdlib-only Python, so they add
no dependency of their own.

Each harness runs hard-coded **controls** (deliberate leaks it must catch, and
broken targets it must call errors) before the **product targets** listed in the
registry. A clean result on a product target counts only because the same run
caught every control. Registries hold product targets only, and each must expect
`clean` / `pass`: no registry edit can relax a gate or drop a control. Until P1-3
(vault) and P1-2 (broker) register targets, only controls run, and the jobs print
a note saying so.

## Canary harness (`tools/canary.py`, registry `canary-targets.json`)

Per round the harness mints one fresh canary of every kind (API key, bearer token,
session cookie, password, TOTP seed, private key, recovery code; each at least 128
bits of entropy, shaped like the real thing, no shared marker) and runs the target
command with:

| Variable | Meaning |
|---|---|
| `CANARY_PLANT` | JSON file of `{kind, value}` canaries. Trusted side only: load them into the vault or a credentialed browser session. |
| `CANARY_ACK` | The trusted side writes `{"loaded": [fingerprint, ...]}` here, one per canary it actually loaded (`canary.fingerprint(value)`: first 16 hex digits of SHA-256). |
| `CANARY_SURFACE_DIR` | Copy here everything the adversary could reach: guest files, `canary.py sweep` dumps, protocol transcripts, packet captures. |

The harness scans that directory and the target's stdout and stderr. A canary is
caught raw, as hex, URL-encoded, UTF-16, base64 at any alignment inside a larger
blob, in upper or lower case (hex and base32 kinds), as any fragment of its secret
core at least 15 characters long, and, for kinds whose text is an encoding (hex
cookie, base32 TOTP seed, base64 key, base64url token), as its decoded bytes or
any decoded fragment of at least 10 bytes. Reports carry fingerprints, kinds,
encodings, and locations, never values, and the harness checks its own report
before writing it.

A round is an **error**, never clean, when the target exits nonzero, the ack is
missing or incomplete, the surface is empty, or the scan budget (`--max-bytes`,
default 4 GiB) runs out. `canary.py sweep` likewise fails rather than truncate.

The adversary with full root is `canary.py sweep --root / --pid all --out DIR`,
run inside the guest: it dumps every readable file and every process's
environment, command line, and readable memory.

Register a target:

```json
{"name": "vault-egress", "cmd": ["broker/test/canary-target.sh"]}
```

Product targets always expect `clean`; the registry refuses anything else.

## Dependency audit (`tools/depaudit.py`, registry `dep-targets.json`)

`run` executes each scenario (boot, take STOP and STATUS, recover) in fresh user,
network, and mount namespaces: loopback only, DNS answered NXDOMAIN by a logging
sink, and every `connect`/`send*` of the process tree logged by strace. Host
directories that hold filesystem sockets (`/run`, `/var/run`, `/tmp`, `/var/tmp`,
and `/dev/log`) are hidden under empty tmpfs mounts, so nscd, systemd-resolved,
D-Bus and the like are unreachable, not merely logged. CI also sets
`kernel.io_uring_disabled=2` and the run checks it, because io_uring socket calls
bypass strace. A scenario passes only if it exits 0 and makes no non-loopback
attempt, no DNS lookup (including any loopback port 53 traffic), no attempt at a
host-wide Unix socket, and no socket family the parser does not recognise as
namespaced (`AF_VSOCK` and the like fail closed, as does any sockaddr it cannot
parse). This is the A9 run with every optional dependency removed.

`static` checks that every network endpoint literal in shipping code (`broker/`,
`src/`, excluding tests) is declared in `dependencies.json` with its SPEC.md §2
class, and that nothing matches a forbidden (AgentOS-operated) pattern, even if
declared (DEP-2).

Register a scenario (it must expect `pass`):

```json
{"name": "broker-offline", "cmd": ["broker/test/a9-scenario.sh"]}
```

## Known limits

- The detector finds encodings, not compression or encryption. A target must hand
  over decompressed surfaces; encrypted data at rest is out of scope by design.
- Scanning runs at roughly 13 MB/s per core in pure Python, so a 4 GiB budget is
  minutes, not seconds. Base64 renderings of partial fragments are not indexed;
  full-value base64, text fragments, and decoded fragments are.
- AF_VSOCK and other non-namespaced families are detected and fail the run, but not
  blocked: a seccomp filter would be the enforcement, if a target ever needs it.
- The static scan reads URL literals and skips comment lines and test files. It is
  a tripwire, not a parser; the runtime audit is the authority.
