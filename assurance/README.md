# Assurance gates: canary (A5) and dependency audit (A9)

Two permanent CI jobs in `.github/workflows/assurance.yml`, run on every PR, on
`main`, and daily with fresh canaries. Both are stdlib-only Python, so they add
no dependency of their own.

Each registry lists **controls** (deliberate leaks the harness must catch) next to
the **product targets**. A clean result on a product target counts only because
the same run caught every control. Until P1-3 (vault) and P1-2 (broker) register
targets, only controls run, and the jobs print a note saying so.

## Canary harness (`tools/canary.py`, registry `canary-targets.json`)

Per round the harness mints one fresh canary of every kind (API key, bearer token,
session cookie, password, TOTP seed, private key, recovery code; each at least 128
bits of entropy, shaped like the real thing, no shared marker) and runs the target
command with:

| Variable | Meaning |
|---|---|
| `CANARY_PLANT` | JSON file of `{kind, value}` canaries. Trusted side only: load them into the vault or a credentialed browser session. |
| `CANARY_SURFACE_DIR` | Copy here everything the adversary could reach: guest files, `canary.py sweep` dumps, protocol transcripts, packet captures. |

The harness scans that directory and the target's stdout and stderr. A canary is
caught raw, as hex, URL-encoded, UTF-16, base64 at any alignment inside a larger
blob, or as any fragment of its secret core at least 15 characters long. Reports
carry fingerprints, kinds, encodings, and locations, never values, and the
harness checks its own report before writing it.

The adversary with full root is `canary.py sweep --root / --pid all --out DIR`,
run inside the guest: it dumps every readable file and every process's
environment, command line, and readable memory.

Register a target:

```json
{"name": "vault-egress", "cmd": ["broker/test/canary-target.sh"], "expect": "clean"}
```

Expectations: `clean` (default for product targets), `leak` (controls; every kind
must be caught in every round), `error` (the target crashed; never counts as clean).

## Dependency audit (`tools/depaudit.py`, registry `dep-targets.json`)

`run` executes each scenario (boot, take STOP and STATUS, recover) in fresh user,
network, and mount namespaces: loopback only, DNS answered NXDOMAIN by a logging
sink, and every `connect`/`send*` of the process tree logged by strace. A scenario
passes only if it exits 0 and makes no non-loopback attempt, no DNS lookup, and
no connection to a host-wide Unix socket (nscd and systemd-resolved would carry
lookups out of the namespace). This is the A9 run with every optional dependency
removed.

`static` checks that every network endpoint literal in shipping code (`broker/`,
`src/`, excluding tests) is declared in `dependencies.json` with its SPEC.md §2
class, and that nothing matches a forbidden (AgentOS-operated) pattern, even if
declared (DEP-2).

Register a scenario:

```json
{"name": "broker-offline", "cmd": ["broker/test/a9-scenario.sh"], "expect": "pass"}
```

## Known limits

- The detector finds encodings, not compression or encryption. A target must hand
  over decompressed surfaces; encrypted data at rest is out of scope by design.
- DNS over TCP to the loopback sink is not name-logged; such a lookup still fails.
- The static scan reads URL literals and skips comment lines and test files. It is
  a tripwire, not a parser; the runtime audit is the authority.
