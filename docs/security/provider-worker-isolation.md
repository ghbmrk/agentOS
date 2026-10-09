# S8-W1a: gap map to S8-W1 and LATER

Inventory source: [provider-worker-surfaces.csv](provider-worker-surfaces.csv);
result: [provider-worker-feasibility.md](provider-worker-feasibility.md). Source
draft credit: #262. Anchors at `256b7cc`.

## Trust model

Model-directed tools, workspace contents and returned worker results are hostile.
Under CRED-5 a worker-held CLI may hold its own login; its tools may not
inherit that authority, and every external effect still goes through the broker.

## Gap to step

| Surface (CSV row) | Gap | Where it is handled |
|---|---|---|
| Bash or exec subprocess | Default leak via parent `/proc/<pid>/environ` | S8-W1: bwrap prefix for agentos-toolsh, containment test (BOARD hand-off note) |
| Built-in Read/Glob/Grep, Edit/Write | In-process file tools not shown to run outside the CLI identity | S8-W1: managed-settings denies, observed per tool |
| Plugins, MCP, hooks | Not disabled | S8-W1: managed policy; observation per pinned CLI |
| WebFetch, WebSearch, remote sessions | Server-side tools not disabled | S8-W1 managed policy; tunnel part below |
| Parent ptrace, memory, fd | Same-UID read | S8-W1: separate UID plus PID namespace |
| Provider inference tunnel | No CONNECT/SNI tunnel built | Release, LATER.md `S8-W1-tunnel` (blocks S8-live); live check in S8-live |
| Credential login volume | No volume, schema check or mount rule | Release, LATER.md `S8-W1-volume` (build); W2 qualification in S8-live |
| Cross-job persistence | Destroy/clear handles untested for a login volume | S8-W1 containment test |
| Snapshot, recall, journal, result | Volume exclusion unbuilt; scanning is a tripwire only | Build: LATER.md `S8-W1-volume`; S8-W1 proves it; scan coverage already in `tools/canary.py` |
| Quota refresh label | Real-account behaviour unmeasured | S8-live |

## Adversarial cases S8-W1 should cover

Read of the login by environment, `/proc` environ/mem/maps/fd, ptrace and
`process_vm_readv`, symlink and traversal, via every enabled tool and via another tool
or plugin; privilege changes and setuid; encodings (raw, hex, base64, URL, fragments),
with denied read capability as the primary proof and scanning as added coverage;
direct-IP, DNS, IPv6 and inherited-socket egress; config/hook/binary writes not
surviving a fresh job; no login bytes in snapshot, journal, recall, result or log.
Use synthetic canaries only; reports keep fingerprints, not values.

Implementation state: inventory only. No provider route is enabled.
