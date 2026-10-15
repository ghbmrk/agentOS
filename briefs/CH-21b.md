# CH-21b: Box name: setup suggestion and NAME

Board section: Backlog refill (2026-10-05). Part of CH-21 (briefs/CH-21.md); SPEC CH-21, A14.

CH-21 / CH-11 `NAME`: the name at setup (suggested made-up full name on the contact-card screen), validation per SPEC CH-21 (1 to 32 letters, spaces, hyphens, apostrophes; not a control word; no "AgentOS"/"assistant"; not the owner's name), `NAME <name>` held for an unlock with fixed-wording confirmation and the name check, spoofed NAME refused (LATER.md CH-21 row).

**Needs:** CH-21a

**Gate:** lenses (security first: V1, V2)

## Scope

`broker/boxname/boxname.go`, `broker/boxname/boxname_test.go`, `broker/owner/channel.go` (the `NAME <name>` command and its held confirmation), `broker/control/handler.go`, `broker/loops/plainname.go`, `broker/localui/server.go` (contact-card suggestion). Tier A. Overlaps CH-21f and the CH-21 sweep.
