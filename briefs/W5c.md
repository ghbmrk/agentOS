# W5c: Clean-room builder

Board section: Integration: wiring merged packages into the box.

Clean-room builder (#43 C11): PS2 (its spare-meter share with a `Max`, or its own Source) and PC1 (ARC-6 (d) uncredentialed egress before `adapter_gap` hints)

**Precondition:** #43 merged, W3

**Owner:** clean-room thread (P4-2)

**State on the board before the 2026-10-08 index split:** queued

## Scope

`broker/cleanroom/builder.go`, `broker/cleanroom/services.go`, `broker/meter/**` (PS2 spare-meter share), `broker/egress/**` (PC1 uncredentialed egress before `adapter_gap` hints), `broker/cmd/agentos-builder/**`. Tier A. Blocked on #43 and W3.
